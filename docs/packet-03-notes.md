# Packet 03 — Detection Engine Design Notes

## Decisions

### detect.Check signature
Takes `db.CompiledEntry` (not just `db.Confirm`) so the function has access to
pre-compiled `CompiledPatterns` / `CompiledNegate` from the loader. Zero
recompilation per request.

### Body cap (MaxScanBytes = 1 MiB)
The detector scans only the first 1 MiB of a response body. Bodies larger than
this are almost certainly not the target file (HTML error pages tend to be
small; large files are detected in the first few bytes anyway). This bounds
memory and prevents adversarially large responses from causing excessive work.

### minBodyLen = 4 bytes
Responses shorter than 4 bytes cannot contain any meaningful content
(shortest real confirm keyword is `net:` at 4 chars). This filters empty 200s
and single-byte responses without needing a separate zero-body check.

### Non-2xx status = automatic miss
The status check happens before any pattern matching. This encodes the
semantics: the file wasn't read if the server returned an error code. The
response body content is irrelevant for error responses.

### Keyword confirm: case-insensitive
`strings.ToLower` on both body and pattern. This handles `NAMESERVER` in
resolv.conf being matched by a lowercase keyword pattern.

### keyword-all: requires ALL patterns, ignores MinMatches
The `keyword-all` type semantics are ALL-or-nothing. `EffectiveMinMatches` is
not applied here — if 3 patterns are given, all 3 must appear. This matches
the intended use case (e.g., Laravel `.env` needing both `APP_KEY=` and
`DB_PASSWORD=`).

### Scan output format
- `[CONFIRMED]` prefix for confirmed hits with snippets
- `[responded]` prefix for unconfirmed (200 but pattern miss, non-2xx, etc.)
- `--only-hits` suppresses `[responded]` lines entirely
- Summary line at end: total requests, confirmed, unconfirmed counts

### Decoy fixture
`testbed/fakeroot/etc/error-decoy` contains a PHP-style error page that echoes
a path. It proves two things:
1. Getting a 200 response alone is NOT sufficient for a hit
2. The negate logic correctly suppresses matches in error pages

### E2E test architecture
Integration tests use `net/http/httptest.Server` serving from `testbed/fakeroot/`.
This is faster and more portable than starting the real testbed process. The
`findFakeroot` helper walks up from the test's working directory to locate the
fakeroot, so the test works whether run from the repo root or the package dir.
