# Packet 04 — Extraction & Chaining Design Notes

## Decisions

### extract.Parse dispatch by hint
Parser selection is a string switch on `entry.Parser`. Unknown hints fall back
to the generic-secrets sweep rather than returning nothing — this means every
confirmed file at least gets a chance at credential extraction.

### Redaction scheme
`Finding.Redacted = true` marks a finding's value as sensitive. `DisplayValue(showSecrets bool)`
applies `redact()`: shows first 3 + `***` + last 3 characters for values > 8 chars,
or just `***` for shorter values. `--show-secrets` on the scan command passes
`showSecrets=true` through to all print calls.

### chain.Queue thread safety
`sync.Mutex` guards all queue operations. The chain engine is called from the
main scan loop (single goroutine) but could be used from concurrent workers in
future. Safe-by-construction costs nothing.

### synthEntry for chain targets
Chain follow-on targets need a `db.CompiledEntry` to run through the scan
engine. `synthEntry` creates a minimal entry with `type: regex`, pattern `.`
(matches any non-empty body) and infers the parser hint from the path suffix.
This means ANY readable file in the chain is a hit — appropriate for derived
targets where we've already established the scan target is reachable.

### Chain MaxDepth semantics
A Finding at `Depth N` generates Targets at `Depth N+1`. If `N+1 > MaxDepth`,
the target is silently dropped. The default MaxDepth=3 means:
- Depth 0: initial DB walk
- Depth 1: first-generation follow-ons (home-dir SSH keys, etc.)
- Depth 2: second-generation (follow-ons from follow-ons)
- Depth 3: blocked

### Missing parsers for ini-style detection
The `ini-config` parser also handles `env` files by looking for `KEY=VALUE`
and `KEY:VALUE` patterns where the key matches a credential-indicating regex.
This covers both `.env` (equals) and config files using colon separators.

### Testbed fixtures
- `home/app/.ssh/id_rsa` — fake RSA private key for E2E chain test
- `home/app/.bash_history` — fake history for chain completeness
- `home/alice/.ssh/id_rsa` — second user fixture
- `/etc/passwd` updated with `app` and `alice` users and proper home dirs

## Test counts
- extract: 13 unit tests
- chain: 7 unit tests + 3 E2E integration tests = 10 tests
- All existing tests still passing
