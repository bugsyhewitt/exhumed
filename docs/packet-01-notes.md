# Packet 01 — Design Notes

## What was built

Repo scaffold, HTTP engine, injection layer, traversal payload generator,
deliberately-vulnerable testbed server, unit and integration tests, CI workflow.

## Decisions made

### engine.Request header type: `http.Header`

**Decision:** `Request.Headers` uses `http.Header` (`map[string][]string`)
rather than `map[string]string`.

**Reason:** `http.Header` is the canonical Go HTTP type. Using it directly
avoids conversions when building `http.Request`, supports multi-value headers,
and lets callers use `.Set()`, `.Add()`, `.Get()` with canonical key handling.
The inject layer's `Clone()` call is also free on this type.

### engine.Request cookie type: `map[string]string`

**Decision:** Cookies use `map[string]string` rather than `[]*http.Cookie`.

**Reason:** The injection use case only needs name→value substitution. A flat
map is simpler and sufficient; callers that need attributes like `HttpOnly` can
extend this in a later packet.

### Traversal payload ordering

**Decision:** plain `../` first, then Windows, then mixed, then encoded, then
exotic (null-byte, absolute), then wrappers last.

**Reason:** Plain sequences work on the broadest range of vulnerable targets.
Encoded variants are useful against WAFs and input sanitisers. Wrappers are
PHP-specific and low-frequency, so they run last to avoid noisy requests on
non-PHP targets.

### Traversal: `....//` mixed-separator technique

**Decision:** Each level of the mixed-separator technique is `....//` (four
dots, two slashes), not `../` with mixed separators.

**Reason:** The canonical bypass for naive `../` stripping is `....//` — when
the application strips `../` once, `....//` collapses to `../`. This is the
form documented by dotdotpwn.

### Demo path in `scan`

**Decision:** `scan` uses `etc/passwd` as a hardcoded demo path to make the
pipeline exercisable end-to-end in Packet 01.

**Reason:** The file database arrives in Packet 02. Rather than stub with no
output, `etc/passwd` provides a meaningful sanity check against the testbed.
This is clearly labeled as a demo and will be replaced.

### Testbed sandboxing: `filepath.Clean` + `strings.HasPrefix`

**Decision:** The testbed uses `filepath.Join(absRoot, filepath.Clean("/"+userPath))`
followed by `strings.HasPrefix(resolved, absRoot+string(os.PathSeparator))`.

**Reason:** `filepath.Clean` normalises all traversal sequences (`../`, `./`,
double slashes). Joining with the absolute root before the prefix check means
the resolved path must start with the root — path escapes return 403. The
trailing separator in the prefix prevents the `/tmp/fakeroot2` prefix collision
edge case.

**Known limitation:** Symlinks inside the fakeroot could escape the sandbox if
the symlink target points outside. This is acceptable for a dev-only testbed;
a production tool would use `os.Readlink` resolution or chroot.

### Parallel agents failed

**Decision:** Implemented traversal and testbed packages sequentially rather
than via parallel background agents.

**Reason:** Background agent dispatch requires a git repo with at least one
commit for worktree creation. The repo had no commits at dispatch time, causing
the agent system to fail with "Cannot create agent worktree". Sequential
implementation completed in the same time budget.

### JSON inject encoding

**Decision:** For JSON surface injection, the body is unmarshalled, values
replaced, and the result re-marshalled via `encoding/json`.

**Reason:** This guarantees that special characters in the payload (double
quotes, backslashes, control bytes) are correctly JSON-escaped in the output,
producing valid JSON. The alternative (raw string replacement in the serialised
document) would break JSON validity for payloads containing quote characters.

**Trade-off:** Unmarshall+marshall may reorder JSON object keys. This is
acceptable — HTTP servers that process JSON don't depend on key ordering.

### go 1.26 directive

**Decision:** `go 1.26` in go.mod (no toolchain directive).

**Reason:** Go 1.21 introduced the `toolchain` directive, but it is optional.
The `go` directive alone is sufficient to express the minimum version. The
installed version (1.26.1) exceeds the directive, which is valid.

## Dependency choices

| Dependency | License | Purpose |
|-----------|---------|---------|
| `github.com/spf13/cobra` | Apache-2.0 | CLI framework |
| `github.com/inconshreveable/mousetrap` | Apache-2.0 | cobra dep (Windows) |
| `github.com/spf13/pflag` | BSD-3-Clause | cobra dep |
| `golang.org/x/time` | BSD-3-Clause | Rate limiter |

All dependencies are MIT/BSD/Apache-2.0 compatible. No copyleft dependencies.

## Risks and watch-items for later packets

- **engine.Request/Result type stability** — these are the type contract for
  Packets 02–08. Changing field types (especially `Headers` or `Body`) will
  require coordinated updates across all downstream packets.
- **inject JSON ordering** — detection/extraction packets should match on
  field *values*, not positional byte offsets in the body, since JSON
  re-serialisation may reorder keys.
- **traversal depth interaction with database** — when the database arrives in
  Packet 02, the traversal generator will need to be driven per-file rather than
  per-scan. The current demo path wiring in `scan` will be replaced wholesale.
- **testbed symlink escape** — document in Packet 03 if detection tests need
  to simulate symlink traversal.
