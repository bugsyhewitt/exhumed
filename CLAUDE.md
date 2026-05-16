# exhumed — Developer Guide for Claude Code Sessions

## What this project is

`exhumed` is a modern Local File Inclusion (LFI) exploitation CLI written in Go.
It is a revival of `panoptic` (github.com/lightos/Panoptic), a Python 2 LFI tool
that died around 2014. The moat is the **file database**, not the code — knowing
which files matter and what to extract from them is the value. The request
pipeline is intentionally boring plumbing.

Given a parameter known or suspected to be vulnerable to LFI/path traversal,
`exhumed` walks a curated database of high-value file paths, confirms which files
are readable, extracts content, and uses that content to generate follow-on targets
recursively.

## Locked technical decisions

- **Language:** Go, latest stable release
- **CLI framework:** `spf13/cobra`
- **License:** MIT. No GPL/AGPL/LGPL dependencies — MIT/BSD/Apache-2.0 only
- **Distribution:** Single static binary. `CGO_ENABLED=0`. No cgo
- **Module path:** `github.com/bugsyhewitt/exhumed`
- **Go version:** directive tracks installed minor version

## Repository layout

```
cmd/exhumed/       — Thin entrypoint; delegates immediately to internal/cli
internal/cli/      — cobra command tree: root, scan, version, update (stub)
internal/engine/   — Concurrent HTTP engine; defines Request and Result types
internal/inject/   — Marker substitution across 5 surfaces (query, body, header, cookie, JSON)
internal/traversal/ — LFI traversal payload generator; defines Payload struct
internal/version/  — Build-time version/commit/date vars set via -ldflags
testbed/server/    — Deliberately-vulnerable dev server (localhost only, sandboxed)
testbed/fakeroot/  — Fake filesystem fixtures for the testbed
docs/              — Design notes and packet decisions
.github/workflows/ — CI (build + vet + test)
```

**Reserved for later packets (do not create prematurely):**
`db/`, `detect/`, `extract/`, `chain/`, `feed/`, `output/`, `database/`

## Packet-based workflow

Work arrives in numbered packets. Each packet has a strict scope:

| Packet | Scope |
|--------|-------|
| 01 | Scaffold, HTTP engine, injection layer, traversal generator, testbed |
| 02 | File database (local, versioned) |
| 03 | Detection engine (regex/keyword confirmation) |
| 04 | Content extraction (format-aware parsers) |
| 05 | Remote feed (`exhumed update`) |
| 06 | Recursive follow-on chaining |
| 07 | JSON-first output + TTY mode |
| 08 | Single static binary release via GoReleaser |

**Do not scope-creep beyond the current packet.** If a later packet's reserved
directory doesn't exist, don't create it — that's intentional.

## Key type contracts (defined in Packet 01, depended on by all later packets)

```go
// engine.Request — the injection template
type Request struct {
    Method  string
    URL     string
    Headers http.Header        // canonical Go HTTP headers
    Cookies map[string]string  // name → value
    Body    []byte
}

// engine.Result — the HTTP response outcome
type Result struct {
    URL        string
    StatusCode int
    Headers    http.Header
    Body       []byte
    Elapsed    time.Duration
    Err        error
}

// traversal.Payload — a single LFI payload with metadata
type Payload struct {
    Value     string  // the payload string
    Technique string  // e.g. "dotdot-slash", "url-encoded"
    Category  string  // "traversal" or "wrapper"
}
```

If you need to change these types, understand that Packets 02–08 depend on them.
Discuss before breaking changes.

## Conventions

- **Error wrapping:** `fmt.Errorf("context: %w", err)` — always wrap with context
- **Doc comments:** all exported types and functions get a doc comment
- **Formatting:** `gofmt`-clean — run `gofmt -l .` before committing
- **Dead code:** no TODO-as-implementation; no half-finished logic
- **No panics** in library code; CLI may `os.Exit(1)` with a clear message
- **Single shared http.Client** — never create one per request

## Running the testbed

```bash
# Start (binds 127.0.0.1:8080, prints warning banner)
go run ./testbed/server

# Custom port
go run ./testbed/server -port 9090

# The fake filesystem is in testbed/fakeroot/ — edit fixtures there
```

**Safety requirement:** the testbed is sandboxed to `testbed/fakeroot/` and
cannot read real host files. The containment check uses `filepath.Clean` +
`strings.HasPrefix(resolved, absRoot+"/")`. Do not modify this logic without
understanding the security implications.

## Running tests

```bash
CGO_ENABLED=0 go test ./...         # full suite
CGO_ENABLED=0 go test -v ./internal/inject/...    # inject unit + integration
CGO_ENABLED=0 go test -v ./internal/traversal/... # traversal unit tests
CGO_ENABLED=0 go test -v ./internal/engine/...    # engine unit tests
```

## Building

```bash
CGO_ENABLED=0 go build -o exhumed ./cmd/exhumed
```

With version metadata:
```bash
CGO_ENABLED=0 go build \
  -ldflags "-X github.com/bugsyhewitt/exhumed/internal/version.Version=0.1.0 \
            -X github.com/bugsyhewitt/exhumed/internal/version.Commit=$(git rev-parse --short HEAD) \
            -X github.com/bugsyhewitt/exhumed/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o exhumed ./cmd/exhumed
```
