# Changelog

All notable changes to `exhumed` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-06-19

The first production-ready release of `exhumed`, a modern LFI / path-traversal
exploitation CLI written in Go and a revival of the abandoned `panoptic` Python 2
tool. All 7 roadmap packets are complete (file database, remote feed, detection
engine, content extraction, recursive chaining, JSON output, single static binary).
The GoReleaser cross-compile pipeline (Packet 08) is a follow-up packet; operators
can install from source via `go install github.com/bugsyhewitt/exhumed/cmd/exhumed@v1.0.0`.

### Added

- **Repo scaffold, HTTP engine, injection layer, traversal generator, testbed** — Packet 01: spf13/cobra CLI, custom HTTP engine (single shared `http.Client`), injection layer covering 5 surfaces (query / body / header / cookie / JSON), traversal payload generator, deliberately-vulnerable testbed server sandboxed to `testbed/fakeroot/`.
- **Versioned file database** — Packet 02: 63 curated high-value file paths loaded from local files, spanning OS, web-server, framework, cloud, CI/CD, version-control, credential-store, and language-runtime targets. Schema-validated via `exhumed db validate`.
- **Remote feed** — Packet 05: `exhumed update` pulls the latest database from a versioned feed (atomic temp-write + rename swap).
- **Detection engine** — Packet 03: confirms successful inclusion via regex / keyword / keyword-all matching across body / header / title / size / time / word / line / code / body-json / response-status filters.
- **Content extraction** — Packet 04: format-aware parsers for passwd, PHP config, env files, YAML / JSON / TOML configs, AWS credentials, GitHub tokens, etc.
- **Recursive follow-on chaining** — Packet 06: uses extracted content (PWD, DOCUMENT_ROOT, AWS keys, etc.) to generate next targets and queue them as depth+1.
- **JSON-first output** — Packet 07: machine-readable results (`--output json` / `--output csv`) plus a human TTY mode. Schema versioned (`schema_version: "1"`).

### Changed

- Version constant bumped from `dev` to `1.0.0` (production-ready release). The `-ldflags "-X ...internal/version.Version=1.0.0"` build now produces a binary whose `exhumed version` reports `exhumed 1.0.0 (commit: ..., built: ...)` instead of `exhumed dev (commit: none, built: unknown)`.
- README §Status updated from `Under active development — pre-v1.0.` to `Released as v1.0.0. APIs are production-stable.`
- README §Build-from-source example release-build `-ldflags` bumped from `Version=0.1.0` to `Version=1.0.0`.
