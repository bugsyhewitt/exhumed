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

### Local testbed (deliberately vulnerable dev server)

```bash
# Start the testbed (localhost only, sandboxed fake filesystem)
go run ./testbed/server

# Then scan against it
exhumed scan --url "http://127.0.0.1:8080/?file=FUZZ" --verbose
```

### Other commands

```bash
exhumed version          # print version, commit, date
exhumed update           # update file database (Packet 05 — stub for now)
exhumed --help
exhumed scan --help
```

---

## Roadmap to v1.0

1. **Repo scaffold, HTTP engine, injection layer, traversal generator, testbed** ← *you are here*
2. **Versioned file database** — curated high-value paths loaded from local files
3. **Remote feed** — `exhumed update` pulls the latest database from a versioned feed
4. **Detection engine** — confirms successful inclusion via regex/keyword matching
5. **Content extraction** — format-aware parsers (passwd, PHP config, env files, etc.)
6. **Recursive follow-on chaining** — use extracted content to generate next targets
7. **JSON-first output** — machine-readable results plus a human TTY mode
8. **Single static binary release** — cross-compiled for Linux/macOS/Windows via GoReleaser

---

## License

MIT — see [LICENSE](LICENSE).
