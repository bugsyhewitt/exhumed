# exhumed — Post-v0.1 Improvement Roadmap

**Generated:** 2026-05-26 by Worker (Rotation 2, research lap)
**Baseline:** exhumed is a modern LFI / path-traversal exploitation CLI in Go (a revival of `panoptic`) — it walks a curated 63-entry YAML file-path database, fires ~20 traversal/encoding techniques per entry through an injection layer that covers query/body/header/cookie/JSON surfaces, confirms reads via regex/keyword `confirm` blocks, extracts credentials with format-aware parsers, recursively chains follow-on targets, and emits text or `--output json`. Build/vet/tests are green on `go 1.26`, `CGO_ENABLED=0`.

> **Scope note for the operator.** The dispatch brief described exhumed as a *"CVE-to-exploit mapping and patch-diff tool backed by SQLite."* The actual repository on `origin/main` is none of those things — it is an LFI exploitation tool with a YAML file database (no SQLite driver in `go.mod`, no CVE/patch-diff code anywhere). The README, `CLAUDE.md`, and all of `internal/` agree. This roadmap is written against the **real** codebase. If the operator genuinely wants a CVE-mapping tool, that is a different project, not a Phase-2 improvement to this one — flag it before any implement lap is dispatched.

## Methodology

I read every Go source file under `cmd/` and `internal/`, the `README.md`, `CLAUDE.md`, `go.mod`, the curated database YAML, and the packet design notes in `docs/`. I then compared exhumed's capabilities against the live LFI/path-traversal tooling landscape practitioners use in 2025/2026 — `dotdotpwn`, `kadimus`, `LFISuite`, `ffuf`/`feroxbuster`, the `php_filter_chain_generator` technique, and Burp's traversal tooling — and against what bug-bounty and pentest workflows actually ask for (RCE escalation from a confirmed read, WAF-evasion, resumable scans, SecLists interop, blind/OOB confirmation). Items are ranked by **signal-to-noise improvement × inverse implementation complexity**: high-leverage, low-risk changes that build on existing seams come first; large-surface features that need new subsystems come last. Every item is scoped as ONE shippable deliverable a single Phase-2 lap can complete inside a 100–300K budget.

---

## Item 1 — Auto-prefer the feed cache over the bundled database (Priority: CRITICAL)

### What
After `exhumed update` downloads a newer database into the OS cache dir, `scan`/`db` still load the in-repo `database/` directory unless the user manually passes `--db <cachedir>`. This silently defeats the entire feed system: users update, then scan stale data and never notice. Make `--db` default to the freshest available source.

### How
`internal/cli/scan.go`, `db.go`, and `update.go` all hardcode `--db` default `"database"`. Introduce a resolver in `internal/feed` (or a small `internal/cli` helper): `ResolveDBPath(explicit string) (path, source string)`. When `--db` is left at its default, compare the feed cache dir (`defaultCacheDir()`, already implemented in `update.go`) against the bundled `database/`. If the cache exists and its manifest version is newer (reuse `feed.Check`'s comparison), return the cache path; otherwise return the bundled path. Print the resolved source to stderr in verbose/text mode (`[*] database: <path> (cache, v2026-05-20)`). An explicit `--db` always wins and disables the resolver. This is the single biggest correctness gap shipped at v0.1 — it is called out as concern #4 in `docs/final-report-packets-02b-05.md`.

### Effort estimate
Low (~120–160K). One resolver function, three call-site edits, table-driven tests for newer/older/missing-cache cases. No new dependencies, no schema change.

### Rationale
This is pure signal recovery: the feed feature already exists and is tested, but its output is unreachable in the default code path, so every `update` is wasted. Highest correctness-per-line-of-code item in the repo. Fixing it makes Items 4 and 6 (database growth, feed semver) actually reach users.

---

## Item 2 — `/proc/self/environ` & `/proc/self/cmdline` auto-harvest with env-secret extraction (Priority: HIGH)

### What
The single most valuable LFI primitive on Linux targets is reading `/proc/self/environ` (and `/proc/<pid>/environ`) — it dumps the web process's environment, which routinely contains `DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, API tokens, and the document root path. The curated DB has `linux-proc` entries, but there is no dedicated parser: `environ` is NUL-delimited `KEY=VALUE` pairs, which the current line-based `parseKeyValue` (`internal/extract/extract.go`) cannot split. Add a first-class `proc-environ` parser and ensure the high-value proc paths are confirmed and chained.

### How
Add `parseProcEnviron(body, source)` to `internal/extract/extract.go`: split on `\x00`, then run each `KEY=VALUE` through the existing `secretKeyRE` filter, emitting `FindingTypeSecret` findings with `Confidence: 0.85`. Wire it into the `Parse` dispatch switch under hint `"proc-environ"`, and set `parser: proc-environ` on the `/proc/self/environ` DB entry. Bonus chain rule in `internal/chain/chain.go`: when a `path`-type or environ finding reveals `PWD`/`DOCUMENT_ROOT`, queue `<docroot>/.env`, `<docroot>/config.php`, `<docroot>/.git/config` as depth+1 targets. Reuse the existing `Finding`/`Target` structs — no new types.

### Effort estimate
Medium (~180–220K). One new parser (~40 lines) + dispatch wiring + a couple of DB entry edits + chain rule + unit tests with a synthetic NUL-delimited fixture and a testbed fixture under `testbed/fakeroot/proc/`.

### Rationale
`environ` harvesting is the difference between "I can read files" and "I have the database password" in real engagements — it is the headline feature of `kadimus` and the first thing a pentester tries after confirming LFI. The current generic parser misses it entirely because of the NUL delimiter. Very high signal, isolated change against an existing extraction seam.

---

## Item 3 — Resumable scans via `--resume` state file (Priority: HIGH)

### What
A full scan over a grown database (Item 4 pushes toward 200+ entries) × ~20 techniques × traversal depth is thousands of requests. If the operator Ctrl-C's, hits a rate limit, or the target flaps, all progress is lost and re-running re-hammers the target — bad for both scan time and stealth. Add `--resume <file>` to persist per-entry completion state and skip already-attempted entries on restart.

### How
Add a small `internal/scanstate` package: a JSON file of `{target, marker, db_version, attempted_entry_ids: [...], confirmed_hits: [...]}`. In `runScan` (`internal/cli/scan.go`), before the `for _, entry := range entries` loop, load the state file if `--resume` is set and build a skip-set; after each `scanEntry` returns, append the entry ID and flush (atomic temp-write + rename, mirroring the feed's existing atomic-swap pattern). Guard against mismatched target/db_version by refusing to resume a file whose target or db hash differs (fail closed with a clear message). The JSON output already has all the hit data, so confirmed-hit replay is straightforward.

### Effort estimate
Medium (~200–250K). New package (~120 lines), one integration point in the scan loop, atomic-write helper (pattern already exists in `internal/feed`), tests covering fresh/resumed/mismatched-target cases.

### Rationale
Long scans against rate-limited or fragile targets are the norm in bug bounty (scope-mandated throttling) and pentest (don't trip the WAF). Resumability is a frequently requested quality-of-life feature that no lightweight LFI tool offers cleanly, and it directly reduces request volume — a stealth win. Self-contained, no changes to the request pipeline.

---

## Item 4 — Promote curated database from 63 → ~150 entries with confirm-quality pass (Priority: HIGH)

### What
The moat is the database, per `CLAUDE.md` ("the moat is the file database, not the code"). It currently holds 63 curated entries — concern #2 in the final report flags this as below the 75–100 target. Meanwhile `database/_raw/` holds 11,000+ harvested paths. Promote the highest-value raw entries (cloud metadata endpoints, modern framework configs — Laravel `.env`, Django `settings.py`, Next.js, Spring `application.properties`, Rails `secrets.yml`, K8s service-account tokens, Docker/containerd) into the curated set with **real** `confirm` blocks, not the `regex: .` weak-confirm placeholder.

### How
This is a data lap, not a code lap. Triage `_raw/` against the `info_goal`/`category` taxonomy in `internal/db/schema.go`, write ~85 new curated entries across the existing group files (or new groups for `cloud`, `framework`, `container`), each with a tight `confirm` (keyword/keyword-all/regex with a discriminating pattern) and a correct `parser` hint. Add `tags: [r2-curated]` for provenance. Validate with the existing `exhumed db validate` (it already enforces enum membership, regex compilation, path-absoluteness) — the gate is "0 validate problems and entry count ≥ 150." Add a few testbed fixtures for the new high-value paths so detection is regression-tested.

### Effort estimate
Medium (~200–280K). No Go code; mostly curation judgment and YAML authoring, gated by the existing validator. Time goes into picking discriminating confirm patterns, not plumbing.

### Rationale
Coverage *is* the product for this tool — a traversal engine that doesn't know modern cloud/framework secret locations finds nothing on a 2026 target. The infrastructure (loader, validator, stats) is done and tested, so this is the cleanest high-impact lever available. Best done after Item 1 so the larger DB actually reaches users via the feed.

---

## Item 5 — `php://filter` chain generator for RCE escalation (Priority: MEDIUM) — ✅ SHIPPED (r8)

> Shipped on branch `worker-r8-exhumed`: new `internal/phpfilter` package ports the
> verified synacktiv conversion table and chain-assembly algorithm, exposed as
> `exhumed payload php-filter --rce '<php>'` (with `--resource` and a `--raw-base64
> --debug` verification mode). Output is byte-for-byte identical to the reference
> `php_filter_chain_generator`, pinned by a SHA-256 golden test. Pure-Go string
> construction, no network I/O, MIT-clean.


### What
exhumed emits exactly one PHP wrapper payload: `php://filter/convert.base64-encode/resource=<path>` (read-only source disclosure, `internal/traversal/traversal.go`). The 2023+ state of the art is the **PHP filter chain** technique (`synacktiv/php_filter_chains_oracle_exploit`, `php_filter_chain_generator`) that abuses chained `convert.iconv` filters to *generate arbitrary bytes* and turn a file-read primitive into code execution where the sink is `include()`/`require()`. Add a generator subcommand that emits these chains.

### How
Add `internal/phpfilter` implementing the iconv-chain construction algorithm (well-documented; deterministic byte-prefix generation via `convert.iconv.<from>.<to>` steps that prepend known bytes). Expose it as `exhumed payload php-filter --rce '<php>'` (or a `--php-filter-chain` mode on `scan`) that prints the `php://filter/...|...|.../resource=` string. Keep it as a payload *generator* first (emit the string, let the operator place it) — full automated injection-and-confirm is a larger follow-on. This stays MIT-clean (pure-Go string construction, no GPL deps) per `CLAUDE.md`'s license constraint.

### Effort estimate
Medium-high (~250–300K). The chain-construction algorithm is the bulk of the work; needs careful unit tests asserting generated chains decode to the target bytes. Net-new package but no changes to existing types.

### Rationale
The recurring practitioner complaint about lightweight LFI tools is "it confirms the read, then I leave the tool and go do the RCE by hand." Filter-chain generation is the highest-leverage escalation primitive that doesn't require log-poisoning preconditions. Ranked MEDIUM (not HIGH) only because the algorithm is intricate and easy to get subtly wrong — it warrants its own focused lap rather than being rushed alongside higher-certainty wins.

---

## Item 6 — Proper semver feed comparison + `--db-version` surfacing (Priority: MEDIUM) — ✅ SHIPPED (r6)

> Shipped on branch `worker-r6-exhumed`: `feed.newer` now uses `golang.org/x/mod/semver`
> (semver compare when both versions are semver-shaped, lexicographic date fallback otherwise),
> and `exhumed version --db` surfaces the resolved active database version and source.

### What
The feed compares versions with lexicographic string comparison (`internal/feed`, concern #3 in the final report). `1.10.0 < 1.9.0` evaluates wrong; only date-based `YYYY-MM-DD` versions are safe today. Swap in a real semver comparator and surface the active DB version to the user so they can trust "am I current?"

### How
Add `golang.org/x/mod/semver` (BSD-licensed — MIT-clean per `CLAUDE.md`) and replace the lexicographic compare in `feed.Check`/`feed.Update` with `semver.Compare`, falling back to date-string compare when versions aren't semver-shaped (detect with `semver.IsValid`). Add `exhumed version --db` (or extend `db stats`) to print the loaded database version and source. Update `internal/feed` tests to cover the `1.10.0 > 1.9.0` case that currently fails silently.

### Effort estimate
Low (~120–160K). One dependency add, one comparison-function swap behind an `IsValid` guard, a version-surfacing print, and targeted tests. Zero-risk per the final report's own assessment ("a proper semver parser would be a zero-risk swap").

### Rationale
Low-effort correctness fix that the project's own retro already identified and pre-blessed. It compounds with Items 1 and 4: once the cache is auto-preferred and the DB is growing, version comparison must be correct or the feed will install the wrong snapshot. Ranked below Item 1 because the lexicographic scheme is only *latently* wrong (fine for the current date-based versioning), whereas Item 1 is wrong *today*.

---

## Item 7 — Out-of-band / blind-LFI confirmation hooks (Priority: MEDIUM) — ✅ SHIPPED (r9 generator + r10 listener)

> **Generator half — shipped on branch `worker-r9-exhumed`:** new `internal/oob`
> package + `exhumed payload oob --domain <collaborator>` emits four OOB payload
> classes (`smb-unc`, `http-wrapper`, `https-wrapper`, `dns-resolve`) ordered most-
> to-least reliable, with `--label` (per-technique subdomain attribution),
> `--share`/`--path` customisation, and `--json` output. Pure-Go string
> construction, no network I/O, no listener, no cgo, MIT-clean.
>
> **Listener / correlation half — shipped on branch `worker-r10-exhumed`:** the
> follow-on slice the roadmap warned about, resolved *without* an external-backend
> dependency. New `oob.Listener` (in `internal/oob/listener.go`) is a
> self-contained `net/http` collaborator exposed as `exhumed payload oob listen
> --addr <host:port>`. It records every callback as an `Interaction` (seq, time,
> source IP, Host, method, path, user-agent), attributes each hit to its technique
> by matching the request's leading `Host` subdomain against the `--label`
> labels the generator emits, streams hits live to stderr, and emits a JSON array
> of all interactions on Ctrl-C with `--json`. Graceful signal-driven shutdown,
> `--addr :0` for an OS-assigned port, pure-Go, no cgo, no outbound I/O —
> preserving the static-binary constraint.
>
> The external-backend design question is sidestepped: the built-in listener
> covers the `http`/`https` techniques for local and lab use (where the operator
> controls DNS or points payloads at the listener directly); the SMB/DNS-only
> techniques, and internet-facing blind testing that needs a public resolver, are
> documented as the domain of an external collaborator (interactsh / Burp). The
> `--oob` flag wiring `scan` to fire these live during a scan remains an optional
> future enhancement, but the core capability gap — confirming a blind sink with
> exhumed alone — is now closed.

### What
Detection today is purely response-body pattern matching (`internal/detect`). Many real LFI sinks are *blind*: the file is read into a template/log/SSRF path but never reflected in the HTTP response. Add an OOB confirmation path so a blind read can still be proven — e.g. force the target to read an attacker-controlled UNC/`http://` path (`\\\\<collab>\\share`, `php://filter` to an external resource) and confirm via an interaction callback.

### How
Add `internal/oob` with a pluggable `Interaction` interface and a simple built-in poller (HTTP callback server the operator runs, or a Burp Collaborator / interactsh-compatible domain passed via `--oob-domain`). Generate UNC/remote-wrapper payloads in `internal/traversal` gated behind an `--oob` flag, tag the corresponding `Detection` as `Confidence: "oob-callback"` when the poller observes a hit. Keep the network-listener piece optional and out-of-process so the static-binary/no-cgo constraint holds. Default off — purely additive.

### Effort estimate
High (~280–300K, likely needs scoping to "interactsh-client mode only" to fit one lap). New package, new payload class, new flag, and the confirmation-correlation logic. The largest-surface item here.

### Rationale
Blind LFI is a meaningful slice of real findings that exhumed currently *cannot* detect at all — it's a genuine capability gap, not a polish item. Ranked last/MEDIUM because it has the largest surface, an external-dependency design question (which OOB backend), and the lowest certainty of fitting a single Phase-2 lap. Worth doing, but only after the high-certainty wins above land. Recommend a dedicated scoping note before dispatch.

---

## Suggested lap ordering

1. **Item 1** (cache auto-prefer) — unblocks the value of everything feed-related; do first. ✅
2. **Item 2** (`/proc/self/environ` parser) — highest signal-per-line capability win. ✅
3. **Item 4** (database growth) — the moat; pairs naturally after Item 1 ships the delivery path. ✅
4. **Item 6** (semver) — cheap correctness, compounds with 1 + 4. ✅
5. **Item 3** (resumable scans) — quality-of-life + stealth, self-contained. ✅
6. **Item 5** (php filter chains) — high-value escalation, needs a careful dedicated lap. ✅
7. **Item 7** (OOB/blind) — biggest capability gap but largest surface; split into generator (r9) + self-contained listener (r10). ✅

**All seven roadmap items are now shipped.** Next-lap candidates beyond this roadmap: wiring an optional `--oob` flag into `scan` to fire OOB payloads live during a scan and auto-tag matching listener callbacks; SMB/DNS listener support; ~~SecLists interop~~ ✅ shipped (r12); ~~WAF-evasion encodings~~ ✅ shipped (r11). A fresh research lap should re-rank against the 2026 tooling landscape before dispatch.

> **SecLists interop — shipped on branch `worker-r12-exhumed`:** new
> `internal/pathlist` package parses SecLists-style wordlists (one path per line,
> `#` comments and blanks skipped, de-duplicated first-occurrence-wins) into
> synthetic weak-confirm `db.CompiledEntry` values with a pre-compiled confirm
> regex and a path-inferred parser hint. Exposed via a `scan --paths-file
> <wordlist>` flag: the named paths are scanned through the normal traversal
> engine *alongside* the curated database (curated first, wordlist extends
> coverage). A missing/unreadable wordlist is a hard error (fail loud, never
> silently scan the curated set only). Pure-Go, no new dependencies, no
> type-contract changes, default off (purely additive). Combines with
> `--techniques` to bound request volume on large lists.

> **WAF-evasion encodings — shipped on branch `worker-r11-exhumed`:** five new
> WAF-bypass traversal techniques added to `internal/traversal` (`waf-double-slash`
> mixed double-encoding, `waf-overlong-slash`, `waf-encoded-backslash`,
> `waf-dotslash-prefix`, `waf-null-interstitial`), each ordered after the standard
> encodings in the most-to-least-likely sequence. New `traversal.Techniques()`
> (canonical name set in emission order) and `traversal.GenerateFiltered()`
> (ordering-preserving allowlist filter). Exposed via a `scan --techniques` flag:
> a comma-separated allowlist to focus or trim the technique set, `--techniques
> list` to print available names, and a clear error on unknown names. Pure-Go
> string construction, no new dependencies, no type-contract changes, fully
> backward compatible (empty selection = all techniques = prior behaviour).
