# Packet 02a — Design Notes

## What was built

Database schema (Go structs + YAML), loader with curated/raw mode separation, structural
validator returning all errors, `exhumed db validate` and `exhumed db stats` CLI commands,
Pass A raw corpus (11,145 entries from SecLists + PayloadsAllTheThings), and scan rewiring
off the hardcoded demo path.

---

## Schema decisions

### `confirm` block is mandatory, not optional

Every raw entry has a provisional confirm block. This is better than a nullable confirm
because Packet 03 can then always assume the field is populated and pattern-match without
nil checks. Entries needing review are tagged `needs-confirm-review`.

### `http.Header`-compatible regex type: RE2 only

Go's `regexp` package uses RE2 semantics. This means no lookaheads, no backreferences.
All confirm patterns must be RE2-compatible. This is documented in the schema spec and
enforced at load time. Patterns that require PCRE must be converted to keyword-type checks.

### `min_matches` defaults to 1 in validator, not schema

The YAML `min_matches` field defaults to 0 in Go (zero value for int). The runtime
interpretation is: if `MinMatches == 0`, treat as 1 (i.e., at least one pattern must hit).
This means callers must handle 0 as "not set → 1". This is documented in the struct comment.
An alternative (storing `*int`) was considered but adds complexity for all callers.

### Loader modes: `LoadDir` vs `LoadCurated`

`LoadDir` loads everything under root including `_raw/`. `LoadCurated` skips `_raw/`
via a directory skip in `WalkDir`. Scan uses `LoadCurated` by default so developers
running against the empty curated root don't accidentally wait for 11K raw-corpus entries
to be traversal-fuzzed. Using `--db database/_raw` explicitly opts into the raw corpus.

### group id uniqueness is cross-file, entry id uniqueness is within-file

This matches the intended use: one YAML file per logical group, one group ID per file.
Entry IDs only need to be unique within their group. Cross-group entry ID collisions are
allowed (e.g., both `linux-os.yaml` and `applications.yaml` can have an entry `passwd`).

---

## Enum gaps found

**No new enum values were needed.** All 11,145 raw entries fit within the existing
vocabulary. However, two categories of near-misses were observed:

1. **`process-info`** — `/proc/self/cmdline`, `/proc/self/status`, `/proc/net/*` fit
   better as a dedicated goal than `system-info`. Flagged here for Pass B consideration.
   Using `system-info` for now.

2. **`audit-logs`** — some entries (utmp, wtmp, lastlog) are audit/accounting logs
   distinct from web server access/error logs. Using `logs` for now with `info_goal: logs`.

If Pass B curators feel strongly, add a new enum value and update the validator's
`ValidInfoGoals` map — it is trivial to extend (one line). Do not extend silently.

---

## Raw corpus provenance

| Source | URL | Entries harvested |
|---|---|---|
| SecLists LFI-gracefulsecurity-linux | https://github.com/danielmiessler/SecLists | 854 |
| SecLists LFI-LFISuite-pathtotest | https://github.com/danielmiessler/SecLists | 258 |
| SecLists LFI-etc-files-of-all-linux-packages | https://github.com/danielmiessler/SecLists | 5,000 (capped) |
| SecLists Windows-Paths | https://github.com/danielmiessler/SecLists | 5,000 (capped) |
| PayloadsAllTheThings File Inclusion | https://github.com/swisskyrepo/PayloadsAllTheThings | ~33 (hand-crafted from README) |

**Sources not harvested:**
- `dotdotpwn` — dotdotpwn ships traversal payload strings, not file path lists. Its
  technique coverage is already in `internal/traversal`. No new paths to add.
- `liffy` — liffy's source is Python, not a path list. The paths it knows are a subset
  of what SecLists already covers. No unique additions found. Noted in report.

**Windows list truncation:** SecLists Windows-Paths.txt has 5,270 paths; truncated to
5,000 to stay within practical limits. The truncated 270 are mostly edge-case `$sysreset`
log variants. Flagged for Pass B to decide whether to include the tail.

---

## Confirm block provisional strategy

For raw entries with no obvious confirmation signature, the generator applied these heuristics:
- `/etc/passwd` family → keyword `root:`
- shadow → keyword `root:`
- log files → keyword `GET /`
- /proc/self/environ → keyword `PATH=`
- /proc/self/fd/* → keyword `/` (deliberately minimal — these are not reliably confirmable without content)
- config files → keyword `/` or file-type-specific (e.g. `[mysqld]` for MySQL)
- Windows paths → keyword from a known content marker or `[`

All provisional entries are tagged `needs-confirm-review`. Pass B must replace these with
specific, tested patterns before the curated database ships.

---

## Scan rewiring

The hardcoded `etc/passwd` demo path from Packet 01 was completely removed. The scan
command now:
1. Loads the database via `db.LoadCurated(f.dbPath)` (curated root, excluding `_raw/`)
2. If empty → prints informational message, exits 0
3. If non-empty → walks every entry, generates traversal payloads per entry, fires
   requests, prints raw results with `(confirmation: Packet 03)` annotation
4. `--db database/_raw` triggers `db.LoadDir()` instead for raw corpus scanning

---

## Risks for Packets 02b–06

- **`min_matches` zero-value ambiguity** — callers must treat 0 as "use 1". Document
  this clearly in Packet 03's detection implementation.
- **Regex compilation cost** — 11K entries with regex patterns are compiled at load time.
  For curated-only loads (small DB) this is instant. For raw corpus loads, verify
  load time stays under 1 second before shipping.
- **Windows path validation** — the validator accepts `C:\...` and `\\...` forms.
  Windows entries in the raw corpus come from SecLists and have not been tested against
  real Windows LFI targets. Pass B should verify Windows entries.
- **`database/` root is empty until Packet 02b** — `exhumed scan` with default `--db`
  prints the "database is empty" message and exits 0. This is correct behavior, not a bug.
