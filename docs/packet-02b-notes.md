# Packet 02b — Curated Database Design Notes

## Decisions

### EffectiveMinMatches zero-value rule
`Confirm.MinMatches` defaults to 0 in YAML unmarshaling (Go zero value for `int`).
`EffectiveMinMatches()` encodes the "zero means one" semantic in exactly one place so
Packet 03 detection never needs its own default logic.

### Relative paths (wp-config.php, .env, .htpasswd, .git/config, etc.)
The validator requires `path` to start with `/` for any entry whose `os` list includes
a Unix family. Entries like `wordpress-config` and `laravel-env` that are inherently
web-root-relative use an absolute canonical path (e.g. `/var/www/html/wp-config.php`)
as `path` and list the relative form as the first `alt_paths` entry. The traversal
layer (Packet 01) handles both primary and alt paths during scan.

### "keyword (any)" entries — weak-confirm
Several entries (etc-hostname, etc-issue, root-bash-history, proc-self-cmdline,
mysql-history, postgres-conf, win-sam, win-sam-repair, win-netsetup, docker-env,
docker-secrets) have no universally-present substring short of "the file is non-empty."
These use `type: regex` with pattern `.` (matches any byte), which the RE2 engine
handles in linear time. They are tagged `weak-confirm` so Packet 03 or downstream
triage tooling can flag them for human review. This is a documented, intentional
tradeoff — detection for these files is presence-based, not content-verified.

### IIS entries in webservers.yaml
The webservers group declares `os: [linux, windows]` but IIS entries are
`os: [windows]` at the entry level. The validator checks entry-level `os` for path
validation (not group-level), so Windows paths are accepted for those entries.

### Group-level tags not supported
The schema's `Group` struct has no `tags` field. Container/cloud entries that should
be tagged `modern` have `tags: [modern]` on each individual entry instead.

### Database structure
- `database/` (this dir): curated, shipping entries — what `exhumed scan` uses by default.
- `database/_raw/`: unfiltered Pass A harvest from SecLists/PayloadsAllTheThings — not
  promoted into the curated set. `LoadCurated()` skips `_raw/` automatically.

## Entry counts
| Group | Count |
|-------|-------|
| linux-os | 16 |
| linux-proc | 8 |
| webservers | 10 |
| windows-os | 6 |
| applications | 10 |
| databases | 6 |
| container-cloud | 7 |
| **Total** | **63** |

## Optional enrichment (§02b.4)
No entries added beyond the authoritative list in §02b.3. The list was complete enough
that no obvious PayloadsAllTheThings additions were identified that weren't already covered.
