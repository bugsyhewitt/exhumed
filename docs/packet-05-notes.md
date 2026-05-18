# Packet 05 — Feed System Design Notes

## Decisions

### Manifest format: JSON
The manifest uses JSON (not YAML) because it is consumed by Go's
`encoding/json`, not by the DB YAML loader. Keeping the two formats
distinct avoids any ambiguity about which loader to use for which files.
The `schema_version` field in the manifest refers to the db entry schema,
matching `db.SchemaVersion` — this is what the schema-version gate checks.

### Version comparison: lexicographic string comparison
Both date-based (`YYYY-MM-DD`) and semver strings (`1.2.0`) compare
correctly with Go's `>` operator when consistently formatted:
- `2026-05-17 > 2026-05-10` ✓
- `1.10.0 > 1.9.0` ✗ (this is a known gotcha for naive semver)

For now, date-based versioning is the primary scheme (matching the project
cadence). A proper semver parser can be added if needed. The limitation
is documented here.

### Atomic swap via temp file → rename
All downloads go to temp files in the same `cacheDir` directory (ensuring
same-filesystem for `os.Rename`). Only after ALL files are downloaded and
verified does the rename step begin. If any rename fails, the cleanup
function removes remaining temp files. Existing files are never overwritten
until the rename step — which is atomic at the OS level.

### schema_version gate
`feed.Config.SupportedSchema` is set by the CLI to `db.SchemaVersion`.
If the manifest declares a higher schema_version, `Update` returns an
"upgrade exhumed" error before downloading anything. This prevents a new DB
format from being applied to an old binary that would silently misinterpret it.

### Cache dir loading
`scan`, `db validate`, and `db stats` accept any `--db <path>` argument.
Users who ran `exhumed update` can point scan at the cache dir:

```bash
exhumed scan --url "..." --db ~/.local/share/exhumed/db
```

The bundled `database/` is the default when no `--db` is given. Auto-detection
(preferring the cache dir if newer) is left for Packet 06 / future work.

### file:// support for tests
`fetchBytes` checks the URL scheme: `file://` URLs read directly from disk.
This allows all tests to use a temp-dir "feed" with no network dependency.
The httptest-based tests also work without network by using `httptest.NewServer`.

### tools/build-feed
Standalone `main` package (not imported by the binary). Run with:
```bash
go run ./tools/build-feed --db database --out dist/feed --version 2026-05-17
```
Excludes `_raw/` and `_schema/` subdirectories automatically.

## Test coverage
9 unit tests covering: manifest round-trip, good checksum, tampered file, atomic
swap partial failure, version newer/same/older, unsupported schema, check
does-not-mutate. All use local httptest or temp dirs — no live network.
