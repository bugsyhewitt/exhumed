# build-feed — Database Release Tool

`build-feed` generates a publishable feed package from the curated `database/`
directory. It computes SHA-256 checksums for every YAML file and produces a
`manifest.json` that the `exhumed update` command can consume.

## Usage

```bash
go run ./tools/build-feed \
  --db database \
  --out dist/feed \
  --version 2026-05-17
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db` | `database` | Curated database directory (excludes `_raw/` and `_schema/` automatically) |
| `--out` | `dist/feed` | Output directory for the manifest and copied YAML files |
| `--version` | *(required)* | Release version string, e.g. `2026-05-17` or `1.2.0` |

## Output

```
dist/feed/
├── manifest.json          ← version, schema_version, per-file SHA-256
├── linux-os.yaml
├── linux-proc.yaml
├── webservers.yaml
└── ...
```

## Publishing

After running `build-feed`, upload the contents of `dist/feed/` to a publicly
accessible URL. Point `exhumed update --feed-url` at the manifest URL.

For GitHub releases: commit the feed output to a `feed/` branch or upload as a
release artifact. The default feed URL in `exhumed update` points at:

```
https://raw.githubusercontent.com/bugsyhewitt/exhumed/main/database/feed/manifest.json
```

## Cutting a release

1. Curate the database (edit YAML files in `database/`).
2. Run `exhumed db validate --db database` to verify 0 problems.
3. Run `build-feed --db database --out dist/feed --version YYYY-MM-DD`.
4. Commit `dist/feed/` or push as a release artifact.
5. Users run `exhumed update` to receive the new database.

## Schema version compatibility

`build-feed` embeds `schema_version: 1` in the manifest. Old binaries that
only understand schema 1 will refuse a manifest declaring a higher schema
version, protecting users from silent breakage when the format changes.
