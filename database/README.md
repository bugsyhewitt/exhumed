# exhumed Database

This directory contains the curated file-path database used during LFI scans.

## Structure

```
database/
├── README.md              # this file
├── _schema/
│   └── entry.schema.md    # authoritative schema spec with worked examples
├── _raw/
│   ├── README.md          # explains the raw corpus
│   └── *.yaml             # unfiltered Pass A harvest — not the shipping DB
└── *.yaml                 # curated group files (populated in Packet 02b)
```

## Two-pass curation model

- **Pass A (`_raw/`):** Faithful, unfiltered harvest from public sources (SecLists, PayloadsAllTheThings, etc.). Every entry is tagged `raw` and provisionally confirmed. This corpus is used for tooling and bulk testing, not as the primary scan database.
- **Pass B (this root):** Human-curated entries promoted from `_raw/` or written from scratch. Each entry has a precise, tested `confirm` block and verified path information. This is what `exhumed scan` uses by default.

## Adding curated entries

See `_schema/entry.schema.md` for the full field specification and worked examples.

Run `exhumed db validate` after editing to catch errors before committing.

Group files in this root (e.g. `linux.yaml`, `apache.yaml`) are populated in Packet 02b.
