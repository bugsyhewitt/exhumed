# Raw Corpus (`database/_raw/`)

This directory contains the **Pass A** unfiltered harvest — faithful conversion of public LFI
path lists into the exhumed schema. It is **not** the shipping database.

## What is here

| File | Source | Entries |
|---|---|---|
| `linux-os.yaml` | SecLists LFI-gracefulsecurity-linux.txt | 854 |
| `linux-proc.yaml` | SecLists LFI-LFISuite-pathtotest.txt | 258 |
| `linux-packages.yaml` | SecLists LFI-etc-files-of-all-linux-packages.txt | 5000 |
| `windows-os.yaml` | SecLists Windows-Paths.txt | 5000 |
| `webservers.yaml` | PayloadsAllTheThings + SecLists | 13 |
| `databases.yaml` | PayloadsAllTheThings + SecLists | 8 |
| `applications.yaml` | PayloadsAllTheThings + SecLists | 12 |

## Tags on every raw entry

- `raw` — this entry came from a bulk harvest, not individual curation
- `needs-confirm-review` — the `confirm` block is provisional; Pass B will sharpen it

## What Pass B (Packet 02b) does

Pass B promotes selected entries to `database/` root group files, sharpens confirm blocks
with tested regex/keyword patterns, merges near-duplicates, and discards noise.

## Using the raw corpus for testing

```bash
exhumed db validate --db database/_raw     # all 11,000+ entries pass validation
exhumed db stats    --db database/_raw     # entry counts by group/category/OS
exhumed scan --url "http://target/?file=FUZZ" --db database/_raw  # scan with raw corpus
```

## Do not edit raw entries directly

If a raw entry needs improvement, promote it to a curated entry in `database/` instead.
Raw entries will be overwritten when the harvest is re-run.
