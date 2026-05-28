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
└── *.yaml                 # curated group files (one group per file)
```

## Curated groups

The curated set holds **150 entries** across these group files:

| File | Category | What it covers |
|---|---|---|
| `linux-os.yaml`, `linux-proc.yaml` | `os` | Core Linux files and the `/proc` filesystem |
| `windows-os.yaml` | `os` | Windows OS, SAM, and unattend files |
| `webservers.yaml` | `webserver` | Apache, nginx, IIS, Tomcat config and logs |
| `applications.yaml` | `application` | WordPress, Drupal, Joomla, phpMyAdmin, Jenkins |
| `databases.yaml` | `database` | MySQL, PostgreSQL, Redis, MongoDB config and history |
| `frameworks.yaml` | `framework` | Laravel, Symfony, Django, Rails, Spring, Next.js, Node, Flask, .NET |
| `cloud.yaml` | `cloud` | AWS/GCP/Azure credential caches and IMDS/metadata endpoints |
| `container-cloud.yaml` | `container` | Kubernetes tokens, Docker markers, cloud creds |
| `ci-cd.yaml` | `ci-cd` | GitHub Actions, GitLab CI, Jenkins, CircleCI, Drone |
| `version-control.yaml` | `version-control` | Exposed `.git`/`.svn`/`.hg`, `.git-credentials`, `.netrc` |
| `credential-stores.yaml` | `credential-store` | kubeconfig, Docker auth, Vault, npmrc/pypirc, SSH config |
| `language-runtime.yaml` | `language-runtime` | php.ini/FPM, PHP sessions, pip, gem, JVM logging |
| `linux-services.yaml` | `misc` | sshd, sudo, cron, mail, VPN, Samba, FTP, systemd units |

## Two-pass curation model

- **Pass A (`_raw/`):** Faithful, unfiltered harvest from public sources (SecLists, PayloadsAllTheThings, etc.). Every entry is tagged `raw` and provisionally confirmed. This corpus is used for tooling and bulk testing, not as the primary scan database.
- **Pass B (this root):** Human-curated entries promoted from `_raw/` or written from scratch. Each entry has a precise, tested `confirm` block and verified path information. This is what `exhumed scan` uses by default.

## Adding curated entries

See `_schema/entry.schema.md` for the full field specification and worked examples.

Run `exhumed db validate` after editing to catch errors before committing.

Each curated group file lives at this root and carries a unique `group.id`.
Entries promoted or authored during a curation lap are tagged with a provenance
marker (e.g. `r2-curated`) so a later pass can audit their origin.
