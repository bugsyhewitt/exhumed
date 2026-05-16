# exhumed Database Schema v1

This is the authoritative specification for `exhumed` database YAML files.
Contributors write new entries by following this document. No other reference is needed.

---

## File structure

Each YAML file represents one **group** of related targets. Top-level shape:

```yaml
schema_version: 1        # required; must be 1
group:
  id: wordpress          # unique slug, [a-z0-9-], required
  name: WordPress        # human display name, required
  description: >-        # what this group is about, required
    WordPress CMS configuration, credential, and source files.
  os: [linux, windows]   # OS families this group covers, required
  category: application  # see Category enum below
entries:
  - <entry>
  - <entry>
```

---

## Entry fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | **yes** | Unique within file. Must match `[a-z0-9-]+`. E.g. `wp-config-php` |
| `name` | string | **yes** | Human label. E.g. `"WordPress wp-config.php"` |
| `description` | string | **yes** | What the file is and why an attacker wants it |
| `path` | string | **yes** | Canonical absolute path. Unix paths start with `/`; Windows paths with drive letter e.g. `C:\` |
| `alt_paths` | []string | no | Common alternative locations for the same logical file |
| `os` | []string | **yes** | OS families: subset of `linux`, `windows`, `bsd`, `macos` |
| `info_goal` | string | **yes** | What the attacker gains — see InfoGoal enum |
| `privilege` | string | **yes** | Readability requirement — see Privilege enum |
| `confirm` | Confirm | **yes** | How to confirm successful inclusion — see Confirm block |
| `parser` | string | no | Hint for Packet 04 extractor: `unix-passwd`, `unix-shadow`, `ini-config`, `none`. Free-form for now |
| `references` | []string | no | URLs documenting the path or its significance |
| `tags` | []string | no | Free-form: `raw`, `needs-confirm-review`, `modern`, `container`, `cloud` |
| `min_traversal` | int | no | Minimum `../` depth typically needed. 0 means absolute path inclusion works |

---

## Enums

### Category (group-level)

| Value | Meaning |
|---|---|
| `os` | Core operating system files |
| `webserver` | Web server config and logs (Apache, nginx, IIS, etc.) |
| `application` | CMS, web apps (WordPress, Joomla, Django, etc.) |
| `framework` | Development frameworks (Rails, Laravel, Spring, etc.) |
| `database` | Database servers (MySQL, PostgreSQL, Redis, etc.) |
| `language-runtime` | Language runtime config (PHP ini, Python, Ruby, etc.) |
| `container` | Container/orchestration config (Docker, Kubernetes, etc.) |
| `cloud` | Cloud provider config (AWS, GCP, Azure, etc.) |
| `ci-cd` | CI/CD pipeline config (Jenkins, GitHub Actions, etc.) |
| `version-control` | VCS config (git credentials, SVN, etc.) |
| `credential-store` | Dedicated credential stores (Vault, keyrings, etc.) |
| `misc` | Does not fit another category |

### InfoGoal (entry-level)

| Value | Meaning |
|---|---|
| `credentials` | Username/password pairs, API keys, database passwords |
| `config` | Application or server configuration |
| `source-code` | Application source code |
| `session-data` | Session tokens, cookies, auth state |
| `logs` | Log files (access logs, error logs, audit logs) |
| `ssh-keys` | SSH private keys or authorized_keys |
| `tls-keys` | TLS/SSL private keys or certificates |
| `tokens` | API tokens, OAuth secrets, webhook tokens |
| `cron` | Scheduled task definitions |
| `command-history` | Shell history (bash_history, etc.) |
| `system-info` | OS/hardware/software inventory |
| `network-info` | Network topology, routing, DNS |
| `database-data` | Raw database files or dumps |
| `environment` | Environment variable files |
| `service-account` | Service account keys (GCP, AWS IAM, etc.) |

### Privilege (entry-level)

| Value | Meaning |
|---|---|
| `any` | World-readable; any process can read it |
| `app-user` | Readable by the web application's process user (www-data, apache, nginx, etc.) |
| `elevated` | Requires root/admin; only readable by privileged processes |
| `unknown` | Privilege requirement is not known |

### OS values

`linux`, `windows`, `bsd`, `macos`

---

## The `confirm` block

This is the most important field. A 200 HTTP response does **not** mean the file was
included — many applications return 200 with an error page. The `confirm` block tells
Packet 03 (detection) how to verify that the file's actual contents are in the response.

```yaml
confirm:
  type: regex            # regex | keyword | keyword-all
  patterns:
    - 'root:.*:0:0:'     # for regex: RE2-compatible patterns
  min_matches: 1         # how many patterns must hit (default: 1, optional)
  negate:
    - 'No such file'     # if any negate pattern matches, this is NOT a hit
```

### `type: regex`

Patterns are [RE2](https://github.com/google/re2/wiki/Syntax)-compatible regular expressions
(Go's `regexp` package). At least `min_matches` patterns must match the response body.
All regex patterns are compiled at database load time — an invalid pattern is a load error.

### `type: keyword`

Patterns are literal substrings, matched case-insensitively. At least one must be present.

### `type: keyword-all`

ALL patterns must be present in the response body.

### `negate`

Optional list. If any negate pattern matches the response, the entire confirm is a **miss**,
even if the positive patterns matched. Use this to defend against error pages that echo
the requested filename back:

```yaml
negate:
  - 'No such file or directory'
  - 'failed to open stream'
```

### `min_matches`

Only meaningful for `type: regex`. Defaults to 1. Set to 2 to require two distinct
regex patterns to hit before declaring a confirmed read.

---

## Worked examples

### Example 1: Linux OS file

```yaml
schema_version: 1
group:
  id: linux-core
  name: Linux Core OS Files
  description: Fundamental Linux system files revealing users, authentication, and network topology.
  os: [linux, bsd, macos]
  category: os
entries:
  - id: passwd
    name: /etc/passwd
    description: Local user account database. Reveals usernames, UIDs, home directories, and login shells. Required by almost every privilege-escalation chain.
    path: /etc/passwd
    os: [linux, bsd, macos]
    info_goal: credentials
    privilege: any
    confirm:
      type: regex
      patterns:
        - 'root:.*:0:0:'
        - '^[a-z_][a-z0-9_-]*:[x*!]?:\d+:\d+:'
      min_matches: 1
      negate:
        - 'No such file or directory'
        - 'failed to open'
    parser: unix-passwd
    references:
      - https://man7.org/linux/man-pages/man5/passwd.5.html
    tags: [core]
```

### Example 2: Application credential file

```yaml
  - id: wp-config-php
    name: WordPress wp-config.php
    description: WordPress main configuration file. Contains DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, and AUTH_KEY constants. Obtaining this file gives direct database access.
    path: /var/www/html/wp-config.php
    os: [linux]
    info_goal: credentials
    privilege: app-user
    confirm:
      type: keyword-all
      patterns:
        - 'DB_PASSWORD'
        - 'AUTH_KEY'
      negate:
        - '<?php'  # negate only if you want to exclude PHP-wrapped error pages — typically NOT negated here
    alt_paths:
      - /var/www/wordpress/wp-config.php
      - /srv/www/wordpress/wp-config.php
    parser: none
    references:
      - https://developer.wordpress.org/apis/wp-config-php/
    tags: [cms, wordpress]
    min_traversal: 2
```

### Example 3: Modern/container target

```yaml
  - id: k8s-service-account-token
    name: Kubernetes service account token
    description: In-pod Kubernetes service account JWT. If the pod mounts the default service account, this token can be used to authenticate to the Kubernetes API and enumerate/control cluster resources.
    path: /var/run/secrets/kubernetes.io/serviceaccount/token
    os: [linux]
    info_goal: service-account
    privilege: app-user
    confirm:
      type: regex
      patterns:
        - '^eyJ[A-Za-z0-9+/]+'
      negate:
        - 'No such file'
    parser: none
    references:
      - https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
    tags: [container, kubernetes, modern, cloud]
    min_traversal: 0
```

---

## Validation rules

All entries must pass `exhumed db validate`. The validator checks:

1. `id` present and matches `[a-z0-9-]+`; unique within the file
2. `name`, `description`, `path` non-empty
3. `os` non-empty; all values in OS enum
4. `info_goal` in InfoGoal enum
5. `privilege` in Privilege enum
6. `path` is absolute for its OS (`/` prefix for unix; `C:\` or `\\` for windows)
7. `confirm.type` in `{regex, keyword, keyword-all}`
8. `confirm.patterns` non-empty; each pattern non-empty string
9. For `type: regex`: every pattern is a valid RE2 regex
10. `min_traversal` >= 0 if present
11. `schema_version` == 1

---

## Contributing new entries

1. Find a source (CVE writeup, pentest report, public research) confirming the path is a real LFI target.
2. Determine the correct `confirm` block — a specific regex or keyword that would appear in the actual file content, not in error pages. This is the hardest part. Do not use generic patterns.
3. Use `exhumed db validate --db database/` to verify before committing.
4. Add at least one `references` URL.
5. Curated entries go in `database/<group>.yaml`. Raw/unreviewed entries go in `database/_raw/`.
