---
name: osv-uv-scan
description: >-
  Scans Python projects for known vulnerabilities by matching installed
  uv.lock versions against the OSV.dev API. Use whenever the user asks about
  vulnerabilities, CVEs, security advisories, dependency risk, or whether a
  Python project managed by uv is affected, including when they mention
  osv.dev or a uv.lock. Do not use this skill for Node, npm, C#, or NuGet
  projects.
license: MIT
compatibility: Requires Python 3.11 or newer and network access to https://api.osv.dev. Reads uv.lock version 1.
metadata:
  author: Alessandro Filippo Annini
  version: "1.0.0"
  ecosystem: PyPI
---

# osv-uv-scan

Match every registry version in a project's `uv.lock` files against [OSV.dev](https://osv.dev). Report the advisories the API returns. Do not reimplement the scan, and do not edit the script.

This skill emits the same JSON shape as `osv-npm-scan`, documented in [references/report-schema.md](references/report-schema.md).

## Run

From any working directory, run the script that sits next to this file. The argument is the project root:

```bash
python3 /absolute/path/to/osv-uv-scan/scripts/osv-scan.py /absolute/path/to/project
```

The script writes one JSON document to stdout and progress lines to stderr. It does not modify the project.

If stdout contains an `error` field, say what it says and stop. A missing lockfile is not a clean scan. If `warnings` is present, say each one. A warning is a lockfile or directory that could not be read, or an install that was not queried because it is not a registry package.

## What the script covers

- Every `uv.lock` under the project root, except paths inside `.git`, `node_modules`, `site-packages`, or a virtualenv, and except files reached only through a symlink
- `uv.lock` version 1. Production versions are those reachable from a project dependency, including an extra that dependency selects. Other locked versions, including dev groups, are the rest
- Transitive dependencies, and the dependency edges needed for `introducedBy`

It does not query the project itself, or git, path, or direct-URL installs recorded in the lock. It reads `uv.lock` only. Do not guess versions from anywhere else.

## How to report

Read [references/report-schema.md](references/report-schema.md) before summarizing.

Lead with the answer: whether any locked version is in an OSV advisory, how many package versions were queried, and how many of those versions have at least one advisory.

Then a table of production findings at CRITICAL and HIGH, one row per package version:

- Package and locked version
- Lockfile, and whether it is a direct production dependency
- `introducedBy` when it is transitive
- Worst advisory id, a short summary, and `upgradeTo`

`severity` on a finding is already the worst advisory. `MEDIUM` means GitHub's MODERATE. Do not rescore advisories from the CVSS vector. `score` is informational.

When advisories on the same version disagree by major (one fixed in 4.x, another only in 5.x), name the advisory that forces `upgradeTo`. When `upgradeTo` is null, an advisory has no fixed version. Report the highest `fixed` among the advisories that have one, and name the advisory that has none.

Versions are ordered with PEP 440, so `1.0a1` is older than `1.0`, and `1.0` equals `1.0.0`. Package names are matched with PEP 503 normalization.

Mention dev-only CRITICAL and HIGH findings in a short paragraph after the production table. Count the remaining MEDIUM and LOW production findings instead of listing every advisory. Call out a direct production dependency in that remainder when there is one.

This is a lockfile match against known advisories. It does not show whether the vulnerable code runs. Say that once.

Do not upgrade packages unless the user asks.
