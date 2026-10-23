# osv-uv-scan

Author: Alessandro Filippo Annini

[![skills.sh](https://skills.sh/b/AlessandroAnnini/osv-uv-scan)](https://skills.sh/AlessandroAnnini/osv-uv-scan)

Agent skill that matches registry versions in `uv.lock` against the [OSV.dev](https://osv.dev) API. The project package, and git, path, and direct-URL installs, are left out of the query. Third-party installs that were not queried are named in `warnings`. The format follows the [Agent Skills specification](https://agentskills.io/specification), which is what [skills.sh](https://skills.sh) publishes.

```
osv-uv-scan/
├── SKILL.md
├── LICENSE
├── scripts/osv-scan.py
├── scripts/osv-scan.test.py
└── references/report-schema.md
```

Requires Python 3.11 or newer and network access to `https://api.osv.dev`, `https://www.python.org`, and `https://peps.python.org`. No packages to install.

```bash
python3 scripts/osv-scan.py /path/to/project
```

Stdout is one JSON document. The fields match `osv-npm-scan` and are described in `references/report-schema.md`. `ecosystem` is `PyPI`.

The report also has a separate `runtime` section for CPython itself. An upstream interpreter (from `.venv`, or the one running the script) is matched against the [Python Software Foundation advisories](https://github.com/psf/advisory-database) in OSV, and against newer patch releases on python.org. A Debian or Ubuntu Python is matched against that distro's own records, since distros backport fixes without changing the version. `.python-version` and `requires-python` get the support phase and end-of-life date of their line. To check another version, such as the one in your Docker image:

```bash
python3 scripts/osv-scan.py /path/to/project --python-version 3.12.3
```

```bash
python3 scripts/osv-scan.test.py
```

Install:

```bash
npx skills add AlessandroAnnini/osv-uv-scan
```
