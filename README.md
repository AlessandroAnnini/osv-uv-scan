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

Requires Python 3.11 or newer and network access to `https://api.osv.dev`. No packages to install.

```bash
python3 scripts/osv-scan.py /path/to/project
```

Stdout is one JSON document. The fields match `osv-npm-scan` and are described in `references/report-schema.md`. `ecosystem` is `PyPI`.

```bash
python3 scripts/osv-scan.test.py
```

Install:

```bash
npx skills add AlessandroAnnini/osv-uv-scan
```
