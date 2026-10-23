# Report schema

`scripts/osv-scan.py` prints this document to stdout. The fields match `osv-npm-scan`. `ecosystem` is `PyPI`. The only lockfile is `uv.lock`.

## Success

```json
{
  "ecosystem": "PyPI",
  "scannedAt": "2026-10-23T08:00:00.000Z",
  "root": "/absolute/project",
  "lockfiles": ["uv.lock"],
  "packageVersions": 42,
  "vulnerablePackageVersions": 3,
  "findings": []
}
```

`packageVersions` is the number of distinct name@version pairs sent to OSV. Names are PEP 503 normalized. `vulnerablePackageVersions` counts those that have at least one current advisory. Withdrawn advisories are omitted.

Findings are sorted with production installs first, then by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), then by name.

### Finding

| Field | Meaning |
| --- | --- |
| `name`, `version` | Installed package and the locked version string. `name` is the PEP 503 form |
| `severity` | Worst advisory label on this version |
| `upgradeTo` | Highest per-advisory fix, compared with PEP 440. Null when any advisory has no fixed version |
| `locations` | One entry per lockfile that installs this version |
| `advisories` | One entry per advisory, aliases already collapsed |

### Location

| Field | Meaning |
| --- | --- |
| `lockfile` | Path relative to `root` |
| `production` | True when this version is reachable from a project dependency, including an extra that dependency selects |
| `direct` | True when a project package selects this version in its dependencies or a dev group |
| `directProduction` | True when that selection is a project dependency. A dev-group dependency is direct, and `directProduction` is false |
| `introducedBy` | Direct dependency names that pull this version in. Empty when `direct` is true |

`uv sync` also installs the dev group unless `--no-dev` is passed. `production` does not include that group. A locked package that no selected dependency reaches, such as an unrequested extra, is not production. When the lock contains more than one distribution of a name, only the version and source named by the edge are followed.

### Advisory

| Field | Meaning |
| --- | --- |
| `id` | Preferred id. A GHSA id when one exists, otherwise the first id |
| `aliases` | Other ids for the same advisory, including CVEs |
| `summary` | OSV summary |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`. `MEDIUM` is GitHub MODERATE. A publisher label wins over a score computed from an alias that has no label |
| `score` | Highest CVSS v3 base score on the merged advisory. Null when the advisory has no numeric score and no usable v3 base vector. Scope must be `U` or `C`. Does not change `severity` |
| `fixed` | Lowest fixed version above the installed version for this advisory, under PEP 440. Null when OSV lists no fix, or none of the listed fixes are newer than the install |
| `url` | `https://osv.dev/vulnerability/<id>` |

`upgradeTo` is the highest `fixed` among advisories that have one, and only when every advisory has a fix. It assumes each advisory stays fixed after that version.

A skipped lockfile, an unreadable directory, or a non-registry install does not fail the scan. `warnings` is present only then. Each entry is the path and the reason. A git, path, direct-URL, or other non-registry install is named and was not queried. The project package is not queried and is not a warning.

## Error

Exit code 1. Stdout is still JSON:

```json
{
  "ecosystem": "PyPI",
  "error": "no uv.lock found under /absolute/project"
}
```
