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
  "findings": [],
  "runtime": {}
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

## Runtime (PyPI)

`runtime` is the CPython interpreter checked against the [PSF advisory database](https://github.com/psf/advisory-database) through OSV, the [python.org release list](https://www.python.org/api/v2/downloads/release/?is_published=true), and the [release cycle](https://peps.python.org/api/release-cycle.json). It is separate from `findings` and does not change `vulnerablePackageVersions`. The npm and NuGet skills have a `runtime` with the same intent. The fields differ because the sources differ.

| Field | Meaning |
| --- | --- |
| `name` | Always `python` |
| `recommendedLine` | The newest line in the `bugfix` phase |
| `vulnerable` | True when any checked interpreter is vulnerable. Null when none could be checked |
| `interpreters` | One entry per interpreter. See below |
| `targets` | `.python-version` and `requires-python` entries. See below |
| `lockfilesWithoutVenv` | Present when some lockfiles have a `.venv` and these do not. No interpreter was checked for them. When no lockfile has a venv, the Python running the script is checked instead |
| `error` | Present instead of the result fields when python.org or peps.python.org could not be fetched. The package scan still completes |

Interpreter entry, always: `source` (`venv` from `.venv/pyvenv.cfg`, `flag` for `--python-version`, or `process` for the Python running the script), `venv` when the source is `venv`, `version`, `build` (`upstream` or `distro`), `releaseLine`, `supportPhase` (`feature`, `prerelease`, `bugfix`, `security`, or `end-of-life`), `endOfLife` (from the phase, null when the line is unknown), `endOfLifeDate` (a day for past dates, often only a month for future ones), `vulnerable`, and `advisories`. An entry that could not be checked has `error` or `note` instead of the result fields. A version that is not a published CPython release is an error, because OSV returns nothing for a tag it does not know.

Upstream only: `missedPatchReleases` (newer patch releases in the line, ascending) and `upgradeTo` (the latest patch in the line, or null when it is current). On a line in the `security` or `end-of-life` phase, every patch release is a security release, so a missed one makes `vulnerable` true even with no advisory.

Distro only: `package` and `packageVersion` (the dpkg source package and version), and `ecosystem` (such as `Ubuntu:24.04:LTS`).

Runtime advisory: `id` (CVE first, then PSF), `aliases`, `summary`, `severity` (from a publisher label, the distro priority, or CVSS v3; `UNKNOWN` otherwise), `score`, and `url`. Upstream advisories also have `fixedInLine` (false when the latest patch in the line still has it) and `inferred` (true when it was found on the next patch release and added back, because OSV misses some release tags such as `x.y.0`). Distro advisories have `fixAvailable` (true when a newer package in that distro fixes it).

Target entry: `file`, `kind` (`python-version` or `requires-python`), `value`, `line` (null when no line could be read), and, when `line` is set, `releaseLine`, `supportPhase`, `endOfLife`, and `endOfLifeDate`. For `requires-python` the line is the declared minimum.

## Error

Exit code 1. Stdout is still JSON:

```json
{
  "ecosystem": "PyPI",
  "error": "no uv.lock found under /absolute/project"
}
```

The error document has no `runtime`.
