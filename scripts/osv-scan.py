#!/usr/bin/env python3
"""Match uv.lock versions against https://api.osv.dev.

Stdout is one JSON document. Progress goes to stderr. No dependencies.
"""

import json
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ECOSYSTEM = "PyPI"
API = "https://api.osv.dev/v1"
BATCH = 800
PAGE_LIMIT = 20
FETCH_WORKERS = 12
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "site-packages"}
LOCK_NAMES = {"uv.lock"}
_PRE_RANK = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "c": 2,
    "rc": 2,
    "pre": 2,
    "preview": 2,
}
_VERSION_RE = re.compile(
    r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?P<pre>
            [-_\.]?
            (?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>
            (?:
                (?:[-_\.]?(?P<post_l>post|rev|r))
                [-_\.]?
                (?P<post_n1>[0-9]+)?
            )
            |
            (?:-(?P<post_n2>[0-9]+))
        )?
        (?P<dev>
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
    """,
    re.IGNORECASE | re.VERBOSE,
)


def fail(error):
    sys.stdout.write(json.dumps({"ecosystem": ECOSYSTEM, "error": error}, indent=2) + "\n")
    raise SystemExit(1)


def eprint(message):
    print(message, file=sys.stderr)


def normalize_name(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _release_key(text):
    nums = [int(part) for part in text.split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return tuple(nums)


def _local_key(local):
    if not local:
        return (-1,)
    parts = []
    for part in re.split(r"[-_.]", local.lower()):
        if part.isdigit():
            parts.append((1, int(part)))
        else:
            parts.append((0, part))
    return (0, tuple(parts))


def parse_version(value):
    match = _VERSION_RE.fullmatch(str(value).strip())
    if not match:
        return None
    # A dev release with no pre and no post sorts before every pre-release.
    if match.group("pre"):
        pre = (0, _PRE_RANK[match.group("pre_l").lower()], int(match.group("pre_n") or 0))
    elif match.group("dev") and not match.group("post"):
        pre = (-1,)
    else:
        pre = (1,)
    if match.group("post"):
        number = match.group("post_n1")
        if number is None:
            number = match.group("post_n2")
        post = (0, int(number or 0))
    else:
        post = (-1,)
    dev = (0, int(match.group("dev_n") or 0)) if match.group("dev") else (1,)
    return (
        int(match.group("epoch") or 0),
        _release_key(match.group("release")),
        pre,
        post,
        dev,
        _local_key(match.group("local")),
    )


def compare_versions(left, right):
    parsed_left = parse_version(left)
    parsed_right = parse_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    if parsed_left < parsed_right:
        return -1
    if parsed_left > parsed_right:
        return 1
    return 0


def lowest_fix(versions, installed):
    later = []
    for version in versions:
        cmp = compare_versions(version, installed)
        if cmp is not None and cmp > 0:
            later.append(version)
    later.sort(key=parse_version)
    return later[0] if later else None


def round_up_score(value):
    # Half away from zero, matching the CVSS v3 roundup used by the npm skill.
    int_input = int(value * 100000 + 0.5)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def cvss_v3(vector):
    if not vector or not str(vector).startswith("CVSS:3"):
        return None
    metrics = {}
    for part in str(vector).split("/")[1:]:
        key, sep, val = part.partition(":")
        if sep and key and val:
            metrics[key] = val
    if metrics.get("S") not in {"U", "C"}:
        return None
    changed = metrics["S"] == "C"
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV"))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC"))
    pr_table = {"N": 0.85, "L": 0.68, "H": 0.5} if changed else {"N": 0.85, "L": 0.62, "H": 0.27}
    pr = pr_table.get(metrics.get("PR"))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI"))
    c = {"N": 0, "L": 0.22, "H": 0.56}.get(metrics.get("C"))
    i = {"N": 0, "L": 0.22, "H": 0.56}.get(metrics.get("I"))
    a = {"N": 0, "L": 0.22, "H": 0.56}.get(metrics.get("A"))
    if None in (av, ac, pr, ui, c, i, a):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    exploit = 8.22 * av * ac * pr * ui
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0
    raw = min(1.08 * (impact + exploit), 10) if changed else min(impact + exploit, 10)
    return round_up_score(raw)


def numeric_score(record):
    db = record.get("database_specific") or {}
    cvss = db.get("cvss") or {}
    if isinstance(cvss, dict) and isinstance(cvss.get("score"), (int, float)):
        return cvss["score"]
    if isinstance(db.get("cvss_score"), (int, float)):
        return db["cvss_score"]
    scores = []
    for item in record.get("severity") or []:
        if isinstance(item.get("score"), str):
            score = cvss_v3(item["score"])
            if score is not None:
                scores.append(score)
    return max(scores) if scores else None


def publisher_severity(record):
    raw = (record.get("database_specific") or {}).get("severity")
    if not isinstance(raw, str) or not raw.strip():
        return None
    label = raw.strip().upper()
    if label == "MODERATE":
        return "MEDIUM"
    if label in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return label
    return None


def label_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def fixed_versions(record, name):
    found = set()
    norm = normalize_name(name)
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != ECOSYSTEM or normalize_name(pkg.get("name") or "") != norm:
            continue
        for rang in affected.get("ranges") or []:
            for event in rang.get("events") or []:
                if event.get("fixed"):
                    found.add(event["fixed"])
    return list(found)


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, value):
        self.parent.setdefault(value, value)
        parent = self.parent[value]
        if parent != value:
            root = self.find(parent)
            self.parent[value] = root
            return root
        return value

    def union(self, left, right):
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[left_root] = right_root


def group_records(records):
    groups = _UnionFind()
    for record in records:
        if record.get("withdrawn"):
            continue
        for alias in record.get("aliases") or []:
            groups.union(record["id"], alias)
    buckets = {}
    for record in records:
        if record.get("withdrawn"):
            continue
        root_id = groups.find(record["id"])
        buckets.setdefault(root_id, []).append(record)
    return list(buckets.values())


def summarize_group(group, package_name, installed):
    published = [label for label in (publisher_severity(record) for record in group) if label]
    pool = published or [label_from_score(numeric_score(record)) for record in group]
    pool.sort(key=lambda label: RANK.get(label, 0), reverse=True)
    scores = [score for score in (numeric_score(record) for record in group) if score is not None]
    primary = next((record for record in group if str(record.get("id", "")).startswith("GHSA-") and record.get("summary")), None)
    if primary is None:
        primary = next((record for record in group if str(record.get("id", "")).startswith("GHSA-")), None)
    if primary is None:
        primary = next((record for record in group if record.get("summary")), group[0])
    aliases = sorted(
        {
            alias
            for record in group
            for alias in [record.get("id"), *(record.get("aliases") or [])]
            if alias and alias != primary.get("id")
        }
    )
    fixes = []
    seen = set()
    for record in group:
        for version in fixed_versions(record, package_name):
            if version not in seen:
                seen.add(version)
                fixes.append(version)
    return {
        "id": primary.get("id"),
        "aliases": aliases,
        "summary": primary.get("summary") or "",
        "severity": pool[0] if pool else "UNKNOWN",
        "score": max(scores) if scores else None,
        "fixed": lowest_fix(fixes, installed),
        "url": f"https://osv.dev/vulnerability/{primary.get('id')}",
    }


def upgrade_to(advisories):
    if not advisories or any(not item.get("fixed") for item in advisories):
        return None
    return max((item["fixed"] for item in advisories), key=parse_version)


def _add_parent(parents, child, parent):
    if child is None or parent is None or child == parent:
        return
    parents.setdefault(child, set()).add(parent)


def _dep_edges(items):
    edges = []
    if not isinstance(items, list):
        return edges
    for item in items:
        if isinstance(item, str) and item.strip():
            edges.append({"norm": normalize_name(item), "version": None, "source": None, "extras": ()})
            continue
        if not isinstance(item, dict) or not item.get("name"):
            continue
        version = item.get("version") if isinstance(item.get("version"), str) else None
        source = item.get("source") if isinstance(item.get("source"), dict) else None
        raw_extras = item.get("extra")
        if raw_extras is None:
            raw_extras = item.get("extras")
        if isinstance(raw_extras, str):
            raw_extras = [raw_extras]
        extras = tuple(
            sorted({normalize_name(extra) for extra in raw_extras or [] if isinstance(extra, str) and extra.strip()})
        )
        edges.append(
            {
                "norm": normalize_name(item["name"]),
                "version": version,
                "source": source,
                "extras": extras,
            }
        )
    return edges


def _edges_from_groups(table):
    edges = []
    if not isinstance(table, dict):
        return edges
    for value in table.values():
        edges.extend(_dep_edges(value))
    return edges


def _optional_edges(table):
    found = {}
    if not isinstance(table, dict):
        return found
    for key, value in table.items():
        found.setdefault(normalize_name(key), []).extend(_dep_edges(value))
    return found


def _source_matches(package_source, edge_source):
    if not edge_source:
        return True
    if not isinstance(package_source, dict):
        return False
    return all(package_source.get(key) == value for key, value in edge_source.items())


def _resolve_nodes(nodes, by_name, edge):
    found = []
    for index in by_name.get(edge["norm"], ()):
        node = nodes[index]
        if edge["version"] is not None and node["version"] != edge["version"]:
            continue
        if not _source_matches(node["source"], edge["source"]):
            continue
        found.append(index)
    return found


def _introduced_by(index, parents, direct, nodes):
    found = set()
    seen = {index}
    queue = deque([index])
    while queue:
        current = queue.popleft()
        for parent in parents.get(current, ()):
            if parent in direct:
                found.add(nodes[parent]["norm"])
                continue
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
    return sorted(found)


def uv_skip_reason(source):
    if not isinstance(source, dict):
        return "non-registry"
    if "registry" in source:
        return None
    if any(key in source for key in ("editable", "virtual", "workspace")):
        return "project"
    if "git" in source:
        return "git"
    if "path" in source or "directory" in source:
        return "path"
    if "url" in source:
        return "url"
    return "non-registry"


def collect_uv_lock(text, rel="uv.lock"):
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        return {"error": f"{rel}: {err}"}
    version = data.get("version")
    if version != 1:
        shown = version if version is not None else "missing"
        return {"error": f"{rel}: uv lock version {shown} is not supported (need 1)"}
    packages = data.get("package") or []
    if isinstance(packages, dict):
        packages = [packages]
    nodes = []
    for pkg in packages:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        nodes.append(
            {
                "name": str(pkg["name"]),
                "norm": normalize_name(pkg["name"]),
                "version": pkg.get("version") if isinstance(pkg.get("version"), str) else None,
                "source": source,
                "reason": uv_skip_reason(source),
                "base": _dep_edges(pkg.get("dependencies")),
                "dev": _edges_from_groups(pkg.get("dev-dependencies"))
                + _edges_from_groups(pkg.get("dependency-groups")),
                "optional": _optional_edges(pkg.get("optional-dependencies")),
            }
        )
    by_name = {}
    for index, node in enumerate(nodes):
        by_name.setdefault(node["norm"], []).append(index)
    roots = [index for index, node in enumerate(nodes) if node["reason"] == "project"]
    parents = {}
    children = [set() for _ in nodes]
    pending = []
    for index in roots:
        pending.extend((index, edge) for edge in nodes[index]["base"])
        pending.extend((index, edge) for edge in nodes[index]["dev"])
    seen_edges = set()
    while pending:
        parent, edge = pending.pop()
        for target in _resolve_nodes(nodes, by_name, edge):
            mark = (parent, target, edge["extras"])
            if mark in seen_edges:
                continue
            seen_edges.add(mark)
            _add_parent(parents, target, parent)
            children[parent].add(target)
            pending.extend((target, base_edge) for base_edge in nodes[target]["base"])
            for extra in edge["extras"]:
                pending.extend((target, opt_edge) for opt_edge in nodes[target]["optional"].get(extra, ()))
    direct_prod = set()
    direct_dev = set()
    for index in roots:
        for edge in nodes[index]["base"]:
            direct_prod.update(_resolve_nodes(nodes, by_name, edge))
        for edge in nodes[index]["dev"]:
            direct_dev.update(_resolve_nodes(nodes, by_name, edge))
    direct_dev -= direct_prod
    direct = direct_prod | direct_dev
    if roots:
        production = set()
        queue = deque(direct_prod)
        while queue:
            current = queue.popleft()
            if current in production:
                continue
            production.add(current)
            queue.extend(children[current])
    else:
        production = None
    warnings = []
    if not roots:
        warnings.append(f"{rel}: no project package in the lock, so direct and dev are unknown")
    rows = []
    skipped = {}
    installed = set()
    for index, node in enumerate(nodes):
        if node["version"] is None:
            continue
        key = f"{node['norm']}@{node['version']}"
        if node["reason"] == "project":
            continue
        if node["reason"]:
            skipped.setdefault(key, (node["name"], node["version"], node["reason"]))
            continue
        installed.add(key)
        is_direct = index in direct
        rows.append(
            {
                "version": node["version"],
                "norm": node["norm"],
                "production": True if production is None else index in production,
                "direct": is_direct,
                "direct_production": index in direct_prod,
                "introduced_by": (
                    []
                    if is_direct or production is None
                    else _introduced_by(index, parents, direct, nodes)
                ),
            }
        )
    for key, (name, version, reason) in sorted(skipped.items()):
        if key in installed:
            continue
        warnings.append(f"{rel}: {name}@{version} is a {reason} install and was not queried")
    return {"rel": rel, "rows": rows, "warnings": warnings}


def walk(root):
    root = root.resolve()
    lockfiles = []
    warnings = []

    def rel_of(path):
        text = path.resolve().relative_to(root).as_posix()
        return text or path.name

    def visit(directory):
        try:
            entries = list(directory.iterdir())
        except OSError as err:
            message = f"cannot read {rel_of(directory) if directory != root else directory}: {err}"
            if directory == root:
                fail(message)
            warnings.append(message)
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in SKIP_DIRS or (entry / "pyvenv.cfg").is_file():
                    continue
                visit(entry)
                continue
            if not entry.is_file():
                continue
            rel = rel_of(entry)
            if entry.name in LOCK_NAMES:
                lockfiles.append(rel)

    visit(root)
    lockfiles.sort()
    return lockfiles, warnings


def read_lock(root, rel):
    path = root / rel
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        return {"error": f"{rel}: {err}"}
    return collect_uv_lock(text, rel)


def request_json(url, payload=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    last = None
    for attempt in range(1, 5):
        try:
            request = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as err:
            if err.code == 429 or err.code >= 500:
                last = RuntimeError(f"{err.code} {url}")
                _sleep(0.4 * attempt)
                continue
            body = err.read().decode(errors="replace")[:300]
            raise RuntimeError(f"{err.code} {url}: {body}") from err
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            last = err
            if attempt == 4:
                break
            _sleep(0.4 * attempt)
    raise RuntimeError(str(last))


def _sleep(seconds):
    time.sleep(seconds)


def _fetch_record(vuln_id):
    return vuln_id, request_json(f"{API}/vulns/{quote(vuln_id, safe='')}")


def add_location(entry, location):
    for existing in entry["locations"]:
        if existing["lockfile"] != location["lockfile"]:
            continue
        existing["production"] = existing["production"] or location["production"]
        existing["direct"] = existing["direct"] or location["direct"]
        existing["directProduction"] = existing["directProduction"] or location["directProduction"]
        existing["introducedBy"] = sorted(set(existing["introducedBy"]) | set(location["introducedBy"]))
        return
    entry["locations"].append(location)


def scan(root):
    root = Path(root).resolve()
    if not root.is_dir():
        fail(f"not a directory: {root}")
    lockfiles, warnings = walk(root)
    if not lockfiles:
        fail(f"no uv.lock found under {root}")
    parsed = [read_lock(root, rel) for rel in lockfiles]
    for item in parsed:
        if item.get("error"):
            warnings.append(item["error"])
        else:
            warnings.extend(item.get("warnings") or [])
    if all(item.get("error") for item in parsed):
        fail("; ".join(warnings))
    by_key = {}
    for item in parsed:
        if item.get("error"):
            continue
        for row in item["rows"]:
            key = f"{row['norm']}@{row['version']}"
            entry = by_key.get(key)
            if entry is None:
                entry = {"name": row["norm"], "version": row["version"], "locations": []}
                by_key[key] = entry
            add_location(
                entry,
                {
                    "lockfile": item["rel"],
                    "production": row["production"],
                    "direct": row["direct"],
                    "directProduction": row["direct_production"],
                    "introducedBy": row["introduced_by"],
                },
            )
    packages = list(by_key.values())
    readable = [item for item in parsed if not item.get("error")]
    eprint(f"lockfiles: {len(readable)}")
    eprint(f"package versions: {len(packages)}")
    queries = [
        {"version": pkg["version"], "package": {"name": pkg["name"], "ecosystem": ECOSYSTEM}}
        for pkg in packages
    ]
    results = []
    for start in range(0, len(queries), BATCH):
        chunk = queries[start : start + BATCH]
        eprint(f"querybatch {start + 1}-{start + len(chunk)} of {len(queries)}")
        data = request_json(f"{API}/querybatch", {"queries": chunk})
        got = data.get("results") if isinstance(data, dict) else None
        if not isinstance(got, list) or len(got) != len(chunk):
            fail(f"OSV querybatch returned {len(got) if isinstance(got, list) else 0} results for {len(chunk)} queries")
        results.extend(got)
    for index, pkg in enumerate(packages):
        vulns = list((results[index] or {}).get("vulns") or [])
        token = (results[index] or {}).get("next_page_token")
        pages = 0
        while token:
            pages += 1
            if pages > PAGE_LIMIT:
                fail(f"OSV kept paging {pkg['name']}@{pkg['version']}")
            page = request_json(
                f"{API}/query",
                {
                    "version": pkg["version"],
                    "package": {"name": pkg["name"], "ecosystem": ECOSYSTEM},
                    "page_token": token,
                },
            )
            vulns.extend(page.get("vulns") or [])
            token = page.get("next_page_token")
        pkg["vuln_ids"] = list(dict.fromkeys(vuln.get("id") for vuln in vulns if vuln.get("id")))
    hits = [pkg for pkg in packages if pkg["vuln_ids"]]
    ids = list(dict.fromkeys(vuln_id for pkg in hits for vuln_id in pkg["vuln_ids"]))
    eprint(f"advisory ids: {len(ids)}")
    records = {}
    if ids:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            for vuln_id, record in pool.map(_fetch_record, ids):
                records[vuln_id] = record
    findings = []
    for hit in hits:
        present = [records[vuln_id] for vuln_id in hit["vuln_ids"] if vuln_id in records]
        advisories = [summarize_group(group, hit["name"], hit["version"]) for group in group_records(present)]
        advisories.sort(key=lambda item: (-RANK.get(item["severity"], 0), -(item["score"] if item["score"] is not None else -1), item["id"]))
        if not advisories:
            continue
        hit["locations"].sort(key=lambda loc: loc["lockfile"])
        findings.append(
            {
                "name": hit["name"],
                "version": hit["version"],
                "severity": advisories[0]["severity"],
                "upgradeTo": upgrade_to(advisories),
                "locations": hit["locations"],
                "advisories": advisories,
            }
        )
    def sort_key(finding):
        prod = 0 if any(loc["production"] for loc in finding["locations"]) else 1
        version_key = parse_version(finding["version"])
        return (prod, -RANK.get(finding["severity"], 0), finding["name"], version_key or (999,), finding["version"])

    findings.sort(key=sort_key)
    eprint(f"vulnerable versions: {len(findings)}")
    report = {
        "ecosystem": ECOSYSTEM,
        "scannedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "root": str(root),
        "lockfiles": [item["rel"] for item in readable],
        "packageVersions": len(packages),
        "vulnerablePackageVersions": len(findings),
        "findings": findings,
    }
    if warnings:
        report["warnings"] = warnings
    sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    try:
        scan(sys.argv[1] if len(sys.argv) > 1 else Path.cwd())
    except SystemExit:
        raise
    except Exception as err:
        fail(str(err))
