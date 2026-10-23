#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("osv-scan.py")
spec = importlib.util.spec_from_file_location("osv_scan", SCRIPT)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
UV_LOCK = """
version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "httpx" }, { name = "PySocks" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "httpx"
version = "0.28.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "httpcore" }]

[[package]]
name = "httpcore"
version = "1.0.9"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.3.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "localpkg"
version = "1.0.0"
source = { path = "packages/localpkg" }

[[package]]
name = "gitpkg"
version = "2.0.0"
source = { git = "https://example.com/gitpkg.git" }
"""


def row(result, name):
    found = [item for item in result["rows"] if item["norm"] == name]
    if len(found) != 1:
        raise AssertionError(f"{name}: {found}")
    return found[0]


class ScanTests(unittest.TestCase):
    def test_pep440_orders_a_dev_release_before_the_final(self):
        order = [
            "1.0.dev0",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1",
            "1.1",
        ]
        for earlier, later in zip(order, order[1:]):
            self.assertEqual(scan.compare_versions(earlier, later), -1, f"{earlier} < {later}")
        self.assertEqual(scan.compare_versions("1.0", "1.0.0"), 0)
        self.assertEqual(scan.compare_versions("1.0c1", "1.0rc1"), 0)
        self.assertEqual(scan.compare_versions("2.0", "1!1.0"), -1)
        self.assertEqual(scan.compare_versions("1.0", "1.0+local"), -1)
        self.assertEqual(scan.compare_versions("1.0+a", "1.0+1"), -1)
        self.assertIsNone(scan.compare_versions("1.2.3", "not-a-version"))

    def test_lowest_fix_is_the_next_version_above_the_install(self):
        self.assertEqual(scan.lowest_fix(["1.0.0", "1.2.4", "2.0.0"], "1.2.3"), "1.2.4")
        self.assertEqual(scan.lowest_fix(["1.0a1", "1.0"], "1.0.dev1"), "1.0a1")
        self.assertIsNone(scan.lowest_fix(["not-a-version", "1.2.3"], "1.2.3"))

    def test_cvss_v3_scores_known_vectors_and_rejects_a_missing_scope(self):
        self.assertEqual(scan.cvss_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(scan.cvss_v3(HIGH_VECTOR), 7.5)
        self.assertEqual(scan.cvss_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10)
        self.assertEqual(scan.cvss_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), 8.8)
        self.assertEqual(scan.cvss_v3("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2)
        self.assertIsNone(scan.cvss_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"))
        self.assertIsNone(scan.cvss_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))

    def test_publisher_moderate_wins_over_an_alias_cvss_vector(self):
        advisory = scan.summarize_group(
            [
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "summary": "example",
                    "aliases": ["CVE-2026-1"],
                    "database_specific": {"severity": "MODERATE"},
                },
                {
                    "id": "CVE-2026-1",
                    "aliases": ["GHSA-aaaa-bbbb-cccc"],
                    "severity": [{"type": "CVSS_V3", "score": HIGH_VECTOR}],
                },
            ],
            "httpx",
            "0.28.1",
        )
        self.assertEqual(advisory["severity"], "MEDIUM")
        self.assertEqual(advisory["score"], 7.5)
        self.assertEqual(advisory["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(advisory["aliases"], ["CVE-2026-1"])

    def test_a_withdrawn_record_does_not_merge_two_live_advisories(self):
        groups = scan.group_records(
            [
                {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1"]},
                {"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2026-2"]},
                {"id": "OSV-dead", "aliases": ["CVE-2026-1", "CVE-2026-2"], "withdrawn": "2026-01-01T00:00:00Z"},
            ]
        )
        self.assertEqual(sorted(group[0]["id"] for group in groups), ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"])

    def test_uv_lock_marks_prod_dev_and_skips_path_and_git(self):
        result = scan.collect_uv_lock(UV_LOCK)
        self.assertNotIn("error", result)
        self.assertEqual(
            sorted(item["norm"] for item in result["rows"]),
            ["httpcore", "httpx", "pluggy", "pysocks", "pytest"],
        )
        httpx = row(result, "httpx")
        self.assertTrue(httpx["production"])
        self.assertTrue(httpx["direct"])
        self.assertTrue(httpx["direct_production"])
        self.assertEqual(httpx["introduced_by"], [])
        httpcore = row(result, "httpcore")
        self.assertTrue(httpcore["production"])
        self.assertFalse(httpcore["direct"])
        self.assertEqual(httpcore["introduced_by"], ["httpx"])
        self.assertTrue(row(result, "pysocks")["direct_production"])
        pytest = row(result, "pytest")
        self.assertFalse(pytest["production"])
        self.assertTrue(pytest["direct"])
        self.assertFalse(pytest["direct_production"])
        pluggy = row(result, "pluggy")
        self.assertFalse(pluggy["production"])
        self.assertEqual(pluggy["introduced_by"], ["pytest"])
        self.assertEqual(
            result["warnings"],
            [
                "uv.lock: gitpkg@2.0.0 is a git install and was not queried",
                "uv.lock: localpkg@1.0.0 is a path install and was not queried",
            ],
        )

    def test_empty_dev_group_is_not_a_package_name(self):
        result = scan.collect_uv_lock(
            """
            version = 1
            [[package]]
            name = "httpx"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [{ name = "dev" }]
            [[package]]
            name = "dev"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [{ name = "httpx" }]
            [package.dev-dependencies]
            dev = []
            """
        )
        dev = row(result, "dev")
        self.assertTrue(dev["production"])
        self.assertFalse(dev["direct"])
        self.assertEqual(dev["introduced_by"], ["httpx"])

    def test_selected_extra_is_production_and_unselected_extra_is_not(self):
        result = scan.collect_uv_lock(
            """
            version = 1
            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [{ name = "httpx", extra = ["http2"] }]
            [[package]]
            name = "httpx"
            version = "0.28.1"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [{ name = "httpcore" }]
            [package.optional-dependencies]
            http2 = [{ name = "h2" }]
            socks = [{ name = "socksio" }]
            [[package]]
            name = "httpcore"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "h2"
            version = "4.0.0"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "socksio"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            """
        )
        self.assertEqual(row(result, "h2")["introduced_by"], ["httpx"])
        self.assertTrue(row(result, "h2")["production"])
        self.assertFalse(row(result, "socksio")["production"])
        self.assertEqual(row(result, "socksio")["introduced_by"], [])

    def test_version_edge_does_not_follow_the_other_locked_version(self):
        result = scan.collect_uv_lock(
            """
            version = 1
            [[package]]
            name = "foo"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [{ name = "left" }]
            [[package]]
            name = "foo"
            version = "2.0.0"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [{ name = "right" }]
            [[package]]
            name = "left"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "right"
            version = "1.0.0"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
                { name = "foo", version = "1.0.0", source = { registry = "https://pypi.org/simple" } },
            ]
            """
        )
        foo_old = [item for item in result["rows"] if item["norm"] == "foo" and item["version"] == "1.0.0"][0]
        foo_new = [item for item in result["rows"] if item["norm"] == "foo" and item["version"] == "2.0.0"][0]
        self.assertTrue(foo_old["direct_production"])
        self.assertFalse(foo_new["production"])
        self.assertFalse(foo_new["direct"])
        self.assertTrue(row(result, "left")["production"])
        self.assertEqual(row(result, "left")["introduced_by"], ["foo"])
        self.assertFalse(row(result, "right")["production"])

    def test_source_edge_does_not_follow_the_other_registry(self):
        result = scan.collect_uv_lock(
            """
            version = 1
            [[package]]
            name = "torch"
            version = "2.5.1"
            source = { registry = "https://pypi.org/simple" }
            dependencies = [{ name = "left" }]
            [[package]]
            name = "torch"
            version = "2.5.1"
            source = { registry = "https://download.pytorch.org/whl/cpu" }
            dependencies = [{ name = "right" }]
            [[package]]
            name = "left"
            version = "1"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "right"
            version = "1"
            source = { registry = "https://pypi.org/simple" }
            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [
                { name = "torch", version = "2.5.1", source = { registry = "https://pypi.org/simple" } },
            ]
            """
        )
        chosen = [item for item in result["rows"] if item["norm"] == "torch" and item["direct"]]
        other = [item for item in result["rows"] if item["norm"] == "torch" and not item["direct"]]
        self.assertEqual(len(chosen), 1)
        self.assertTrue(chosen[0]["production"])
        self.assertEqual(len(other), 1)
        self.assertFalse(other[0]["production"])
        self.assertTrue(row(result, "left")["production"])
        self.assertFalse(row(result, "right")["production"])

    def test_same_lockfile_location_keeps_one_entry(self):
        entry = {"locations": []}
        scan.add_location(
            entry,
            {"lockfile": "uv.lock", "production": False, "direct": False, "directProduction": False, "introducedBy": ["right"]},
        )
        scan.add_location(
            entry,
            {"lockfile": "uv.lock", "production": True, "direct": True, "directProduction": True, "introducedBy": ["left"]},
        )
        self.assertEqual(
            entry["locations"],
            [
                {
                    "lockfile": "uv.lock",
                    "production": True,
                    "direct": True,
                    "directProduction": True,
                    "introducedBy": ["left", "right"],
                }
            ],
        )

    def test_uv_lock_version_2_is_rejected(self):
        result = scan.collect_uv_lock('version = 2\npackage = []\n')
        self.assertIn("uv lock version 2", result["error"])

    def test_walk_finds_locks_and_skips_virtualenvs_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            (root / "poetry.lock").write_text("package = []\n", encoding="utf-8")
            venv = root / ".venv" / "lib"
            venv.mkdir(parents=True)
            (venv / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            (root / "linked").symlink_to(root / "pkg")
            lockfiles, warnings = scan.walk(root)
            self.assertEqual(lockfiles, ["pkg/uv.lock"])
            self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
