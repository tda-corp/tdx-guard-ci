"""
The Python counts against the jq filters of ci-templates/tdxguard-lib.sh, which they replace
in the engine. The filters are read from that file, so a change there without a change in
tdxguard/engine/counts.py fails here. jq runs only in the test; it is skipped where jq is
not installed (the engine never needs it).
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tdxguard.engine import counts

REPOSITORY = Path(__file__).resolve().parents[2]
LIB = REPOSITORY / "ci-templates" / "tdxguard-lib.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "reports"
JQ = shutil.which("jq")

# Which filter applies to which fixture, as the engine pairs them.
FIXTURE_FILTERS = {
    "betterleaks.fixture.json": ["length"],
    "opengrep.fixture.json": ["TG_SARIF_ALL", "TG_OPENGREP_ERR", "TG_SARIF_ERR"],
    "trivy.fixture.json": ["TG_SARIF_ALL", "TG_SARIF_ERR", "TG_OPENGREP_ERR"],
    "trivy-image-secrets.fixture.json": ["TG_SARIF_ALL", "TG_SARIF_ERR"],
    "sbom.fixture.json": ["TG_CDX_ALL", "TG_CDX_SEV"],
    "sbom-image.fixture.json": ["TG_CDX_ALL", "TG_CDX_SEV"],
}

# The counts of the fixtures, so that the Python side is checked even without jq. They are
# what jq printed for these files when the fixtures were recorded (smoke-test fixture).
EXPECTED = {
    ("betterleaks.fixture.json", "length"): 1,
    ("opengrep.fixture.json", "TG_SARIF_ALL"): 7,
    ("opengrep.fixture.json", "TG_OPENGREP_ERR"): 5,
    ("opengrep.fixture.json", "TG_SARIF_ERR"): 0,
    ("trivy.fixture.json", "TG_SARIF_ALL"): 3,
    ("trivy.fixture.json", "TG_SARIF_ERR"): 2,
    ("trivy-image-secrets.fixture.json", "TG_SARIF_ALL"): 1,
    ("sbom.fixture.json", "TG_CDX_ALL"): 11,
    ("sbom.fixture.json", "TG_CDX_SEV"): 6,
    ("sbom-image.fixture.json", "TG_CDX_ALL"): 25,
    ("sbom-image.fixture.json", "TG_CDX_SEV"): 22,
}

# Documents at the edges of the filters: missing keys, null, wrong types, duplicate rule ids,
# mixed-case severities, a malformed rating after a matching one (jq's `any` stops early).
EDGE_CASES = [
    None,
    [],
    [1, 2, 3],
    {},
    "text",
    3,
    -2.5,
    True,
    {"runs": []},
    {"runs": None},
    {"runs": [{}]},
    {"runs": [{"results": []}]},
    {"runs": [{"results": None}]},
    {"runs": [{"results": "x"}]},
    {"runs": [{"results": [{"level": "error"}, {"level": "warning"}, {}, None]}]},
    {"runs": [{"results": [1]}]},
    {"runs": {"a": {"results": {"x": {"level": "error"}}}}},
    {"runs": [{"tool": {"driver": {"rules": []}}, "results": [{"ruleId": "a"}]}]},
    {"runs": [{"tool": {"driver": {}}, "results": []}]},
    {"runs": [{"tool": {"driver": {}}, "results": [{"ruleId": "a"}]}]},
    {"runs": [{"tool": "x", "results": []}]},
    {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "a", "defaultConfiguration": {"level": "error"}},
                            {"id": "a", "defaultConfiguration": {"level": "error"}},
                            {"id": "b", "defaultConfiguration": {"level": "warning"}},
                            {"id": "c"},
                            {"id": 1, "defaultConfiguration": {"level": "error"}},
                            {"id": True, "defaultConfiguration": "not an object"},
                        ]
                    }
                },
                "results": [{"ruleId": "a"}, {"ruleId": "b"}, {"ruleId": "c"}, {"ruleId": 1}, {"ruleId": 1.0}, {}],
            },
            {
                "tool": {"driver": {"rules": [{"id": None, "defaultConfiguration": {"level": "error"}}]}},
                "results": [{}],
            },
        ]
    },
    {
        "runs": [
            {"tool": {"driver": {"rules": [{"id": "a", "defaultConfiguration": "x"}]}}, "results": [{"ruleId": "a"}]}
        ]
    },
    {"vulnerabilities": None},
    {"vulnerabilities": "s"},
    {"vulnerabilities": 5},
    {"vulnerabilities": []},
    {"vulnerabilities": [{}]},
    {"vulnerabilities": ["str"]},
    {"vulnerabilities": [{"ratings": "x"}]},
    {"vulnerabilities": [{"ratings": None}]},
    {"vulnerabilities": [{"ratings": [1]}]},
    {"vulnerabilities": [{"ratings": [{"severity": None}]}]},
    {"vulnerabilities": [{"ratings": [{}]}]},
    {"vulnerabilities": [{"ratings": [{"severity": "high"}, 1]}]},
    {"vulnerabilities": [{"ratings": [{"severity": "LOW"}, {"severity": "HiGh"}]}]},
    {"vulnerabilities": [{"ratings": [{"severity": "Critical"}, {"severity": "critical"}]}]},
    {"vulnerabilities": [{"ratings": [{"severity": "medium"}]}, {"ratings": [{"severity": "İ"}]}]},
    {"vulnerabilities": {"a": {"ratings": {"r": {"severity": "HIGH"}}}}},
    {"vulnerabilities": [{"ratings": [{"severity": "unknown"}, {"severity": 3}]}]},
]


def lib_filters():
    """TG_* filters from tdxguard-lib.sh: NAME='filter'."""
    text = LIB.read_text(encoding="utf-8")
    return {m.group(1): m.group(2) for m in re.finditer(r"^(TG_[A-Z_]+)='(.*)'$", text, re.MULTILINE)}


def python_count(name, document):
    function = counts.length if name == "length" else counts.FILTERS[name]
    try:
        return function(document)
    except counts.CountError:
        return "error"


def jq_count(jq_filter, path):
    result = subprocess.run([JQ, jq_filter, str(path)], capture_output=True, text=True)
    if result.returncode != 0:
        return "error"
    return json.loads(result.stdout)


class TestFixtures(unittest.TestCase):
    def test_expected_counts(self):
        for (fixture, name), expected in EXPECTED.items():
            document = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
            with self.subTest(fixture=fixture, filter=name):
                self.assertEqual(expected, python_count(name, document))

    def test_clean_betterleaks_is_zero(self):
        self.assertEqual(0, counts.length(None))
        self.assertEqual(0, counts.length([]))


@unittest.skipUnless(LIB.is_file(), "ci-templates/tdxguard-lib.sh is not next to the package")
class TestFiltersKnown(unittest.TestCase):
    def test_every_summary_filter_has_a_python_twin(self):
        filters = lib_filters()
        for name in ("TG_SARIF_ALL", "TG_SARIF_ERR", "TG_OPENGREP_ERR", "TG_CDX_ALL", "TG_CDX_SEV"):
            self.assertIn(name, filters)
            self.assertIn(name, counts.FILTERS)


@unittest.skipUnless(JQ, "jq is not installed")
@unittest.skipUnless(LIB.is_file(), "ci-templates/tdxguard-lib.sh is not next to the package")
class TestAgainstJq(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.filters = dict(lib_filters(), length="length")

    def test_fixtures(self):
        checked = 0
        for fixture, names in FIXTURE_FILTERS.items():
            path = FIXTURES / fixture
            document = json.loads(path.read_text(encoding="utf-8"))
            for name in names:
                with self.subTest(fixture=fixture, filter=name):
                    self.assertEqual(jq_count(self.filters[name], path), python_count(name, document))
                    checked += 1
        self.assertEqual(13, checked)

    def test_edge_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i, document in enumerate(EDGE_CASES):
                path = Path(tmp) / f"{i}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                for name in ("length", *counts.FILTERS):
                    with self.subTest(case=i, document=document, filter=name):
                        self.assertEqual(jq_count(self.filters[name], path), python_count(name, document))


if __name__ == "__main__":
    unittest.main()
