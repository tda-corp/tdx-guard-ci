import json
import tempfile
import unittest
from pathlib import Path

from tdxguard import reports


def cdx(*severity_lists):
    return {
        "vulnerabilities": [
            {"id": f"CVE-{i}", "ratings": [{"severity": s} for s in sev]} for i, sev in enumerate(severity_lists)
        ]
    }


class TestCounts(unittest.TestCase):
    def test_cyclonedx_highest_rating_counts_once(self):
        data = cdx(["CRITICAL", "high"], ["high"], ["medium"], ["High", "low"], [])
        self.assertEqual((1, 2), reports.cyclonedx_counts(data))

    def test_cyclonedx_ignore_unfixed(self):
        data = {
            "vulnerabilities": [
                {"ratings": [{"severity": "critical"}], "recommendation": "Upgrade openssl to version 3.0.15"},
                {"ratings": [{"severity": "critical"}]},
                {"ratings": [{"severity": "high"}], "recommendation": ""},
                {"ratings": [{"severity": "high"}], "recommendation": "Upgrade a to version 2"},
            ]
        }
        self.assertEqual((1, 1), reports.cyclonedx_counts(data, ignore_unfixed=True))
        self.assertEqual((2, 2), reports.cyclonedx_counts(data))

    def test_cyclonedx_empty(self):
        self.assertEqual((0, 0), reports.cyclonedx_counts({"components": []}))
        self.assertEqual((0, 0), reports.cyclonedx_counts(None))

    def test_sarif_trivy_security_severity(self):
        data = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "c", "properties": {"security-severity": "9.8"}},
                                {"id": "h", "properties": {"security-severity": "7.5"}},
                                {"id": "m", "properties": {"security-severity": "5.0"}},
                            ]
                        }
                    },
                    # level error on the medium one: the score wins
                    "results": [{"ruleId": "c"}, {"ruleId": "h"}, {"ruleId": "h"}, {"ruleId": "m", "level": "error"}],
                }
            ]
        }
        self.assertEqual((1, 2), reports.sarif_counts(data))

    def test_sarif_opengrep_level_on_rule(self):
        # Opengrep leaves result.level empty and carries the severity on the rule.
        data = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "e", "defaultConfiguration": {"level": "error"}},
                                {"id": "w", "defaultConfiguration": {"level": "warning"}},
                            ]
                        }
                    },
                    "results": [{"ruleId": "e"}, {"ruleId": "w"}, {"ruleId": "e"}, {"ruleId": "x", "level": "error"}],
                }
            ]
        }
        self.assertEqual((0, 3), reports.sarif_counts(data))

    def test_sarif_tags(self):
        data = {
            "runs": [
                {
                    "tool": {"driver": {"rules": [{"id": "t", "properties": {"tags": ["secret", "CRITICAL"]}}]}},
                    "results": [{"ruleId": "t"}],
                }
            ]
        }
        self.assertEqual((1, 0), reports.sarif_counts(data))

    def test_count_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "sbom.cdx.json").write_text(json.dumps(cdx(["critical"], ["high"])))
            (out / "sbom-image-api.cdx.json").write_text(json.dumps(cdx(["critical"])))
            (out / "betterleaks.json").write_text(json.dumps([{"RuleID": "aws"}, {"RuleID": "gh"}]))
            (out / "opengrep.sarif").write_text("not json")
            (out / "summary.json").write_text(json.dumps({"rows": []}))
            counts = reports.count(out)
            self.assertEqual(2, counts.critical)
            self.assertEqual(3, counts.high)
            self.assertEqual((0, 0), counts.per_report["opengrep.sarif"])


class TestGate(unittest.TestCase):
    def counts(self, critical, high):
        counts = reports.Counts()
        counts.add("x", critical, high)
        return counts

    def test_no_gate(self):
        self.assertTrue(reports.evaluate_gate({}, self.counts(5, 5)).passed)

    def test_critical_zero(self):
        result = reports.evaluate_gate({"critical": 0, "high": None}, self.counts(1, 100))
        self.assertFalse(result.passed)
        self.assertEqual(["1 critical finding(s), the gate allows 0"], result.violations)

    def test_within_limits(self):
        self.assertTrue(reports.evaluate_gate({"critical": 0, "high": 3}, self.counts(0, 3)).passed)

    def test_high_exceeded(self):
        result = reports.evaluate_gate({"critical": 0, "high": 3}, self.counts(0, 4))
        self.assertFalse(result.passed)
        self.assertEqual({"critical": 0, "high": 4}, result.counts)


class TestUploadPlan(unittest.TestCase):
    def test_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            for name in (
                "opengrep.sarif",
                "trivy.sarif",
                "sbom.cdx.json",
                "sbom-image-docker-backend.cdx.json",
                "trivy-image-docker-backend.sarif",
                "summary.json",
            ):
                (out / name).write_text("{}")
            (out / "betterleaks.json").write_text(json.dumps([{"RuleID": "x"}]))

            plan = reports.upload_plan(out, {"docker-backend": "tdxguard-local/docker-backend:scan"})

            self.assertEqual(
                [
                    ("betterleaks.json", "Betterleaks", None),
                    ("opengrep.sarif", "SARIF", None),
                    ("trivy.sarif", "SARIF", None),
                    ("sbom.cdx.json", "CycloneDX", None),
                    ("sbom-image-docker-backend.cdx.json", "CycloneDX", "tdxguard-local/docker-backend:scan"),
                    ("trivy-image-docker-backend.sarif", "SARIF", "tdxguard-local/docker-backend:scan"),
                ],
                [(u.path.name, u.parser, u.docker_image_name_tag) for u in plan],
            )
            self.assertEqual(
                {
                    "product_name": "p",
                    "branch_name": "local/jane/main",
                    "parser_name": "CycloneDX",
                    "docker_image_name_tag": "tdxguard-local/docker-backend:scan",
                },
                plan[4].fields("p", "local/jane/main"),
            )
            self.assertEqual(
                {"product_name": "p", "branch_name": "b", "parser_name": "SARIF"}, plan[1].fields("p", "b")
            )

    def test_clean_betterleaks_is_uploaded(self):
        # A clean scan goes up too, so that TDxGuard records that the secrets scan ran
        for content in ("null", "[]"):
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                (out / "betterleaks.json").write_text(content)
                plan = reports.upload_plan(out, {})
                self.assertEqual([("betterleaks.json", "Betterleaks")], [(u.path.name, u.parser) for u in plan])

    def test_broken_betterleaks_is_skipped(self):
        for content in ("", "{}", "true"):
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                (out / "betterleaks.json").write_text(content)
                self.assertEqual([], reports.upload_plan(out, {}))


if __name__ == "__main__":
    unittest.main()
