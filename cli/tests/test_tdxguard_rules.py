"""
TDxGuard's own Opengrep rules (tdxguard/engine/helpers/tdxguard_rules.yaml) against their test
cases in fixtures/tdxguard_rules/.

A test case is a comment on the line before the code it is about, in the style of Opengrep's
own rule tests: `ruleid: <id>` when a finding of that rule must cover the next line, `ok: <id>`
when none may. The fixtures sit in the directories the rules' `paths` expect (routes/,
app/Http/, .github/workflows/, next.config.*), so the path filters are tested too.

The scan needs an Opengrep binary: $OPENGREP, `opengrep` on the PATH, or one the native engine
installed into the tools cache. Without one only the static checks run.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

from tdxguard.engine import helpers, tools

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tdxguard_rules"
ANNOTATION = re.compile(r"(?:#|//)\s*(ruleid|ok):\s*([\w.-]+)")


def find_opengrep() -> Optional[str]:
    candidates = [os.environ.get("OPENGREP", ""), shutil.which("opengrep") or ""]
    candidates += [str(p) for p in sorted((tools.tools_dir() / "opengrep").glob("*/opengrep"), reverse=True)]
    return next((c for c in candidates if c and os.access(c, os.X_OK)), None)


def annotations() -> List[Tuple[str, str, str, int]]:
    """(kind, rule id, path relative to the fixtures, line the annotation is about)."""
    found = []
    for path in sorted(p for p in FIXTURES.rglob("*") if p.is_file()):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = ANNOTATION.search(line)
            if match:
                found.append((match.group(1), match.group(2), path.relative_to(FIXTURES).as_posix(), number + 1))
    return found


def rules() -> List[Dict]:
    return yaml.safe_load(helpers.TDXGUARD_RULES.read_text(encoding="utf-8"))["rules"]


class TestRuleFile(unittest.TestCase):
    def test_every_rule_is_a_security_rule(self):
        for rule in rules():
            with self.subTest(rule=rule["id"]):
                self.assertEqual("security", rule["metadata"]["category"])
                self.assertIn(rule["severity"], ("ERROR", "WARNING", "INFO"))
                self.assertTrue(rule["metadata"].get("cwe"), "a rule names its CWE")
                self.assertTrue(rule["message"].strip())

    def test_rule_ids_start_with_a_language(self):
        """The id reads tdxguard-rules.<language>.<name> in TDxGuard, like the community rules' ids."""
        for rule in rules():
            with self.subTest(rule=rule["id"]):
                language = rule["id"].split(".", 1)[0]
                self.assertTrue(
                    language in rule["languages"] or language == "javascript" and "typescript" in rule["languages"]
                )

    def test_every_rule_has_test_cases(self):
        ids = {rule["id"] for rule in rules()}
        tested = {rule for kind, rule, _, _ in annotations() if kind == "ruleid"}
        self.assertEqual(set(), ids - tested, "rules without a `ruleid:` test case")
        self.assertEqual(set(), {rule for _, rule, _, _ in annotations()} - ids, "test cases of unknown rules")

    def test_the_root_is_no_rule_language(self):
        """sarif-enrich.py trims the ids at the first root it meets; the root must be our own."""
        self.assertNotIn(helpers.TDXGUARD_RULES_ROOT, tools.RULE_LANGUAGES)
        # The engine's work directory is tdxguard.<random>, split on dots by the trimming.
        self.assertNotEqual("tdxguard", helpers.TDXGUARD_RULES_ROOT)


@unittest.skipUnless(find_opengrep(), "no opengrep binary (set $OPENGREP or run `tdxguard tools install`)")
class TestRulesFindWhatTheyShould(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output = subprocess.run(  # nosec B603
            [find_opengrep(), "scan", "--config", str(helpers.TDXGUARD_RULES), "--json", "--quiet", "."],
            cwd=str(FIXTURES),
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PYTHONUTF8": "1"},
        ).stdout
        document = json.loads(output)
        cls.errors = document["errors"]
        cls.findings: Dict[Tuple[str, str], Set[int]] = {}
        for result in document["results"]:
            # The id carries the --config path; the rule's own id is its last two segments.
            rule = ".".join(result["check_id"].split(".")[-2:])
            lines = set(range(result["start"]["line"], result["end"]["line"] + 1))
            cls.findings.setdefault((rule, result["path"]), set()).update(lines)

    def test_no_rule_errors(self):
        self.assertEqual([], self.errors)

    def test_test_cases(self):
        for kind, rule, path, line in annotations():
            with self.subTest(kind=kind, rule=rule, at=f"{path}:{line}"):
                covered = line in self.findings.get((rule, path), set())
                self.assertEqual(kind == "ruleid", covered)


if __name__ == "__main__":
    unittest.main()
