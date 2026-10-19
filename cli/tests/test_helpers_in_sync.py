"""
The CI templates cannot fetch files from this repository, so they embed the helper scripts
as heredocs. These tests keep every embedded copy byte-identical to its one source:

  sarif-enrich.py, opengrep-prune-rules.py  cli/tdxguard/engine/helpers/ (the engine runs them)
  mobsf-scan.py                             cli/tdxguard/engine/helpers/ (tdxguard scan imports it)
  zen-collector.py, tdxguard-lib.sh         ci-templates/

After changing a source, paste it into the heredocs of both templates (indented like the
surrounding block); the failure message names the template and the script.
"""

import re
import unittest
from pathlib import Path

from tdxguard.engine import helpers

REPOSITORY = Path(__file__).resolve().parents[2]
TEMPLATES = REPOSITORY / "ci-templates"

SOURCES = {
    "sarif-enrich.py": helpers.SARIF_ENRICH,
    "opengrep-prune-rules.py": helpers.OPENGREP_PRUNE_RULES,
    "mobsf-scan.py": helpers.MOBSF_SCAN,
    "zen-collector.py": TEMPLATES / "zen-collector.py",
    "tdxguard-lib.sh": TEMPLATES / "tdxguard-lib.sh",
}
# Which template embeds which script.
EMBEDDED = {
    "github/tdxguard.yml": [
        "sarif-enrich.py",
        "opengrep-prune-rules.py",
        "zen-collector.py",
        "mobsf-scan.py",
        "tdxguard-lib.sh",
    ],
    "gitlab/tdxguard.yml": ["sarif-enrich.py", "opengrep-prune-rules.py", "zen-collector.py"],
}


def embedded_copy(template_text: str, name: str):
    """The body of `cat > <name> <<'TDXGUARD_SCRIPT_EOF'`, with the block's indent removed."""
    match = re.search(
        r"^( *)cat > " + re.escape(name) + r" <<'TDXGUARD_SCRIPT_EOF'\n(.*?)^ *TDXGUARD_SCRIPT_EOF$",
        template_text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        return None
    indent = len(match.group(1))
    return "".join(line[indent:] if line.strip() else line.lstrip(" ") for line in match.group(2).splitlines(True))


@unittest.skipUnless(TEMPLATES.is_dir(), "ci-templates/ is not next to the package")
class TestEmbeddedCopies(unittest.TestCase):
    def test_templates_embed_the_sources(self):
        for template, names in EMBEDDED.items():
            text = (TEMPLATES / template).read_text(encoding="utf-8")
            for name in names:
                with self.subTest(template=template, script=name):
                    copy = embedded_copy(text, name)
                    self.assertIsNotNone(copy, f"{template} no longer embeds {name}")
                    self.assertEqual(
                        SOURCES[name].read_text(encoding="utf-8"),
                        copy,
                        f"the copy of {name} in ci-templates/{template} differs from {SOURCES[name]}",
                    )

    def test_rule_languages_match_the_templates(self):
        """The templates load the same opengrep-rules languages as the native engine and the scanner image."""
        from tdxguard.engine.tools import RULE_LANGUAGES

        for script in ("github/tdxguard.yml", "gitlab/tdxguard.yml", "local/tdxguard-scan.sh"):
            with self.subTest(script=script):
                text = (TEMPLATES / script).read_text(encoding="utf-8")
                found = re.findall(r'OPENGREP_RULE_LANGUAGES[:=] ?"([^"]+)"', text)
                self.assertEqual([" ".join(RULE_LANGUAGES)], found, f"ci-templates/{script}")

    def test_betterleaks_default_config_matches_the_templates(self):
        """A repository without a secrets config gets the same allowlist from the CLI and from CI."""
        from tdxguard.engine.scan import BETTERLEAKS_DEFAULT_CONFIG

        for template in ("github/tdxguard.yml", "gitlab/tdxguard.yml"):
            with self.subTest(template=template):
                text = (TEMPLATES / template).read_text(encoding="utf-8")
                match = re.search(r"^( +)BETTERLEAKS_DEFAULT_CONFIG: \|\n((?:\1 +.*\n|\n)+)", text, re.MULTILINE)
                self.assertIsNotNone(match, f"ci-templates/{template} no longer sets BETTERLEAKS_DEFAULT_CONFIG")
                indent = len(match.group(1)) + 2
                block = "".join(line[indent:] or "\n" for line in match.group(2).splitlines(keepends=True))
                self.assertEqual(BETTERLEAKS_DEFAULT_CONFIG, block, f"ci-templates/{template}")

    def test_opengrep_skips_vendored_dirs_in_the_templates(self):
        """Every Opengrep run in the templates excludes the directories the CLI excludes as vendored."""
        from tdxguard.engine.scan import VENDORED_DIRS

        for script in ("github/tdxguard.yml", "gitlab/tdxguard.yml", "local/tdxguard-scan.sh"):
            text = (TEMPLATES / script).read_text(encoding="utf-8")
            # A run spans continuation lines; the exclusions all sit before its final " ." argument.
            runs = re.findall(r"opengrep scan (?:[^\n]*\\\n)*[^\n]*", text) or re.findall(r'OG_EXCL="[^"]*"', text)
            self.assertTrue(runs, f"ci-templates/{script} runs no opengrep scan")
            for run in runs:
                for directory in VENDORED_DIRS:
                    with self.subTest(script=script, directory=directory):
                        self.assertIn(f"--exclude={directory} ", run + " ", f"ci-templates/{script}: {run[:80]}")

    def test_trivy_skips_vendored_dirs_in_the_templates(self):
        """Every Trivy fs run in the templates skips the vendored directories at any depth, as the CLI does."""
        from tdxguard.engine.scan import TRIVY_SKIP_DIRS

        for script in ("github/tdxguard.yml", "gitlab/tdxguard.yml", "local/tdxguard-scan.sh"):
            text = (TEMPLATES / script).read_text(encoding="utf-8")
            # A command, not a comment: `trivy fs .` (or the local script's `fs .` after docker run) opens the line.
            runs = re.findall(r"^[ -]*(?:trivy )?fs \. (?:[^\n]*\\\n)*[^\n]*", text, re.MULTILINE)
            self.assertTrue(runs, f"ci-templates/{script} runs no trivy fs")
            for run in runs:
                for directory in TRIVY_SKIP_DIRS:
                    quoted = f"'{directory}'" if "*" in directory else directory
                    with self.subTest(script=script, directory=directory):
                        self.assertIn(f"--skip-dirs {quoted}", run, f"ci-templates/{script}: {run[:80]}")

    def test_firebase_client_key_pattern_matches_the_templates_and_the_backend(self):
        """The CLI's gate, both templates' SECRETS_SEVERE and the backend's risk model agree on a Firebase client key."""
        from tdxguard.engine.scan import FIREBASE_CONFIG_PATTERN, FIREBASE_KEY_RULE

        for template in ("github/tdxguard.yml", "gitlab/tdxguard.yml"):
            with self.subTest(template=template):
                text = (TEMPLATES / template).read_text(encoding="utf-8")
                found = re.findall(r"SECRETS_SEVERE: '(.*)'", text)
                self.assertEqual(1, len(found), f"ci-templates/{template}")
                expected = FIREBASE_CONFIG_PATTERN.replace("\\", "\\\\")
                self.assertIn(f'.RuleID == "{FIREBASE_KEY_RULE}" and (.File | test("{expected}"))', found[0])
                # Both the summary row and the gate use it.
                self.assertNotIn("jq 'length' betterleaks.json", text)
        risk = (REPOSITORY / "backend" / "application" / "core" / "services" / "risk.py").read_text(encoding="utf-8")
        self.assertIn(f'FIREBASE_KEY_RULE = "{FIREBASE_KEY_RULE}"', risk)
        self.assertRegex(risk, r'_FIREBASE_CONFIG = re\.compile\(\s*r"' + re.escape(FIREBASE_CONFIG_PATTERN) + '"')

    def test_opengrep_skipped_rules_in_the_templates(self):
        """The templates remove the rule directories the CLI removes."""
        from tdxguard.engine.scan import OPENGREP_SKIPPED_RULES

        for template in ("github/tdxguard.yml", "gitlab/tdxguard.yml"):
            text = (TEMPLATES / template).read_text(encoding="utf-8")
            for skipped in OPENGREP_SKIPPED_RULES:
                with self.subTest(template=template, skipped=skipped):
                    self.assertIn(f"rm -rf ogrules-security/{skipped}\n", text)
        local = (TEMPLATES / "local" / "tdxguard-scan.sh").read_text(encoding="utf-8")
        for skipped in OPENGREP_SKIPPED_RULES:
            self.assertIn(f"*/{skipped}/*) continue", local)

    def test_no_stale_copies_in_ci_templates(self):
        """The two helpers moved into the package; a file left behind would become a second source."""
        for name in ("sarif-enrich.py", "opengrep-prune-rules.py"):
            self.assertFalse((TEMPLATES / name).exists(), f"ci-templates/{name} is back; the source is {SOURCES[name]}")


class TestHelpersRun(unittest.TestCase):
    def test_importable(self):
        from tdxguard.engine.helpers import opengrep_prune_rules, sarif_enrich

        self.assertTrue(callable(sarif_enrich.main))
        self.assertTrue(callable(opengrep_prune_rules.main))
        self.assertTrue(helpers.SARIF_ENRICH.is_file())
        self.assertTrue(helpers.OPENGREP_PRUNE_RULES.is_file())


if __name__ == "__main__":
    unittest.main()
