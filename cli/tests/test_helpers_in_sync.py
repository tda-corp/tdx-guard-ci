"""
The CI templates cannot fetch files from this repository, so they embed the helper scripts
as heredocs. These tests keep every embedded copy byte-identical to its one source:

  sarif-enrich.py, opengrep-prune-rules.py  cli/tdxguard/engine/helpers/ (the engine runs them)
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
    "zen-collector.py": TEMPLATES / "zen-collector.py",
    "tdxguard-lib.sh": TEMPLATES / "tdxguard-lib.sh",
}
# Which template embeds which script.
EMBEDDED = {
    "github/tdxguard.yml": ["sarif-enrich.py", "opengrep-prune-rules.py", "zen-collector.py", "tdxguard-lib.sh"],
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
