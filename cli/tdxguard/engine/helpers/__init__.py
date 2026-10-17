"""
The helper scripts the CI templates run after the scanners. These files are the one source:
ci-templates/github/tdxguard.yml and ci-templates/gitlab/tdxguard.yml embed byte-identical
copies (as `sarif-enrich.py` and `opengrep-prune-rules.py`), and tests/test_helpers_in_sync.py
fails when an embedded copy drifts from the file here.

They are standard library only and run as scripts (`python3 <file> <args>`), in CI as here.
"""

from pathlib import Path

HELPERS = Path(__file__).resolve().parent
SARIF_ENRICH = HELPERS / "sarif_enrich.py"
OPENGREP_PRUNE_RULES = HELPERS / "opengrep_prune_rules.py"
