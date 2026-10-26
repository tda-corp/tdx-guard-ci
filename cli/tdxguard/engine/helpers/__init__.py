"""
The helper scripts the CI templates run after the scanners. These files are the one source:
ci-templates/github/tdxguard.yml and ci-templates/gitlab/tdxguard.yml embed byte-identical
copies (as `sarif-enrich.py` and `opengrep-prune-rules.py`; the GitHub template also
`mobsf-scan.py`), and tests/test_helpers_in_sync.py
fails when an embedded copy drifts from the file here.

They are standard library only and run as scripts (`python3 <file> <args>`), in CI as here.
"""

from pathlib import Path

HELPERS = Path(__file__).resolve().parent
SARIF_ENRICH = HELPERS / "sarif_enrich.py"
OPENGREP_PRUNE_RULES = HELPERS / "opengrep_prune_rules.py"
MOBSF_SCAN = HELPERS / "mobsf_scan.py"
# TDxGuard's own Opengrep rules, embedded in both templates as `tdxguard-rules.yaml`. The scan
# puts them below a directory of this name, which sarif-enrich.py's --rule-roots trims to.
TDXGUARD_RULES = HELPERS / "tdxguard_rules.yaml"
TDXGUARD_RULES_ROOT = "tdxguard-rules"
