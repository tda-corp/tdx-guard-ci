"""The scanner's reports: the summary, the upload plan, severity counts and the gate."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from tdxguard.dast import NUCLEI_REPORT, ZAP_REPORT, zap_counts
from tdxguard.engine.scan import is_firebase_client_key

SUMMARY_FILE = "summary.json"
IMAGE_SBOM = re.compile(r"^sbom-image-(?P<slug>.+)\.cdx\.json$")
IMAGE_SARIF = re.compile(r"^trivy-image-(?P<slug>.+)\.sarif$")
MOBSF_REPORT = re.compile(r"^mobsf-(?P<slug>.+)\.json$")


def load_json(path: Path) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_summary(out: Path) -> Optional[Dict[str, Any]]:
    data = load_json(out / SUMMARY_FILE)
    return data if isinstance(data, dict) else None


# --- upload ---


@dataclass
class Upload:
    path: Path
    parser: str
    docker_image_name_tag: Optional[str] = None
    endpoint_url: Optional[str] = None

    def fields(self, product: str, branch: str, licenses: bool = True) -> Dict[str, str]:
        """
        The same form fields as tg_push in ci-templates/tdxguard-lib.sh. Without `licenses`
        TDxGuard imports the vulnerabilities of a CycloneDX SBOM but not its components and
        licenses, like the CI templates do on a pull request.
        """
        fields = {"product_name": product, "branch_name": branch, "parser_name": self.parser}
        if self.docker_image_name_tag:
            fields["docker_image_name_tag"] = self.docker_image_name_tag
        if self.endpoint_url:
            fields["endpoint_url"] = self.endpoint_url
        if self.parser == "CycloneDX" and not licenses:
            fields["suppress_licenses"] = "true"
        return fields


def upload_plan(out: Path, image_refs: Mapping[str, str], dast_target: Optional[str] = None) -> List[Upload]:
    """
    Which report goes up with which parser, in the CI template's order. `image_refs` maps
    an image slug to the locally built reference, which becomes docker_image_name_tag.
    """
    plan: List[Upload] = []
    betterleaks = out / "betterleaks.json"
    # Also when Betterleaks found nothing (null or []), like the CI templates: TDxGuard then
    # records that the secrets scan ran, and leaves the open secrets alone.
    if betterleaks.is_file() and _betterleaks_report(betterleaks):
        plan.append(Upload(betterleaks, "Betterleaks"))
    for name, parser in (
        ("opengrep.sarif", "SARIF"),
        ("trivy.sarif", "SARIF"),
        ("sbom.cdx.json", "CycloneDX"),
        ("zizmor.sarif", "SARIF"),
    ):
        if (out / name).is_file():
            plan.append(Upload(out / name, parser))
    for path in sorted(out.iterdir()) if out.is_dir() else []:
        sarif = IMAGE_SARIF.match(path.name)
        sbom = IMAGE_SBOM.match(path.name)
        if sarif:
            slug = sarif.group("slug")
            plan.append(Upload(path, "SARIF", image_refs.get(slug, f"tdxguard-local/{slug}:scan")))
        elif sbom:
            slug = sbom.group("slug")
            plan.append(Upload(path, "CycloneDX", image_refs.get(slug, f"tdxguard-local/{slug}:scan")))
    # The mobile app analysis (MobSF), written by tdxguard.engine.helpers.mobsf_scan
    for path in sorted(out.iterdir()) if out.is_dir() else []:
        if MOBSF_REPORT.match(path.name):
            plan.append(Upload(path, "MobSF"))
    # DAST against the running application, with the target as the endpoint, as in CI.
    if (out / ZAP_REPORT).is_file():
        plan.append(Upload(out / ZAP_REPORT, "ZAP", endpoint_url=dast_target))
    if (out / NUCLEI_REPORT).is_file():
        plan.append(Upload(out / NUCLEI_REPORT, "SARIF", endpoint_url=dast_target))
    return plan


FIXED_REPORTS = (
    "betterleaks.json",
    "opengrep.sarif",
    "trivy.sarif",
    "sbom.cdx.json",
    "zizmor.sarif",
    ZAP_REPORT,
    NUCLEI_REPORT,
    SUMMARY_FILE,
)


def report_files(out: Path) -> List[Path]:
    """The files of out that a scan writes and upload_plan picks up, whatever their content."""
    if not out.is_dir():
        return []
    return sorted(
        path
        for path in out.iterdir()
        if path.is_file()
        and (
            path.name in FIXED_REPORTS
            or IMAGE_SARIF.match(path.name)
            or IMAGE_SBOM.match(path.name)
            or MOBSF_REPORT.match(path.name)
        )
    )


def _betterleaks_report(path: Path) -> bool:
    """A list of findings, empty included, or the null of a clean scan; not a broken file."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    return data is None or isinstance(data, list)


# --- severity counts ---


@dataclass
class Counts:
    critical: int = 0
    high: int = 0
    per_report: Dict[str, Tuple[int, int]] = field(default_factory=dict)

    def add(self, report: str, critical: int, high: int) -> None:
        self.critical += critical
        self.high += high
        self.per_report[report] = (critical, high)


def cyclonedx_counts(data: Any, ignore_unfixed: bool = False) -> Tuple[int, int]:
    """
    Each vulnerability counts once, at the highest severity among its ratings. With
    ignore_unfixed, only vulnerabilities with a fixed version count: Trivy writes a
    `recommendation` ("Upgrade x to version y") exactly when there is one.
    """
    critical = high = 0
    if not isinstance(data, dict):
        return 0, 0
    for vulnerability in data.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue
        if ignore_unfixed and not vulnerability.get("recommendation"):
            continue
        severities = {
            str(rating.get("severity", "")).lower()
            for rating in (vulnerability.get("ratings") or [])
            if isinstance(rating, dict)
        }
        if "critical" in severities:
            critical += 1
        elif "high" in severities:
            high += 1
    return critical, high


def sarif_counts(data: Any) -> Tuple[int, int]:
    """
    Per result: the rule's security-severity score when there is one (Trivy; >= 9.0 is
    critical, >= 7.0 high, GitHub's scale), else a CRITICAL/HIGH tag, else level "error"
    on the result or on the rule's default configuration (Opengrep) counts as high. That
    is the template's "severe" column, split into critical and high.
    """
    critical = high = 0
    if not isinstance(data, dict):
        return 0, 0
    for run in data.get("runs") or []:
        rules = {}
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[rule["id"]] = rule
        for result in run.get("results") or []:
            severity = _sarif_severity(result, rules.get(result.get("ruleId")) or {})
            if severity == "critical":
                critical += 1
            elif severity == "high":
                high += 1
    return critical, high


def _sarif_severity(result: Dict[str, Any], rule: Dict[str, Any]) -> str:
    properties = rule.get("properties") or {}
    score = properties.get("security-severity")
    if score is not None:
        try:
            value = float(score)
            if value >= 9.0:
                return "critical"
            if value >= 7.0:
                return "high"
            return "other"
        except (TypeError, ValueError):
            pass
    tags = {str(tag).upper() for tag in (properties.get("tags") or [])}
    if "CRITICAL" in tags:
        return "critical"
    if "HIGH" in tags:
        return "high"
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return "high" if level == "error" else "other"


def count(out: Path, ignore_unfixed: bool = False) -> Counts:
    counts = Counts()
    for path in sorted(out.iterdir()) if out.is_dir() else []:
        if path.name == SUMMARY_FILE:
            continue
        if path.name.endswith(".cdx.json"):
            counts.add(path.name, *cyclonedx_counts(load_json(path), ignore_unfixed))
        elif path.name.endswith(".sarif"):
            counts.add(path.name, *sarif_counts(load_json(path)))
        elif path.name == "betterleaks.json":
            # A committed secret is always severe, except a Firebase app's client key; the
            # templates count the same.
            findings = load_json(path)
            severe = [f for f in findings if not is_firebase_client_key(f)] if isinstance(findings, list) else []
            counts.add(path.name, 0, len(severe))
        elif path.name == ZAP_REPORT:
            # ZAP has no critical; its High alerts (riskcode 3) count as high, as in the templates.
            counts.add(path.name, 0, zap_counts(load_json(path))[1])
    return counts


# --- gate ---


@dataclass
class GateResult:
    passed: bool
    violations: List[str]
    counts: Dict[str, int]
    limits: Dict[str, Optional[int]]


def evaluate_gate(limits: Mapping[str, Optional[int]], counts: Counts) -> GateResult:
    values = {"critical": counts.critical, "high": counts.high}
    violations = []
    for key in ("critical", "high"):
        limit = limits.get(key)
        if limit is not None and values[key] > limit:
            violations.append(f"{values[key]} {key} finding(s), the gate allows {limit}")
    return GateResult(passed=not violations, violations=violations, counts=values, limits=dict(limits))
