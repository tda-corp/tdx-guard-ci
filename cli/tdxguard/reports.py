"""The scanner's reports: the summary, the upload plan, severity counts and the gate."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

SUMMARY_FILE = "summary.json"
IMAGE_SBOM = re.compile(r"^sbom-image-(?P<slug>.+)\.cdx\.json$")
IMAGE_SARIF = re.compile(r"^trivy-image-(?P<slug>.+)\.sarif$")


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

    def fields(self, product: str, branch: str) -> Dict[str, str]:
        """The same form fields as tg_push in ci-templates/tdxguard-lib.sh."""
        fields = {"product_name": product, "branch_name": branch, "parser_name": self.parser}
        if self.docker_image_name_tag:
            fields["docker_image_name_tag"] = self.docker_image_name_tag
        return fields


def upload_plan(out: Path, image_refs: Mapping[str, str]) -> List[Upload]:
    """
    Which report goes up with which parser, in the CI template's order. `image_refs` maps
    an image slug to the locally built reference, which becomes docker_image_name_tag.
    """
    plan: List[Upload] = []
    betterleaks = out / "betterleaks.json"
    # Betterleaks writes null or [] when it finds nothing, which its parser rejects.
    if betterleaks.is_file() and _non_empty_list(load_json(betterleaks)):
        plan.append(Upload(betterleaks, "Betterleaks"))
    for name, parser in (("opengrep.sarif", "SARIF"), ("trivy.sarif", "SARIF"), ("sbom.cdx.json", "CycloneDX")):
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
    return plan


def _non_empty_list(data: Any) -> bool:
    return isinstance(data, list) and len(data) > 0


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
            # A committed secret is always severe; the template counts every finding.
            findings = load_json(path)
            counts.add(path.name, 0, len(findings) if isinstance(findings, list) else 0)
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
