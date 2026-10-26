#!/usr/bin/env python3
"""tdxguard-report — turn a product's findings in TDxGuard into a security assessment report.

The dashboard is right for the people who work on findings every day. Everyone else — a
customer's security team, an auditor (ISO 27001 A.8.8/A.8.28/A.8.29, SOC 2 CC7.1/CC8.1) or a
manager — needs one document they can read in ten minutes and act on. This produces it.

Standard library only; Python 3.9 or later.

    export TDXGUARD_URL=https://tdxguard.tda.internal
    export TDXGUARD_API_TOKEN=...
    export TDXGUARD_UI_URL=https://tdxguard.tda.internal    # links back to the dashboard

    python3 compliance-report.py --product tdxrecruify --branch main \\
        --format both --out report.md --html report.html --csv findings.csv \\
        --prepared-for "ACME Corp. security team" --classification "Confidential"

Open the HTML and print it to PDF (A4, page numbers and page breaks are in the print CSS).

WHAT THIS REPORT IS

Everything in it is derived from data TDxGuard recorded: the kinds of testing and the tool
versions come from the vulnerability checks that actually ran, the findings are grouped by
vulnerability and source package, and the decisions section lists only decisions people made
plus the rules that changed a status. A control is only called "evidenced" when the matching
test ran.

WHAT IT IS NOT

It is signed by whoever ran it, not by an independent third party. No automated tool finds
business logic flaws (cross-tenant access, privilege escalation through an approval workflow,
a race condition in a payment flow); the report says so in its methodology section.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import mimetypes
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

REPORT_FORMAT_VERSION = "2.0"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unknown"]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}

# backend/application/core/types.py: Status.STATUS_ACTIVE
ACTIVE_STATUSES = ["Open", "Affected", "In review"]
STATUS_RESOLVED = "Resolved"
# Statuses that close a finding by a judgement (person, rule or VEX), not by a rescan.
DECIDED_STATUSES = ["Not affected", "False positive", "Risk accepted", "Duplicate", "Not security"]

# backend/application/core/types.py: Observation_Log_Comment.AUTOMATED_COMMENTS. Log entries
# with these comments are written by the importer and carry no human judgement.
AUTOMATED_COMMENTS = {
    "Set by parser",
    "Updated by parser",
    "Observation not found in latest scan",
}
RULE_LOG_FIELDS = ("general_rule", "product_rule", "general_rule_rego", "product_rule_rego")

# Observation.cve_found_in lists where exploitation of the CVE is documented. The KEV
# catalogues record exploitation in the wild; the others only show that an exploit is public.
KEV_SOURCES = {"CISA KEV", "VulnCheck KEV"}

# Observation_Log age choices of the backend, which the period has to match.
PERIOD_AGES = {7: "Past 7 days", 30: "Past 30 days", 90: "Past 90 days", 365: "Past 365 days"}

# Package ecosystems where one source package builds several binary packages that share the
# version string (ffmpeg -> libavcodec58, libavformat58, ...). Those are reported as one entry.
OS_PURL_TYPES = {"deb", "rpm", "apk", "alpm"}

DEFAULT_SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}

PAGE_SIZE = 1000

# --- kinds of testing -------------------------------------------------------------------------

SCA, SAST, SECRET, CONFIG, DAST, IAST, OTHER = "SCA", "SAST", "SECRET", "CONFIG", "DAST", "IAST", "OTHER"
IMAGE = "IMAGE"  # a kind of testing (container image scan), findings land in SCA or CONFIG
MOBILE = "MOBILE"  # the static analysis of a mobile app (MobSF), of the built app or of its source
FINDING_KINDS = [SCA, SAST, SECRET, CONFIG, DAST, IAST, MOBILE, OTHER]
TEST_KINDS = [SAST, SCA, IMAGE, SECRET, CONFIG, DAST, IAST, MOBILE]
# Kinds that apply to some products only: a web service has no mobile app to analyse. They are
# listed (performed, not performed, how to enable) only where they ran.
APPLICABLE_WHEN_RUN = {MOBILE}

# The dashboard's scan coverage classifies vulnerability checks with the same word lists and the
# same order as check_kinds() below (backend/application/core/services/scan_coverage.py); a test
# in ci-templates/tests keeps both in sync.

_SECRET_WORDS = ("leak", "secret", "trufflehog", "detect-secrets")
_IAST_WORDS = ("zen", "aikido", "iast")
_DAST_WORDS = ("zap", "nuclei", "nikto", "strix", "dast")
_MOBILE_WORDS = ("mobsf",)
_SAST_WORDS = ("opengrep", "semgrep", "bandit", "codeql", "sonar", "eslint", "gosec", "brakeman", "spotbugs")
_SCA_WORDS = ("dependency-check", "grype", "osv", "npm audit", "pip-audit", "snyk", "dependabot")
_IAC_WORDS = ("trivy", "checkov", "kics", "terrascan", "kubescape", "prowler", "hadolint", "zizmor")

# The opengrep-rules languages whose security rules TDxGuard's Opengrep loads: RULE_LANGUAGES of
# cli/tdxguard/engine/tools.py and OPENGREP_RULE_LANGUAGES of the CI templates (a test in
# ci-templates/tests keeps them equal). The methodology section names them, so that the report
# does not read as SAST of a language that had no rules.
OPENGREP_LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "go",
    "generic",
    "php",
    "java",
    "kotlin",
    "scala",
    "ruby",
    "csharp",
    "c",
)
_LANGUAGE_NAMES = {"javascript": "JavaScript", "typescript": "TypeScript", "php": "PHP", "csharp": "C#"}


def _contains(text: str, words: Iterable[str]) -> bool:
    text = (text or "").lower()
    return any(word in text for word in words)


def finding_kind(observation: dict) -> str:
    """The kind of a finding, with the same priorities as the dashboard's "Type" badge
    (backend/application/core/api/filters.py: scan_type_q)."""
    scanner = observation.get("scanner") or observation.get("scanner_name") or ""
    if _contains(scanner, _SECRET_WORDS):
        return SECRET
    if _contains(scanner, _IAST_WORDS):
        return IAST
    if _contains(scanner, _DAST_WORDS) or observation.get("origin_endpoint_url"):
        return DAST
    if _contains(scanner, _MOBILE_WORDS):
        return MOBILE
    if (
        observation.get("vulnerability_id")
        or observation.get("origin_component_purl")
        or observation.get("origin_component_name")
    ):
        return SCA
    if (
        observation.get("origin_cloud_qualified_resource")
        or observation.get("origin_kubernetes_qualified_resource")
        or observation.get("origin_docker_image_name")
        or _contains(scanner, _IAC_WORDS)
    ):
        return CONFIG
    if observation.get("origin_source_file"):
        return SAST
    return OTHER


def check_kinds(check: dict, observed: Iterable[str] = ()) -> set:
    """The kinds of testing a vulnerability check stands for: what its findings were, plus what
    its scanner and report name say (a check without open findings still counts as run)."""
    scanner = f"{check.get('scanner') or ''} {check.get('scanner_name') or ''}"
    report = f"{check.get('filename') or ''} {check.get('api_configuration_name') or ''}".lower()
    kinds = set(observed)
    if _contains(scanner, _SECRET_WORDS):
        kinds.add(SECRET)
    elif _contains(scanner, _IAST_WORDS):
        kinds.add(IAST)
    elif _contains(scanner, _DAST_WORDS):
        kinds.add(DAST)
    elif _contains(scanner, _MOBILE_WORDS):
        kinds.add(MOBILE)
    elif _contains(scanner, _SAST_WORDS):
        kinds.add(SAST)
    elif "sbom" in report or "cdx" in report or "cyclonedx" in report or _contains(scanner, _SCA_WORDS):
        kinds.add(SCA)
    elif _contains(scanner, _IAC_WORDS):
        kinds.add(CONFIG)
    if "image" in report or "container" in report:
        kinds.add(IMAGE)
    return kinds


# --- translations -----------------------------------------------------------------------------

STRINGS = {
    "en": {
        "title": "Security assessment report",
        "doc_control": "Document control",
        "document_id": "Document ID",
        "version": "Version",
        "product": "Product",
        "branch": "Branch",
        "all_branches": "all branches",
        "commit": "Commit assessed",
        "period": "Reporting period",
        "generated": "Generated",
        "prepared_by": "Prepared by",
        "prepared_for": "Prepared for",
        "classification": "Classification",
        "approved_by": "Approved by",
        "signature": "name, date, signature",
        "toc": "Contents",
        "s_summary": "Executive summary",
        "s_scope": "Scope and methodology",
        "s_sca": "Findings: dependencies and container images (SCA)",
        "s_sast": "Findings: source code (SAST)",
        "s_secret": "Findings: secrets",
        "s_config": "Findings: configuration and infrastructure as code",
        "s_dast": "Findings: running application (DAST/IAST)",
        "s_mobile": "Findings: mobile app (MobSF)",
        "s_other": "Findings: other",
        "s_decisions": "Decisions and risk treatment",
        "s_controls": "Control mapping",
        "s_appendix_a": "Appendix A — All vulnerabilities",
        "s_appendix_b": "Appendix B — Findings of superseded images",
        "s_appendix_c": "Appendix C — How this report is built",
        "verdict": "Overall assessment",
        "v_action": "Action required",
        "v_attention": "Attention needed",
        "v_acceptable": "Acceptable",
        "key_figures": "Open vulnerabilities by severity",
        "severity": "Severity",
        "distinct": "Distinct",
        "unique_ids": "Unique IDs",
        "observations": "Observations",
        "fixable": "Fix available",
        "kev": "Known exploited (KEV)",
        "poc": "Public exploit",
        "by_kind": "Open findings by kind (distinct)",
        "kind": "Kind",
        "total": "Total",
        "top_risks": "Top risks",
        "rank": "#",
        "vulnerability": "Vulnerability",
        "where": "Package / location",
        "fix": "Fix",
        "epss": "EPSS",
        "exploit": "Exploitation",
        "link": "Link",
        "open": "open",
        "period_changes": "Changes in the reporting period",
        "trend": "Trend (default branch, daily metrics)",
        "date": "Date",
        "gate": "Security gate",
        "threshold": "Threshold",
        "current": "Current",
        "result": "Result",
        "passed": "passed",
        "failed": "failed",
        "disabled": "not active",
        "scope": "Scope",
        "testing_performed": "Testing performed",
        "performed": "Performed",
        "not_performed": "Not performed",
        "tools": "Tools",
        "reports": "Reports",
        "first_run": "First run",
        "last_run": "Last run",
        "scan_runs": "Scan runs",
        "tool": "Tool",
        "tool_version": "Version",
        "report": "Report",
        "new": "New",
        "updated": "Updated",
        "resolved": "Resolved",
        "images": "Container images",
        "image": "Image",
        "latest_scan": "Latest scan",
        "tags_on_findings": "Commit tags recorded on findings",
        "not_covered": "What this does not cover",
        "rule": "Rule",
        "cwe": "CWE",
        "occurrences": "Occurrences",
        "files": "Files",
        "location": "Location",
        "age": "Age (days)",
        "closed_status": "Status of closed findings",
        "status": "Status",
        "count": "Count",
        "human_decisions": "Decisions by people",
        "rule_decisions": "Decisions by rules",
        "accepted_risks": "Accepted risks",
        "expiry": "Expiry",
        "finding": "Finding",
        "decision": "Decision",
        "by": "By",
        "justification": "Justification",
        "new_status": "New status",
        "reason": "Reason",
        "control": "Control",
        "name": "Name",
        "evidence": "Evidence in this report",
        "missing": "Missing",
        "assessment": "Assessment",
        "evidenced": "Evidenced",
        "partial": "Partially evidenced",
        "not_evidenced": "Not evidenced",
        "none": "None.",
        "more": "more",
        "kind_SCA": "Dependencies and image packages (SCA)",
        "kind_SAST": "Source code (SAST)",
        "kind_SECRET": "Secrets",
        "kind_CONFIG": "Configuration / IaC",
        "kind_DAST": "Running application (DAST)",
        "kind_IAST": "Instrumented runtime (IAST)",
        "kind_MOBILE": "Mobile app (MobSF)",
        "kind_OTHER": "Other",
        "kind_IMAGE": "Container image scan",
        # How to enable a kind of testing that did not run (TDxGuard CI template inputs)
        "enable_SAST": "SAST: Opengrep runs in every TDxGuard pipeline run; check that its job succeeds.",
        "enable_SCA": "SCA: Trivy writes the SBOM in every TDxGuard pipeline run; check that its job succeeds.",
        "enable_IMAGE": "Container image scan: set dockerfile: or image_ref: in the TDxGuard workflow "
        "(IMAGE_REF on GitLab).",
        "enable_SECRET": "Secrets: Betterleaks runs in every TDxGuard pipeline run; templates older than October 2026 "
        "reported it only when it found a secret.",
        "enable_CONFIG": "Configuration / IaC: Trivy checks the configuration in every TDxGuard pipeline run; check "
        "that its job succeeds.",
        "enable_DAST": "DAST: set zap_target: in the TDxGuard workflow (ZAP_TARGET on GitLab).",
        "enable_IAST": "IAST: set app_start_command: in the TDxGuard workflow (APP_START_COMMAND on GitLab).",
        "enable_MOBILE": "Mobile app: set mobile_app: (the built .apk/.ipa) or mobile_source: in the TDxGuard "
        "workflow (GitHub), or mobile: in .tdxguard.yml for tdxguard scan.",
        "short_SCA": "dependency / image package",
        "short_SAST": "source code",
        "short_SECRET": "secret",
        "short_CONFIG": "configuration",
        "short_DAST": "running application",
        "short_IAST": "instrumented runtime",
        "short_MOBILE": "mobile app",
        "short_OTHER": "other",
        "sla": "SLA (days)",
        "overdue": "Over SLA",
        "ages": "Age of open vulnerabilities (distinct)",
        "footer": "Prepared by the party named on the cover; this is not an independent third-party attestation.",
    },
    "vi": {
        "title": "Báo cáo đánh giá bảo mật",
        "doc_control": "Kiểm soát tài liệu",
        "document_id": "Mã tài liệu",
        "version": "Phiên bản",
        "product": "Sản phẩm",
        "branch": "Nhánh",
        "all_branches": "tất cả các nhánh",
        "commit": "Commit được đánh giá",
        "period": "Kỳ báo cáo",
        "generated": "Thời điểm tạo",
        "prepared_by": "Người lập",
        "prepared_for": "Gửi đến",
        "classification": "Phân loại",
        "approved_by": "Người phê duyệt",
        "signature": "họ tên, ngày, chữ ký",
        "toc": "Mục lục",
        "s_summary": "Tóm tắt dành cho lãnh đạo",
        "s_scope": "Phạm vi và phương pháp",
        "s_sca": "Phát hiện: thư viện phụ thuộc và container image (SCA)",
        "s_sast": "Phát hiện: mã nguồn (SAST)",
        "s_secret": "Phát hiện: bí mật (secrets)",
        "s_config": "Phát hiện: cấu hình và hạ tầng dạng mã (IaC)",
        "s_dast": "Phát hiện: ứng dụng đang chạy (DAST/IAST)",
        "s_mobile": "Phát hiện: ứng dụng di động (MobSF)",
        "s_other": "Phát hiện: khác",
        "s_decisions": "Quyết định và xử lý rủi ro",
        "s_controls": "Đối chiếu với các control",
        "s_appendix_a": "Phụ lục A — Toàn bộ lỗ hổng",
        "s_appendix_b": "Phụ lục B — Phát hiện của image đã bị thay thế",
        "s_appendix_c": "Phụ lục C — Cách lập báo cáo này",
        "verdict": "Đánh giá tổng thể",
        "v_action": "Cần hành động",
        "v_attention": "Cần chú ý",
        "v_acceptable": "Chấp nhận được",
        "key_figures": "Lỗ hổng đang mở theo mức độ",
        "severity": "Mức độ",
        "distinct": "Số lỗ hổng",
        "unique_ids": "Số ID duy nhất",
        "observations": "Số bản ghi",
        "fixable": "Có bản vá",
        "kev": "Đã bị khai thác (KEV)",
        "poc": "Có exploit công khai",
        "by_kind": "Phát hiện đang mở theo loại (không trùng lặp)",
        "kind": "Loại",
        "total": "Tổng",
        "top_risks": "Rủi ro hàng đầu",
        "rank": "#",
        "vulnerability": "Lỗ hổng",
        "where": "Gói / vị trí",
        "fix": "Bản vá",
        "epss": "EPSS",
        "exploit": "Khai thác",
        "link": "Liên kết",
        "open": "đang mở",
        "period_changes": "Thay đổi trong kỳ báo cáo",
        "trend": "Xu hướng (nhánh mặc định, số liệu theo ngày)",
        "date": "Ngày",
        "gate": "Security gate",
        "threshold": "Ngưỡng",
        "current": "Hiện tại",
        "result": "Kết quả",
        "passed": "đạt",
        "failed": "không đạt",
        "disabled": "không bật",
        "scope": "Phạm vi",
        "testing_performed": "Các loại kiểm thử đã thực hiện",
        "performed": "Đã thực hiện",
        "not_performed": "Không thực hiện",
        "tools": "Công cụ",
        "reports": "Báo cáo",
        "first_run": "Lần chạy đầu",
        "last_run": "Lần chạy cuối",
        "scan_runs": "Các lần quét",
        "tool": "Công cụ",
        "tool_version": "Phiên bản",
        "report": "Báo cáo",
        "new": "Mới",
        "updated": "Cập nhật",
        "resolved": "Đã xử lý",
        "images": "Container image",
        "image": "Image",
        "latest_scan": "Lần quét gần nhất",
        "tags_on_findings": "Tag commit ghi trên các phát hiện",
        "not_covered": "Những gì báo cáo không bao gồm",
        "rule": "Rule",
        "cwe": "CWE",
        "occurrences": "Số lần xuất hiện",
        "files": "Tệp",
        "location": "Vị trí",
        "age": "Tuổi (ngày)",
        "closed_status": "Trạng thái các phát hiện đã đóng",
        "status": "Trạng thái",
        "count": "Số lượng",
        "human_decisions": "Quyết định của con người",
        "rule_decisions": "Quyết định do rule",
        "accepted_risks": "Rủi ro được chấp nhận",
        "expiry": "Hết hạn",
        "finding": "Phát hiện",
        "decision": "Quyết định",
        "by": "Người quyết định",
        "justification": "Lý do",
        "new_status": "Trạng thái mới",
        "reason": "Lý do",
        "control": "Control",
        "name": "Tên",
        "evidence": "Bằng chứng trong báo cáo",
        "missing": "Còn thiếu",
        "assessment": "Đánh giá",
        "evidenced": "Có bằng chứng",
        "partial": "Bằng chứng một phần",
        "not_evidenced": "Không có bằng chứng",
        "none": "Không có.",
        "more": "khác",
        "kind_SCA": "Thư viện và gói trong image (SCA)",
        "kind_SAST": "Mã nguồn (SAST)",
        "kind_SECRET": "Bí mật (secrets)",
        "kind_CONFIG": "Cấu hình / IaC",
        "kind_DAST": "Ứng dụng đang chạy (DAST)",
        "kind_IAST": "Runtime có instrument (IAST)",
        "kind_MOBILE": "Ứng dụng di động (MobSF)",
        "kind_OTHER": "Khác",
        "kind_IMAGE": "Quét container image",
        # Cách bật một loại kiểm thử chưa chạy (tham số của CI template TDxGuard)
        "enable_SAST": "SAST: Opengrep chạy trong mọi lần chạy pipeline TDxGuard; kiểm tra job của nó thành công.",
        "enable_SCA": "SCA: Trivy tạo SBOM trong mọi lần chạy pipeline TDxGuard; kiểm tra job của nó thành công.",
        "enable_IMAGE": "Quét container image: đặt dockerfile: hoặc image_ref: trong workflow TDxGuard "
        "(IMAGE_REF trên GitLab).",
        "enable_SECRET": "Bí mật: Betterleaks chạy trong mọi lần chạy pipeline TDxGuard; các template trước tháng "
        "10/2026 chỉ gửi kết quả khi tìm thấy bí mật.",
        "enable_CONFIG": "Cấu hình / IaC: Trivy kiểm tra cấu hình trong mọi lần chạy pipeline TDxGuard; kiểm tra job "
        "của nó thành công.",
        "enable_DAST": "DAST: đặt zap_target: trong workflow TDxGuard (ZAP_TARGET trên GitLab).",
        "enable_IAST": "IAST: đặt app_start_command: trong workflow TDxGuard (APP_START_COMMAND trên GitLab).",
        "enable_MOBILE": "Ứng dụng di động: đặt mobile_app: (tệp .apk/.ipa đã build) hoặc mobile_source: trong "
        "workflow TDxGuard (GitHub), hoặc mobile: trong .tdxguard.yml cho tdxguard scan.",
        "short_SCA": "thư viện / gói trong image",
        "short_SAST": "mã nguồn",
        "short_SECRET": "bí mật",
        "short_CONFIG": "cấu hình",
        "short_DAST": "ứng dụng đang chạy",
        "short_IAST": "runtime",
        "short_MOBILE": "ứng dụng di động",
        "short_OTHER": "khác",
        "sla": "SLA (ngày)",
        "overdue": "Quá SLA",
        "ages": "Tuổi của các lỗ hổng đang mở (không trùng lặp)",
        "footer": "Báo cáo do bên ghi trên trang bìa lập; đây không phải là chứng nhận độc lập của bên thứ ba.",
    },
}

# Severity names stay in English in both languages: they are the values used in the
# dashboard, in the scanners and in every advisory, and a translation would only add doubt.


# --- small helpers ----------------------------------------------------------------------------


def parse_time(value: Any) -> Optional[datetime]:
    """An API timestamp (ISO 8601, any offset) as an aware UTC datetime."""
    if not value:
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            # Python < 3.11 does not accept more than 6 fractional digits
            match = re.match(r"^(.*?\.\d{6})\d*(.*)$", text)
            if not match:
                return None
            moment = datetime.fromisoformat(match.group(1) + match.group(2))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def fmt_time(value: Any, with_time: bool = True) -> str:
    """ISO 8601 in UTC with its offset, e.g. 2026-10-16 15:13 +00:00."""
    moment = parse_time(value)
    if moment is None:
        return "—"
    return moment.strftime("%Y-%m-%d %H:%M +00:00") if with_time else moment.strftime("%Y-%m-%d")


def short_text(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


_FENCE = re.compile(r"```.*?(```|$)", re.S)
_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
_META_LINE = re.compile(r"^\s*\*\*[^*]{1,60}:\*\*")


def clean_description(text: Any, limit: int = 500) -> str:
    """The first real paragraph of an advisory or rule description, as plain text.

    Advisories are Markdown written by third parties: headings ("### Summary"), code fences,
    tables, and the metadata lines scanners append ("**Rule short description:** ..."). None
    of that may leak into the report's structure, so it is reduced to plain text here and
    escaped again by the renderer."""
    if not text:
        return ""
    text = _FENCE.sub("\n\n", str(text).replace("\r\n", "\n"))
    paragraphs, current = [], []
    for line in text.split("\n"):
        stripped = line.strip()
        is_break = (
            not stripped
            or stripped.startswith("#")
            or _META_LINE.match(stripped)
            or stripped.startswith("|")
            or set(stripped) <= set("-=*_ ")
        )
        if is_break:
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        current.append(stripped.lstrip(">").strip())
    if current:
        paragraphs.append(" ".join(current))
    for paragraph in paragraphs:
        plain = _MD_LINK.sub(r"\1", paragraph)
        plain = re.sub(r"[`*]+", "", plain)
        plain = re.sub(r"(?<!\w)_{1,2}([^_]+)_{1,2}(?!\w)", r"\1", plain)
        plain = " ".join(plain.split())
        if len(plain) >= 15 and plain.lower() not in ("[unknown description]", "description not available"):
            return short_text(plain, limit)
    return ""


_UPGRADE = re.compile(r"Upgrade\s+(\S+)\s+to\s+version\s+([^\s;,]+)", re.I)


def fix_versions(observation: dict) -> list:
    """("package", "fixed version") pairs from the scanner's recommendation."""
    return [(m.group(1), m.group(2)) for m in _UPGRADE.finditer(observation.get("recommendation") or "")]


def is_fixable(observation: dict) -> bool:
    return bool(observation.get("fix_available")) or bool(fix_versions(observation))


def exploit_sources(observation: dict) -> set:
    """The API returns cve_found_in as [{"source": "CISA KEV"}, ...]; the database stores a
    comma-separated string. Both are accepted."""
    value = observation.get("cve_found_in") or []
    if isinstance(value, str):
        value = value.split(",")
    sources = set()
    for part in value:
        if isinstance(part, dict):
            part = part.get("source") or ""
        part = str(part).strip()
        if part:
            sources.add(part)
    return sources


def cvss_of(observation: dict) -> tuple:
    """(score, version) of the highest CVSS score present."""
    best = (None, "")
    for score_key, vector_key, default_version in (
        ("cvss4_score", "cvss4_vector", "4.0"),
        ("cvss3_score", "cvss3_vector", "3.x"),
    ):
        score = observation.get(score_key)
        if score is None or score == "":
            continue
        try:
            score = float(score)
        except (TypeError, ValueError):
            continue
        match = re.match(r"CVSS:(\d\.\d)", observation.get(vector_key) or "")
        version = match.group(1) if match else default_version
        if best[0] is None or score > best[0]:
            best = (score, version)
    return best


def as_float(value: Any) -> Optional[float]:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


def fmt_epss(score: Optional[float], percentile: Optional[float]) -> str:
    if score is None:
        return "—"
    text = "<0.1 %" if 0 < score < 0.1 else f"{score:.1f} %"
    if percentile is not None:
        text += f" (p{round(percentile)})"
    return text


def image_name(observation: dict) -> str:
    short = observation.get("origin_docker_image_name_tag_short") or ""
    if short:
        return short.split(":")[0]
    name = observation.get("origin_docker_image_name") or ""
    return name.rsplit("/", 1)[-1]


def image_tag(observation: dict) -> str:
    tag = observation.get("origin_docker_image_tag") or ""
    if not tag:
        short = observation.get("origin_docker_image_name_tag_short") or ""
        tag = short.split(":", 1)[1] if ":" in short else ""
    return tag


def purl_type(observation: dict) -> str:
    purl = observation.get("origin_component_purl") or ""
    match = re.match(r"pkg:([a-zA-Z0-9.+-]+)/", purl)
    return match.group(1).lower() if match else ""


def tool_of(check: dict) -> tuple:
    """(name, version) of the scanner of a check; "trivy" and "Trivy" are one tool."""
    scanner = check.get("scanner") or check.get("scanner_name") or ""
    name, _, version = scanner.partition(" / ")
    name = (name or check.get("scanner_name") or "?").strip()
    if name.islower():
        name = name[:1].upper() + name[1:]
    return name, version.strip()


def anchor_of(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


# --- grouping ---------------------------------------------------------------------------------


@dataclass
class Group:
    """One reportable issue: a vulnerability in one source package, a SAST rule, a secret
    rule, a configuration check, ... with every observation that belongs to it."""

    kind: str
    key: tuple
    ident: str
    title: str
    observations: list = field(default_factory=list)

    # filled by finish()
    severity: str = "Unknown"
    packages: list = field(default_factory=list)
    source_package: str = ""
    images: list = field(default_factory=list)
    locations: list = field(default_factory=list)
    fixes: list = field(default_factory=list)
    fixable: bool = False
    kev: bool = False
    exploit_public: bool = False
    exploit_sources: list = field(default_factory=list)
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    cvss: Optional[float] = None
    cvss_version: str = ""
    cwe: Optional[int] = None
    first_seen: Optional[datetime] = None
    description: str = ""
    severity_source: str = ""
    link_id: Any = None

    def finish(self) -> "Group":
        obs = self.observations
        self.severity = min(
            (o.get("current_severity") or "Unknown" for o in obs), key=lambda s: SEVERITY_RANK.get(s, 99)
        )
        packages = sorted({o.get("origin_component_name_version") for o in obs if o.get("origin_component_name")})
        self.packages = packages
        names = sorted({o.get("origin_component_name") for o in obs if o.get("origin_component_name")}, key=len)
        self.source_package = names[0] if names else ""
        self.images = sorted({image_name(o) for o in obs if image_name(o)})
        locations = []
        for o in obs:
            if o.get("origin_source_file"):
                line = o.get("origin_source_line_start")
                locations.append(o["origin_source_file"] + (f":{line}" if line else ""))
            elif o.get("origin_endpoint_url"):
                locations.append(o["origin_endpoint_url"])
            elif o.get("origin_cloud_qualified_resource"):
                locations.append(o["origin_cloud_qualified_resource"])
            elif o.get("origin_kubernetes_qualified_resource"):
                locations.append(o["origin_kubernetes_qualified_resource"])
            elif image_name(o) and not o.get("origin_component_name"):
                locations.append(f"image {image_name(o)}")
        self.locations = sorted(set(locations))
        fixes = {}
        for o in obs:
            for package, version in fix_versions(o):
                fixes.setdefault(package.lower(), (package, version))
        self.fixes = sorted(fixes.values())
        self.fixable = any(is_fixable(o) for o in obs)
        sources = set()
        for o in obs:
            sources |= exploit_sources(o)
        self.exploit_sources = sorted(sources)
        self.kev = bool(sources & KEV_SOURCES)
        self.exploit_public = bool(sources - KEV_SOURCES) or self.kev
        epss_values = [(as_float(o.get("epss_score")), as_float(o.get("epss_percentile"))) for o in obs]
        epss_values = [value for value in epss_values if value[0] is not None]
        if epss_values:
            self.epss, self.epss_percentile = max(epss_values)
        for o in obs:
            score, version = cvss_of(o)
            if score is not None and (self.cvss is None or score > self.cvss):
                self.cvss, self.cvss_version = score, version
        cwes = [o.get("cwe") for o in obs if o.get("cwe")]
        self.cwe = Counter(cwes).most_common(1)[0][0] if cwes else None
        created = [parse_time(o.get("created")) for o in obs]
        created = [c for c in created if c]
        self.first_seen = min(created) if created else None
        representative = sorted(
            obs, key=lambda o: (SEVERITY_RANK.get(o.get("current_severity"), 99), o.get("id") or 0)
        )[0]
        self.link_id = representative.get("id")
        self.description = clean_description(representative.get("description"))
        if any(o.get("assessment_severity") for o in obs):
            self.severity_source = "assessed"
        elif any(o.get("rule_severity") or o.get("rule_rego_severity") for o in obs):
            self.severity_source = "rule"
        else:
            self.severity_source = "scanner"
        return self

    @property
    def count(self) -> int:
        return len(self.observations)

    def age_days(self, now: datetime) -> Optional[int]:
        return (now - self.first_seen).days if self.first_seen else None

    def rank_key(self) -> tuple:
        """Known exploited and fixable first, then known exploited, then by EPSS, severity, CVSS."""
        tier = 0 if (self.kev and self.fixable) else 1 if self.kev else 2
        return (
            tier,
            -(self.epss or 0.0),
            SEVERITY_RANK.get(self.severity, 99),
            -(self.cvss or 0.0),
            0 if self.fixable else 1,
            -self.count,
            self.ident,
        )


def group_key(observation: dict, kind: str) -> tuple:
    title = observation.get("title") or "(untitled)"
    if kind == SCA:
        vuln = observation.get("vulnerability_id") or title
        ptype = purl_type(observation)
        version = observation.get("origin_component_version") or ""
        if ptype in OS_PURL_TYPES and version:
            # binary packages built from one source package share the version
            return (kind, vuln, ptype, version)
        # one entry per component, whatever versions of it are installed
        return (kind, vuln, ptype, (observation.get("origin_component_name") or "").lower())
    return (kind, title)


def group_observations(observations: Iterable[dict]) -> list:
    groups: dict = {}
    for observation in observations:
        kind = finding_kind(observation)
        key = group_key(observation, kind)
        group = groups.get(key)
        if group is None:
            ident = (observation.get("vulnerability_id") if kind == SCA else "") or observation.get("title") or "?"
            group = groups[key] = Group(kind=kind, key=key, ident=ident, title=observation.get("title") or ident)
        group.observations.append(observation)
    return [group.finish() for group in groups.values()]


def split_superseded(observations: list, tolerance_hours: int = 24) -> tuple:
    """Separate findings of container images that the latest scan of that image no longer saw.

    The importer keeps the image tag a finding was first seen with, so tags on current findings
    can be old commits; that alone does not make a finding stale. A finding is superseded when
    its last sighting is older than the latest scan of the same image by more than the
    tolerance (one image scan takes minutes, not hours)."""
    latest: dict = {}
    for o in observations:
        name = image_name(o)
        seen = parse_time(o.get("import_last_seen"))
        if name and seen and (name not in latest or seen > latest[name]):
            latest[name] = seen
    current, superseded = [], []
    for o in observations:
        name = image_name(o)
        seen = parse_time(o.get("import_last_seen"))
        if name and seen and latest[name] - seen > timedelta(hours=tolerance_hours):
            superseded.append(o)
        else:
            current.append(o)
    return current, superseded


# --- verdict, gate, controls ------------------------------------------------------------------


@dataclass
class Verdict:
    level: str  # "action" | "attention" | "acceptable"
    reasons: list


def compute_verdict(groups: list, gate: dict, overdue: dict) -> Verdict:
    """The overall verdict. The rule is deliberately simple, so that a reader can check it:

    - Action required: any open vulnerability listed in a known-exploited catalogue (CISA or
      VulnCheck KEV), any open Critical vulnerability with a fix available, or any open
      Critical/High secret.
    - Attention needed: otherwise, any open Critical or High finding, a failed security gate,
      or any finding open longer than its SLA.
    - Acceptable: none of the above.
    """
    reasons_action, reasons_attention = [], []
    kev = [g for g in groups if g.kev]
    critical_fixable = [g for g in groups if g.kind == SCA and g.severity == "Critical" and g.fixable]
    secrets = [g for g in groups if g.kind == SECRET and g.severity in ("Critical", "High")]
    if kev:
        reasons_action.append(("kev", len(kev)))
    if critical_fixable:
        reasons_action.append(("critical_fixable", len(critical_fixable)))
    if secrets:
        reasons_action.append(("secrets", len(secrets)))
    critical_high = [g for g in groups if g.severity in ("Critical", "High")]
    if critical_high:
        reasons_attention.append(("critical_high", len(critical_high)))
    if gate.get("passed") is False:
        reasons_attention.append(("gate_failed", 0))
    overdue_total = sum(overdue.values())
    if overdue_total:
        reasons_attention.append(("overdue", overdue_total))
    if reasons_action:
        return Verdict("action", reasons_action + reasons_attention)
    if reasons_attention:
        return Verdict("attention", reasons_attention)
    return Verdict("acceptable", [])


def evaluate_gate(product: dict, product_group: Optional[dict], settings: Optional[dict]) -> dict:
    """Thresholds and result of the security gate, resolved like
    backend/application/core/services/security_gate.py: product group, then product, then the
    global settings."""
    gate = {"passed": product.get("security_gate_passed"), "source": None, "thresholds": {}, "exceeded": []}

    def thresholds_of(entity: dict, zero_if_missing: bool) -> dict:
        result = {}
        for severity in SEVERITY_ORDER:
            value = entity.get(f"security_gate_threshold_{severity.lower()}")
            if value is None and zero_if_missing:
                value = 0
            if value is not None:
                result[severity] = int(value)
        return result

    if product_group and product_group.get("security_gate_active") is not None:
        if product_group.get("security_gate_active"):
            gate["source"] = "product_group"
            gate["thresholds"] = thresholds_of(product_group, True)
        else:
            gate["source"] = "product_group_off"
    elif product.get("security_gate_active") is not None:
        if product.get("security_gate_active"):
            gate["source"] = "product"
            gate["thresholds"] = thresholds_of(product, True)
        else:
            gate["source"] = "product_off"
    elif settings is not None:
        if settings.get("security_gate_active"):
            gate["source"] = "settings"
            gate["thresholds"] = thresholds_of(settings, False)
        else:
            gate["source"] = "settings_off"
    else:
        gate["source"] = "unknown"
    for severity, limit in gate["thresholds"].items():
        current = product.get(f"active_{severity.lower()}_observation_count")
        if current is not None and current > limit:
            gate["exceeded"].append((severity, current, limit))
    return gate


CONTROLS = [
    ("ISO 27001:2022 A.8.8", "c_a88"),
    ("ISO 27001:2022 A.8.28", "c_a828"),
    ("ISO 27001:2022 A.8.29", "c_a829"),
    ("SOC 2 CC7.1", "c_cc71"),
    ("SOC 2 CC8.1", "c_cc81"),
]


def evaluate_controls(
    kinds_run: set,
    human_decisions: int,
    rule_decisions: int,
    stale_days: Optional[int],
    gate: dict,
    gate_enforced: bool,
    has_branch: bool,
) -> list:
    """Per control: (control, key, status, evidence, missing) — status from what actually ran."""
    rows = []

    def add(control, key, evidence, missing, required_any):
        if not required_any:
            status = "not_evidenced"
        elif missing:
            status = "partial"
        else:
            status = "evidenced"
        rows.append((control, key, status, evidence, missing))

    # A.8.8 — technical vulnerabilities identified, evaluated and treated
    evidence, missing = [], []
    scanning = kinds_run & {SCA, IMAGE}
    if scanning:
        evidence.append("ev_vuln_scan")
    else:
        missing.append("mi_vuln_scan")
    if human_decisions or rule_decisions:
        evidence.append("ev_decisions")
        if not human_decisions:
            missing.append("mi_human_decisions")
    else:
        missing.append("mi_decisions")
    add(*CONTROLS[0], evidence, missing, scanning)

    # A.8.28 — secure coding
    evidence, missing = [], []
    if SAST in kinds_run:
        evidence.append("ev_sast")
    else:
        missing.append("mi_sast")
    if SECRET in kinds_run:
        evidence.append("ev_secrets")
    else:
        missing.append("mi_secrets")
    add(*CONTROLS[1], evidence, missing, kinds_run & {SAST, SECRET})

    # A.8.29 — security testing in development and acceptance
    evidence, missing = [], []
    dev = kinds_run & {SAST, SCA, IMAGE, SECRET, CONFIG, MOBILE}
    if dev:
        evidence.append("ev_dev_testing")
    if DAST in kinds_run or IAST in kinds_run:
        evidence.append("ev_runtime_testing")
    else:
        missing.append("mi_runtime_testing")
    add(*CONTROLS[2], evidence, missing, dev or (kinds_run & {DAST, IAST}))

    # CC7.1 — detection of vulnerabilities and configuration changes
    evidence, missing = [], []
    if kinds_run:
        evidence.append("ev_detection")
    if CONFIG not in kinds_run:
        missing.append("mi_config")
    if stale_days is not None and stale_days > 30:
        missing.append("mi_stale")
    add(*CONTROLS[3], evidence, missing, kinds_run)

    # CC8.1 — change management
    evidence, missing = [], []
    if has_branch and kinds_run:
        evidence.append("ev_branch")
    if gate.get("source") in ("product", "product_group", "settings"):
        evidence.append("ev_gate")
        if not gate_enforced:
            missing.append("mi_gate_enforcement")
    else:
        missing.append("mi_gate")
    add(*CONTROLS[4], evidence, missing, has_branch and kinds_run)
    return rows


CONTROL_TEXT = {
    "en": {
        "c_a88": "Management of technical vulnerabilities",
        "c_a828": "Secure coding",
        "c_a829": "Security testing in development and acceptance",
        "c_cc71": "Detection of vulnerabilities and configuration changes",
        "c_cc81": "Change management",
        "ev_vuln_scan": "Dependency and container image scans with their run dates (section 2) and the "
        "open vulnerabilities ranked by exploitation, EPSS and severity (sections 1 and {sca}).",
        "mi_vuln_scan": "No dependency or container image scan ran for this scope.",
        "ev_decisions": "Decisions on findings, by people and by rules, with their reasons (section {decisions}).",
        "mi_decisions": "No finding in this scope has been assessed by a person or a rule: open findings are "
        "detected, but there is no documented evaluation of them.",
        "mi_human_decisions": "No open finding has been assessed by a person; only rules closed findings, so the "
        "evaluation and treatment of the open findings is not evidenced.",
        "ev_sast": "Static analysis of the source code (section 2: tools, versions, run dates).",
        "mi_sast": "No static code analysis (SAST) ran for this scope.",
        "ev_secrets": "Secret detection on the repository.",
        "mi_secrets": "No secret detection ran for this scope.",
        "ev_dev_testing": "Automated security tests recorded per branch during development (section 2).",
        "ev_runtime_testing": "Tests against a running instance (DAST/IAST).",
        "mi_runtime_testing": "No DAST or IAST against a running instance: acceptance testing of the running "
        "application is not evidenced by this report.",
        "ev_detection": "Scans with first and last run per tool; results and their history retained in TDxGuard.",
        "mi_config": "No configuration / infrastructure-as-code scan ran: configuration changes are not covered.",
        "mi_stale": "The most recent scan is older than 30 days.",
        "ev_branch": "Every scan is recorded against the branch it ran on.",
        "ev_gate": "The security gate is evaluated against the configured thresholds (section 1).",
        "mi_gate_enforcement": "Whether the pipeline blocks a change when the gate fails is configured in CI and is "
        "not visible to this report; it is not claimed.",
        "mi_gate": "No security gate is active for this product.",
    },
    "vi": {
        "c_a88": "Quản lý lỗ hổng kỹ thuật",
        "c_a828": "Lập trình an toàn",
        "c_a829": "Kiểm thử bảo mật trong phát triển và nghiệm thu",
        "c_cc71": "Phát hiện lỗ hổng và thay đổi cấu hình",
        "c_cc81": "Quản lý thay đổi",
        "ev_vuln_scan": "Quét thư viện phụ thuộc và container image cùng ngày chạy (mục 2), lỗ hổng đang mở "
        "được xếp hạng theo khai thác, EPSS và mức độ (mục 1 và {sca}).",
        "mi_vuln_scan": "Không có lần quét thư viện hay container image nào trong phạm vi này.",
        "ev_decisions": "Các quyết định về phát hiện, của con người và của rule, kèm lý do (mục {decisions}).",
        "mi_decisions": "Chưa có phát hiện nào trong phạm vi này được con người hoặc rule đánh giá: lỗ hổng được "
        "phát hiện nhưng chưa có bằng chứng đánh giá.",
        "mi_human_decisions": "Chưa có phát hiện đang mở nào được con người đánh giá; chỉ rule đóng phát hiện, nên "
        "việc đánh giá và xử lý các phát hiện đang mở chưa có bằng chứng.",
        "ev_sast": "Phân tích tĩnh mã nguồn (mục 2: công cụ, phiên bản, ngày chạy).",
        "mi_sast": "Không có phân tích tĩnh mã nguồn (SAST) trong phạm vi này.",
        "ev_secrets": "Phát hiện bí mật trong repository.",
        "mi_secrets": "Không có quét bí mật trong phạm vi này.",
        "ev_dev_testing": "Kiểm thử bảo mật tự động được ghi nhận theo từng nhánh trong quá trình phát triển (mục 2).",
        "ev_runtime_testing": "Kiểm thử trên ứng dụng đang chạy (DAST/IAST).",
        "mi_runtime_testing": "Không có DAST hay IAST trên ứng dụng đang chạy: kiểm thử nghiệm thu ứng dụng đang "
        "chạy không có bằng chứng trong báo cáo này.",
        "ev_detection": "Các lần quét với lần chạy đầu và cuối của từng công cụ; kết quả và lịch sử lưu "
        "trong TDxGuard.",
        "mi_config": "Không có quét cấu hình / IaC: thay đổi cấu hình không được bao phủ.",
        "mi_stale": "Lần quét gần nhất đã cũ hơn 30 ngày.",
        "ev_branch": "Mỗi lần quét được ghi nhận theo nhánh mà nó chạy.",
        "ev_gate": "Security gate được đánh giá theo ngưỡng đã cấu hình (mục 1).",
        "mi_gate_enforcement": "Việc pipeline có chặn thay đổi khi gate không đạt hay không được cấu hình trong CI và "
        "báo cáo này không nhìn thấy; báo cáo không khẳng định điều đó.",
        "mi_gate": "Không có security gate nào được bật cho sản phẩm này.",
    },
}


# --- standards mapping ------------------------------------------------------------------------
#
# Controls of standards a customer or an auditor already knows, with the kinds of testing whose
# results are evidence for them. A control is satisfied by the organisation's processes; testing
# evidences part of it. `requires` is a tuple of alternatives: each entry is met when any of its
# kinds ran. `needs_manual` marks a control that automated testing can only partly evidence, so
# it is never reported as fully evidenced. `count_kinds` and `cwes` select the open findings
# shown next to the control: every finding of those kinds, plus code and runtime findings whose
# CWE is in the official OWASP Top 10 2021 mapping of the category.

ISO27001, SSDF, OWASP = "iso27001", "ssdf", "owasp"
STANDARDS = [
    (ISO27001, "ISO/IEC 27001:2022 Annex A"),
    (SSDF, "NIST SP 800-218 SSDF v1.1"),
    (OWASP, "OWASP Top 10 (2021)"),
]
CWE_KINDS = (SAST, SECRET, DAST, IAST)


@dataclass(frozen=True)
class StandardControl:
    standard: str
    ident: str
    title: str  # the official English title, as the standard words it
    requires: tuple = ()
    needs_manual: bool = False
    needs_gate: bool = False
    process: bool = False  # the manual part is an organisational process rather than a review or a test
    count_kinds: frozenset = frozenset()
    cwes: frozenset = frozenset()

    @property
    def key(self) -> str:
        return anchor_of(f"{self.standard} {self.ident}")


# https://owasp.org/Top10/ — "List of Mapped CWEs" of each category (A04 and A09 have no automated evidence)
OWASP_CWES = {
    "A01": frozenset(
        (22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540)
        + (548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275)
    ),
    "A02": frozenset(
        (261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347)
        + (523, 720, 757, 759, 760, 780, 818, 916)
    ),
    "A03": frozenset(
        (20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184)
        + (470, 471, 564, 610, 643, 644, 652, 917)
    ),
    "A05": frozenset((2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174)),
    "A07": frozenset(
        (255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940)
        + (1216,)
    ),
    "A08": frozenset((345, 353, 426, 494, 502, 565, 784, 829, 830, 915)),
    "A10": frozenset((918,)),
}

_RUNTIME = frozenset({DAST, IAST})
_SAST_ONLY = frozenset({SAST})
_SCA_ONLY = frozenset({SCA})
_IMAGE_ONLY = frozenset({IMAGE})
_SECRET_ONLY = frozenset({SECRET})
_CONFIG_ONLY = frozenset({CONFIG})

STANDARD_CONTROLS = [
    # ISO/IEC 27001:2022 Annex A
    StandardControl(
        ISO27001,
        "A.5.21",
        "Managing information security in the information and communication technology (ICT) supply chain",
        (_SCA_ONLY,),
        needs_manual=True,
        process=True,
        count_kinds=_SCA_ONLY,
    ),
    StandardControl(
        ISO27001,
        "A.8.8",
        "Management of technical vulnerabilities",
        (_SCA_ONLY, _IMAGE_ONLY),
        count_kinds=_SCA_ONLY,
    ),
    StandardControl(
        ISO27001,
        "A.8.9",
        "Configuration management",
        (_CONFIG_ONLY,),
        needs_manual=True,
        process=True,
        count_kinds=_CONFIG_ONLY,
    ),
    StandardControl(
        ISO27001,
        "A.8.25",
        "Secure development life cycle",
        (_SAST_ONLY, _SCA_ONLY, _SECRET_ONLY),
        needs_manual=True,
        process=True,
        needs_gate=True,
    ),
    StandardControl(
        ISO27001,
        "A.8.28",
        "Secure coding",
        (_SAST_ONLY, _SECRET_ONLY),
        needs_manual=True,
        count_kinds=frozenset({SAST, SECRET}),
    ),
    StandardControl(
        ISO27001,
        "A.8.29",
        "Security testing in development and acceptance",
        (frozenset({SAST, MOBILE}), _RUNTIME),
        needs_manual=True,
        count_kinds=frozenset({SAST, DAST, IAST, MOBILE}),
    ),
    # NIST SP 800-218 SSDF v1.1, the task texts
    StandardControl(
        SSDF,
        "PS.3.2",
        "Collect, safeguard, maintain, and share provenance data for all components of each software release "
        "(e.g., in a software bill of materials [SBOM]).",
        (_SCA_ONLY,),
        needs_manual=True,
        process=True,
    ),
    StandardControl(
        SSDF,
        "PW.4.4",
        "Verify that acquired commercial, open-source, and all other third-party software components comply with "
        "the requirements, as defined by the organization, that are defined throughout their life cycles.",
        (_SCA_ONLY,),
        count_kinds=_SCA_ONLY,
    ),
    StandardControl(
        SSDF,
        "PW.7.2",
        "Perform the code review and/or code analysis based on the organization's secure coding standards, and "
        "record and triage all discovered issues and recommended remediations in the development team's workflow "
        "or issue tracking system.",
        (frozenset({SAST, MOBILE}), _SECRET_ONLY),
        count_kinds=frozenset({SAST, SECRET, MOBILE}),
    ),
    StandardControl(
        SSDF,
        "PW.8.2",
        "Scope the testing, design the tests, perform the testing, and document the results, including recording "
        "and triaging all discovered issues and recommended remediations in the development team's workflow or "
        "issue tracking system.",
        (_RUNTIME,),
        count_kinds=_RUNTIME | {MOBILE},
    ),
    StandardControl(
        SSDF,
        "RV.1.1",
        "Gather information from software acquirers, users, and public sources on potential vulnerabilities in the "
        "software and third-party components that the software uses, and investigate all credible reports.",
        (_SCA_ONLY,),
        needs_manual=True,
        process=True,
        count_kinds=_SCA_ONLY,
    ),
    StandardControl(
        SSDF,
        "RV.2.1",
        "Analyze each vulnerability to gather sufficient information about risk to plan its remediation or other "
        "risk response.",
        (_SCA_ONLY,),
        count_kinds=_SCA_ONLY,
    ),
    StandardControl(
        SSDF,
        "RV.2.2",
        "Plan and implement risk responses for vulnerabilities.",
        (_SCA_ONLY,),
        needs_manual=True,
        process=True,
    ),
    # OWASP Top 10 (2021)
    StandardControl(
        OWASP, "A01:2021", "Broken Access Control", (_SAST_ONLY, _RUNTIME), needs_manual=True, cwes=OWASP_CWES["A01"]
    ),
    StandardControl(
        OWASP, "A02:2021", "Cryptographic Failures", (_SAST_ONLY,), needs_manual=True, cwes=OWASP_CWES["A02"]
    ),
    StandardControl(OWASP, "A03:2021", "Injection", (_SAST_ONLY, _RUNTIME), cwes=OWASP_CWES["A03"]),
    StandardControl(OWASP, "A04:2021", "Insecure Design", needs_manual=True),
    StandardControl(
        OWASP,
        "A05:2021",
        "Security Misconfiguration",
        (_CONFIG_ONLY, frozenset({DAST})),
        count_kinds=_CONFIG_ONLY,
        cwes=OWASP_CWES["A05"],
    ),
    StandardControl(
        OWASP, "A06:2021", "Vulnerable and Outdated Components", (_SCA_ONLY, _IMAGE_ONLY), count_kinds=_SCA_ONLY
    ),
    StandardControl(
        OWASP,
        "A07:2021",
        "Identification and Authentication Failures",
        (_SAST_ONLY, _RUNTIME, _SECRET_ONLY),
        needs_manual=True,
        count_kinds=_SECRET_ONLY,
        cwes=OWASP_CWES["A07"],
    ),
    StandardControl(
        OWASP,
        "A08:2021",
        "Software and Data Integrity Failures",
        (_SCA_ONLY, _SECRET_ONLY),
        needs_manual=True,
        cwes=OWASP_CWES["A08"],
    ),
    StandardControl(OWASP, "A09:2021", "Security Logging and Monitoring Failures", needs_manual=True),
    StandardControl(
        OWASP,
        "A10:2021",
        "Server-Side Request Forgery (SSRF)",
        (_SAST_ONLY, _RUNTIME),
        needs_manual=True,
        cwes=OWASP_CWES["A10"],
    ),
]

STD_EVIDENCE, STD_PARTIAL, STD_NONE = "evidence", "partial", "none"


@dataclass
class StandardStatus:
    control: StandardControl
    status: str  # STD_EVIDENCE | STD_PARTIAL | STD_NONE
    ran: list  # kinds that ran, of those the control relies on
    missing: list  # alternatives (frozensets of kinds) of which none ran
    gate_missing: bool = False


def evaluate_standard_control(control: StandardControl, kinds_run: set, gate_active: bool) -> StandardStatus:
    """Evidence when every kind of testing the control relies on ran (and its security gate is active,
    where it needs one) and the control needs nothing else; Partial when only some of it is there, or
    all of it but the control also needs manual work; No evidence when no testing it relies on ran,
    which is always the case for a control that only manual work can evidence."""
    ran: list = []
    missing: list = []
    for alternatives in control.requires:
        hit = [kind for kind in TEST_KINDS if kind in alternatives and kind in kinds_run]
        if hit:
            ran.extend(kind for kind in hit if kind not in ran)
        else:
            missing.append(alternatives)
    gate_missing = control.needs_gate and not gate_active
    if not ran:
        status = STD_NONE
    elif missing or gate_missing or control.needs_manual:
        status = STD_PARTIAL
    else:
        status = STD_EVIDENCE
    return StandardStatus(control, status, ran, missing, gate_missing)


def related_groups(control: StandardControl, groups: Iterable[Group]) -> list:
    """Open findings related to a control: every finding of its kinds, plus code and runtime findings
    whose recorded CWE is mapped to it."""
    result = []
    for group in groups:
        if group.kind in control.count_kinds:
            result.append(group)
        elif control.cwes and group.kind in CWE_KINDS and group.cwe is not None:
            try:
                cwe = int(group.cwe)
            except (TypeError, ValueError):
                continue
            if cwe in control.cwes:
                result.append(group)
    return result


STANDARD_TEXT = {
    "en": {
        "s_standards": "Standards mapping",
        "intro": "For each control of a standard the reader may already work with, this section shows whether the "
        "automated testing recorded for this product provides evidence for it, and what that testing cannot cover. "
        "Automated testing evidences only part of a control: a control is satisfied by the organisation's "
        "processes (policies, roles, reviews, supplier management, incident handling), which this report does not "
        "assess. Business logic, authorisation and design weaknesses need a manual review or a penetration test.",
        "legend": '"Evidence": every kind of testing the control relies on ran for this scope. "Partial": only some '
        'of it ran, or the control also needs manual work that automation cannot replace. "No evidence": none of '
        "it ran, or only manual work can evidence the control. The status follows from the testing listed in "
        'section {scope} ("Testing performed"), never from the absence of findings.',
        "status_evidence": "Evidence",
        "status_partial": "Partial",
        "status_none": "No evidence",
        "control": "Control",
        "status": "Status",
        "evidence_from": "Evidence from",
        "missing": "What is missing",
        "findings": "Open findings",
        "not_tested": "not tested",
        "or": "or",
        "gate_missing": "an active security gate",
        "gate_ok": "security gate",
        "manual": "Manual review / penetration test",
        "manual_process": "Organisational process",
        "manual_only": "Not testable by automation",
        "how_to_enable": "How to enable the missing kinds of testing",
        "cwe_note": "OWASP counts: open source code and runtime findings whose CWE, as recorded by the scanner, is "
        "in the category's official CWE mapping (OWASP Top 10 2021); secrets also count under A07, configuration "
        "checks under A05 and vulnerable components under A06. Findings without a CWE are not counted, so these "
        "are lower bounds. A finding is one rule or one vulnerability (distinct), as everywhere in this report.",
        "kind_SAST": "SAST",
        "kind_SCA": "SCA",
        "kind_IMAGE": "Image scan",
        "kind_SECRET": "Secrets",
        "kind_CONFIG": "IaC / configuration",
        "kind_DAST": "DAST",
        "kind_IAST": "IAST",
        "kind_MOBILE": "Mobile app (MobSF)",
        "mobile_note": "MobSF is static analysis of the mobile app (the built app, or its source): it counts as "
        "code analysis (PW.7.2) and as security testing during development (A.8.29), and its findings are listed "
        "under PW.8.2, but it is no test of the running app. OWASP MASVS is not mapped as a standard: automated "
        "analysis evidences only a small part of it. MobSF's findings name their MASVS control in their "
        "description.",
        # what automation leaves to people, per control
        "m_iso27001-a-5-21": "supplier selection, agreements and monitoring.",
        "m_iso27001-a-8-9": "documented baselines and change control of configurations.",
        "m_iso27001-a-8-25": "security requirements, design review, separation of environments, training.",
        "m_iso27001-a-8-28": "peer code review against secure coding guidelines.",
        "m_iso27001-a-8-29": "acceptance testing and a penetration test of the running system.",
        "m_ssdf-ps-3-2": "provenance attestations; safeguarding and sharing the SBOM of each release.",
        "m_ssdf-rv-1-1": "a channel for vulnerability reports from users and researchers, and their investigation.",
        "m_ssdf-rv-2-2": "risk responses are decided and implemented by people (decisions section).",
        "m_owasp-a01-2021": "authorisation of every function and object (IDOR, tenant isolation).",
        "m_owasp-a02-2021": "data classification, key management, TLS configuration of the deployment.",
        "m_owasp-a04-2021": "threat modelling and design review.",
        "m_owasp-a07-2021": "login, session and password reset flows, multi-factor authentication.",
        "m_owasp-a08-2021": "integrity of the CI/CD pipeline, signed updates, deserialisation of untrusted data.",
        "m_owasp-a09-2021": "review of logging, alerting and incident response.",
        "m_owasp-a10-2021": "outbound requests built from user input, network egress controls.",
    },
    "vi": {
        "s_standards": "Đối chiếu tiêu chuẩn",
        "intro": "Với từng control của các tiêu chuẩn mà người đọc có thể đang áp dụng, mục này cho biết kiểm thử tự "
        "động ghi nhận cho sản phẩm có cung cấp bằng chứng hay không, và những gì kiểm thử đó không bao quát được. "
        "Kiểm thử tự động chỉ chứng minh một phần của control: control được đáp ứng bởi quy trình của tổ chức "
        "(chính sách, vai trò, rà soát, quản lý nhà cung cấp, xử lý sự cố), và báo cáo này không đánh giá các quy "
        "trình đó. Lỗi logic nghiệp vụ, phân quyền và thiết kế cần rà soát thủ công hoặc kiểm thử xâm nhập "
        "(penetration test).",
        "legend": '"Có bằng chứng": mọi loại kiểm thử mà control dựa vào đều đã chạy trong phạm vi này. "Một phần": '
        'chỉ một số đã chạy, hoặc control còn cần công việc thủ công mà tự động hoá không thay thế được. "Không có '
        'bằng chứng": không loại nào đã chạy, hoặc chỉ công việc thủ công mới chứng minh được control. Trạng thái '
        'được suy ra từ các kiểm thử ở mục {scope} ("Các loại kiểm thử đã thực hiện"), không bao giờ từ việc không '
        "có phát hiện.",
        "status_evidence": "Có bằng chứng",
        "status_partial": "Một phần",
        "status_none": "Không có bằng chứng",
        "control": "Control",
        "status": "Trạng thái",
        "evidence_from": "Bằng chứng từ",
        "missing": "Còn thiếu",
        "findings": "Phát hiện đang mở",
        "not_tested": "chưa kiểm thử",
        "or": "hoặc",
        "gate_missing": "security gate đang bật",
        "gate_ok": "security gate",
        "manual": "Rà soát thủ công / kiểm thử xâm nhập",
        "manual_process": "Quy trình của tổ chức",
        "manual_only": "Tự động hoá không kiểm thử được",
        "how_to_enable": "Cách bật các loại kiểm thử còn thiếu",
        "cwe_note": "Số liệu OWASP: phát hiện mã nguồn và runtime đang mở có CWE (do scanner ghi) nằm trong danh sách "
        "CWE chính thức của hạng mục (OWASP Top 10 2021); bí mật cũng được tính vào A07, kiểm tra cấu hình vào A05 "
        "và thư viện có lỗ hổng vào A06. Phát hiện không có CWE không được tính, nên đây là giá trị tối thiểu. Mỗi "
        "phát hiện là một rule hoặc một lỗ hổng (không trùng lặp), như trong toàn bộ báo cáo.",
        "kind_SAST": "SAST",
        "kind_SCA": "SCA",
        "kind_IMAGE": "Quét image",
        "kind_SECRET": "Bí mật",
        "kind_CONFIG": "IaC / cấu hình",
        "kind_DAST": "DAST",
        "kind_IAST": "IAST",
        "kind_MOBILE": "Ứng dụng di động (MobSF)",
        "mobile_note": "MobSF là phân tích tĩnh ứng dụng di động (bản đã build hoặc mã nguồn): được tính là phân "
        "tích mã (PW.7.2) và kiểm thử bảo mật trong phát triển (A.8.29), các phát hiện của nó được liệt kê ở PW.8.2, "
        "nhưng nó không phải kiểm thử ứng dụng đang chạy. OWASP MASVS không được đối chiếu như một tiêu chuẩn: phân "
        "tích tự động chỉ chứng minh một phần nhỏ của nó. Mỗi phát hiện của MobSF ghi control MASVS trong mô tả.",
        # Vietnamese renderings of the official titles, shown under the English title
        "t_iso27001-a-5-21": "Quản lý an toàn thông tin trong chuỗi cung ứng công nghệ thông tin và truyền thông (ICT)",
        "t_iso27001-a-8-8": "Quản lý lỗ hổng kỹ thuật",
        "t_iso27001-a-8-9": "Quản lý cấu hình",
        "t_iso27001-a-8-25": "Vòng đời phát triển an toàn",
        "t_iso27001-a-8-28": "Lập trình an toàn",
        "t_iso27001-a-8-29": "Kiểm thử bảo mật trong phát triển và nghiệm thu",
        "t_ssdf-ps-3-2": "Thu thập, bảo vệ, duy trì và chia sẻ dữ liệu nguồn gốc của mọi thành phần trong mỗi bản "
        "phát hành (ví dụ trong SBOM).",
        "t_ssdf-pw-4-4": "Xác minh rằng các thành phần phần mềm bên thứ ba (thương mại, mã nguồn mở và khác) tuân thủ "
        "yêu cầu do tổ chức đặt ra trong suốt vòng đời của chúng.",
        "t_ssdf-pw-7-2": "Rà soát và/hoặc phân tích mã theo chuẩn lập trình an toàn của tổ chức; ghi nhận và phân "
        "loại mọi vấn đề phát hiện được trong quy trình của nhóm phát triển.",
        "t_ssdf-pw-8-2": "Xác định phạm vi, thiết kế và thực hiện kiểm thử, lập hồ sơ kết quả; ghi nhận và phân loại "
        "mọi vấn đề phát hiện được.",
        "t_ssdf-rv-1-1": "Thu thập thông tin về lỗ hổng tiềm ẩn của phần mềm và các thành phần bên thứ ba từ khách "
        "hàng, người dùng và nguồn công khai, và điều tra mọi báo cáo đáng tin cậy.",
        "t_ssdf-rv-2-1": "Phân tích từng lỗ hổng để có đủ thông tin về rủi ro nhằm lập kế hoạch khắc phục hoặc xử lý.",
        "t_ssdf-rv-2-2": "Lập kế hoạch và thực hiện biện pháp xử lý rủi ro cho các lỗ hổng.",
        "t_owasp-a01-2021": "Lỗi kiểm soát truy cập",
        "t_owasp-a02-2021": "Lỗi mật mã",
        "t_owasp-a03-2021": "Lỗi chèn mã (injection)",
        "t_owasp-a04-2021": "Thiết kế không an toàn",
        "t_owasp-a05-2021": "Cấu hình bảo mật sai",
        "t_owasp-a06-2021": "Thành phần có lỗ hổng và lỗi thời",
        "t_owasp-a07-2021": "Lỗi định danh và xác thực",
        "t_owasp-a08-2021": "Lỗi toàn vẹn phần mềm và dữ liệu",
        "t_owasp-a09-2021": "Lỗi ghi log và giám sát bảo mật",
        "t_owasp-a10-2021": "Giả mạo yêu cầu phía máy chủ (SSRF)",
        "m_iso27001-a-5-21": "lựa chọn, thoả thuận và giám sát nhà cung cấp.",
        "m_iso27001-a-8-9": "cấu hình chuẩn được lập thành văn bản và kiểm soát thay đổi cấu hình.",
        "m_iso27001-a-8-25": "yêu cầu bảo mật, rà soát thiết kế, tách biệt môi trường, đào tạo.",
        "m_iso27001-a-8-28": "rà soát mã chéo theo hướng dẫn lập trình an toàn.",
        "m_iso27001-a-8-29": "kiểm thử nghiệm thu và kiểm thử xâm nhập hệ thống đang chạy.",
        "m_ssdf-ps-3-2": "chứng thực nguồn gốc (provenance); lưu giữ và chia sẻ SBOM của mỗi bản phát hành.",
        "m_ssdf-rv-1-1": "kênh tiếp nhận báo cáo lỗ hổng từ người dùng và nhà nghiên cứu, và việc điều tra chúng.",
        "m_ssdf-rv-2-2": "biện pháp xử lý rủi ro do con người quyết định và thực hiện (mục quyết định).",
        "m_owasp-a01-2021": "phân quyền cho từng chức năng và đối tượng (IDOR, cách ly tenant).",
        "m_owasp-a02-2021": "phân loại dữ liệu, quản lý khoá, cấu hình TLS khi triển khai.",
        "m_owasp-a04-2021": "mô hình hoá mối đe doạ và rà soát thiết kế.",
        "m_owasp-a07-2021": "luồng đăng nhập, phiên làm việc và đặt lại mật khẩu, xác thực đa yếu tố.",
        "m_owasp-a08-2021": "toàn vẹn của pipeline CI/CD, bản cập nhật có chữ ký, giải tuần tự hoá dữ liệu không tin cậy.",
        "m_owasp-a09-2021": "rà soát ghi log, cảnh báo và ứng phó sự cố.",
        "m_owasp-a10-2021": "request ra ngoài được tạo từ dữ liệu người dùng, kiểm soát lưu lượng ra.",
    },
}


# --- data -------------------------------------------------------------------------------------


class ApiError(Exception):
    pass


class Api:
    def __init__(self, url: str, token: str, timeout: int = 300):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.requests = 0

    def get(self, path: str, params: Optional[list] = None) -> Any:
        query = "?" + urllib.parse.urlencode(params, doseq=True) if params else ""
        request = urllib.request.Request(
            f"{self.url}{path}{query}",
            headers={"Authorization": f"APIToken {self.token}", "Accept": "application/json"},
        )
        self.requests += 1
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # nosec B310
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            raise ApiError(f"GET {path} -> HTTP {error.code}: {error.read()[:200]!r}") from error
        except OSError as error:
            raise ApiError(f"GET {path} -> {error}") from error

    def all_pages(self, path: str, params: list, limit: Optional[int] = None) -> list:
        results: list = []
        page = 1
        while True:
            data = self.get(path, list(params) + [("page_size", PAGE_SIZE), ("page", page)])
            results.extend(data.get("results", []))
            if not data.get("next") or (limit is not None and len(results) >= limit):
                return results[:limit] if limit is not None else results
            page += 1

    def count(self, path: str, params: list) -> int:
        return int(self.get(path, list(params) + [("page_size", 1)]).get("count") or 0)


def _slim(observation: dict) -> dict:
    """Drop the nested product copy each observation carries; it is the same for all."""
    observation = dict(observation)
    observation.pop("product_data", None)
    return observation


def fetch_data(api: Api, args: argparse.Namespace, log: Callable[[str], None]) -> dict:
    products = api.get("/api/products/", [("name", args.product)]).get("results", [])
    product = next((p for p in products if p.get("name") == args.product), None)
    if product is None:
        raise ApiError(f"Product '{args.product}' not found in TDxGuard")

    branch = None
    branch_name = "" if args.all_branches else (args.branch or product.get("repository_default_branch_name") or "")
    if branch_name:
        candidates = api.get("/api/branches/", [("product", product["id"]), ("name", branch_name)]).get("results", [])
        branch = next((b for b in candidates if b.get("name") == branch_name), None)
        if branch is None:
            raise ApiError(f"Branch '{branch_name}' not found in product '{args.product}'")

    scope = [("product", product["id"])] + ([("branch", branch["id"])] if branch else [])
    data: dict = {
        "format_version": REPORT_FORMAT_VERSION,
        "fetched": datetime.now(timezone.utc).isoformat(),
        "product": product,
        "branch": branch,
        "warnings": [],
    }

    log("observations (active)")
    data["active"] = [
        _slim(o) for o in api.all_pages("/api/observations/", scope + [("current_status", s) for s in ACTIVE_STATUSES])
    ]
    log("observations (decided)")
    data["decided"] = [
        _slim(o) for o in api.all_pages("/api/observations/", scope + [("current_status", s) for s in DECIDED_STATUSES])
    ]
    data["resolved_count"] = api.count("/api/observations/", scope + [("current_status", STATUS_RESOLVED)])
    log("vulnerability checks")
    data["checks"] = api.all_pages("/api/vulnerability_checks/", scope)

    log("observation logs")
    data["logs"], data["logs_mode"] = fetch_decision_logs(api, scope, args, data["warnings"])

    period_age = PERIOD_AGES[args.period_days]
    data["period"] = {"days": args.period_days, "age": period_age}
    data["period"]["resolved"] = api.count(
        "/api/observation_logs/", scope + [("status", STATUS_RESOLVED), ("age", period_age)]
    )

    data["settings"] = None
    try:
        data["settings"] = api.get("/api/settings/1/")
    except ApiError:
        data["warnings"].append("settings_unreadable")
    data["product_group"] = None
    if product.get("product_group"):
        try:
            data["product_group"] = api.get(f"/api/product_groups/{product['product_group']}/")
        except ApiError:
            pass

    data["metrics"] = None
    if branch and branch.get("id") == product.get("repository_default_branch"):
        try:
            data["metrics"] = api.get(
                "/api/metrics/product_metrics_timeline/", [("product", product["id"]), ("age", period_age)]
            )
        except ApiError:
            pass

    rules = {}
    for observation in data["decided"] + data["active"]:
        for field_name, endpoint in (("general_rule", "general_rules"), ("product_rule", "product_rules")):
            rule_id = observation.get(field_name)
            if rule_id and (endpoint, rule_id) not in rules:
                try:
                    rules[(endpoint, rule_id)] = api.get(f"/api/{endpoint}/{rule_id}/")
                except ApiError:
                    rules[(endpoint, rule_id)] = {"id": rule_id, "name": f"{endpoint} #{rule_id}"}
    data["rules"] = {f"{endpoint}:{rule_id}": rule for (endpoint, rule_id), rule in rules.items()}
    return data


def fetch_decision_logs(api: Api, scope: list, args: argparse.Namespace, warnings: list) -> tuple:
    """The log entries that may be decisions, as cheaply as the server allows.

    A server with the `automated` filter on /api/observation_logs/ returns exactly the
    non-automated entries. It is detected by asking: an older server ignores the unknown
    parameter, and then `automated=true` and `automated=false` both return everything."""
    path = "/api/observation_logs/"
    total = api.count(path, scope)
    if total == 0:
        return [], "empty"
    manual = api.count(path, scope + [("automated", "false")])
    automated = api.count(path, scope + [("automated", "true")])
    if manual + automated == total and not (manual == total and automated == total):
        logs = api.all_pages(path, scope + [("automated", "false"), ("ordering", "-created")])
        return [_slim_log(x) for x in logs if is_human_decision(x)], "server"

    # Older server: every entry whose status is a decision, plus the most recent entries (for
    # decisions that changed only the severity or priority, or reopened a finding), capped.
    logs: dict = {}
    for status in DECIDED_STATUSES + ["In review", "Affected"]:
        for entry in api.all_pages(path, scope + [("status", status), ("ordering", "-created")]):
            logs[entry["id"]] = _slim_log(entry)
    recent = api.all_pages(path, scope + [("ordering", "-created")], limit=args.max_log_scan)
    for entry in recent:
        logs[entry["id"]] = _slim_log(entry)
    if total > len(recent):
        warnings.append(f"log_scan_capped:{args.max_log_scan}:{total}")
    # only decisions are kept: the report needs nothing else, and saved data stays small
    return [x for x in logs.values() if is_human_decision(x)], "fallback"


def _slim_log(entry: dict) -> dict:
    entry = dict(entry)
    observation = entry.get("observation_data")
    if isinstance(observation, dict):
        entry["observation_data"] = _slim(observation)
    return entry


def is_human_decision(entry: dict) -> bool:
    if (entry.get("comment") or "").strip() in AUTOMATED_COMMENTS:
        return False
    if any(entry.get(name) for name in RULE_LOG_FIELDS):
        return False
    return bool(entry.get("status") or entry.get("severity") or entry.get("priority") or entry.get("comment"))


# --- document model ---------------------------------------------------------------------------
#
# Inline content is a str (plain text, always escaped) or a tuple:
#   ("b", inline) bold · ("code", str) · ("a", inline, href) · ("chip", severity) ·
#   ("tag", str, css class) · ("small", inline) · ("br",)
# or a list of those. Text that came from a scanner or an advisory is only ever passed as a
# plain str, so it cannot open a heading, a table or a code span in either output.


class Doc:
    def __init__(self):
        self.blocks: list = []

    def h(self, level: int, text: str, anchor: str = "", number: str = "", toc: bool = True, page_break=False):
        self.blocks.append(("h", level, text, anchor or anchor_of(text), number, toc, page_break))

    def p(self, *inlines, cls: str = ""):
        self.blocks.append(("p", list(inlines), cls))

    def ul(self, items: list):
        self.blocks.append(("ul", items))

    def table(self, headers: list, rows: list, cls: str = "", numeric: Iterable[int] = ()):
        self.blocks.append(("table", headers, rows, cls, set(numeric)))

    def raw(self, html: str, markdown: str = ""):
        self.blocks.append(("raw", html, markdown))

    def toc(self, title: str):
        self.blocks.append(("toc", title))


_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~])")


def md_text(text: str) -> str:
    return _MD_SPECIAL.sub(r"\\\1", re.sub(r"\s+", " ", str(text)))


def md_inline(item: Any) -> str:
    if item is None:
        return ""
    if isinstance(item, str):
        return md_text(item)
    if isinstance(item, list):
        return "".join(md_inline(i) for i in item)
    kind = item[0]
    if kind == "b":
        return f"**{md_inline(item[1])}**"
    if kind == "code":
        text = " ".join(str(item[1]).split()).replace("|", "\\|")
        fence = "``" if "`" in text else "`"
        return f"{fence}{text}{fence}"
    if kind == "a":
        return f"[{md_inline(item[1])}]({item[2]})"
    if kind == "chip":
        return f"**{md_text(item[1])}**"
    if kind == "tag":
        return f"[{md_text(item[1])}]"
    if kind == "small":
        return md_inline(item[1])
    if kind == "br":
        return "<br>"
    return md_text(str(item))


def html_inline(item: Any) -> str:
    if item is None:
        return ""
    if isinstance(item, str):
        return escape(item)
    if isinstance(item, list):
        return "".join(html_inline(i) for i in item)
    kind = item[0]
    if kind == "b":
        return f"<strong>{html_inline(item[1])}</strong>"
    if kind == "code":
        return f"<code>{escape(str(item[1]))}</code>"
    if kind == "a":
        href = escape(item[2], quote=True)
        external = not str(item[2]).startswith("#")
        attrs = ' rel="noopener" target="_blank"' if external else ""
        return f'<a href="{href}"{attrs}>{html_inline(item[1])}</a>'
    if kind == "chip":
        severity = str(item[1])
        return f'<span class="chip sev-{anchor_of(severity)}">{escape(severity)}</span>'
    if kind == "tag":
        return f'<span class="tag {escape(item[2], quote=True)}">{escape(str(item[1]))}</span>'
    if kind == "small":
        return f'<span class="small">{html_inline(item[1])}</span>'
    if kind == "br":
        return "<br>"
    return escape(str(item))


def render_markdown(doc: Doc) -> str:
    out: list = []
    headings = [b for b in doc.blocks if b[0] == "h" and b[5] and b[1] <= 2]
    for block in doc.blocks:
        kind = block[0]
        if kind == "h":
            _, level, text, anchor, number, _, _ = block
            out.append(f"{'#' * level} {md_text((number + ' ' if number else '') + text)}")
            out.append("")
        elif kind == "p":
            out.append(md_inline(block[1]))
            out.append("")
        elif kind == "ul":
            out.extend(f"- {md_inline(item)}" for item in block[1])
            out.append("")
        elif kind == "table":
            _, headers, rows, _, numeric = block
            out.append("| " + " | ".join(md_inline(h) for h in headers) + " |")
            out.append("|" + "|".join("---:" if i in numeric else "---" for i in range(len(headers))) + "|")
            for row in rows:
                out.append("| " + " | ".join(md_inline(c).replace("\n", " ") or " " for c in row) + " |")
            out.append("")
        elif kind == "raw":
            if block[2]:
                out.append(block[2])
                out.append("")
        elif kind == "toc":
            out.append(f"**{md_text(block[1])}**")
            out.append("")
            for _, level, text, anchor, number, _, _ in headings:
                out.append(f"- [{md_text((number + ' ' if number else '') + text)}](#{anchor})")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_html_body(doc: Doc) -> str:
    out: list = []
    headings = [b for b in doc.blocks if b[0] == "h" and b[5] and b[1] <= 3]
    for block in doc.blocks:
        kind = block[0]
        if kind == "h":
            _, level, text, anchor, number, _, page_break = block
            cls = ' class="new-page"' if page_break else ""
            num = f'<span class="num">{escape(number)}</span> ' if number else ""
            out.append(f'<h{level} id="{escape(anchor, quote=True)}"{cls}>{num}{escape(text)}</h{level}>')
        elif kind == "p":
            cls = f' class="{escape(block[2], quote=True)}"' if block[2] else ""
            out.append(f"<p{cls}>{html_inline(block[1])}</p>")
        elif kind == "ul":
            out.append("<ul>" + "".join(f"<li>{html_inline(item)}</li>" for item in block[1]) + "</ul>")
        elif kind == "table":
            _, headers, rows, cls, numeric = block
            numeric_attr = ' class="n"'
            head = "".join(
                f"<th{numeric_attr if i in numeric else ''}>{html_inline(h)}</th>" for i, h in enumerate(headers)
            )
            body = "".join(
                "<tr>"
                + "".join(f"<td{numeric_attr if i in numeric else ''}>{html_inline(c)}</td>" for i, c in enumerate(row))
                + "</tr>"
                for row in rows
            )
            cls_attr = f' class="{escape(cls, quote=True)}"' if cls else ""
            out.append(f"<table{cls_attr}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
        elif kind == "raw":
            out.append(block[1])
        elif kind == "toc":
            items = []
            for _, level, text, anchor, number, _, _ in headings:
                label = escape((number + " " if number else "") + text)
                items.append(f'<li class="toc-{level}"><a href="#{escape(anchor, quote=True)}">{label}</a></li>')
            out.append(f'<nav class="toc"><h2 class="toc-title">{escape(block[1])}</h2><ol>{"".join(items)}</ol></nav>')
    return "\n".join(out)


# Severity chip colours: white text on each background has a contrast ratio of at least 4.5:1
# (WCAG 2.1 AA for normal text); tests/test_compliance_report.py checks it.
SEVERITY_COLOURS = {
    "Critical": "#8f1d1d",
    "High": "#b3400b",
    "Medium": "#8a5a00",
    "Low": "#1d4ed8",
    "None": "#57534e",
    "Unknown": "#57534e",
}

VERDICT_COLOURS = {"action": "#8f1d1d", "attention": "#8a5a00", "acceptable": "#166534"}


def html_document(title: str, body: str, footer_left: str, lang: str) -> str:
    chips = "\n".join(f"  .sev-{anchor_of(s)} {{ background: {c}; }}" for s, c in SEVERITY_COLOURS.items())
    verdicts = "\n".join(
        f"  .verdict-{k} {{ border-color: {c}; }} .verdict-{k} .verdict-label {{ background: {c}; }}"
        for k, c in VERDICT_COLOURS.items()
    )
    footer = footer_left.replace("\\", "\\\\").replace('"', '\\"')
    return f"""<!doctype html>
<html lang="{escape(lang, quote=True)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>
  :root {{ --ink: #1c1917; --muted: #44403c; --rule: #d6d3d1; --soft: #f5f5f4; --accent: #9a3412; }}
  html {{ background: #fff; }}
  body {{ font: 14px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
         max-width: 60rem; margin: 2rem auto; padding: 0 1.25rem; color: var(--ink); background: #fff; }}
  h1 {{ font-size: 1.8rem; margin: 0 0 .5rem; }}
  h2 {{ font-size: 1.35rem; margin-top: 2.2rem; border-bottom: 2px solid var(--accent); padding-bottom: .25rem; }}
  h3 {{ font-size: 1.1rem; margin-top: 1.6rem; color: var(--ink); }}
  h4 {{ font-size: 1rem; margin: 1.2rem 0 .3rem; }}
  .num {{ color: var(--accent); }}
  a {{ color: #1d4ed8; }}
  table {{ border-collapse: collapse; width: 100%; margin: .6rem 0 1rem; font-size: .9em; }}
  th, td {{ border: 1px solid var(--rule); padding: .3rem .45rem; text-align: left; vertical-align: top; }}
  th {{ background: var(--soft); }}
  td.n, th.n {{ text-align: right; }}
  td.n {{ white-space: nowrap; }}
  table.compact {{ font-size: .8em; }}
  table.compact td, table.compact th {{ padding: .12rem .3rem; }}
  table.findings {{ font-size: .86em; }}
  table.appendix {{ table-layout: fixed; font-size: .68em; line-height: 1.2; }}
  table.appendix td {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding: 0 .25rem; }}
  table.findings, table.toprisks, table.rules {{ table-layout: fixed; }}
  table.findings th:nth-child(1) {{ width: 33%; }} table.findings th:nth-child(2) {{ width: 9%; }}
  table.findings th:nth-child(3) {{ width: 20%; }} table.findings th:nth-child(4) {{ width: 13%; }}
  table.findings th:nth-child(5) {{ width: 14%; }} table.findings th:nth-child(6) {{ width: 6%; }}
  table.findings th:nth-child(7) {{ width: 5%; }}
  table.toprisks th:nth-child(1) {{ width: 4%; }} table.toprisks th:nth-child(2) {{ width: 22%; }}
  table.toprisks th:nth-child(3) {{ width: 10%; }} table.toprisks th:nth-child(4) {{ width: 26%; }}
  table.toprisks th:nth-child(5) {{ width: 14%; }} table.toprisks th:nth-child(6) {{ width: 17%; }}
  table.toprisks th:nth-child(7) {{ width: 7%; }}
  table.rules th:nth-child(1) {{ width: 72%; }} table.rules th:nth-child(2) {{ width: 10%; }}
  table.rules th:nth-child(3) {{ width: 9%; }} table.rules th:nth-child(4) {{ width: 9%; }}
  table.appendix th:nth-child(1) {{ width: 19%; }} table.appendix th:nth-child(2) {{ width: 9%; }}
  table.appendix th:nth-child(3) {{ width: 30%; }} table.appendix th:nth-child(4) {{ width: 16%; }}
  table.appendix th:nth-child(5) {{ width: 11%; }} table.appendix th:nth-child(6) {{ width: 10%; }}
  table.appendix th:nth-child(7) {{ width: 5%; }}
  table.appendix .chip {{ font-size: .95em; padding: 0 .25rem; }}
  table.standards {{ table-layout: fixed; font-size: .84em; }}
  table.standards th:nth-child(1) {{ width: 34%; }} table.standards th:nth-child(2) {{ width: 11%; }}
  table.standards th:nth-child(3) {{ width: 14%; }} table.standards th:nth-child(4) {{ width: 29%; }}
  table.standards th:nth-child(5) {{ width: 12%; }}
  table.standards .tag {{ white-space: normal; }}
  td {{ overflow-wrap: anywhere; }}
  code {{ background: var(--soft); padding: 0 .25rem; border-radius: 3px; font-size: .92em; overflow-wrap: anywhere; }}
  .small {{ color: var(--muted); font-size: .88em; }}
  .chip {{ display: inline-block; color: #fff; border-radius: 3px; padding: 0 .4rem; font-weight: 600;
           font-size: .85em; white-space: nowrap; }}
{chips}
  .tag {{ display: inline-block; border: 1px solid currentColor; border-radius: 3px; padding: 0 .3rem;
          font-size: .8em; font-weight: 600; white-space: nowrap; }}
  .tag.kev {{ color: #8f1d1d; }} .tag.poc {{ color: #8a5a00; }} .tag.fix {{ color: #166534; }}
  .tag.nofix {{ color: #44403c; }} .tag.ok {{ color: #166534; }} .tag.partial {{ color: #8a5a00; }}
  .tag.missing {{ color: #8f1d1d; }}
  .verdict {{ border: 2px solid; border-radius: 6px; padding: .8rem 1rem; margin: 1rem 0; }}
  .verdict-label {{ display: inline-block; color: #fff; font-weight: 700; padding: .1rem .6rem; border-radius: 3px;
                    margin-right: .5rem; }}
{verdicts}
  .verdict ul {{ margin: .4rem 0 0; }}
  .note {{ color: var(--muted); font-size: .9em; }}
  .warning {{ border-left: 4px solid #8a5a00; background: #fffbeb; padding: .4rem .7rem; }}
  .cover {{ min-height: 80vh; display: flex; flex-direction: column; }}
  .cover .logos {{ display: flex; justify-content: space-between; align-items: center; min-height: 3rem; }}
  .cover .logos img {{ max-height: 3.5rem; max-width: 14rem; }}
  .cover h1 {{ font-size: 2.3rem; margin-top: 4rem; border: 0; }}
  .cover .subtitle {{ font-size: 1.25rem; color: var(--muted); margin-bottom: 2rem; }}
  .cover table {{ font-size: 1em; }}
  .cover th {{ width: 30%; }}
  .classification {{ display: inline-block; border: 2px solid #8f1d1d; color: #8f1d1d; font-weight: 700;
                     letter-spacing: .08em; text-transform: uppercase; padding: .15rem .6rem; }}
  nav.toc ol {{ list-style: none; padding-left: 0; }}
  nav.toc li.toc-3 {{ padding-left: 1.5rem; font-size: .93em; }}
  nav.toc a {{ text-decoration: none; color: var(--ink); }}
  .footer {{ margin-top: 2rem; border-top: 1px solid var(--rule); padding-top: .6rem; }}
  @media print {{
    @page {{ size: A4; margin: 16mm 14mm 18mm;
             @bottom-left {{ content: "{footer}"; font-size: 8pt; color: #44403c; }}
             @bottom-right {{ content: counter(page) " / " counter(pages); font-size: 8pt; color: #44403c; }} }}
    @page :first {{ @bottom-left {{ content: none; }} @bottom-right {{ content: none; }} }}
    body {{ margin: 0; max-width: none; padding: 0; font-size: 10pt; }}
    a {{ color: inherit; text-decoration: none; }}
    .cover {{ min-height: 0; height: 250mm; break-after: page; }}
    h2.new-page {{ break-before: page; }}
    h2, h3, h4 {{ break-after: avoid; }}
    thead {{ display: table-header-group; }}
    tr, .verdict {{ break-inside: avoid; }}
    .chip, .verdict-label {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style></head><body>
{body}
</body></html>
"""


# --- report -----------------------------------------------------------------------------------


class Report:
    """Builds the document from the fetched data. Pure: no network, no clock except `now`."""

    def __init__(self, data: dict, args: argparse.Namespace, now: Optional[datetime] = None):
        self.data = data
        self.args = args
        self.lang = args.lang if args.lang in STRINGS else "en"
        self.now = now or datetime.now(timezone.utc)
        self.product = data["product"]
        self.branch = data.get("branch")
        self.ui = (args.ui_url or "").rstrip("/")
        self.sla = dict(DEFAULT_SLA_DAYS)
        self.sla.update(parse_sla(args.sla))

        active, self.superseded = split_superseded(list(data.get("active") or []))
        self.active = active
        self.groups = group_observations(active)
        self.superseded_groups = group_observations(self.superseded)
        self.by_kind: dict = defaultdict(list)
        for group in self.groups:
            self.by_kind[group.kind].append(group)
        for groups in self.by_kind.values():
            groups.sort(key=lambda g: (SEVERITY_RANK.get(g.severity, 99), g.rank_key()))

        self.decided = list(data.get("decided") or [])
        logs = list(data.get("logs") or [])
        self.human_logs = sorted(
            (entry for entry in logs if is_human_decision(entry)),
            key=lambda entry: parse_time(entry.get("created")) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        self.gate = evaluate_gate(self.product, data.get("product_group"), data.get("settings"))
        self.overdue = self._overdue()
        self.verdict = compute_verdict(self.groups, self.gate, self.overdue)
        self.kinds_run, self.kind_checks = self._kinds_run()
        self.section_numbers: dict = {}

    # -- helpers --

    def t(self, key: str) -> str:
        return STRINGS[self.lang].get(key) or STRINGS["en"].get(key) or key

    def ct(self, key: str) -> str:
        return CONTROL_TEXT[self.lang].get(key) or CONTROL_TEXT["en"][key]

    def vi(self) -> bool:
        return self.lang == "vi"

    def obs_link(self, observation_id: Any, label: Any = None) -> Any:
        label = label if label is not None else f"#{observation_id}"
        if self.ui and observation_id:
            return ("a", label, f"{self.ui}/observations/{observation_id}/show")
        return label

    def kind_label(self, kind: str) -> str:
        return self.t(f"kind_{kind}")

    def test_kinds(self) -> list:
        """TEST_KINDS without the kinds that apply to some products only and did not run here."""
        return [kind for kind in TEST_KINDS if kind not in APPLICABLE_WHEN_RUN or kind in self.kinds_run]

    def _overdue(self) -> dict:
        overdue: Counter = Counter()
        for group in self.groups:
            limit = self.sla.get(group.severity)
            age = group.age_days(self.now)
            if limit is not None and age is not None and age > limit:
                overdue[group.severity] += 1
        return dict(overdue)

    def _kinds_run(self) -> tuple:
        observed: dict = defaultdict(set)
        for observation in list(self.data.get("active") or []) + self.decided:
            name = observation.get("upload_filename") or observation.get("api_configuration_name") or ""
            observed[name].add(finding_kind(observation))
            if observation.get("origin_docker_image_name"):
                observed[name].add(IMAGE)
        kinds: set = set()
        per_kind: dict = defaultdict(list)
        for check in self.data.get("checks") or []:
            name = check.get("filename") or check.get("api_configuration_name") or ""
            for kind in check_kinds(check, observed.get(name, set()) - {OTHER}):
                kinds.add(kind)
                per_kind[kind].append(check)
        return kinds, per_kind

    def _scope_label(self) -> str:
        if self.branch:
            return self.branch.get("name") or ""
        return self.t("all_branches")

    def _period_start(self) -> datetime:
        return self.now - timedelta(days=self.data["period"]["days"])

    def _latest_scan(self) -> Optional[datetime]:
        lasts = [parse_time(c.get("last_import")) for c in self.data.get("checks") or []]
        lasts = [x for x in lasts if x]
        return max(lasts) if lasts else None

    # -- build --

    def build(self) -> Doc:
        doc = Doc()
        self._cover(doc)
        doc.toc(self.t("toc"))
        number = 0

        def section(key: str, builder: Callable[[Doc, str], None], appendix: str = ""):
            nonlocal number
            if appendix:
                label = appendix
            else:
                number += 1
                label = f"{number}."
            self.section_numbers[key] = label.rstrip(".")
            builder(doc, label)

        section("summary", self._summary)
        section("scope", self._scope)
        section("standards", self._standards)
        section("sca", self._sca)
        section("sast", self._sast)
        section("secret", self._secrets)
        section("config", self._config)
        section("dast", self._dast)
        if MOBILE in self.kinds_run or self.by_kind.get(MOBILE):
            section("mobile", self._mobile)
        if self.by_kind.get(OTHER):
            section("other", self._other)
        section("decisions", self._decisions)
        section("controls", self._controls)
        section("appendix_a", self._appendix_a, appendix="A")
        if self.superseded:
            section("appendix_b", self._appendix_b, appendix="B")
        section("appendix_c", self._appendix_c, appendix="C")
        doc.p(
            (
                "small",
                self.t("footer")
                + f" TDxGuard compliance-report.py {REPORT_FORMAT_VERSION}, "
                + fmt_time(self.now)
                + ".",
            ),
            cls="footer",
        )
        return doc

    # -- cover --

    def _cover_rows(self) -> list:
        args = self.args
        start = self._period_start()
        rows = [
            (self.t("product"), self.product.get("name")),
            (self.t("branch"), self._scope_label()),
        ]
        if args.commit:
            rows.append((self.t("commit"), ("code", args.commit)))
        rows.append((self.t("latest_scan"), fmt_time(self._latest_scan())))
        rows += [
            (
                self.t("period"),
                f"{fmt_time(start, False)} – {fmt_time(self.now, False)} ({self.data['period']['days']} d)",
            ),
            (self.t("generated"), fmt_time(self.now)),
            (self.t("document_id"), args.doc_id or f"SAR-{anchor_of(self.product.get('name', ''))}-{self.now:%Y%m%d}"),
            (self.t("version"), args.doc_version),
            (self.t("prepared_by"), args.tester),
        ]
        if args.prepared_for:
            rows.append((self.t("prepared_for"), args.prepared_for))
        if args.classification:
            rows.append((self.t("classification"), ("b", args.classification)))
        rows.append((self.t("approved_by"), ("small", f"________________________  ({self.t('signature')})")))
        return rows

    def _cover(self, doc: Doc) -> None:
        args = self.args
        rows = self._cover_rows()
        logos = "".join(
            f'<img src="{escape(src, quote=True)}" alt="">' if src else "<span></span>"
            for src in (image_source(args.logo), image_source(args.customer_logo))
        )
        table = "".join(f"<tr><th>{escape(k)}</th><td>{html_inline(v)}</td></tr>" for k, v in rows)
        classification = (
            f'<p><span class="classification">{escape(args.classification)}</span></p>' if args.classification else ""
        )
        subtitle = escape(self.product.get("name") or "") + (f" · {escape(self._scope_label())}" if self.branch else "")
        html = (
            f'<section class="cover"><div class="logos">{logos}</div>'
            f"<h1>{escape(args.title or self.t('title'))}</h1>"
            f'<div class="subtitle">{subtitle}</div>{classification}'
            f"<table><tbody>{table}</tbody></table></section>"
        )
        md_rows = "\n".join(f"| {md_text(k)} | {md_inline(v)} |" for k, v in rows)
        markdown = f"# {md_text(args.title or self.t('title'))}\n\n| | |\n|---|---|\n{md_rows}"
        doc.raw(html, markdown)

    # -- 1. executive summary --

    def _summary(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_summary"), "summary", number)
        self._verdict_box(doc)

        doc.h(3, self.t("key_figures"), "key-figures")
        sca_or_all = self.groups
        rows = []
        totals = [0, 0, 0, 0, 0, 0]
        for severity in SEVERITY_ORDER:
            groups = [g for g in sca_or_all if g.severity == severity]
            if not groups:
                continue
            vulns = [g for g in groups if g.kind == SCA]
            values = [
                len(groups),
                len({(g.kind, g.ident) for g in groups}),
                sum(g.count for g in groups),
                sum(1 for g in vulns if g.fixable),
                sum(1 for g in vulns if g.kev),
                sum(1 for g in vulns if g.exploit_public and not g.kev),
            ]
            totals = [a + b for a, b in zip(totals, values)]
            rows.append([("chip", severity)] + [str(v) for v in values])
        if rows:
            # unique IDs are not additive across severities (one CVE can sit in two packages)
            totals[1] = len({(g.kind, g.ident) for g in sca_or_all})
            rows.append([("b", self.t("total"))] + [("b", str(v)) for v in totals])
            doc.table(
                [
                    self.t("severity"),
                    self.t("distinct"),
                    self.t("unique_ids"),
                    self.t("observations"),
                    self.t("fixable"),
                    self.t("kev"),
                    self.t("poc"),
                ],
                rows,
                numeric=range(1, 7),
            )
            doc.p(self._key_figures_note(), cls="note")
        else:
            doc.p(self.t("none"))

        if self.groups:
            doc.h(3, self.t("by_kind"), "by-kind")
            severities = [s for s in SEVERITY_ORDER if any(g.severity == s for g in self.groups)]
            kind_rows = []
            for kind in FINDING_KINDS:
                groups = self.by_kind.get(kind) or []
                if not groups:
                    continue
                counts = Counter(g.severity for g in groups)
                kind_rows.append(
                    [("a", self.kind_label(kind), f"#{kind.lower()}")]
                    + [str(counts.get(s, 0)) for s in severities]
                    + [str(len(groups))]
                )
            doc.table(
                [self.t("kind")] + [("chip", s) for s in severities] + [self.t("total")],
                kind_rows,
                numeric=range(1, len(severities) + 2),
            )

        self._top_risks(doc)
        self._period_changes(doc)
        self._gate(doc)

    def _key_figures_note(self) -> str:
        if self.vi():
            text = (
                '"Số lỗ hổng" đếm mỗi lỗ hổng một lần cho mỗi gói nguồn (một CVE trong ffmpeg ảnh hưởng '
                "17 gói nhị phân là một lỗ hổng); rule SAST, rule bí mật và kiểm tra cấu hình được đếm theo rule. "
                '"Số ID duy nhất" đếm mỗi CVE, advisory hay rule một lần. '
                '"Số bản ghi" là số dòng trên dashboard. Bản vá và khai thác chỉ áp dụng cho lỗ hổng SCA.'
            )
        else:
            text = (
                '"Distinct" counts a vulnerability once per source package (one CVE in ffmpeg that affects '
                "17 binary packages is one); SAST rules, secret rules and configuration checks count once per "
                'rule. "Unique IDs" counts each CVE, advisory or rule once, whatever the package. '
                '"Observations" is the number of rows in the dashboard. Fix and exploitation columns '
                "apply to vulnerabilities (SCA) only."
            )
        if self.superseded:
            text += " " + (
                f"{len(self.superseded)} observations of superseded images are excluded (appendix B)."
                if not self.vi()
                else f"{len(self.superseded)} bản ghi của image đã bị thay thế không được tính (phụ lục B)."
            )
        return text

    def _verdict_box(self, doc: Doc) -> None:
        verdict = self.verdict
        label = self.t(f"v_{verdict.level}")
        reasons = [self._reason_text(key, n) for key, n in verdict.reasons]
        if not reasons:
            reasons = [
                (
                    "No open Critical or High finding, no known-exploited vulnerability, and the security gate passes."
                    if not self.vi()
                    else "Không có phát hiện Critical hay High đang mở, không có lỗ hổng đã bị khai thác, và security "
                    "gate đạt."
                )
            ]
        items = "".join(f"<li>{escape(r)}</li>" for r in reasons)
        html = (
            f'<div class="verdict verdict-{verdict.level}"><span class="verdict-label">{escape(label)}</span>'
            f"<strong>{escape(self.t('verdict'))}</strong><ul>{items}</ul>"
            f'<p class="note">{escape(self._verdict_rule_text())}</p></div>'
        )
        markdown = (
            f"> **{md_text(self.t('verdict'))}: {md_text(label)}**\n>\n"
            + "\n".join(f"> - {md_text(r)}" for r in reasons)
            + f"\n>\n> {md_text(self._verdict_rule_text())}"
        )
        doc.raw(html, markdown)

    def _reason_text(self, key: str, n: int) -> str:
        one = n == 1
        en = {
            "kev": f"{n} open {'vulnerability is' if one else 'vulnerabilities are'} listed as exploited in the wild "
            "(CISA / VulnCheck KEV).",
            "critical_fixable": f"{n} open Critical {'vulnerability has' if one else 'vulnerabilities have'} "
            "a fix available.",
            "secrets": f"{n} Critical/High secret {'finding is' if one else 'findings are'} open.",
            "critical_high": f"{n} distinct Critical or High {'finding is' if one else 'findings are'} open.",
            "gate_failed": "The security gate fails (section 1, Security gate).",
            "overdue": f"{n} distinct {'finding is' if one else 'findings are'} open longer than their SLA.",
        }
        vi = {
            "kev": f"{n} lỗ hổng đang mở nằm trong danh mục đã bị khai thác thực tế (CISA / VulnCheck KEV).",
            "critical_fixable": f"{n} lỗ hổng Critical đang mở đã có bản vá.",
            "secrets": f"{n} phát hiện bí mật mức Critical/High đang mở.",
            "critical_high": f"{n} phát hiện Critical hoặc High (không trùng lặp) đang mở.",
            "gate_failed": "Security gate không đạt (mục 1, Security gate).",
            "overdue": f"{n} phát hiện đang mở quá thời hạn SLA.",
        }
        return (vi if self.vi() else en)[key]

    def _verdict_rule_text(self) -> str:
        if self.vi():
            return (
                'Quy tắc: "Cần hành động" khi có lỗ hổng thuộc KEV, lỗ hổng Critical đã có bản vá, hoặc bí mật '
                'Critical/High; "Cần chú ý" khi còn phát hiện Critical/High, gate không đạt hoặc quá SLA; '
                'còn lại là "Chấp nhận được" (phụ lục C).'
            )
        return (
            'Rule: "Action required" when a KEV-listed vulnerability, a Critical vulnerability with a fix, or a '
            'Critical/High secret is open; "Attention needed" when Critical/High findings are open, the gate '
            'fails or findings are over SLA; otherwise "Acceptable" (appendix C).'
        )

    def _top_risks(self, doc: Doc) -> None:
        doc.h(3, self.t("top_risks"), "top-risks")
        candidates = [g for g in self.groups if g.severity in ("Critical", "High") or g.kev]
        candidates.sort(key=lambda g: g.rank_key())
        top = candidates[: self.args.top_risks]
        if not top:
            doc.p(self.t("none"))
            return
        rows = []
        for index, group in enumerate(top, 1):
            rows.append(
                [
                    str(index),
                    [
                        self.obs_link(group.link_id, ("b", group.ident)),
                        ("br",),
                        ("small", self.t(f"short_{group.kind}")),
                    ],
                    ("chip", group.severity),
                    self._where(group, 3),
                    self._fix_cell(group),
                    self._exploit_cell(group),
                    str(group.age_days(self.now) if group.first_seen else "—"),
                ]
            )
        doc.table(
            [
                self.t("rank"),
                self.t("vulnerability"),
                self.t("severity"),
                self.t("where"),
                self.t("fix"),
                self.t("exploit"),
                self.t("age"),
            ],
            rows,
            cls="toprisks",
            numeric=(0, 6),
        )
        doc.p(
            (
                "Ranking: known exploited (KEV) with a fix first, then known exploited, then by EPSS (probability of "
                "exploitation in the next 30 days), severity and CVSS."
                if not self.vi()
                else "Xếp hạng: lỗ hổng đã bị khai thác (KEV) có bản vá trước, rồi KEV, rồi theo EPSS (xác suất bị "
                "khai "
                "thác trong 30 ngày tới), mức độ và CVSS."
            ),
            cls="note",
        )

    def _where(self, group: Group, limit: int) -> list:
        parts: list = []
        if group.kind == SCA:
            others = len(group.packages) - 1
            first = group.packages[0] if group.packages else group.source_package
            parts.append(("code", first))
            if others > 0:
                parts.append(f" +{others} " + ("gói" if self.vi() else "packages"))
            if group.images:
                parts += [("br",), ("small", ("image " if not self.vi() else "image ") + ", ".join(group.images))]
        else:
            shown = group.locations[:limit]
            for i, location in enumerate(shown):
                if i:
                    parts.append(("br",))
                parts.append(("code", location))
            rest = len(group.locations) - len(shown)
            if rest > 0:
                parts += [("br",), ("small", f"+{rest} {self.t('more')}")]
        return parts

    def _fix_cell(self, group: Group) -> Any:
        if group.kind != SCA:
            return "—"
        if group.fixes:
            versions = sorted({version for _, version in group.fixes})
            return [("tag", "fix", "fix"), " ", ("code", ", ".join(versions[:2]) + (" …" if len(versions) > 2 else ""))]
        if group.fixable:
            return ("tag", "fix", "fix")
        return ("tag", "no fix" if not self.vi() else "chưa có", "nofix")

    def _exploit_cell(self, group: Group) -> Any:
        parts: list = []
        if group.kev:
            parts.append(("tag", "KEV", "kev"))
        elif group.exploit_public:
            parts.append(("tag", "exploit public" if not self.vi() else "exploit công khai", "poc"))
        if group.epss is not None:
            if parts:
                parts.append(" ")
            parts.append(f"EPSS {fmt_epss(group.epss, group.epss_percentile)}")
        if group.cvss is not None:
            parts += ([("br",)] if parts else []) + [("small", f"CVSS {group.cvss_version} {group.cvss:g}")]
        return parts or "—"

    def _period_changes(self, doc: Doc) -> None:
        doc.h(3, self.t("period_changes"), "period")
        start = self._period_start()
        new_groups = [g for g in self.groups if g.first_seen and g.first_seen >= start]
        new_obs = sum(
            1 for o in self.active if (parse_time(o.get("created")) or start) >= start and parse_time(o.get("created"))
        )
        decisions = [
            e
            for e in self.human_logs
            if (parse_time(e.get("created")) or start) >= start and parse_time(e.get("created"))
        ]
        decision_counts = Counter(e.get("status") or "comment/severity" for e in decisions)
        resolved = self.data["period"].get("resolved", 0)
        rule_closed = Counter(
            o.get("current_status")
            for o in self.decided
            if o.get("rule_status") and (parse_time(o.get("modified")) or start) >= start
        )
        if self.vi():
            items = [
                f"Phát hiện mới, vẫn đang mở: {len(new_groups)} (không trùng lặp), {new_obs} bản ghi.",
                f"Chuyển sang Resolved (không còn trong lần quét gần nhất hoặc được đóng): {resolved} bản ghi.",
                "Quyết định của con người: "
                + (", ".join(f"{k} {v}" for k, v in decision_counts.items()) or "không có")
                + ".",
                "Đóng bởi rule: " + (", ".join(f"{k} {v}" for k, v in rule_closed.items()) or "không có") + ".",
            ]
        else:
            items = [
                f"New findings, still open: {len(new_groups)} distinct, {new_obs} observations.",
                f"Changed to Resolved (no longer reported by the latest scan, or closed): {resolved} observations.",
                "Decisions by people: " + (", ".join(f"{k} {v}" for k, v in decision_counts.items()) or "none") + ".",
                "Closed by rules: " + (", ".join(f"{k} {v}" for k, v in rule_closed.items()) or "none") + ".",
            ]
        doc.ul(items)
        self._trend(doc)
        self._ages(doc)

    def _trend(self, doc: Doc) -> None:
        metrics = self.data.get("metrics") or {}
        if not metrics:
            return
        days = sorted(metrics)
        step = max(1, -(-len(days) // 6))
        sample = days[::step]
        if days[-1] not in sample:
            sample.append(days[-1])
        doc.h(4, self.t("trend"), "trend", toc=False)
        rows = []
        for day in sample:
            m = metrics[day]
            rows.append(
                [day]
                + [str(m.get(f"active_{s.lower()}", 0)) for s in ("Critical", "High", "Medium", "Low")]
                + [str(m.get("resolved", 0)), str(m.get("not_affected", 0))]
            )
        doc.table(
            [
                self.t("date"),
                ("chip", "Critical"),
                ("chip", "High"),
                ("chip", "Medium"),
                ("chip", "Low"),
                "Resolved",
                "Not affected",
            ],
            rows,
            numeric=range(1, 7),
        )
        last = metrics[days[-1]]
        live = Counter(o.get("current_severity") for o in self.data.get("active") or [])
        mismatch = any(
            abs(int(last.get(f"active_{s.lower()}", 0)) - live.get(s, 0)) > max(5, live.get(s, 0) * 0.05)
            for s in ("Critical", "High")
        )
        note = (
            "Observation counts (not distinct), from the daily product metrics of the default branch."
            if not self.vi()
            else "Số bản ghi (không gộp), lấy từ số liệu hằng ngày của nhánh mặc định."
        )
        if mismatch:
            note += (
                " The latest metrics do not match the live counts in this report; the trend is indicative only "
                "(metrics are recalculated by a background task)."
                if not self.vi()
                else " Số liệu gần nhất không khớp với số liệu trực tiếp trong báo cáo; xu hướng chỉ mang tính tham "
                "khảo "
                "(số liệu được tính lại bởi tác vụ nền)."
            )
        doc.p(note, cls="note")

    def _ages(self, doc: Doc) -> None:
        buckets = [(7, "≤ 7"), (30, "8–30"), (90, "31–90"), (None, "> 90")]
        rows = []
        for severity in ("Critical", "High", "Medium", "Low"):
            groups = [g for g in self.groups if g.severity == severity and g.first_seen]
            if not groups:
                continue
            counts = [0, 0, 0, 0]
            for group in groups:
                age = group.age_days(self.now)
                for index, (limit, _) in enumerate(buckets):
                    if limit is None or age <= limit:
                        counts[index] += 1
                        break
            rows.append(
                [("chip", severity)]
                + [str(c) for c in counts]
                + [str(self.sla.get(severity, "—")), str(self.overdue.get(severity, 0))]
            )
        if not rows:
            return
        doc.h(4, self.t("ages"), "ages", toc=False)
        doc.table(
            [self.t("severity")] + [f"{label} d" for _, label in buckets] + [self.t("sla"), self.t("overdue")],
            rows,
            numeric=range(1, 7),
        )

    def _gate(self, doc: Doc) -> None:
        doc.h(3, self.t("gate"), "gate")
        gate = self.gate
        source_text = {
            "product": ("thresholds set on the product", "ngưỡng đặt trên sản phẩm"),
            "product_group": ("thresholds set on the product group", "ngưỡng đặt trên nhóm sản phẩm"),
            "settings": (
                "global thresholds (the product sets none)",
                "ngưỡng toàn cục (sản phẩm không đặt ngưỡng riêng)",
            ),
            "product_off": ("switched off for this product", "đã tắt cho sản phẩm này"),
            "product_group_off": ("switched off for the product group", "đã tắt cho nhóm sản phẩm"),
            "settings_off": ("not active (globally off, the product sets nothing)", "không bật (tắt toàn cục)"),
            "unknown": (
                "thresholds not readable with this API token (global settings need a superuser)",
                "không đọc được ngưỡng với API token này (cần quyền superuser)",
            ),
        }[gate["source"]][1 if self.vi() else 0]
        passed = gate.get("passed")
        result = self.t("disabled") if passed is None else self.t("passed") if passed else self.t("failed")
        doc.p(("b", f"{self.t('result')}: {result}"), f" — {source_text}.")
        if gate["thresholds"]:
            rows = []
            exceeded = {s for s, _, _ in gate["exceeded"]}
            for severity, limit in gate["thresholds"].items():
                current = self.product.get(f"active_{severity.lower()}_observation_count")
                if limit >= 99999:
                    continue
                rows.append(
                    [
                        ("chip", severity),
                        f"≤ {limit}",
                        str(current if current is not None else "—"),
                        ("tag", "exceeded", "missing") if severity in exceeded else ("tag", "ok", "ok"),
                    ]
                )
            doc.table(
                [self.t("severity"), self.t("threshold"), self.t("current"), self.t("result")], rows, numeric=(1, 2)
            )
            doc.p(
                (
                    "The gate counts open observations (not distinct vulnerabilities) on the product's default branch, "
                    "as the dashboard does."
                    if not self.vi()
                    else "Gate đếm số bản ghi đang mở (không gộp) trên nhánh mặc định của sản phẩm, giống dashboard."
                ),
                cls="note",
            )

    # -- 2. scope and methodology --

    def _scope(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_scope"), "scope", number, page_break=True)
        doc.h(3, self.t("scope"), "scope-statement")
        if self.args.scope:
            doc.p(self.args.scope)
        branch = self.branch
        if self.vi():
            items = [
                f"Sản phẩm {self.product.get('name')}, nhánh {self._scope_label()}"
                + (" (nhánh mặc định)." if branch and branch.get("is_default_branch") else "."),
                "Các nhánh khác (ví dụ nhánh pull request) không thuộc phạm vi báo cáo.",
                "Chỉ tính phát hiện đang mở (Open, Affected, In review); phát hiện đã đóng ở mục "
                f"{self.section_numbers.get('decisions', '')}.",
            ]
        else:
            items = [
                f"Product {self.product.get('name')}, branch {self._scope_label()}"
                + (" (the default branch)." if branch and branch.get("is_default_branch") else "."),
                "Other branches (for example pull request refs) are outside the scope of this report.",
                "Findings counted as open: status Open, Affected or In review; closed findings are covered in the "
                "decisions section.",
            ]
        if self.product.get("description"):
            items.insert(
                1, ("Mô tả: " if self.vi() else "Description: ") + short_text(self.product["description"], 300)
            )
        doc.ul(items)

        doc.h(3, self.t("testing_performed"), "testing")
        rows = []
        for kind in self.test_kinds():
            checks = self.kind_checks.get(kind) or []
            if checks:
                tools = sorted({" ".join(filter(None, tool_of(c))) for c in checks}, key=str.lower)
                firsts = [parse_time(c.get("first_import")) for c in checks]
                lasts = [parse_time(c.get("last_import")) for c in checks]
                firsts = [f for f in firsts if f]
                lasts = [x for x in lasts if x]
                rows.append(
                    [
                        self.kind_label(kind),
                        ("tag", self.t("performed"), "ok"),
                        ", ".join(tools),
                        str(len(checks)),
                        fmt_time(min(firsts)) if firsts else "—",
                        fmt_time(max(lasts)) if lasts else "—",
                    ]
                )
            else:
                rows.append([self.kind_label(kind), ("tag", self.t("not_performed"), "missing"), "—", "0", "—", "—"])
        doc.table(
            [
                self.t("kind"),
                self.t("performed"),
                self.t("tools"),
                self.t("reports"),
                self.t("first_run"),
                self.t("last_run"),
            ],
            rows,
            numeric=(3,),
        )
        doc.p(
            (
                "Derived from the vulnerability checks TDxGuard recorded for this scope: a kind of testing is only "
                "listed "
                "as performed when a check of that kind exists. Times are UTC."
                if not self.vi()
                else "Suy ra từ các vulnerability check TDxGuard ghi nhận cho phạm vi này: một loại kiểm thử chỉ được "
                "ghi "
                "là đã thực hiện khi có check tương ứng. Thời gian theo UTC."
            ),
            cls="note",
        )

        doc.h(3, self.t("scan_runs"), "scan-runs")
        checks = sorted(self.data.get("checks") or [], key=lambda c: (tool_of(c)[0].lower(), c.get("filename") or ""))
        rows = []
        for check in checks:
            name, version = tool_of(check)
            rows.append(
                [
                    name,
                    version or "—",
                    ("code", check.get("filename") or check.get("api_configuration_name") or "—"),
                    fmt_time(check.get("last_import")),
                    str(check.get("last_import_observations_new") or 0),
                    str(check.get("last_import_observations_updated") or 0),
                    str(check.get("last_import_observations_resolved") or 0),
                ]
            )
        if rows:
            doc.table(
                [
                    self.t("tool"),
                    self.t("tool_version"),
                    self.t("report"),
                    self.t("last_run"),
                    self.t("new"),
                    self.t("updated"),
                    self.t("resolved"),
                ],
                rows,
                cls="compact",
                numeric=(4, 5, 6),
            )
        else:
            doc.p(self.t("none"))

        self._images(doc)
        self._method_notes(doc)

        doc.h(3, self.t("not_covered"), "not-covered")
        missing = [self.kind_label(k) for k in self.test_kinds() if k not in self.kinds_run]
        if self.vi():
            paragraphs = [
                "Kiểm thử tự động không tìm ra lỗi logic nghiệp vụ: truy cập dữ liệu của tenant khác qua một request "
                "trông hợp lệ, leo thang đặc quyền qua quy trình phê duyệt, race condition trong luồng thanh toán, "
                "hay lạm dụng một tính năng hoạt động đúng như thiết kế. Những lỗi đó cần người kiểm thử, và báo cáo "
                "này không khẳng định gì về chúng.",
            ]
            if missing:
                paragraphs.append(
                    "Các loại kiểm thử không được thực hiện trong phạm vi này: "
                    + ", ".join(missing)
                    + ". Việc không có phát hiện thuộc các loại này KHÔNG có nghĩa là không có lỗ hổng: "
                    "chúng chưa được kiểm tra."
                )
        else:
            paragraphs = [
                "Automated testing does not find business logic flaws: access to another tenant's data through a "
                "legitimate-looking request, privilege escalation through an approval workflow, race conditions in a "
                "payment flow, or abuse of a feature that works as designed. Those require a human tester, and this "
                "report makes no claim about them.",
            ]
            if missing:
                paragraphs.append(
                    "Kinds of testing not performed for this scope: "
                    + ", ".join(missing)
                    + ". The absence of findings of these kinds does not mean the absence of vulnerabilities: "
                    "they were not tested for."
                )
        sast_languages = self._sast_languages()
        if sast_languages:
            paragraphs.append(sast_languages)
        for paragraph in paragraphs:
            doc.p(paragraph)
        hints = [self.t(f"enable_{k}") for k in self.test_kinds() if k not in self.kinds_run]
        if hints:
            doc.ul(hints)

    def _sast_languages(self) -> str:
        """Which languages Opengrep's static analysis covered; empty when Opengrep did not run."""
        if not any("opengrep" in tool_of(c)[0].lower() for c in self.kind_checks.get(SAST) or []):
            return ""
        names = [_LANGUAGE_NAMES.get(x, x.capitalize()) for x in OPENGREP_LANGUAGES if x != "generic"]
        if self.vi():
            return (
                "Phân tích tĩnh (Opengrep) dùng các rule bảo mật cho: "
                + ", ".join(names)
                + ", cùng các mẫu không phụ thuộc ngôn ngữ. Mã nguồn bằng ngôn ngữ khác (ví dụ Rust, Swift, Dart, "
                "C++) không được phân tích tĩnh."
            )
        return (
            "Static analysis (Opengrep) applied security rules for: "
            + ", ".join(names)
            + ", plus language-independent patterns. Source code in other languages (for example Rust, Swift, "
            "Dart, C++) was not statically analysed."
        )

    def _images(self, doc: Doc) -> None:
        images: dict = defaultdict(lambda: {"tags": Counter(), "seen": None})
        for o in list(self.active) + list(self.superseded):
            name = image_name(o)
            if not name:
                continue
            entry = images[name]
            tag = image_tag(o)
            if tag:
                entry["tags"][tag[:12]] += 1
            seen = parse_time(o.get("import_last_seen"))
            if seen and (entry["seen"] is None or seen > entry["seen"]):
                entry["seen"] = seen
        if not images:
            return
        doc.h(3, self.t("images"), "images")
        rows = []
        for name in sorted(images):
            entry = images[name]
            tags = ", ".join(f"{tag} ({n})" for tag, n in entry["tags"].most_common(4))
            if len(entry["tags"]) > 4:
                tags += f", +{len(entry['tags']) - 4}"
            rows.append([("code", name), fmt_time(entry["seen"]), tags or "—"])
        doc.table([self.t("image"), self.t("latest_scan"), self.t("tags_on_findings")], rows)
        doc.p(
            (
                "TDxGuard keeps the image tag a finding was first seen with, so one image can show several commit "
                "tags. "
                "Every finding counted in this report was still reported by the latest scan of its image; findings the "
                "latest scan no longer saw are listed separately (appendix B) and not counted."
                if not self.vi()
                else "TDxGuard giữ tag image tại lần đầu phát hiện, nên một image có thể có nhiều tag commit. Mọi "
                "phát hiện "
                "được tính trong báo cáo đều còn xuất hiện ở lần quét gần nhất của image đó; phát hiện mà lần quét gần "
                "nhất không còn thấy được liệt kê riêng (phụ lục B) và không được tính."
            ),
            cls="note",
        )

    def _method_notes(self, doc: Doc) -> None:
        doc.h(3, "Severity, EPSS and exploitation" if not self.vi() else "Mức độ, EPSS và khai thác", "method")
        if self.vi():
            items = [
                "Mức độ là mức độ hiện tại trong TDxGuard: do scanner báo (với gói hệ điều hành là mức của bản tin "
                "distro, không phải CVSS), trừ khi một rule hoặc một người đã đổi nó.",
                "CVSS ghi kèm phiên bản (3.x hoặc 4.0). EPSS là xác suất bị khai thác trong 30 ngày tới (FIRST.org), "
                "kèm phân vị.",
                'KEV: lỗ hổng nằm trong danh mục đã bị khai thác thực tế (CISA KEV, VulnCheck KEV). "Exploit công '
                'khai": có PoC hoặc exploit công khai (PoC GitHub, Exploit-DB, Nuclei) nhưng không thuộc KEV.',
                "Phát hiện có mức Unknown là lỗ hổng mới chưa được chấm điểm.",
            ]
        else:
            items = [
                "Severity is the current severity in TDxGuard: as reported by the scanner (for operating system "
                "packages that is the distribution's advisory rating, not CVSS), unless a rule or a person changed it.",
                "CVSS is shown with its version (3.x or 4.0). EPSS is the probability of exploitation in the next 30 "
                "days (FIRST.org), with its percentile.",
                "KEV: listed in a catalogue of vulnerabilities exploited in the wild (CISA KEV, VulnCheck KEV). "
                '"Exploit public": a proof of concept or exploit is published (PoC GitHub, Exploit-DB, Nuclei) but '
                "the vulnerability is not KEV-listed.",
                "Findings with severity Unknown are recent vulnerabilities that have not been scored yet.",
            ]
        doc.ul(items)

    # -- 3.. findings --

    def _sca(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_sca"), "sca", number, page_break=True)
        groups = self.by_kind.get(SCA) or []
        if not self._ran_or_empty(doc, groups, (SCA, IMAGE)):
            return
        shown = [g for g in groups if g.severity in ("Critical", "High")]
        shown.sort(key=lambda g: g.rank_key())
        shown = shown[: self.args.top]
        intro = (
            f"{len(groups)} distinct vulnerabilities ({sum(g.count for g in groups)} observations). The "
            f"{len(shown)} most important Critical and High ones are described below; appendix A lists "
            + (
                "every one."
                if self._appendix_min_rank() >= SEVERITY_RANK["Unknown"]
                else f"all with severity {self.args.appendix_severity} or higher."
            )
            if not self.vi()
            else f"{len(groups)} lỗ hổng không trùng lặp ({sum(g.count for g in groups)} bản ghi). {len(shown)} lỗ "
            f"hổng "
            "Critical và High quan trọng nhất được mô tả dưới đây; phụ lục A liệt kê "
            + (
                "toàn bộ."
                if self._appendix_min_rank() >= SEVERITY_RANK["Unknown"]
                else f"toàn bộ lỗ hổng từ mức {self.args.appendix_severity} trở lên."
            )
        )
        doc.p(intro)
        rows = []
        for group in shown:
            title = [self.obs_link(group.link_id, ("b", group.ident)), " — ", group.source_package or group.title]
            if group.description:
                title += [("br",), ("small", short_text(group.description, 240))]
            packages = ", ".join(group.packages[:3]) + (
                f" +{len(group.packages) - 3} {self.t('more')}" if len(group.packages) > 3 else ""
            )
            where = [("small", packages)]
            if group.images:
                where += [("br",), ("small", ("image " if not self.vi() else "image ") + ", ".join(group.images))]
            if group.fixes:
                fix = [("tag", "fix", "fix"), " ", ("small", "; ".join(f"{p} → {v}" for p, v in group.fixes[:4]))]
            else:
                fix = self._fix_cell(group)
            severity = [("chip", group.severity)]
            if group.severity_source != "scanner":
                severity += [("br",), ("small", group.severity_source)]
            rows.append(
                [
                    title,
                    severity,
                    where,
                    fix,
                    self._exploit_cell(group),
                    str(group.age_days(self.now)) if group.first_seen else "—",
                    str(group.count),
                ]
            )
        doc.table(
            [
                self.t("vulnerability"),
                self.t("severity"),
                self.t("where"),
                self.t("fix"),
                self.t("exploit"),
                self.t("age"),
                "Obs.",
            ],
            rows,
            cls="findings",
            numeric=(5, 6),
        )

    def _ran_or_empty(self, doc: Doc, groups: list, kinds: tuple) -> bool:
        if groups:
            return True
        ran = any(kind in self.kinds_run for kind in kinds)
        if ran:
            doc.p("No open findings." if not self.vi() else "Không có phát hiện đang mở.")
        else:
            doc.p(
                ("tag", self.t("not_performed"), "missing"),
                " ",
                (
                    "No test of this kind ran for this scope, so this report makes no statement about it."
                    if not self.vi()
                    else "Không có kiểm thử loại này trong phạm vi, nên báo cáo không kết luận gì về nó."
                ),
            )
        return False

    def _rule_table(self, doc: Doc, groups: list, with_cwe: bool = True, with_locations: bool = True) -> None:
        rows = []
        for group in groups[: self.args.top_rules]:
            cell = [self.obs_link(group.link_id, ("code", group.title))]
            if group.description and group.description.strip(" .") != group.title.strip(" ."):
                cell += [" ", ("small", "— " + short_text(group.description, 80))]
            if with_locations and group.locations:
                shown = group.locations[:2]
                rest = len(group.locations) - len(shown)
                cell += [("br",), ("small", ", ".join(shown) + (f" +{rest} {self.t('more')}" if rest > 0 else ""))]
            row = [cell, ("chip", group.severity)]
            if with_cwe:
                row.append(f"CWE-{group.cwe}" if group.cwe else "—")
            row.append(str(group.count))
            rows.append(row)
        headers = [self.t("rule"), self.t("severity")] + ([self.t("cwe")] if with_cwe else []) + [self.t("occurrences")]
        doc.table(headers, rows, cls="compact rules", numeric=(3 if with_cwe else 2,))
        rest = len(groups) - len(rows)
        if rest > 0:
            doc.p(f"+{rest} {self.t('more')} (CSV / dashboard).", cls="note")

    def _sast(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_sast"), "sast", number, page_break=True)
        groups = self.by_kind.get(SAST) or []
        if not self._ran_or_empty(doc, groups, (SAST,)):
            return
        doc.p(
            f"{len(groups)} rules matched {sum(g.count for g in groups)} times. One row per rule; the first files "
            "are listed, the dashboard has every occurrence."
            if not self.vi()
            else f"{len(groups)} rule khớp {sum(g.count for g in groups)} lần. Mỗi dòng một rule; liệt kê vài tệp đầu, "
            "dashboard có đầy đủ."
        )
        self._rule_table(doc, groups)

    def _secrets(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_secret"), "secret", number)
        groups = self.by_kind.get(SECRET) or []
        if not self._ran_or_empty(doc, groups, (SECRET,)):
            return
        doc.p(
            "Secret values are never printed in this report; rotate any secret listed here and remove it from the "
            "history of the repository."
            if not self.vi()
            else "Giá trị bí mật không bao giờ được in trong báo cáo; hãy thay mới mọi bí mật được liệt kê và xoá khỏi "
            "lịch sử repository."
        )
        self._rule_table(doc, groups, with_cwe=False)

    def _config(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_config"), "config", number)
        groups = self.by_kind.get(CONFIG) or []
        if not self._ran_or_empty(doc, groups, (CONFIG,)):
            return
        doc.p(
            "Configuration checks (Dockerfiles, Kubernetes manifests, infrastructure as code, container images). "
            "These are hardening issues rather than vulnerabilities with a CVE; there is no CVSS or EPSS."
            if not self.vi()
            else "Kiểm tra cấu hình (Dockerfile, manifest Kubernetes, IaC, container image). Đây là vấn đề hardening, "
            "không phải lỗ hổng có CVE; không có CVSS hay EPSS."
        )
        self._rule_table(doc, groups, with_cwe=False)

    def _dast(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_dast"), "dast", number)
        groups = (self.by_kind.get(DAST) or []) + (self.by_kind.get(IAST) or [])
        if not self._ran_or_empty(doc, groups, (DAST, IAST)):
            return
        self._rule_table(doc, groups)

    def _mobile(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_mobile"), "mobile", number)
        groups = self.by_kind.get(MOBILE) or []
        if not self._ran_or_empty(doc, groups, (MOBILE,)):
            return
        doc.p(
            "Static analysis of the mobile app by MobSF: its code, manifest or Info.plist, network security "
            "configuration, signing certificate and native binaries. The analysis of a built app covers its "
            "libraries too; the analysis of the source covers the project's own code only. Each finding names its "
            "OWASP MASVS control in its description. One row per rule."
            if not self.vi()
            else "Phân tích tĩnh ứng dụng di động bằng MobSF: mã, manifest hoặc Info.plist, cấu hình bảo mật mạng, "
            "chứng chỉ ký và các tệp nhị phân native. Phân tích bản đã build bao gồm cả thư viện; phân tích mã nguồn "
            "chỉ bao gồm mã của dự án. Mỗi phát hiện ghi control OWASP MASVS trong mô tả. Mỗi dòng một rule."
        )
        self._rule_table(doc, groups)

    def _other(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_other"), "other", number)
        self._rule_table(doc, self.by_kind.get(OTHER) or [])

    # -- decisions --

    def _decisions(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_decisions"), "decisions", number)

        doc.h(3, self.t("closed_status"), "closed")
        status_counts = Counter(o.get("current_status") for o in self.decided)
        by_rule = Counter(
            o.get("current_status") for o in self.decided if o.get("rule_status") or o.get("rule_rego_status")
        )
        by_person = Counter(o.get("current_status") for o in self.decided if o.get("assessment_status"))
        by_vex = Counter(o.get("current_status") for o in self.decided if o.get("vex_status"))
        rows = [
            [
                STATUS_RESOLVED,
                str(self.data.get("resolved_count", 0)),
                (
                    "No longer reported by the latest scan of its check (or closed by a person)."
                    if not self.vi()
                    else "Không còn trong lần quét gần nhất của check (hoặc được đóng thủ công)."
                ),
            ]
        ]
        for status in DECIDED_STATUSES:
            n = status_counts.get(status, 0)
            if not n:
                continue
            parts = []
            if by_rule.get(status):
                parts.append(f"{by_rule[status]} " + ("by rule" if not self.vi() else "do rule"))
            if by_person.get(status):
                parts.append(f"{by_person[status]} " + ("by a person" if not self.vi() else "do con người"))
            if by_vex.get(status):
                parts.append(f"{by_vex[status]} by VEX")
            rows.append([status, str(n), ", ".join(parts) or "—"])
        doc.table([self.t("status"), self.t("count"), self.t("reason")], rows, numeric=(1,))

        doc.h(3, self.t("human_decisions"), "human-decisions")
        self._human_decisions(doc)

        doc.h(3, self.t("rule_decisions"), "rule-decisions")
        self._rule_decisions(doc)

        doc.h(3, self.t("accepted_risks"), "accepted-risks")
        accepted = [o for o in self.decided if o.get("current_status") == "Risk accepted"]
        if accepted:
            rows = []
            for o in sorted(accepted, key=lambda o: o.get("risk_acceptance_expiry_date") or "9999"):
                rows.append(
                    [
                        self.obs_link(o.get("id"), o.get("title") or "—"),
                        ("chip", o.get("current_severity") or "Unknown"),
                        o.get("risk_acceptance_expiry_date") or ("no expiry" if not self.vi() else "không hạn"),
                    ]
                )
            doc.table([self.t("finding"), self.t("severity"), self.t("expiry")], rows)
        else:
            doc.p(self.t("none"))

    def _human_decisions(self, doc: Doc) -> None:
        mode = self.data.get("logs_mode")
        warnings = [w for w in self.data.get("warnings", []) if w.startswith("log_scan_capped")]
        if not self.human_logs:
            doc.p(
                "No finding in this scope has been assessed by a person. Open findings are as the scanners "
                "reported them; closed ones were closed by a rescan or a rule (below)."
                if not self.vi()
                else "Chưa có phát hiện nào trong phạm vi này được con người đánh giá. Phát hiện đang mở giữ nguyên "
                "như "
                "scanner báo; phát hiện đã đóng là do lần quét lại hoặc do rule (bên dưới)."
            )
        else:
            rows = []
            for entry in self.human_logs[: self.args.max_log]:
                observation = entry.get("observation_data") or {}
                decision = (
                    " / ".join(
                        filter(
                            None,
                            [
                                entry.get("status"),
                                entry.get("severity"),
                                f"priority {entry['priority']}" if entry.get("priority") else None,
                                entry.get("vex_justification"),
                            ],
                        )
                    )
                    or "comment"
                )
                finding = [
                    self.obs_link(observation.get("id") or entry.get("observation"), observation.get("title") or "—")
                ]
                where = observation.get("origin_component_name_version") or observation.get("origin_source_file")
                if where:
                    finding += [("br",), ("small", where)]
                rows.append(
                    [
                        fmt_time(entry.get("created")),
                        finding,
                        decision,
                        entry.get("user_full_name") or str(entry.get("user") or "—"),
                        short_text(entry.get("comment") or "—", 900),
                    ]
                )
            doc.table(
                [self.t("date"), self.t("finding"), self.t("decision"), self.t("by"), self.t("justification")],
                rows,
                cls="compact",
            )
            if len(self.human_logs) > len(rows):
                doc.p(f"+{len(self.human_logs) - len(rows)} {self.t('more')} (--max-log).", cls="note")
        if mode == "fallback" or warnings:
            doc.p(
                (
                    "The server does not offer the automated=false filter on observation logs: decisions were "
                    "collected "
                    "from all entries with a decision status, plus the most recent entries "
                    + (
                        f"(the newest {warnings[0].split(':')[1]} of {warnings[0].split(':')[2]}); "
                        "a decision that changed only the severity or priority before that may be missing."
                        if warnings
                        else "(all of them)."
                    )
                    if not self.vi()
                    else "Server chưa có bộ lọc automated=false cho observation log: quyết định được lấy từ mọi entry "
                    "có "
                    "trạng thái quyết định, cộng các entry gần nhất"
                    + (
                        f" ({warnings[0].split(':')[1]} / {warnings[0].split(':')[2]}); quyết định chỉ đổi mức độ hoặc "
                        "priority trước đó có thể bị thiếu."
                        if warnings
                        else " (toàn bộ)."
                    )
                ),
                cls="note warning",
            )

    def _rule_decisions(self, doc: Doc) -> None:
        rules = self.data.get("rules") or {}
        closed: dict = defaultdict(lambda: Counter())
        severity_changes: dict = defaultdict(lambda: Counter())
        for o in self.decided:
            for field_name, endpoint in (("product_rule", "product_rules"), ("general_rule", "general_rules")):
                if o.get(field_name) and (o.get("rule_status") or o.get("rule_rego_status")):
                    closed[f"{endpoint}:{o[field_name]}"][o.get("current_status")] += 1
                    break
        for o in self.active:
            for field_name, endpoint in (("product_rule", "product_rules"), ("general_rule", "general_rules")):
                if o.get(field_name) and (o.get("rule_severity") or o.get("rule_status")):
                    severity_changes[f"{endpoint}:{o[field_name]}"][o.get("rule_severity") or o.get("rule_status")] += 1
                    break
        if not closed and not severity_changes:
            doc.p(
                "No rule changed the status or severity of a finding in this scope."
                if not self.vi()
                else "Không có rule nào đổi trạng thái hay mức độ của phát hiện trong phạm vi này."
            )
            return
        rows = []
        for key, counts in list(closed.items()) + list(severity_changes.items()):
            rule = rules.get(key) or {"name": key}
            kind = "general" if key.startswith("general") else "product"
            rows.append(
                [
                    [("b", rule.get("name") or key), ("br",), ("small", f"{kind} rule")],
                    ", ".join(f"{status} ({n})" for status, n in counts.items()),
                    str(sum(counts.values())),
                    short_text(rule.get("description") or "—", 900),
                ]
            )
        doc.table([self.t("rule"), self.t("new_status"), self.t("observations"), self.t("reason")], rows, numeric=(2,))
        doc.p(
            (
                "A rule applies the same decision to every matching finding; its reason is recorded once on the rule."
                if not self.vi()
                else "Một rule áp dụng cùng một quyết định cho mọi phát hiện khớp; lý do được ghi một lần " "trên rule."
            ),
            cls="note",
        )

    # -- controls --

    def _controls(self, doc: Doc, number: str) -> None:
        doc.h(2, self.t("s_controls"), "controls", number)
        doc.p(
            'What the evidence in this report supports, control by control. A control is "evidenced" only when '
            "the matching test ran; everything not evidenced is stated. Technical controls only — policies, the risk "
            "register and people-and-process controls are out of scope."
            if not self.vi()
            else 'Bằng chứng trong báo cáo hỗ trợ control nào. Một control chỉ "có bằng chứng" khi kiểm thử tương ứng '
            "đã chạy; những gì không có bằng chứng đều được nêu rõ. Chỉ gồm control kỹ thuật."
        )
        stale_days = None
        lasts = [parse_time(c.get("last_import")) for c in self.data.get("checks") or []]
        lasts = [x for x in lasts if x]
        if lasts:
            stale_days = (self.now - max(lasts)).days
        rule_decisions = sum(1 for o in self.decided if o.get("rule_status") or o.get("rule_rego_status"))
        rows = []
        decisions_section = self.section_numbers.get("decisions", "")
        for control, key, status, evidence, missing in evaluate_controls(
            self.kinds_run,
            len(self.human_logs),
            rule_decisions,
            stale_days,
            self.gate,
            self.args.gate_enforced,
            bool(self.branch),
        ):
            tag_class = {"evidenced": "ok", "partial": "partial", "not_evidenced": "missing"}[status]
            rows.append(
                [
                    [("b", control), ("br",), self.ct(key)],
                    ("tag", self.t(status), tag_class),
                    " ".join(
                        self.ct(e).format(decisions=decisions_section, sca=self.section_numbers.get("sca", ""))
                        for e in evidence
                    )
                    or "—",
                    " ".join(self.ct(m) for m in missing) or "—",
                ]
            )
        doc.table([self.t("control"), self.t("assessment"), self.t("evidence"), self.t("missing")], rows)

    # -- standards mapping --

    def st(self, key: str) -> str:
        return STANDARD_TEXT[self.lang].get(key, STANDARD_TEXT["en"].get(key, ""))

    def standard_statuses(self) -> list:
        gate_active = self.gate.get("source") in ("product", "product_group", "settings")
        return [evaluate_standard_control(control, self.kinds_run, gate_active) for control in STANDARD_CONTROLS]

    def _standards(self, doc: Doc, number: str) -> None:
        doc.h(2, self.st("s_standards"), "standards", number, page_break=True)
        doc.p(self.st("intro"))
        doc.p(self.st("legend").format(scope=self.section_numbers.get("scope", "")), cls="note")
        statuses = self.standard_statuses()
        missing_kinds: set = set()
        for standard, name in STANDARDS:
            doc.h(3, name, f"std-{standard}")
            rows = [self._standard_row(s) for s in statuses if s.control.standard == standard]
            doc.table(
                [
                    self.st("control"),
                    self.st("status"),
                    self.st("evidence_from"),
                    self.st("missing"),
                    self.st("findings"),
                ],
                rows,
                cls="standards",
            )
            if standard == OWASP:
                doc.p(self.st("cwe_note"), cls="note")
            if standard == SSDF and MOBILE in self.kinds_run:
                doc.p(self.st("mobile_note"), cls="note")
        for s in statuses:
            for alternatives in s.missing:
                missing_kinds |= alternatives
        hints = [self.t(f"enable_{kind}") for kind in self.test_kinds() if kind in missing_kinds]
        if hints:
            doc.h(4, self.st("how_to_enable"), "std-enable", toc=False)
            doc.ul(hints)

    def _standard_row(self, s: StandardStatus) -> list:
        control = s.control
        title: list = [("b", control.ident), " ", control.title]
        if self.vi() and self.st(f"t_{control.key}"):
            title += [("br",), ("small", self.st(f"t_{control.key}"))]
        tag_class = {STD_EVIDENCE: "ok", STD_PARTIAL: "partial", STD_NONE: "missing"}[s.status]
        evidence = [self.st(f"kind_{kind}") for kind in s.ran]
        if control.needs_gate and not s.gate_missing:
            evidence.append(self.st("gate_ok"))
        missing: list = []
        for alternatives in s.missing:
            names = [self.st(f"kind_{kind}") for kind in self.test_kinds() if kind in alternatives]
            missing.append(f" {self.st('or')} ".join(names))
        if s.gate_missing:
            missing.append(self.st("gate_missing"))
        cell: list = []
        for item in missing:
            cell += ([("br",)] if cell else []) + [item]
        if control.needs_manual:
            if not control.requires:
                label = self.st("manual_only")
            else:
                label = self.st("manual_process") if control.process else self.st("manual")
            note = self.st(f"m_{control.key}")
            cell += ([("br",)] if cell else []) + [("b", label + (":" if note else ""))]
            if note:
                cell += [" ", ("small", note)]
        return [
            title,
            ("tag", self.st(f"status_{s.status}"), tag_class),
            ", ".join(evidence) or "—",
            cell or "—",
            self._standard_findings(control),
        ]

    def _standard_findings(self, control: StandardControl) -> Any:
        if not control.count_kinds and not control.cwes:
            return "—"
        tested = set(control.count_kinds) | (set(CWE_KINDS) if control.cwes else set())
        if SCA in tested:
            tested.add(IMAGE)
        if not tested & self.kinds_run:
            return ("small", self.st("not_tested"))
        groups = related_groups(control, self.groups)
        if not groups:
            return "0"
        counts = Counter(g.severity for g in groups)
        parts = [f"{severity} {counts[severity]}" for severity in ("Critical", "High") if counts.get(severity)]
        kev = sum(1 for g in groups if g.kev)
        if kev:
            parts.append(f"KEV {kev}")
        cell: list = [("b", str(len(groups)))]
        for part in parts:
            cell += [("br",), ("small", part)]
        return cell

    # -- appendices --

    def _appendix_min_rank(self) -> int:
        return SEVERITY_RANK.get(self.args.appendix_severity, SEVERITY_RANK["Unknown"])

    def _appendix_a(self, doc: Doc, label: str) -> None:
        doc.h(2, self.t("s_appendix_a"), "appendix-a", page_break=True)
        min_rank = self._appendix_min_rank()
        groups = [g for g in self.by_kind.get(SCA) or [] if SEVERITY_RANK.get(g.severity, 99) <= min_rank]
        left_out = [g for g in self.by_kind.get(SCA) or [] if SEVERITY_RANK.get(g.severity, 99) > min_rank]
        groups.sort(key=lambda g: (SEVERITY_RANK.get(g.severity, 99), g.rank_key()))
        if not groups:
            doc.p(self.t("none"))
        else:
            rows = []
            for group in groups:
                packages = group.source_package or (group.packages[0] if group.packages else "")
                if len(group.packages) > 1:
                    packages += f" (+{len(group.packages) - 1})"
                versions = sorted(
                    {o.get("origin_component_version") for o in group.observations if o.get("origin_component_version")}
                )
                rows.append(
                    [
                        self.obs_link(group.link_id, group.ident),
                        ("chip", group.severity),
                        packages + (f" {versions[0]}" if len(versions) == 1 else ""),
                        ", ".join(group.images) or "app",
                        ", ".join(sorted({v for _, v in group.fixes})[:2]) or ("yes" if group.fixable else "—"),
                        ("KEV" if group.kev else "PoC" if group.exploit_public else "")
                        + (f" {group.epss:.1f}%" if group.epss is not None else ""),
                        str(group.count),
                    ]
                )
            doc.table(
                [
                    self.t("vulnerability"),
                    self.t("severity"),
                    "Package",
                    self.t("image"),
                    self.t("fix"),
                    "Expl./EPSS",
                    "Obs.",
                ],
                rows,
                cls="compact appendix",
                numeric=(6,),
            )
        if left_out:
            counts = Counter(g.severity for g in left_out)
            listing = ", ".join(f"{s} {counts[s]}" for s in SEVERITY_ORDER if counts.get(s))
            doc.p(
                (
                    f"Not listed here: {listing} distinct vulnerabilities below {self.args.appendix_severity}"
                    + (
                        f"; all of them are in {Path(self.args.csv).name}."
                        if self.args.csv
                        else "; run with --appendix-severity Low or --csv to include them."
                    )
                    if not self.vi()
                    else f"Không liệt kê ở đây: {listing} lỗ hổng dưới mức {self.args.appendix_severity}"
                    + (
                        f"; toàn bộ có trong {Path(self.args.csv).name}."
                        if self.args.csv
                        else "; dùng --appendix-severity Low hoặc --csv để đưa vào."
                    )
                ),
                cls="note",
            )

    def _appendix_b(self, doc: Doc, label: str) -> None:
        doc.h(2, self.t("s_appendix_b"), "appendix-b", page_break=True)
        doc.p(
            "Findings of container images the latest scan of that image no longer reported (older image builds). "
            "They are open in TDxGuard but not counted in this report."
            if not self.vi()
            else "Phát hiện của các bản build image cũ mà lần quét gần nhất không còn thấy. Chúng vẫn mở trong "
            "TDxGuard nhưng không được tính trong báo cáo."
        )
        rows = []
        for group in sorted(self.superseded_groups, key=lambda g: (SEVERITY_RANK.get(g.severity, 99), g.ident)):
            tags = sorted({image_tag(o)[:12] for o in group.observations if image_tag(o)})
            rows.append(
                [
                    self.obs_link(group.link_id, group.ident),
                    ("chip", group.severity),
                    ", ".join(group.images),
                    ", ".join(tags),
                    str(group.count),
                ]
            )
        doc.table(
            [self.t("vulnerability"), self.t("severity"), self.t("image"), "Tag", "Obs."],
            rows,
            cls="compact",
            numeric=(4,),
        )

    def _appendix_c(self, doc: Doc, label: str) -> None:
        doc.h(2, self.t("s_appendix_c"), "appendix-c")
        if self.vi():
            items = [
                "Nguồn dữ liệu: API của TDxGuard (observations, vulnerability_checks, observation_logs, rules, "
                "settings, product_metrics). Thời gian quy về UTC.",
                "Gộp: một lỗ hổng là một CVE (hoặc ID advisory) trong một gói nguồn; các gói nhị phân của cùng gói "
                "nguồn hệ điều hành (cùng phiên bản) được gộp. SAST, bí mật, cấu hình, ứng dụng di động: gộp theo rule.",
                "Đánh giá tổng thể: " + self._verdict_rule_text(),
                "Xếp hạng rủi ro: KEV có bản vá, KEV, EPSS, mức độ, CVSS.",
                'Quyết định của con người: log entry không phải do importer ghi ("Set by parser", "Updated by '
                'parser", "Observation not found in latest scan") và không do rule.',
                "SLA mặc định (ngày): " + ", ".join(f"{k} {v}" for k, v in self.sla.items()) + " (--sla).",
            ]
        else:
            items = [
                "Data: the TDxGuard API (observations, vulnerability_checks, observation_logs, rules, settings, "
                "product metrics). All times are converted to UTC.",
                "Grouping: a vulnerability is one CVE (or advisory ID) in one source package; binary packages of one "
                "operating system source package (same version) are merged. SAST, secrets, configuration and mobile "
                "app findings: one entry per rule.",
                "Overall assessment: " + self._verdict_rule_text(),
                "Risk ranking: KEV with a fix, KEV, EPSS, severity, CVSS.",
                'Decisions by people: log entries not written by the importer ("Set by parser", "Updated by '
                'parser", "Observation not found in latest scan") and not written by a rule.',
                "Default SLA (days): " + ", ".join(f"{k} {v}" for k, v in self.sla.items()) + " (--sla).",
            ]
        doc.ul(items)

    # -- CSV --

    def csv_rows(self) -> list:
        rows = [
            [
                "kind",
                "id",
                "title",
                "severity",
                "source_package",
                "packages",
                "images",
                "locations",
                "fixed_in",
                "fixable",
                "kev",
                "exploit_sources",
                "epss_percent",
                "epss_percentile",
                "cvss",
                "cvss_version",
                "cwe",
                "observations",
                "first_seen_utc",
                "age_days",
                "link",
            ]
        ]
        for group in sorted(
            self.groups, key=lambda g: (FINDING_KINDS.index(g.kind), SEVERITY_RANK.get(g.severity, 99), g.rank_key())
        ):
            rows.append(
                [
                    group.kind,
                    group.ident,
                    group.title,
                    group.severity,
                    group.source_package,
                    " ".join(group.packages),
                    " ".join(group.images),
                    " ".join(group.locations[:50]),
                    " ".join(f"{p}={v}" for p, v in group.fixes),
                    "yes" if group.fixable else "no",
                    "yes" if group.kev else "no",
                    "; ".join(group.exploit_sources),
                    "" if group.epss is None else f"{group.epss:.3f}",
                    "" if group.epss_percentile is None else f"{group.epss_percentile:.1f}",
                    "" if group.cvss is None else f"{group.cvss:g}",
                    group.cvss_version,
                    group.cwe or "",
                    group.count,
                    fmt_time(group.first_seen),
                    group.age_days(self.now) if group.first_seen else "",
                    f"{self.ui}/observations/{group.link_id}/show" if self.ui else group.link_id,
                ]
            )
        return rows


def parse_sla(text: str) -> dict:
    result = {}
    for part in (text or "").split(","):
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip().capitalize()
            if key in SEVERITY_RANK and value.strip().isdigit():
                result[key] = int(value.strip())
    return result


def image_source(value: str) -> str:
    """A logo as something an <img> can show: URLs as they are, local files embedded."""
    if not value:
        return ""
    if re.match(r"^(https?:|data:)", value):
        return value
    path = Path(value)
    if not path.is_file():
        print(f"WARNING: logo {value} not found, left out", file=sys.stderr)
        return ""
    mime = mimetypes.guess_type(path.name)[0] or "image/png"
    return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")


# --- command line -----------------------------------------------------------------------------


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.getenv("TDXGUARD_URL") or os.getenv("SECOBSERVE_URL"))
    parser.add_argument("--token", default=os.getenv("TDXGUARD_API_TOKEN") or os.getenv("SECOBSERVE_API_TOKEN"))
    parser.add_argument(
        "--ui-url", default=os.getenv("TDXGUARD_UI_URL", ""), help="dashboard URL, to link each finding back to it"
    )
    parser.add_argument("--product", help="product name in TDxGuard")
    parser.add_argument("--branch", default="", help="branch to report on (default: the product's default branch)")
    parser.add_argument("--all-branches", action="store_true", help="report on all branches together")
    parser.add_argument("--title", default="", help="document title (default depends on --lang)")
    parser.add_argument("--scope", default="", help="additional scope statement")
    parser.add_argument(
        "--tester", "--prepared-by", dest="tester", default="TDA security team", help="who prepared the report"
    )
    parser.add_argument("--prepared-for", default="", help="recipient, e.g. the customer's security team")
    parser.add_argument(
        "--classification",
        default="Confidential",
        help="confidentiality marking on the cover and every page ('' for none)",
    )
    parser.add_argument("--doc-id", default="", help="document identifier (default SAR-<product>-<date>)")
    parser.add_argument("--doc-version", default="1.0", help="document version")
    parser.add_argument("--commit", default="", help="commit SHA assessed (default: derived from image tags)")
    parser.add_argument("--logo", default="", help="own logo for the cover (file or URL)")
    parser.add_argument("--customer-logo", default="", help="customer logo for the cover (file or URL)")
    parser.add_argument("--lang", choices=sorted(STRINGS), default="en", help="language of headings and labels")
    parser.add_argument(
        "--period-days",
        type=int,
        choices=sorted(PERIOD_AGES),
        default=30,
        help="reporting period for changes and trend",
    )
    parser.add_argument("--sla", default="", help="SLA days per severity, e.g. Critical=7,High=30,Medium=90,Low=180")
    parser.add_argument("--top-risks", type=int, default=10, help="rows in the executive summary's top risks")
    parser.add_argument("--top", type=int, default=15, help="vulnerabilities described in detail in the SCA section")
    parser.add_argument("--top-rules", type=int, default=60, help="rows per SAST / secret / configuration table")
    parser.add_argument(
        "--appendix-severity",
        choices=SEVERITY_ORDER,
        default="High",
        help="lowest severity listed in appendix A (the CSV always has everything)",
    )
    parser.add_argument(
        "--gate-enforced",
        action="store_true",
        help="state that the pipeline blocks changes when the security gate fails",
    )
    parser.add_argument("--max-log", type=int, default=50, help="human decisions listed")
    parser.add_argument(
        "--max-log-scan", type=int, default=3000, help="log entries scanned when the server lacks the automated filter"
    )
    parser.add_argument(
        "--format",
        choices=["md", "html", "both"],
        default="",
        help="outputs to write (default: md, plus html when --html is given)",
    )
    parser.add_argument("--out", default="report.md", help="Markdown output")
    parser.add_argument("--html", default="", help="HTML output (print it to PDF)")
    parser.add_argument("--csv", default="", help="also write every finding group as CSV")
    parser.add_argument("--save-data", default="", help="save the fetched API data as JSON (for --from-data)")
    parser.add_argument("--from-data", default="", help="render from data saved with --save-data, without the API")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    if not args.from_data:
        if not args.product:
            parser.error("--product is required")
        if not args.url or not args.token:
            parser.error("missing --url/--token (or TDXGUARD_URL / TDXGUARD_API_TOKEN)")
    if not args.format:
        args.format = "both" if args.html else "md"
    if args.format in ("html", "both") and not args.html:
        args.html = str(Path(args.out).with_suffix(".html"))
    return args


def write_outputs(report: Report, args: argparse.Namespace, log: Callable[[str], None]) -> None:
    doc = report.build()
    title = args.title or report.t("title")
    if args.format in ("md", "both"):
        Path(args.out).write_text(render_markdown(doc), encoding="utf-8")
        log(f"wrote {args.out}")
    if args.format in ("html", "both"):
        footer = " · ".join(filter(None, [args.classification, report.product.get("name"), title]))
        Path(args.html).write_text(html_document(title, render_html_body(doc), footer, report.lang), encoding="utf-8")
        log(f"wrote {args.html} — open it and print to PDF")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as handle:
            csv.writer(handle).writerows(report.csv_rows())
        log(f"wrote {args.csv}")


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    started = time.monotonic()

    def log(message: str) -> None:
        if not args.quiet:
            print(f"[{time.monotonic() - started:6.1f}s] {message}", file=sys.stderr)

    if args.from_data:
        data = json.loads(Path(args.from_data).read_text(encoding="utf-8"))
    else:
        api = Api(args.url, args.token)
        try:
            data = fetch_data(api, args, log)
        except ApiError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        log(f"fetched in {api.requests} requests")
        if args.save_data:
            Path(args.save_data).write_text(json.dumps(data), encoding="utf-8")
    for warning in data.get("warnings", []):
        if warning.startswith("log_scan_capped"):
            _, cap, total = warning.split(":")
            print(
                f"WARNING: the server has no automated=false log filter; scanned the newest {cap} of {total} log "
                "entries plus all entries with a decision status",
                file=sys.stderr,
            )
        elif warning == "settings_unreadable":
            print(
                "WARNING: global settings not readable with this token; gate thresholds may be unknown", file=sys.stderr
            )
    report = Report(data, args)
    write_outputs(report, args, log)
    log(
        f"{len(report.active)} open observations -> {len(report.groups)} distinct findings; "
        f"verdict: {report.verdict.level}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
