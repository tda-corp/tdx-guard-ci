"""
`tdxguard report`: the security assessment report of a product, as HTML and PDF.

The data and the document come from compliance_report.py, a byte-identical copy of
ci-templates/compliance-report.py (the generator CI and the backend run as a script).
tests/test_assessment.py fails when the two differ: after changing the script, copy it here
(`cp ci-templates/compliance-report.py cli/tdxguard/assessment/compliance_report.py`).

This module only adapts it to the CLI: the API calls go through tdxguard.http (CA bundles,
proxies and the CLI's error types) with the stored credentials, and its progress goes to the UI.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional

from tdxguard import http
from tdxguard.assessment import compliance_report as generator
from tdxguard.credentials import Credentials
from tdxguard.errors import ApiError, AuthenticationError, CLIError

# One request may return 1000 observations, which takes a while on a large product.
REQUEST_TIMEOUT = 300
LANGUAGES = sorted(generator.STRINGS)
PERIODS = sorted(generator.PERIOD_AGES)


class Api(generator.Api):
    """The generator's API client, on the CLI's HTTP client and credentials."""

    def __init__(self, credentials: Credentials, timeout: int = REQUEST_TIMEOUT):
        super().__init__(credentials.api, credentials.token, timeout)

    def get(self, path: str, params: Optional[list] = None) -> Any:
        # The generator's paths start with /api/; the credentials know where the API lives.
        relative = path[len("/api") :] if path.startswith("/api/") else path
        query = "?" + urllib.parse.urlencode(params, doseq=True) if params else ""
        self.requests += 1
        response = http.get(f"{self.url}{relative}{query}", {"Authorization": f"APIToken {self.token}"}, self.timeout)
        if response.status == 401:
            raise AuthenticationError()
        if not response.ok:
            # The generator's own error: it skips optional data (settings, metrics) on it.
            raise generator.ApiError(f"GET {path} -> HTTP {response.status}: {response.text(200)}")
        data = response.json()
        if data is None:
            raise generator.ApiError(f"GET {path} -> not JSON: {response.text(200)}")
        return data


@dataclass
class Options:
    product: str = ""
    branch: str = ""
    all_branches: bool = False
    lang: str = "vi"
    period_days: int = 30
    prepared_for: str = ""
    prepared_by: str = ""
    classification: Optional[str] = None
    title: str = ""
    ui_url: str = ""

    def generator_args(self) -> argparse.Namespace:
        """The generator's own argument parser fills in every default it has."""
        argv = ["--from-data", "-", "--lang", self.lang, "--period-days", str(self.period_days)]
        for flag, value in (
            ("--product", self.product),
            ("--branch", self.branch),
            ("--prepared-for", self.prepared_for),
            ("--prepared-by", self.prepared_by),
            ("--title", self.title),
            ("--ui-url", self.ui_url),
        ):
            if value:
                argv += [flag, value]
        if self.classification is not None:
            argv += ["--classification", self.classification]
        if self.all_branches:
            argv.append("--all-branches")
        args = generator.parse_args(argv)
        args.from_data = ""
        return args


def fetch(credentials: Credentials, options: Options, log: Callable[[str], None]) -> dict:
    """Everything the report needs, from the API, with the user's permissions."""
    api = Api(credentials)
    try:
        data = generator.fetch_data(api, options.generator_args(), log)
    except generator.ApiError as error:
        message = str(error)
        if message.startswith("Branch") and "not found" in message:
            raise ApiError(
                message + ".", hint="Check the name; without --branch the report covers the default branch."
            ) from error
        if "not found" in message:
            raise ApiError(
                message + ".",
                hint="Check the name (`tdxguard report --product NAME`); you see only the products you are a "
                "member of.",
            ) from error
        raise ApiError(f"Reading the findings failed: {message}") from error
    data["requests"] = api.requests
    return data


def load_data(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise CLIError(f"Cannot read {path}: {error.strerror or error}") from error
    except ValueError as error:
        raise CLIError(f"{path} is not report data saved with --save-data: {error}") from error
    if not isinstance(data, dict) or not isinstance(data.get("product"), dict):
        raise CLIError(f"{path} is not report data saved with --save-data.")
    return data


WARNINGS = {
    "settings_unreadable": "The global settings are not readable with your token; the gate thresholds may be unknown.",
}


def warnings_of(data: dict) -> List[str]:
    """The generator's warnings about incomplete data, as sentences."""
    result = []
    for warning in data.get("warnings") or []:
        if str(warning).startswith("log_scan_capped"):
            _, cap, total = str(warning).split(":")
            result.append(
                f"The server has no filter for automated log entries; the newest {cap} of {total} entries were "
                "searched for decisions, plus every entry with a decision status."
            )
        else:
            result.append(WARNINGS.get(warning, str(warning)))
    return result


VERDICTS = {"action": "action required", "attention": "attention needed", "acceptable": "acceptable"}


@dataclass
class Written:
    html: Path
    markdown: Optional[Path] = None
    csv: Optional[Path] = None
    verdict: str = ""
    findings: int = 0
    observations: int = 0


def render(data: dict, options: Options, base: Path, markdown: bool = False, csv: bool = False) -> Written:
    """Writes <base>.html (and .md, .csv), the way the generator's --format both does."""
    args = options.generator_args()
    args.format = "both" if markdown else "html"
    args.html = str(base.with_name(base.name + ".html"))
    args.out = str(base.with_name(base.name + ".md"))
    args.csv = str(base.with_name(base.name + ".csv")) if csv else ""
    report = generator.Report(data, args)
    try:
        generator.write_outputs(report, args, lambda message: None)
    except OSError as error:
        raise CLIError(f"Cannot write the report: {error}") from error
    return Written(
        html=Path(args.html),
        markdown=Path(args.out) if markdown else None,
        csv=Path(args.csv) if csv else None,
        verdict=VERDICTS.get(report.verdict.level, report.verdict.level),
        findings=len(report.groups),
        observations=len(report.active),
    )


def default_base(product: str, lang: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", product).strip("-.") or "product"
    return f"{slug}-security-report-{lang}"


def output_base(out: Optional[str], product: str, lang: str) -> Path:
    """--out report, report.html or report.pdf all mean report.html and report.pdf."""
    if not out:
        return Path(default_base(product, lang))
    path = Path(out)
    if out.endswith(("/", "\\")) or path.is_dir():
        return path / default_base(product, lang)
    if path.suffix.lower() in (".html", ".htm", ".pdf", ".md"):
        path = path.with_suffix("")
    return path


class Stopwatch:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.started = clock()

    def seconds(self) -> float:
        return self.clock() - self.started

    def text(self) -> str:
        return format_seconds(self.seconds())


def format_seconds(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} s"
    return f"{int(seconds // 60)} min {int(seconds % 60)} s"
