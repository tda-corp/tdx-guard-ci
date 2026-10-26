"""
DAST on a running application: ZAP, and optionally Nuclei, in Docker against a URL the developer
started (`dast:` in .tdxguard.yml, or `tdxguard scan --dast URL`).

The same scans as the runtime job of ci-templates/github/tdxguard.yml, with the same images:

- ZAP's baseline scan (passive) or full scan (active), or its API scan of an OpenAPI definition
  when `api` is set (passive with -S unless the mode is full).
- Signed in when `auth_command` prints a header value: ZAP reads ZAP_AUTH_HEADER,
  ZAP_AUTH_HEADER_VALUE and ZAP_AUTH_HEADER_SITE from its environment and adds the header to
  every request to the target's host only. The value is passed to `docker create -e NAME`, never
  on a command line.
- /zap/wrk is copied into the container before ZAP starts: the image does not create it, and
  with -J and no /zap/wrk the scan scripts exit 3 before scanning anything.

The application runs on this machine, outside Docker. ZAP's container reaches a `localhost`
target through the host network on Linux, and through host.docker.internal on macOS and
Windows, where Docker runs in a VM and the host network is the VM's.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# The images of the CI templates (a test fails when they differ).
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:2.17.0"
NUCLEI_IMAGE = "projectdiscovery/nuclei:v3.11.1"
# Nuclei downloads its templates on the first run (about a minute); the volume keeps them.
NUCLEI_VOLUME = "tdxguard-nuclei"
MODES = ("baseline", "full")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # nosec B104
ZAP_REPORT = "zap.json"
NUCLEI_REPORT = "nuclei.sarif"
REPORTS = (ZAP_REPORT, NUCLEI_REPORT)
EMPTY_NUCLEI_SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "nuclei"}}, "results": []}]}
# A full scan of a large application can run for hours; ZAP stops on its own before this.
ZAP_TIMEOUT = 6 * 3600
NUCLEI_TIMEOUT = 2 * 3600

Log = Callable[[str], None]
Runner = Callable[..., subprocess.CompletedProcess]


class DastError(Exception):
    pass


@dataclass
class Dast:
    target: str
    api: Optional[str] = None  # an OpenAPI definition: a URL, or a file relative to the repository
    auth_command: Optional[str] = None
    auth_header: str = "Authorization"
    mode: str = "baseline"
    nuclei: bool = False


def is_local(url: str) -> bool:
    return (urllib.parse.urlsplit(url).hostname or "") in LOCAL_HOSTS


def container_url(url: str, platform: str = sys.platform) -> str:
    """The URL as a container sees it: a local host becomes host.docker.internal outside Linux."""
    if not is_local(url) or platform.startswith("linux"):
        return url
    parts = urllib.parse.urlsplit(url)
    netloc = "host.docker.internal" + (f":{parts.port}" if parts.port else "")
    return urllib.parse.urlunsplit(parts._replace(netloc=netloc))


def network_args(url: str, platform: str = sys.platform) -> List[str]:
    """On Linux a local target is reached through the host network; elsewhere host.docker.internal."""
    if not is_local(url):
        return []
    if platform.startswith("linux"):
        return ["--network", "host"]
    # Docker Desktop resolves host.docker.internal by itself; on another engine (colima, a
    # remote daemon) this entry provides it.
    return ["--add-host", "host.docker.internal:host-gateway"]


def _run(args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), capture_output=True, text=True, errors="replace", check=False, **kwargs
    )  # nosec B603


def auth_value(command: str, cwd: Path, run: Runner = _run) -> str:
    """The last non-empty line the command prints: the value of the sign-in header."""
    result = run(["sh", "-c", command] if os.name != "nt" else ["cmd", "/c", command], cwd=str(cwd), timeout=120)
    if result.returncode != 0:
        raise DastError(f"the auth command exited with {result.returncode}: {(result.stderr or '').strip()[-300:]}")
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise DastError("the auth command printed nothing")
    return lines[-1]


def zap_counts(document: Any) -> Tuple[int, int]:
    """All alerts, and the high ones (riskcode 3), as the templates' TG_ZAP_ALL and TG_ZAP_SEV count."""
    alerts = [a for site in (document or {}).get("site") or [] for a in site.get("alerts") or []]
    return len(alerts), sum(1 for a in alerts if str(a.get("riskcode")) in ("3", "4"))


def nuclei_kind_fail(path: Path) -> None:
    """Nuclei marks every match kind "open", and TDxGuard imports only "fail" (SARIF 3.27.9)."""
    document = json.loads(path.read_text(encoding="utf-8"))
    for run in document.get("runs") or []:
        for result in run.get("results") or []:
            if result.get("kind") == "open":
                result["kind"] = "fail"
    path.write_text(json.dumps(document), encoding="utf-8")


def _sarif_counts(path: Path) -> Tuple[int, int]:
    document = json.loads(path.read_text(encoding="utf-8"))
    results = [r for run in document.get("runs") or [] for r in run.get("results") or []]
    return len(results), sum(1 for r in results if r.get("level") == "error")


class _Container:
    """A throwaway container, created, filled, started and copied from by name."""

    def __init__(self, run: Runner, log: Log, prefix: str):
        self.run = run
        self.log = log
        self.name = f"{prefix}-{secrets.token_hex(4)}"

    def check(self, args: Sequence[str], what: str, timeout: int = 600, **kwargs: Any) -> subprocess.CompletedProcess:
        result = self.run(list(args), timeout=timeout, **kwargs)
        if result.returncode != 0:
            raise DastError(f"{what} failed: {((result.stderr or '') + (result.stdout or '')).strip()[-300:]}")
        return result

    def remove(self) -> None:
        self.run(["docker", "rm", "-f", "-v", self.name], timeout=120)


def scan_zap(
    dast: Dast,
    root: Path,
    out: Path,
    env: Dict[str, str],
    run: Runner,
    log: Log,
    platform: str = sys.platform,
    image: str = ZAP_IMAGE,
) -> Path:
    target = container_url(dast.target, platform)
    work = Path(tempfile.mkdtemp(prefix="tdxguard-zap."))
    try:
        # Writable by the zap user (uid 1000) whoever owns it here; docker cp keeps the mode.
        os.chmod(work, 0o777)  # nosec B103
        if dast.api:
            script = "zap-api-scan.py"
            if dast.api.startswith(("http://", "https://")):
                arguments = ["-t", container_url(dast.api, platform)]
            else:
                spec = (root / dast.api).resolve()
                if not spec.is_file():
                    raise DastError(f"the API definition {dast.api} is not a file of the repository")
                shutil.copyfile(spec, work / spec.name)
                os.chmod(work / spec.name, 0o644)
                arguments = ["-t", spec.name]
            arguments += ["-f", "openapi", "-O", target]
            if dast.mode != "full":
                arguments.append("-S")
        else:
            script = "zap-full-scan.py" if dast.mode == "full" else "zap-baseline.py"
            arguments = ["-t", target]

        container = _Container(run, log, "tdxguard-zap")
        try:
            container.check(
                ["docker", "create", "--name", container.name, *network_args(dast.target, platform),
                 "-e", "ZAP_AUTH_HEADER", "-e", "ZAP_AUTH_HEADER_VALUE", "-e", "ZAP_AUTH_HEADER_SITE",
                 image, script, *arguments, "-J", ZAP_REPORT, "-I"],
                "docker create (ZAP)", env=env,
            )  # fmt: skip
            container.check(["docker", "cp", f"{work}/.", f"{container.name}:/zap/wrk"], "docker cp into ZAP")
            log(f"ZAP {script} against {dast.target}" + (f" ({dast.api})" if dast.api else ""))
            started = run(["docker", "start", "-a", container.name], timeout=ZAP_TIMEOUT)
            # -I: warnings exit 0; a FAIL rule exits 1, which is still a report. Anything else
            # (3: bad options or no /zap/wrk) leaves none, and the copy below says so.
            if started.returncode not in (0, 1, 2):
                log(f"ZAP exited with {started.returncode}: {(started.stdout or '').strip()[-300:]}")
            report = out / ZAP_REPORT
            container.check(["docker", "cp", f"{container.name}:/zap/wrk/{ZAP_REPORT}", str(report)],
                            "ZAP wrote no report; docker cp")  # fmt: skip
            return report
        finally:
            container.remove()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def scan_nuclei(
    dast: Dast,
    out: Path,
    auth: Optional[str],
    run: Runner,
    log: Log,
    platform: str = sys.platform,
    image: str = NUCLEI_IMAGE,
) -> Path:
    container = _Container(run, log, "tdxguard-nuclei")
    headers = ["-H", f"{dast.auth_header}: {auth}"] if auth else []
    try:
        container.check(
            ["docker", "create", "--name", container.name, *network_args(dast.target, platform),
             "-v", f"{NUCLEI_VOLUME}:/root", image,
             "-target", container_url(dast.target, platform), "-severity", "low,medium,high,critical", *headers,
             "-sarif-export", "/tmp/nuclei.sarif", "-no-interactsh", "-silent"],  # nosec B108
            "docker create (Nuclei)",
        )  # fmt: skip
        log(f"Nuclei against {dast.target} (the first run downloads its templates, about a minute)")
        started = run(["docker", "start", "-a", container.name], timeout=NUCLEI_TIMEOUT)
        report = out / NUCLEI_REPORT
        copied = run(["docker", "cp", f"{container.name}:/tmp/nuclei.sarif", str(report)], timeout=600)  # nosec B108
        if copied.returncode != 0:
            if started.returncode != 0:
                raise DastError(f"Nuclei exited with {started.returncode} and wrote no report: "
                                f"{((started.stderr or '') + (started.stdout or '')).strip()[-300:]}")  # fmt: skip
            # Nuclei writes no SARIF file when nothing matched; the run still counts as done.
            report.write_text(json.dumps(EMPTY_NUCLEI_SARIF), encoding="utf-8")
        nuclei_kind_fail(report)
        return report
    finally:
        container.remove()


def scan(
    dast: Dast, root: Path, out: Path, log: Log, run: Runner = _run, platform: str = sys.platform
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Runs ZAP (and Nuclei); returns the summary rows and the errors."""
    for name in REPORTS:
        (out / name).unlink(missing_ok=True)
    env = dict(os.environ)
    env.pop("ZAP_AUTH_HEADER_VALUE", None)
    auth: Optional[str] = None
    if dast.auth_command:
        try:
            auth = auth_value(dast.auth_command, root, run)
        except (DastError, OSError, subprocess.TimeoutExpired) as e:
            return [], [f"DAST: {e}; nothing was scanned (fix it, or remove auth_command to scan signed out)"]
        env.update(
            ZAP_AUTH_HEADER=dast.auth_header,
            ZAP_AUTH_HEADER_VALUE=auth,
            ZAP_AUTH_HEADER_SITE=urllib.parse.urlsplit(container_url(dast.target, platform)).hostname or "",
        )
        log(f"Signed in: {dast.auth_header} goes to {env['ZAP_AUTH_HEADER_SITE']} only")

    rows: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        report = scan_zap(dast, root, out, env, run, log, platform)
        findings, severe = zap_counts(json.loads(report.read_text(encoding="utf-8")))
        rows.append({"scanner": "dast", "label": "ZAP (DAST)", "report": ZAP_REPORT, "findings": findings,
                     "severe": severe})  # fmt: skip
    except (DastError, OSError, ValueError, subprocess.TimeoutExpired) as e:
        errors.append(f"ZAP: {e}")
    if dast.nuclei:
        try:
            report = scan_nuclei(dast, out, auth, run, log, platform)
            findings, severe = _sarif_counts(report)
            rows.append({"scanner": "dast", "label": "Nuclei (DAST)", "report": NUCLEI_REPORT, "findings": findings,
                         "severe": severe})  # fmt: skip
        except (DastError, OSError, ValueError, subprocess.TimeoutExpired) as e:
            errors.append(f"Nuclei: {e}")
    return rows, errors
