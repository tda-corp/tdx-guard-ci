"""
Smoke test of a built `tdxguard` executable on the machine it runs on: the release
workflow runs it on every platform after the build, and it runs the same way locally.

    python smoke.py <executable> [--work DIR] [--tools-dir DIR] [--no-tools-install]

1. `--version` names the package version and "standalone".
2. `tools install` downloads and verifies Betterleaks, Opengrep (with its rules) and Trivy
   for this platform; `tools list --json` then reports all of them installed.
3. A fixture repository is created (a vulnerable requirements.txt, Python code that the
   Opengrep security rules flag, a Dockerfile with misconfigurations, a secret generated
   at run time so that no secret is ever committed), and
   `tdxguard scan --engine native --no-upload --keep <dir>` runs on it.
4. Every report exists, summary.json has no errors, and every scanner found something.

The executable must not need Python: `python`, `python3` and `py` on its PATH are traps
that record any call, and the test fails if one was made.

Standard library only, Python 3.8 or newer (whatever the runner has); the executable under
test does not use this interpreter.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import string
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path

CLI = Path(__file__).resolve().parents[1]
REPORTS = ("betterleaks.json", "opengrep.sarif", "trivy.sarif", "sbom.cdx.json", "summary.json")
# (scanner, report) rows of summary.json that must have findings.
EXPECTED_FINDINGS = (
    ("betterleaks", "betterleaks.json"),
    ("opengrep", "opengrep.sarif"),
    ("trivy", "trivy.sarif"),
    ("trivy", "sbom.cdx.json"),
)

APP_PY = """\
import hashlib
import subprocess

import yaml


def run(command):
    return subprocess.call(command, shell=True)


def evaluate(expression):
    return eval(expression)


def load(document):
    return yaml.load(document)


def checksum(data):
    return hashlib.md5(data).hexdigest()
"""

REQUIREMENTS = "flask==0.12\nrequests==2.19.0\nPyYAML==5.3\nJinja2==2.10\n"

DOCKERFILE = """\
FROM ubuntu:latest
ADD https://example.com/app.tar.gz /opt/
RUN apt-get update && apt-get install -y curl
EXPOSE 22
CMD ["/opt/app/run"]
"""


def fail(message: str) -> None:
    print(f"SMOKE FAILED: {message}", file=sys.stderr, flush=True)
    sys.exit(1)


def step(message: str) -> None:
    print(f"\n=== {message}", flush=True)


def run(command, env, cwd=None, timeout=1800):
    printable = " ".join(str(part) for part in command)
    print(f"$ {printable}", flush=True)
    started = time.monotonic()
    result = subprocess.run(  # nosec B603
        [str(part) for part in command],
        cwd=None if cwd is None else str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    output = result.stdout.decode("utf-8", "replace")
    print(output.rstrip(), flush=True)
    print(f"(exit {result.returncode}, {time.monotonic() - started:.1f}s)", flush=True)
    return result.returncode, output


def python_traps(directory: Path) -> Path:
    """`python`, `python3` and `py` that record being called; returns the record file."""
    record = directory / "python-was-called.txt"
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("python", "python3", "py"):
        if os.name == "nt":
            (directory / f"{name}.bat").write_text(f'@echo off\r\necho {name} %* >> "{record}"\r\nexit /b 99\r\n')
        else:
            trap = directory / name
            trap.write_text(f'#!/bin/sh\necho "{name} $*" >> "{record}"\nexit 99\n')
            trap.chmod(0o755)
    return record


def fake_secret() -> str:
    """A GitHub token shaped string, random on every run."""
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(random.SystemRandom().choice(alphabet) for _ in range(36))


def make_fixture(repository: Path, env) -> None:
    (repository / "app").mkdir(parents=True)
    (repository / "requirements.txt").write_text(REQUIREMENTS)
    (repository / "app" / "main.py").write_text(APP_PY)
    (repository / "Dockerfile").write_text(DOCKERFILE)
    (repository / "app" / "settings.py").write_text(f'GITHUB_TOKEN = "{fake_secret()}"\n')
    (repository / ".tdxguard.yml").write_text("project: tdxguard-smoke\nengine: native\n")
    code, _ = run(["git", "init", "-q", str(repository)], env)
    if code != 0:
        fail("git init failed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test of a built tdxguard executable.")
    parser.add_argument("executable")
    parser.add_argument("--work", help="work directory (default: a temporary one, removed afterwards)")
    parser.add_argument("--tools-dir", help="TDXGUARD_TOOLS_DIR for the run (default: the user's cache)")
    parser.add_argument("--no-tools-install", action="store_true", help="skip `tools install`")
    args = parser.parse_args()

    executable = Path(args.executable).resolve()
    if not executable.is_file():
        fail(f"{executable} does not exist")
    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="tdxguard-smoke."))
    work.mkdir(parents=True, exist_ok=True)
    record = python_traps(work / "traps")
    env = dict(os.environ)
    env["PATH"] = str(work / "traps") + os.pathsep + env.get("PATH", "")
    env["NO_COLOR"] = "1"
    if args.tools_dir:
        env["TDXGUARD_TOOLS_DIR"] = str(Path(args.tools_dir).resolve())
    version = re.search(r'^__version__ = "([^"]+)"$', (CLI / "tdxguard" / "__init__.py").read_text(), re.M)

    step("version")
    code, output = run([executable, "--version"], env)
    if code != 0 or not version or f"tdxguard {version.group(1)} (" not in output or "standalone" not in output:
        fail(f"--version printed {output.strip()!r}")

    if not args.no_tools_install:
        step("tools install")
        code, _ = run([executable, "tools", "install"], env)
        if code != 0:
            fail("tools install failed")
    code, output = run([executable, "tools", "list", "--json"], env)
    if code != 0:
        fail("tools list failed")
    rows = json.loads(output[output.index("{") :])["tools"]
    missing = [row["tool"] for row in rows if row["state"] != "installed"]
    if len(rows) < 4 or missing:
        fail(f"tools not installed: {missing or rows}")

    step("scan --engine native --no-upload")
    repository = work / "repository"
    keep = work / "reports"
    shutil.rmtree(str(repository), ignore_errors=True)
    shutil.rmtree(str(keep), ignore_errors=True)
    make_fixture(repository, env)
    code, _ = run([executable, "scan", "--engine", "native", "--no-upload", "--keep", keep], env, cwd=repository)
    if code not in (0, 1):
        fail(f"scan exited with {code}")

    step("reports")
    for report in REPORTS:
        path = keep / report
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"{report} is missing or empty")
        json.loads(path.read_text(encoding="utf-8"))
        print(f"ok {report} ({path.stat().st_size} bytes)")
    summary = json.loads((keep / "summary.json").read_text(encoding="utf-8"))
    if summary.get("engine") != "native":
        fail(f"summary.json engine is {summary.get('engine')!r}")
    if summary.get("errors"):
        fail(f"summary.json errors: {summary['errors']}")
    for scanner, report in EXPECTED_FINDINGS:
        row = next((r for r in summary["rows"] if r["scanner"] == scanner and r["report"] == report), None)
        if row is None or row["findings"] <= 0:
            fail(f"no findings from {scanner} in {report}: {row}")
        print(f"ok {row['label']}: {row['findings']} finding(s), {row['severe']} severe")

    step("no Python")
    if record.exists():
        fail(f"the executable started Python: {record.read_text()}")
    print("ok the executable never called python, python3 or py")

    if not args.work:
        shutil.rmtree(str(work), ignore_errors=True)
    print("\nSMOKE PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
