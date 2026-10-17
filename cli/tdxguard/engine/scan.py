"""
The scans of ci-templates/github/tdxguard.yml (jobs betterleaks, opengrep, trivy,
image_scan): the same versions, flags, exclusions and helper scripts, the same report
files, and summary.json. Pushing to TDxGuard and gating are the caller's job.

This used to be the bash entrypoint of the scanner image; the image now runs this module
through `python3 -m tdxguard.engine` and the CLI calls `run()` directly for the native
engine, so both run one implementation.

Portable on purpose: no shell, no jq, no POSIX paths. Every command is an argument list,
temporary files come from `tempfile`, paths are `pathlib` paths, and the scanners run with
the repository as the working directory and `.` as the target, so the paths inside the
reports are relative and identical on every platform.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from tdxguard import frozen
from tdxguard.engine import counts
from tdxguard.engine.helpers import OPENGREP_PRUNE_RULES, SARIF_ENRICH
from tdxguard.engine.tools import MARKER, RULE_LANGUAGES, Toolset

SCANNERS = ("betterleaks", "opengrep", "trivy", "image")
SECRETS_MODES = ("dir", "git")

# The CI template's exclusions.
OPENGREP_EXCLUDES = (
    "node_modules",
    ".venv",
    "vendor",
    "dist",
    "build",
    "*.md",
    "*.example",
    "ogrules",
    "ogrules-security",
)
TRIVY_SKIP_DIRS = ("node_modules", ".venv", "vendor")
OPENGREP_RULE_ROOTS = ",".join(RULE_LANGUAGES)

SUMMARY_FILE = "summary.json"
EXIT_OK = 0
EXIT_SCANNER_FAILED = 1
EXIT_USAGE = 2

Log = Callable[[str], None]


@dataclass
class ImageTarget:
    ref: str
    slug: str
    # Pulled straight from the registry (trivy --image-src remote) instead of the local daemon.
    remote: bool = False


@dataclass
class Options:
    src: Path
    out: Path
    excludes: List[str] = field(default_factory=list)
    images: List[ImageTarget] = field(default_factory=list)
    skips: List[str] = field(default_factory=list)
    secrets_mode: str = "dir"
    log_opts: str = ""
    engine: str = "native"  # recorded in summary.json: native or docker
    version: str = "dev"  # summary.json "version": the image's version, or the CLI's
    # The container warns when local images are to be scanned without a Docker socket.
    check_docker_socket: bool = False


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class Scan:
    def __init__(
        self,
        options: Options,
        tools: Toolset,
        environment: Mapping[str, str],
        *,
        log: Log = _stderr,
        output: Log = _stderr,
        work_root: Optional[Path] = None,
    ):
        """
        `log` receives the progress, warning and error lines ("==> ..."), `output` the
        scanners' own output, line by line. `environment` is the scanners' environment.
        """
        self.options = options
        self.tools = tools
        self.environment = dict(environment)
        self.log = log
        self.output = output
        self.work_root = work_root
        self.rows: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.work = Path(".")

    # --- bookkeeping ---

    def error(self, message: str) -> None:
        self.log(f"ERROR: {message}")
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.log(f"WARNING: {message}")
        self.warnings.append(message)

    def skipped(self, scanner: str) -> bool:
        return scanner in self.options.skips

    def report(self, name: str) -> Path:
        return self.options.out / name

    def remove(self, *names: str) -> None:
        for name in names:
            try:
                self.report(name).unlink()
            except FileNotFoundError:
                pass

    def row(
        self, scanner: str, label: str, report: str, all_count: Callable, severe_count: Callable, image: str = ""
    ) -> None:
        """tg_row of tdxguard-lib.sh, as JSON. A missing report adds no row, as in CI."""
        path = self.report(report)
        if not path.is_file():
            return
        try:
            document = _load_json(path)
            findings, severe = all_count(document), severe_count(document)
        except (OSError, ValueError, counts.CountError):
            self.error(f"{report}: cannot count the findings (not valid for its format)")
            return
        entry: Dict[str, Any] = {
            "scanner": scanner,
            "label": label,
            "report": report,
            "findings": findings,
            "severe": severe,
        }
        if image:
            entry["image"] = image
        self.rows.append(entry)

    def run_command(self, command: Sequence[str]) -> int:
        """Runs a scanner in the repository; its output goes to `output`. 127: not runnable."""
        try:
            process = subprocess.Popen(  # nosec B603
                [str(part) for part in command],
                cwd=str(self.options.src),
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as e:
            self.output(f"{command[0]}: {e}")
            return 127
        with process:
            assert process.stdout is not None  # nosec B101
            for line in process.stdout:
                self.output(line.rstrip("\r\n"))
        return process.returncode

    def run_helper(self, script: Path, arguments: Sequence[str]) -> int:
        # `python -I -X utf8 <script>`, or the standalone executable's equivalent: see
        # tdxguard.frozen.helper_command.
        return self.run_command(frozen.helper_command(script, arguments))

    # --- the scanners ---

    def betterleaks(self) -> None:
        """The template's betterleaks job."""
        report = "betterleaks.json"
        self.remove(report)
        config: List[str] = []
        # The repository's own config, exactly as CI picks it up.
        if (self.options.src / ".gitleaks.toml").is_file():
            config = ["-c", ".gitleaks.toml"]
        if self.options.secrets_mode == "git":
            if self.run_quiet(["git", "rev-parse", "--is-inside-work-tree"]) != 0:
                self.error(
                    f"betterleaks: --secrets-mode git needs {self.options.src} to be a git repository "
                    "(a worktree's .git file pointing outside the mount does not work)"
                )
                return
            mode = ["git", "."]
            if self.options.log_opts:
                mode.append(f"--log-opts={self.options.log_opts}")
        else:
            mode = ["dir", "."]
        self.log("==> betterleaks " + " ".join(mode))
        code = self.run_command(
            [self.tools.betterleaks, *mode, *config, "-f", "json", "-r", str(self.report(report)),
             "--exit-code", "0", "--redact", "--no-banner"]
        )  # fmt: skip
        if code != 0:
            self.error(f"betterleaks exited with status {code}")
        elif not _valid_json(self.report(report)):
            # A clean scan writes [] or null, both valid JSON; no file at all is a failure.
            self.error("betterleaks wrote no valid betterleaks.json")
        self.row("betterleaks", "Betterleaks (secrets)", report, counts.length, counts.length)

    def opengrep(self) -> None:
        """
        The template's opengrep job. The rules come already filtered to the security/
        directories; the pruning depends on the scanned repository, so it runs here, on a
        writable copy.
        """
        report = "opengrep.sarif"
        self.remove(report)
        rules = self.work / "ogrules-security"
        try:
            shutil.copytree(str(self.tools.rules), str(rules), ignore=shutil.ignore_patterns(MARKER))
        except OSError:
            self.error(f"opengrep: cannot copy the rules into {self.work}")
            return
        # CI ignores its own rule trees (ogrules, ogrules-security) inside the checkout; the
        # same names are passed so a repository that happens to hold such a directory
        # behaves alike.
        if self.run_helper(OPENGREP_PRUNE_RULES, [str(rules), ".", "ogrules", "ogrules-security"]) != 0:
            self.error("opengrep-prune-rules.py failed")
            return
        self.log("==> opengrep scan")
        command: List[Any] = [self.tools.opengrep, "scan", "--sarif", "--output", str(self.report(report)), "--quiet",
                              "--config", str(rules)]  # fmt: skip
        command += [f"--exclude={pattern}" for pattern in OPENGREP_EXCLUDES]
        command += [f"--exclude={pattern}" for pattern in self.options.excludes]
        command.append(".")
        code = self.run_command(command)
        if not _valid_json(self.report(report)):
            self.error(f"opengrep wrote no valid opengrep.sarif (exit status {code})")
            self.remove(report)
            return
        # CI runs the scan with `|| true` and pushes whatever SARIF it got; a non-zero status
        # with a valid report is therefore a warning here, not a failure.
        if code != 0:
            self.warning(f"opengrep exited with status {code} but wrote a report")
        enrich = [
            str(self.report(report)),
            ".",
            "--rule-roots",
            OPENGREP_RULE_ROOTS,
            "--context",
            "5",
            "--expand-context",
        ]
        if self.run_helper(SARIF_ENRICH, enrich) != 0:
            self.error("sarif-enrich.py failed on opengrep.sarif")
        self.row("opengrep", "Opengrep (SAST)", report, counts.sarif_all, counts.opengrep_error)

    def trivy(self) -> None:
        """The template's trivy job: misconfigurations to SARIF, vulnerabilities to the CycloneDX SBOM."""
        skip: List[str] = []
        for directory in TRIVY_SKIP_DIRS:
            skip += ["--skip-dirs", directory]
        # A user exclude may name a directory or a file pattern; Trivy keeps the two apart,
        # so it goes to both. A pattern that matches nothing is harmless.
        for pattern in self.options.excludes:
            skip += ["--skip-dirs", pattern, "--skip-files", pattern]
        self.remove("trivy.sarif", "sbom.cdx.json")

        self.log("==> trivy fs (misconfig)")
        sarif = self.report("trivy.sarif")
        code = self.run_command(
            [self.tools.trivy, "fs", ".", "--scanners", "misconfig", "--format", "sarif", "--output", str(sarif), *skip]
        )
        if code == 0 and _valid_json(sarif):
            if self.run_helper(SARIF_ENRICH, [str(sarif), ".", "--unescape-html"]) != 0:
                self.error("sarif-enrich.py failed on trivy.sarif")
        else:
            self.error("trivy fs --scanners misconfig failed")
            self.remove("trivy.sarif")

        self.log("==> trivy fs (vuln, CycloneDX)")
        sbom = self.report("sbom.cdx.json")
        code = self.run_command(
            [self.tools.trivy, "fs", ".", "--format", "cyclonedx", "--scanners", "vuln", "--output", str(sbom), *skip]
        )
        if code != 0 or not _valid_json(sbom):
            self.error("trivy fs --scanners vuln failed")
            self.remove("sbom.cdx.json")

        self.row("trivy", "Trivy (IaC)", "trivy.sarif", counts.sarif_all, counts.sarif_error)
        self.row("trivy", "Trivy (dependencies)", "sbom.cdx.json", counts.cyclonedx_all, counts.cyclonedx_severe)

    def images(self) -> None:
        """
        The template's image_scan job. Locally built images are read from the Docker daemon
        (the CLI builds them first); `remote` images are pulled from their registry.
        """
        local = [image for image in self.options.images if not image.remote]
        if (
            local
            and self.options.check_docker_socket
            and not os.path.exists("/var/run/docker.sock")
            and not self.environment.get("DOCKER_HOST")
        ):
            self.warning("no Docker socket mounted: trivy can only pull the images from a registry")
        for image in self.options.images:
            sbom = f"sbom-image-{image.slug}.cdx.json"
            sarif = f"trivy-image-{image.slug}.sarif"
            self.remove(sbom, sarif)
            source = ["--image-src", "remote"] if image.remote else []
            self.log(f"==> trivy image {image.ref}" + (" (from the registry)" if image.remote else ""))
            code = self.run_command(
                [self.tools.trivy, "image", *source, "--format", "cyclonedx", "--scanners", "vuln",
                 "--output", str(self.report(sbom)), image.ref]
            )  # fmt: skip
            if code != 0 or not _valid_json(self.report(sbom)):
                self.error(f"trivy image --scanners vuln failed for {image.ref}")
                self.remove(sbom)
            code = self.run_command(
                [self.tools.trivy, "image", *source, "--scanners", "secret", "--format", "sarif",
                 "--output", str(self.report(sarif)), image.ref]
            )  # fmt: skip
            if code != 0 or not _valid_json(self.report(sarif)):
                self.error(f"trivy image --scanners secret failed for {image.ref}")
                self.remove(sarif)
            self.row("image", f"Trivy (image `{image.ref}`)", sbom, counts.cyclonedx_all, counts.cyclonedx_severe,
                     image.ref)  # fmt: skip
            self.row("image", "Trivy (image secrets)", sarif, counts.sarif_all, counts.sarif_all, image.ref)

    def run_quiet(self, command: Sequence[str]) -> int:
        try:
            return subprocess.run(  # nosec B603
                list(command),
                cwd=str(self.options.src),
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
        except OSError:
            return 127

    # --- the run ---

    def run(self) -> int:
        """Runs the scanners, writes summary.json, returns 0 (scans ran) or 1 (a scanner failed)."""
        options = self.options
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        start = time.monotonic()
        self.work = make_work_dir(self.work_root)
        try:
            self.log(
                f"==> tdxguard {options.engine} engine {options.version}: scanning {options.src} into {options.out}"
            )
            if not self.skipped("betterleaks"):
                self.betterleaks()
            if not self.skipped("opengrep"):
                self.opengrep()
            if not self.skipped("trivy"):
                self.trivy()
            if options.images and not self.skipped("image"):
                self.images()
        finally:
            shutil.rmtree(str(self.work), ignore_errors=True)
        duration = int(time.monotonic() - start)

        summary = {
            "version": options.version,
            "engine": options.engine,
            "tools": self.tools.versions(),
            "started_at": started_at,
            "duration_seconds": duration,
            "secrets_mode": options.secrets_mode,
            "skipped": sorted(set(options.skips)),
            "rows": self.rows,
            "errors": self.errors,
            "warnings": self.warnings,
        }
        write_summary(options.out, summary)

        for row in self.rows:
            self.log(f"  {row['label']}: {row['findings']} finding(s), {row['severe']} severe  [{row['report']}]")
        if self.errors:
            self.log(f"==> finished with errors after {duration}s:")
            for message in self.errors:
                self.log(f"  - {message}")
            return EXIT_SCANNER_FAILED
        self.log(f"==> finished after {duration}s")
        return EXIT_OK


def run(
    options: Options,
    tools: Toolset,
    environment: Optional[Mapping[str, str]] = None,
    *,
    log: Log = _stderr,
    output: Log = _stderr,
) -> int:
    return Scan(options, tools, scanner_environment(environment), log=log, output=output).run()


def scanner_environment(base: Optional[Mapping[str, str]] = None, platform: str = sys.platform) -> Dict[str, str]:
    """
    The scanners' environment. Log-only settings, which change nothing in the reports: no
    progress bars (they flood a log file) and no "a newer Trivy is available" check, a
    network call the scan does not need. Both can be overridden from the environment.
    Opengrep reads its rule files with the locale's codec, so the locale must be UTF-8.
    """
    environment = dict(os.environ if base is None else base)
    environment.setdefault("TRIVY_NO_PROGRESS", "true")
    environment.setdefault("TRIVY_SKIP_VERSION_CHECK", "true")
    environment["PYTHONUTF8"] = "1"
    locale = environment.get("LC_ALL") or environment.get("LC_CTYPE") or environment.get("LANG") or ""
    if not platform.startswith("win") and "utf-8" not in locale.lower() and "utf8" not in locale.lower():
        # C.UTF-8 exists on every glibc of the last years and on musl; macOS has en_US.UTF-8.
        environment["LC_ALL"] = "en_US.UTF-8" if platform == "darwin" else "C.UTF-8"
    return environment


def make_work_dir(base: Optional[Path] = None) -> Path:
    """
    A private temporary directory. Opengrep prefixes rule ids with the rules' path, and
    sarif-enrich.py trims an id at its first segment named like a rule root, so no segment
    of the work directory may be one ("/var/folders/go/..." on a Mac would cut the id there).
    """
    work = Path(tempfile.mkdtemp(prefix="tdxguard.", dir=str(base) if base else None)).resolve()
    if not set(work.parts) & set(RULE_LANGUAGES):
        return work
    shutil.rmtree(str(work), ignore_errors=True)
    fallback = Path.home() / ".cache" / "tdxguard" / "work"
    fallback.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="tdxguard.", dir=str(fallback))).resolve()


def write_summary(out: Path, summary: Dict[str, Any]) -> None:
    """Written last and atomically, so its presence means the run finished."""
    temporary = out / ".summary.json.tmp"
    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(str(temporary), str(out / SUMMARY_FILE))


def _load_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _valid_json(path: Path) -> bool:
    """
    A report the scanner claims to have written must exist and be JSON; a scanner that
    "succeeds" without one is the silent failure this pipeline has been bitten by before.
    A clean Betterleaks scan writes `null`, which is valid.
    """
    try:
        if path.stat().st_size == 0:
            return False
        _load_json(path)
        return True
    except (OSError, ValueError):
        return False
