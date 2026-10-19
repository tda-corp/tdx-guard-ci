#!/usr/bin/env python3
"""
mobsf-scan.py — analyse a mobile app with MobSF (Mobile Security Framework) and write its JSON
report for TDxGuard.

    mobsf-scan.py --out DIR [--root DIR] [--app PATH]... [--source PLATFORM[:DIR]]...
                  [--app-root DIR] [--image IMAGE] [--name NAME] [--start-timeout SECONDS]

--app     a built app: .apk, .aab, .apks, .xapk or .ipa, relative to --root. A glob is allowed
          when it matches exactly one file (app/build/outputs/apk/release/*.apk).
--app-root  where --app paths start, when the app is not in the repository (a downloaded
          build artifact); defaults to --root.
--name    the container's name, for a caller that removes it should this script be killed.
--source  the source of an Android Studio (android) or Xcode (ios) project, zipped here and
          analysed as source. DIR defaults to the root. Built apps give the better results:
          MobSF decompiles the whole app, its libraries included, and checks the signing
          certificate and the native binaries, none of which a source checkout has.

Every --app and --source writes mobsf-<slug>.json into --out, the slug derived from the
argument (not from the file it matched), so that the report keeps its name from one build to
the next and TDxGuard can resolve what was fixed.

MobSF runs from its official image as a throwaway container, driven through its REST API
from inside the container (docker exec), so no port is published. Its network is cut once
the server is up: the app is analysed without any outbound connection, so neither the app
nor anything found in it leaves the machine. MobSF would otherwise look the package name up
on Google Play or the App Store and query the URLs it finds (Firebase databases, malware
domain lists); without network those checks are skipped. The container needs network only at
start, when MobSF downloads its decompiler (JADX).

Standard library only; Python 3.9 or later; needs the docker CLI. Exit 0: every report
written; 1: a scan failed; 2: bad usage (nothing to analyse, Docker missing).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import plistlib
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:v4.5.3"
APP_SUFFIXES = (".apk", ".aab", ".apks", ".xapk", ".ipa")
PLATFORMS = ("android", "ios")
# Left out of a source zip: VCS data, build output and downloaded dependencies.
SKIPPED_DIRECTORIES = {
    ".git",
    ".gradle",
    ".idea",
    "build",
    "DerivedData",
    "Pods",
    "Carthage",
    "node_modules",
    ".dart_tool",
}
API = "http://127.0.0.1:8000"
START_TIMEOUT = 900
SCAN_TIMEOUT = 3600


class MobSFError(Exception):
    pass


@dataclass
class Target:
    kind: str  # "app" or "source"
    argument: str  # as given, for the messages
    path: Path  # the app, or the source directory
    platform: str = ""  # android or ios, for a source
    slug: str = ""

    @property
    def report_name(self) -> str:
        return f"mobsf-{self.slug}.json"


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:60].strip("-") or "app"


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def resolve_app(root: Path, argument: str) -> Target:
    pattern = argument.strip()
    if not pattern or os.path.isabs(pattern) or ".." in Path(pattern).parts:
        raise MobSFError(f"--app {argument!r}: give a path relative to the repository root.")
    matches = sorted(p for p in glob.glob(str(root / pattern), recursive=True) if os.path.isfile(p))
    if not matches:
        raise MobSFError(
            f"--app {argument!r}: no such file. Build the app first, or download the build artifact into the checkout."
        )
    if len(matches) > 1:
        names = ", ".join(os.path.relpath(m, root) for m in matches[:3])
        raise MobSFError(f"--app {argument!r} matches {len(matches)} files ({names}); make it match one.")
    path = Path(matches[0])
    if path.suffix.lower() not in APP_SUFFIXES:
        raise MobSFError(f"--app {argument!r}: MobSF analyses {', '.join(APP_SUFFIXES)} files, not {path.name}.")
    if not _inside(root, path):
        raise MobSFError(f"--app {argument!r} leaves the repository.")
    return Target("app", argument, path, slug=slugify(pattern))


def resolve_source(root: Path, argument: str) -> Target:
    platform, _, directory = argument.strip().partition(":")
    platform = platform.strip().lower()
    directory = directory.strip() or "."
    if platform not in PLATFORMS:
        raise MobSFError(f"--source {argument!r}: the platform is android or ios.")
    if os.path.isabs(directory) or ".." in Path(directory).parts:
        raise MobSFError(f"--source {argument!r}: give a directory relative to the repository root.")
    path = (root / directory).resolve()
    if not path.is_dir():
        raise MobSFError(f"--source {argument!r}: {directory} is not a directory.")
    layout = source_layout(path)
    if platform == "android" and layout != "android":
        raise MobSFError(
            f"--source {argument!r}: MobSF analyses an Android project with the Android Studio layout, "
            "app/src/main/AndroidManifest.xml next to app/src/main/java or kotlin (or the Eclipse layout), in "
            f"{directory} or one directory below it, and only that app module. Analyse the built APK instead."
        )
    if platform == "ios" and layout != "ios":
        raise MobSFError(
            f"--source {argument!r}: "
            + (
                f"{directory} holds an Android project as well, which MobSF would analyse instead; "
                "point it at the directory of the Xcode project."
                if layout == "android"
                else f"no .xcodeproj in {directory} or one directory below it."
            )
        )
    suffix = "" if directory in (".", "") else "-" + directory
    return Target("source", argument, path, platform=platform, slug=slugify(platform + suffix))


def _android_layout(directory: Path) -> bool:
    eclipse = (directory / "AndroidManifest.xml").is_file() and (directory / "src").exists()
    main = directory / "app" / "src" / "main"
    studio = (main / "AndroidManifest.xml").is_file() and ((main / "java").exists() or (main / "kotlin").exists())
    return eclipse or studio


def _subdirectories(directory: Path) -> List[Path]:
    return sorted(p for p in directory.iterdir() if p.is_dir() and p.name not in SKIPPED_DIRECTORIES)


def source_layout(directory: Path) -> str:
    """What MobSF makes of a zip of this directory: "android", "ios" or "" (not supported). MobSF
    checks for an Android project first, then for an Xcode project, each at the top or one
    directory below it (StaticAnalyzer/views/android/apk.py, valid_source_code)."""
    if _android_layout(directory) or any(_android_layout(d) for d in _subdirectories(directory)):
        return "android"
    for candidate in [directory] + _subdirectories(directory):
        if any(p.suffix == ".xcodeproj" for p in candidate.iterdir()):
            return "ios"
    return ""


def _readable_plist(path: Path) -> bool:
    try:
        with open(path, "rb") as plist:
            plistlib.load(plist)
        return True
    except Exception:  # pylint: disable=broad-exception-caught  # any parse error, whatever its class
        return False


def zip_source(directory: Path, destination: Path, left_out: Optional[List[str]] = None) -> int:
    """
    The project as MobSF expects it, paths relative to the project directory.

    A property list MobSF cannot read is left out (and named in left_out): MobSF 4.5.3 takes any
    *Info.plist for the app's, and one that does not parse (a leftover GoogleService-Info copy
    with a tab before <?xml) made the whole iOS analysis fail with "AttributeError: 'NoneType'
    object has no attribute 'get'".
    """
    count = 0
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for current, subdirectories, files in os.walk(directory):
            subdirectories[:] = sorted(d for d in subdirectories if d not in SKIPPED_DIRECTORIES)
            for name in sorted(files):
                path = Path(current) / name
                if path.is_symlink() or not path.is_file():
                    continue
                relative = path.relative_to(directory).as_posix()
                if name.endswith(".plist") and not _readable_plist(path):
                    if left_out is not None:
                        left_out.append(relative)
                    continue
                archive.write(path, relative)
                count += 1
    return count


IOS_SOURCE_FAILED = (
    "MobSF could not analyse the iOS source in {source} (an error inside MobSF: {error}). Analyse the built app "
    "instead: build the .ipa (flutter build ipa, or an Xcode archive exported as .ipa) and name it with "
    "app: in .tdxguard.yml (mobile_app: in the workflow)."
)


# --- the container ---------------------------------------------------------------------


Runner = Callable[..., subprocess.CompletedProcess]


def _log(message: str) -> None:
    print(message, flush=True)


def _run(args: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)  # nosec B603


class MobSF:
    """A MobSF container, driven with `docker exec ... curl` against its own loopback."""

    def __init__(self, image: str = MOBSF_IMAGE, run: Runner = _run, log: Callable[[str], None] = _log, name: str = ""):
        self.image = image
        self.name = name or f"tdxguard-mobsf-{secrets.token_hex(4)}"
        self.key = secrets.token_hex(24)
        self.run = run
        self.log = log
        self.started = False

    def start(self, timeout: int = START_TIMEOUT) -> None:
        result = self.run(
            [
                "docker", "run", "-d", "--name", self.name,
                "-e", f"MOBSF_API_KEY={self.key}",
                "-e", "MOBSF_DOMAIN_MALWARE_SCAN=0",
                self.image,
            ]
        )  # fmt: skip
        if result.returncode != 0:
            raise MobSFError(f"docker run {self.image} failed: {(result.stderr or '').strip()[-300:]}")
        self.started = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            probe = self.run(
                ["docker", "exec", self.name, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"{API}/login/"]
            )
            if probe.returncode == 0 and (probe.stdout or "").strip()[:1] in ("2", "3"):
                return
            state = self.run(["docker", "inspect", "-f", "{{.State.Running}}", self.name])
            if (state.stdout or "").strip() == "false":
                logs = self.run(["docker", "logs", "--tail", "20", self.name])
                raise MobSFError("MobSF stopped while starting: " + ((logs.stdout or "") + (logs.stderr or ""))[-500:])
            time.sleep(5)
        raise MobSFError(f"MobSF did not come up within {timeout}s.")

    def isolate(self) -> None:
        """Disconnect the container from every network: from here on it reaches nothing but itself."""
        result = self.run(["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", self.name])
        try:
            networks = list(json.loads(result.stdout or "{}") or {})
        except ValueError:
            networks = []
        for network in networks:
            if network == "none":
                continue
            disconnected = self.run(["docker", "network", "disconnect", "-f", network, self.name])
            if disconnected.returncode != 0:
                raise MobSFError(
                    f"Could not disconnect MobSF from the network {network}: {(disconnected.stderr or '').strip()}. "
                    "Not analysing the app with network access."
                )

    def api(self, endpoint: str, *fields: str, timeout: int = SCAN_TIMEOUT) -> str:
        args = ["docker", "exec", self.name, "curl", "-sS", "-m", str(timeout), "-H", f"Authorization: {self.key}"]
        for field in fields:
            args += ["-F" if field.startswith("file=@") else "--data-urlencode", field]
        args.append(f"{API}/api/v1/{endpoint}")
        result = self.run(args, timeout=timeout + 60)
        if result.returncode != 0:
            raise MobSFError(f"MobSF {endpoint} failed: {(result.stderr or '').strip()[-300:]}")
        return result.stdout or ""

    def analyse(self, path: Path, out: Path) -> dict:
        """Upload, scan and fetch the JSON report of one file; returns the report."""
        inside = f"/tmp/{secrets.token_hex(4)}-{re.sub(r'[^A-Za-z0-9._-]', '_', path.name)}"  # nosec B108
        copied = self.run(["docker", "cp", str(path), f"{self.name}:{inside}"], timeout=600)
        if copied.returncode != 0:
            raise MobSFError(f"docker cp {path.name} failed: {(copied.stderr or '').strip()[-300:]}")
        # docker cp keeps the file's mode, and MobSF does not run as root: an app readable by its
        # owner only (a umask of 077) made the upload fail with "curl: (26) Failed to open/read".
        readable = self.run(["docker", "exec", "-u", "0", self.name, "chmod", "a+r", inside], timeout=60)
        if readable.returncode != 0:
            raise MobSFError(f"Could not make {path.name} readable for MobSF: {(readable.stderr or '').strip()[-300:]}")
        upload = _json(self.api("upload", f"file=@{inside}"), "upload")
        if not upload.get("hash"):
            raise MobSFError(f"MobSF did not accept {path.name}: {upload.get('error') or upload}")
        scan = _json(self.api("scan", f"hash={upload['hash']}"), "scan")
        if scan.get("error"):
            raise MobSFError(f"MobSF could not analyse {path.name}: {scan['error']}")
        text = self.api("report_json", f"hash={upload['hash']}")
        report = _json(text, "report_json")
        if not isinstance(report.get("app_type"), str):
            raise MobSFError(f"MobSF returned no report for {path.name}: {str(report.get('error') or '')[:300]}")
        out.write_text(text, encoding="utf-8")
        return report

    def stop(self) -> None:
        if self.started:
            self.run(["docker", "rm", "-f", "-v", self.name])
            self.started = False


def _json(text: str, endpoint: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise MobSFError(f"MobSF {endpoint} answered no JSON: {text[:200]!r}") from e
    if not isinstance(data, dict):
        raise MobSFError(f"MobSF {endpoint} answered {type(data).__name__}, not an object")
    return data


def counts(report: dict) -> tuple:
    """(findings, severe): MobSF's own scorecard, high and warning, and high."""
    appsec = report.get("appsec") if isinstance(report.get("appsec"), dict) else {}
    high = len(appsec.get("high") or [])
    return high + len(appsec.get("warning") or []), high


DEBUG_BUILD_WARNING = (
    "{app} is a debug build: what only a debug build has (android:debuggable, the debug certificate, "
    "LeakCanary, the Compose preview activity) is reported as findings of the app. Scan the release build "
    "(./gradlew assembleRelease or bundleRelease) or the source instead."
)


def is_debug_build(report: dict) -> bool:
    """A built Android app with android:debuggable=true or signed with the debug certificate."""
    if str(report.get("app_type") or "").lower() not in ("apk", "aab", "apks", "xapk"):
        return False
    manifest = report.get("manifest_analysis") if isinstance(report.get("manifest_analysis"), dict) else {}
    for finding in manifest.get("manifest_findings") or []:
        if isinstance(finding, dict) and "android:debuggable=true" in str(finding.get("title") or ""):
            return True
    certificate = report.get("certificate_analysis") if isinstance(report.get("certificate_analysis"), dict) else {}
    for finding in certificate.get("certificate_findings") or []:
        if isinstance(finding, list) and any("debug certificate" in str(part).lower() for part in finding):
            return True
    return False


# --- main ------------------------------------------------------------------------------


def resolve(root: Path, apps: List[str], sources: List[str], app_root: Optional[Path] = None) -> List[Target]:
    targets = [resolve_app(app_root or root, a) for a in apps if a.strip()]
    targets += [resolve_source(root, s) for s in sources if s.strip()]
    names = [t.report_name for t in targets]
    duplicate = next((n for n in names if names.count(n) > 1), None)
    if duplicate:
        raise MobSFError(f"Two inputs would both write {duplicate}; give them distinct paths.")
    return targets


def split_lines(values: Optional[List[str]]) -> List[str]:
    """Repeated arguments and newline-separated ones (a multi-line CI input) alike."""
    lines: List[str] = []
    for value in values or []:
        lines += [line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith("#")]
    return lines


def scan(
    root: Path,
    out: Path,
    apps: List[str],
    sources: List[str],
    image: str = MOBSF_IMAGE,
    start_timeout: int = START_TIMEOUT,
    log: Callable[[str], None] = _log,
    run: Runner = _run,
    app_root: Optional[Path] = None,
    name: str = "",
) -> List[dict]:
    """Analyses every target; returns one row per target: label, report, findings, severe, error."""
    targets = resolve(root, apps, sources, app_root)
    if not targets:
        raise MobSFError("Nothing to analyse: give --app or --source.")
    if shutil.which("docker") is None and run is _run:
        raise MobSFError("MobSF runs in Docker, and the docker command is not available here.")
    out.mkdir(parents=True, exist_ok=True)
    rows: List[dict] = []
    mobsf = MobSF(image, run=run, log=log, name=name)
    with tempfile.TemporaryDirectory(prefix="tdxguard-mobsf-") as temporary:
        try:
            log(f"Starting MobSF ({image}); MobSF downloads its decompiler first, which takes one to three minutes.")
            started = time.monotonic()
            mobsf.start(start_timeout)
            mobsf.isolate()
            log(f"MobSF is up after {round(time.monotonic() - started)}s; its network is cut.")
            for target in targets:
                row = {"label": f"MobSF ({target.kind}: {target.argument})", "report": target.report_name}
                try:
                    path = target.path
                    if target.kind == "source":
                        path = Path(temporary) / f"{target.slug}.zip"
                        left_out: List[str] = []
                        files = zip_source(target.path, path, left_out)
                        log(f"Zipped the {target.platform} project {target.argument}: {files} files.")
                        if left_out:
                            row["warning"] = (
                                f"Left out of the {target.platform} source {len(left_out)} property list(s) that do "
                                f"not parse, which MobSF fails on: {', '.join(left_out[:5])}. Fix or delete them."
                            )
                            log(f"WARNING: {row['warning']}")
                    begun = time.monotonic()
                    report = mobsf.analyse(path, out / target.report_name)
                    row["findings"], row["severe"] = counts(report)
                    if is_debug_build(report):
                        row["warning"] = DEBUG_BUILD_WARNING.format(app=target.argument)
                        log(f"WARNING: {row['warning']}")
                    log(
                        f"{target.report_name}: {report.get('app_type')} analysed in "
                        f"{round(time.monotonic() - begun)}s, {row['findings']} findings ({row['severe']} high)."
                    )
                except (MobSFError, OSError, subprocess.TimeoutExpired) as e:
                    row["error"] = str(e)
                    if target.kind == "source" and target.platform == "ios" and "could not analyse" in str(e):
                        row["error"] = IOS_SOURCE_FAILED.format(source=target.argument, error=e)
                    log(f"ERROR: {target.argument}: {row['error']}")
                rows.append(row)
        finally:
            mobsf.stop()
    return rows


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="mobsf-scan.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=".", help="the repository root (default: .)")
    parser.add_argument("--out", required=True, help="the directory the reports are written to")
    parser.add_argument("--app", action="append", help="a built app (.apk/.aab/.ipa), relative to the root")
    parser.add_argument("--source", action="append", help="android[:DIR] or ios[:DIR], a project to zip and analyse")
    parser.add_argument("--app-root", help="where the --app paths start (default: the root)")
    parser.add_argument("--name", default="", help="the container's name (default: random)")
    parser.add_argument("--image", default=MOBSF_IMAGE, help=f"the MobSF image (default: {MOBSF_IMAGE})")
    parser.add_argument("--start-timeout", type=int, default=START_TIMEOUT, help="seconds to wait for MobSF to start")
    args = parser.parse_args(argv)
    try:
        rows = scan(
            Path(args.root).resolve(),
            Path(args.out),
            split_lines(args.app),
            split_lines(args.source),
            image=args.image,
            start_timeout=args.start_timeout,
            app_root=Path(args.app_root).resolve() if args.app_root else None,
            name=args.name,
        )
    except MobSFError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 1 if any(row.get("error") for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
