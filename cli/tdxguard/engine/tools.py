"""
The scanner tools: the ONE table of pinned versions and sha256 checksums, and their
installation into a cache directory.

The scanner image installs its tools with this very module (ci-templates/scanner/Dockerfile
runs `python3 -m tdxguard.engine.tools install --platform linux-<arch> --dir ...`), so the
image and the native engine run the same binaries, verified against the same checksums.

The versions and the rule commit MUST move together with the env blocks of the betterleaks,
opengrep, trivy and image_scan jobs in ci-templates/github/tdxguard.yml, until the template
runs the scanner image itself. Every checksum comes from the release's own checksum file
(Betterleaks `checksums.txt`, Trivy `trivy_<v>_checksums.txt`) or, where there is none
(Opengrep, the opengrep-rules archive), from the GitHub release API asset digest; see
ci-templates/scanner/README.md for how to refresh them. Never guess one.

Layout: <tools dir>/<tool>/<version>/<binary>, the tools dir being $TDXGUARD_TOOLS_DIR or
~/.cache/tdxguard/tools ($XDG_CACHE_HOME/tdxguard/tools). An install downloads into a
temporary directory next to the target, verifies the checksum, unpacks, and renames the
directory into place, so a version directory that exists is complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as platform_module
import shutil
import ssl
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Callable, Dict, List, Optional, Sequence

from tdxguard import __version__, frozen
from tdxguard.errors import ToolError

ENV_TOOLS_DIR = "TDXGUARD_TOOLS_DIR"
MARKER = ".tdxguard-install.json"
DOWNLOAD_TIMEOUT = 120
CHUNK = 1024 * 1024

# Rule directories kept from opengrep-rules: the security/ directories below these roots,
# as the template's "Fetch Opengrep and its rules" step selects them. This is the one list:
# both CI templates (OPENGREP_RULE_LANGUAGES), ci-templates/local/tdxguard-scan.sh, the
# scanner image (built with this module), `tdxguard doctor` and the report's methodology
# section follow it, and tests fail when one of them differs.
#
# Application languages only. Left out on purpose:
#   terraform, yaml, dockerfile, json  infrastructure as code, which Trivy covers.
#   solidity, apex, ocaml, clojure     no TDA product is written in them; solidity's rules
#                                      are DeFi exploit patterns.
#   bash, html                         curl-pipe-to-shell and missing-integrity checks that
#                                      report deliberate install scripts and CDN links.
RULE_LANGUAGES = (
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
MIN_RULES = 100

# Supported platforms. Opengrep ships separate Linux builds for glibc (manylinux) and musl.
PLATFORMS = {
    "darwin-arm64": "macOS arm64",
    "darwin-x86_64": "macOS x86_64",
    "linux-x86_64": "Linux x86_64 (glibc)",
    "linux-aarch64": "Linux aarch64 (glibc)",
    "linux-x86_64-musl": "Linux x86_64 (musl)",
    "linux-aarch64-musl": "Linux aarch64 (musl)",
    "windows-x86_64": "Windows x86_64",
}
ANY_PLATFORM = "any"


@dataclass(frozen=True)
class Asset:
    name: str  # the file name in the release
    sha256: str
    member: str = ""  # the binary inside the archive; empty: the asset is the binary


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    url: str  # with {version} and {asset}
    assets: Dict[str, Asset]
    binary: str = ""  # the installed executable, without .exe; empty for the rules

    def asset_for(self, platform: str) -> Asset:
        """The asset of a platform key; a musl platform falls back to the static glibc-free build."""
        for key in (platform, platform.replace("-musl", ""), ANY_PLATFORM):
            if key in self.assets:
                return self.assets[key]
        raise ToolError(
            f"{self.name} {self.version} has no build for {PLATFORMS.get(platform, platform)}.",
            "Use the Docker engine instead: tdxguard scan --engine docker",
        )

    def download_url(self, asset: Asset) -> str:
        return self.url.format(version=self.version, asset=asset.name)

    def executable_name(self, platform: str) -> str:
        return self.binary + (".exe" if platform.startswith("windows") else "")


BETTERLEAKS_VERSION = "1.8.1"
OPENGREP_VERSION = "1.29.0"
OPENGREP_RULES_SHA = "f1d2b562b414783763fd02a6ed2736eaed622efa"
TRIVY_VERSION = "0.74.0"

# fmt: off
TOOLS: Dict[str, Tool] = {
    # sha256 from https://github.com/betterleaks/betterleaks/releases/download/v1.8.1/checksums.txt
    "betterleaks": Tool(
        name="betterleaks",
        version=BETTERLEAKS_VERSION,
        url="https://github.com/betterleaks/betterleaks/releases/download/v{version}/{asset}",
        binary="betterleaks",
        assets={
            "darwin-arm64": Asset("betterleaks_1.8.1_darwin_arm64.tar.gz",
                                  "8e80f33b5f2a7426b390347b9fd466033723cb94b6bdffa7572632e2eaec964e", "betterleaks"),
            "darwin-x86_64": Asset("betterleaks_1.8.1_darwin_x64.tar.gz",
                                   "6abc37df76f881cffae406aa2cec72bea6e6ae64b4e771b3ed21b4aac472ed10", "betterleaks"),
            "linux-x86_64": Asset("betterleaks_1.8.1_linux_x64.tar.gz",
                                  "efa407244e1ea8e35f582b8a42becdeac08bdead04f68eb752adda722d583c2a", "betterleaks"),
            "linux-aarch64": Asset("betterleaks_1.8.1_linux_arm64.tar.gz",
                                   "bbb578b12a2f65d7082ab436abf37724232bc71d8a078e3c41336574420f1b48", "betterleaks"),
            "windows-x86_64": Asset("betterleaks_1.8.1_windows_x64.zip",
                                    "94310d028285a1bcce7f160bc19eb62f87de6460c95bfd4319151ef5b501ed3f",
                                    "betterleaks.exe"),
        },
    ),
    # Opengrep publishes no checksum file: sha256 from the asset digests of
    # `gh api repos/opengrep/opengrep/releases/tags/v1.29.0`.
    "opengrep": Tool(
        name="opengrep",
        version=OPENGREP_VERSION,
        url="https://github.com/opengrep/opengrep/releases/download/v{version}/{asset}",
        binary="opengrep",
        assets={
            "darwin-arm64": Asset("opengrep_osx_arm64",
                                  "dacc12a24e95b22c8b1ab55be1777b6eb877a922c5571a95b9a8de30f3963438"),
            "darwin-x86_64": Asset("opengrep_osx_x86",
                                   "7173bd701491b58e1d1f62c24470ca0be124ecd63885c4d6293cbf71fd706508"),
            "linux-x86_64": Asset("opengrep_manylinux_x86",
                                  "3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13"),
            "linux-aarch64": Asset("opengrep_manylinux_aarch64",
                                   "db3cda6e6e53251a3874e62b7c8493c281508480b3f3b4db554be41583b21174"),
            "linux-x86_64-musl": Asset("opengrep_musllinux_x86",
                                       "1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b"),
            "linux-aarch64-musl": Asset("opengrep_musllinux_aarch64",
                                        "6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484"),
            "windows-x86_64": Asset("opengrep_windows_x86.exe",
                                    "ee485b31912704dc6410bc43f04b5c6ad896697db56e360a98204abf95fa1025"),
        },
    ),
    # The rules at a pinned commit, as GitHub's archive of it. sha256 of that archive, as
    # pinned since the scanner image's first version.
    "opengrep-rules": Tool(
        name="opengrep-rules",
        version=OPENGREP_RULES_SHA,
        url="https://github.com/opengrep/opengrep-rules/archive/{version}.tar.gz",
        assets={
            ANY_PLATFORM: Asset(f"{OPENGREP_RULES_SHA}.tar.gz",
                                "9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d"),
        },
    ),
    # sha256 from https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt
    "trivy": Tool(
        name="trivy",
        version=TRIVY_VERSION,
        url="https://github.com/aquasecurity/trivy/releases/download/v{version}/{asset}",
        binary="trivy",
        assets={
            "darwin-arm64": Asset("trivy_0.74.0_macOS-ARM64.tar.gz",
                                  "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11", "trivy"),
            "darwin-x86_64": Asset("trivy_0.74.0_macOS-64bit.tar.gz",
                                   "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485", "trivy"),
            "linux-x86_64": Asset("trivy_0.74.0_Linux-64bit.tar.gz",
                                  "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a", "trivy"),
            "linux-aarch64": Asset("trivy_0.74.0_Linux-ARM64.tar.gz",
                                   "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5", "trivy"),
            "windows-x86_64": Asset("trivy_0.74.0_windows-64bit.zip",
                                    "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842", "trivy.exe"),
        },
    ),
}
# fmt: on

Log = Callable[[str], None]


def _no_log(message: str) -> None:
    pass


# --- where ---


def cache_dir(environ: Optional[Dict[str, str]] = None) -> Path:
    """~/.cache/tdxguard, or $XDG_CACHE_HOME/tdxguard."""
    environ = os.environ if environ is None else environ  # type: ignore[assignment]
    base = environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "tdxguard"


def tools_dir(environ: Optional[Dict[str, str]] = None) -> Path:
    environ = os.environ if environ is None else environ  # type: ignore[assignment]
    override = environ.get(ENV_TOOLS_DIR)
    if override:
        return Path(override).expanduser()
    return cache_dir(environ) / "tools"


def install_dir(tool: Tool, root: Path) -> Path:
    return root / tool.name / tool.version


# --- which platform ---


def detect_platform(system: Optional[str] = None, machine: Optional[str] = None, libc: Optional[str] = None) -> str:
    """The platform key of this machine (or of the given values), e.g. darwin-arm64."""
    system = (system if system is not None else platform_module.system()).lower()
    machine = (machine if machine is not None else platform_module.machine()).lower()
    x86_64 = machine in ("x86_64", "amd64", "x64")
    arm64 = machine in ("arm64", "aarch64", "armv8", "armv8l")
    if system == "darwin":
        if arm64:
            return "darwin-arm64"
        if x86_64:
            return "darwin-x86_64"
    elif system == "linux":
        suffix = "-musl" if (libc if libc is not None else detect_libc()) == "musl" else ""
        if x86_64:
            return "linux-x86_64" + suffix
        if arm64:
            return "linux-aarch64" + suffix
    elif system == "windows" or system.startswith(("cygwin", "msys", "mingw")):
        if x86_64:
            return "windows-x86_64"
    raise ToolError(
        f"The native engine has no tools for {system} {machine}.",
        "Use the Docker engine instead: tdxguard scan --engine docker",
    )


def detect_libc() -> str:
    """glibc or musl (Alpine). Python built against musl reports no glibc version."""
    name, _ = platform_module.libc_ver()
    if name == "glibc":
        return "glibc"
    for directory in ("/lib", "/usr/lib"):
        try:
            if any(entry.startswith("ld-musl-") for entry in os.listdir(directory)):
                return "musl"
        except OSError:
            continue
    return "glibc"


# --- what is installed ---


@dataclass
class Toolset:
    """The paths the engine runs."""

    betterleaks: Path
    opengrep: Path
    trivy: Path
    rules: Path

    @staticmethod
    def versions() -> Dict[str, str]:
        """As summary.json's `tools` reports them."""
        return {
            "betterleaks": BETTERLEAKS_VERSION,
            "opengrep": OPENGREP_VERSION,
            "opengrep_rules": OPENGREP_RULES_SHA,
            "trivy": TRIVY_VERSION,
        }


def installed(tool: Tool, platform: str, root: Path) -> Optional[Path]:
    """
    The install directory when it holds this tool for this platform. The marker records
    the asset's checksum: a cache shared with another platform (a network home, Rosetta)
    or left by an older pin does not count as installed.
    """
    directory = install_dir(tool, root)
    try:
        with open(directory / MARKER, encoding="utf-8") as f:
            marker = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(marker, dict) or marker.get("sha256") != tool.asset_for(platform).sha256:
        return None
    # The rules are a selection from the archive: an install made for another language
    # list is stale although the archive is the same.
    if tool.name == "opengrep-rules" and marker.get("languages") != list(RULE_LANGUAGES):
        return None
    if tool.binary and not (directory / tool.executable_name(platform)).is_file():
        return None
    return directory


def toolset(platform: str, root: Path) -> Toolset:
    """The installed tools; ToolError naming the missing ones."""
    missing = [name for name, tool in TOOLS.items() if installed(tool, platform, root) is None]
    if missing:
        raise ToolError(
            f"Not installed in {root}: {', '.join(missing)}.",
            "Run `tdxguard tools install` (it needs the network once).",
        )
    return _toolset(platform, root)


def _toolset(platform: str, root: Path) -> Toolset:
    def binary(name: str) -> Path:
        tool = TOOLS[name]
        return install_dir(tool, root) / tool.executable_name(platform)

    return Toolset(
        betterleaks=binary("betterleaks"),
        opengrep=binary("opengrep"),
        trivy=binary("trivy"),
        rules=install_dir(TOOLS["opengrep-rules"], root),
    )


def ensure(platform: str, root: Path, log: Log = _no_log, downloader: Optional[Callable] = None) -> Toolset:
    """Installs what is missing, then returns the toolset."""
    for tool in TOOLS.values():
        if installed(tool, platform, root) is None:
            install(tool, platform, root, log=log, downloader=downloader)
    return _toolset(platform, root)


# --- install ---


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, expected: str, what: str) -> None:
    actual = sha256_of(path)
    if actual != expected.lower():
        raise ToolError(
            f"Checksum mismatch for {what}: expected sha256 {expected}, got {actual}.",
            "The download was corrupted or tampered with; nothing was installed. Try again, "
            "and report it if it persists.",
        )


def download(url: str, dest: Path) -> None:
    """Downloads url to dest. Proxies come from the usual environment variables."""
    request = urllib.request.Request(url, headers={"User-Agent": f"tdxguard-cli/{__version__}"})
    hint = (
        "The native engine downloads its tools once, into the tools cache. Connect to the "
        "network and run `tdxguard tools install`, or use --engine docker."
    )
    try:
        with urllib.request.urlopen(
            request, timeout=DOWNLOAD_TIMEOUT, context=_ssl_context()
        ) as response:  # nosec B310
            with open(dest, "wb") as f:
                shutil.copyfileobj(response, f, CHUNK)
    except urllib.error.HTTPError as e:
        raise ToolError(f"Download failed, HTTP {e.code}: {url}", hint) from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise ToolError(
                f"Download failed, the TLS certificate could not be verified: {url}",
                "Behind a TLS-intercepting proxy, set TDXGUARD_CA_BUNDLE to its CA bundle. With the "
                "python.org Python on macOS, run its 'Install Certificates.command' once.",
            ) from e
        raise ToolError(f"Download failed ({e.reason}): {url}", hint) from e
    except (OSError, TimeoutError) as e:
        raise ToolError(f"Download failed ({e}): {url}", hint) from e


def _ssl_context() -> Optional[ssl.SSLContext]:
    for variable in ("TDXGUARD_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        path = os.environ.get(variable)
        if path and os.path.isfile(path):
            return frozen.ssl_context(cafile=path)
    return frozen.ssl_context()


def install(
    tool: Tool,
    platform: str,
    root: Path,
    *,
    log: Log = _no_log,
    downloader: Optional[Callable[[str, Path], None]] = None,
    run_check: Optional[bool] = None,
) -> Path:
    """
    Downloads, verifies and unpacks one tool into <root>/<tool>/<version>, atomically.
    `run_check` (default: when the platform is this machine's) runs `opengrep --version`
    before the directory is renamed into place.
    """
    asset = tool.asset_for(platform)
    target = install_dir(tool, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if run_check is None:
        run_check = _is_host(platform)
    url = tool.download_url(asset)
    log(f"downloading {tool.name} {tool.version} ({asset.name})")

    # Both temporary directories sit next to the target: the final rename stays on one
    # file system, and an interrupted install leaves only dot-directories behind.
    staging = Path(tempfile.mkdtemp(prefix=f".{tool.version}.", suffix=".partial", dir=str(target.parent)))
    scratch = Path(tempfile.mkdtemp(prefix=".download.", dir=str(target.parent)))
    if os.name == "posix":
        # mkdtemp makes it 0700; the scanner image runs the tools under any --user.
        os.chmod(staging, 0o755)
    try:
        archive = scratch / asset.name
        (downloader or download)(url, archive)
        verify(archive, asset.sha256, asset.name)
        if tool.name == "opengrep-rules":
            count = extract_rules(archive, staging)
            log(f"  {count} security rules")
        else:
            executable = staging / tool.executable_name(platform)
            _extract_binary(archive, asset, executable)
            _make_executable(executable, platform)
            if tool.name == "opengrep" and run_check:
                check_opengrep(executable)
        marker: Dict[str, object] = {"tool": tool.name, "version": tool.version, "platform": platform,
                                     "asset": asset.name, "sha256": asset.sha256, "url": url}  # fmt: skip
        if tool.name == "opengrep-rules":
            marker["languages"] = list(RULE_LANGUAGES)
        with open(staging / MARKER, "w", encoding="utf-8") as f:
            json.dump(marker, f, indent=2)
        _move_into_place(staging, target, tool, platform, root)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(staging, ignore_errors=True)
    log(f"  installed in {target}")
    return target


def _move_into_place(staging: Path, target: Path, tool: Tool, platform: str, root: Path) -> None:
    if target.exists():
        if installed(tool, platform, root) is not None:
            return  # another process installed it meanwhile
        # A stale or foreign install: move it aside first, then drop it.
        old = Path(tempfile.mkdtemp(prefix=f".{tool.version}.", suffix=".old", dir=str(target.parent)))
        os.replace(str(target), str(old / "previous"))
        shutil.rmtree(old, ignore_errors=True)
    try:
        os.replace(str(staging), str(target))
    except OSError:
        if installed(tool, platform, root) is None:
            raise


def _is_host(platform: str) -> bool:
    try:
        return detect_platform() == platform
    except ToolError:
        return False


def _extract_binary(archive: Path, asset: Asset, dest: Path) -> None:
    if not asset.member:
        os.replace(str(archive), str(dest))
        return
    if asset.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if not info.is_dir() and PurePosixPath(info.filename).name == asset.member:
                    with zf.open(info) as source, open(dest, "wb") as out:
                        shutil.copyfileobj(source, out, CHUNK)
                    return
    else:
        with tarfile.open(archive, "r:*") as tf:
            for member in tf:
                if member.isfile() and PurePosixPath(member.name).name == asset.member:
                    _copy_member(tf, member, dest)
                    return
    raise ToolError(f"{asset.name} does not contain {asset.member}.")


def _copy_member(tf: tarfile.TarFile, member: tarfile.TarInfo, dest: Path) -> None:
    source: Optional[IO[bytes]] = tf.extractfile(member)
    if source is None:
        raise ToolError(f"Cannot read {member.name} from the archive.")
    with source, open(dest, "wb") as out:
        shutil.copyfileobj(source, out, CHUNK)


def extract_rules(archive: Path, dest: Path) -> int:
    """
    The security/ directories of opengrep-rules below RULE_LANGUAGES, with the archive's
    top directory stripped: what the Dockerfile's `find <roots> -type d -name security`
    plus `cp -R` used to produce. Only regular files are taken, every path is checked to
    stay inside dest. Returns the number of .yaml rules; fewer than MIN_RULES, or a
    language with none, means the ruleset's layout changed, which must not pass as a scan
    without rules.
    """
    root = dest.resolve()
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            parts = PurePosixPath(member.name).parts
            if len(parts) < 4 or not member.isfile():
                continue
            relative = parts[1:]  # --strip-components=1
            if relative[0] not in RULE_LANGUAGES or "security" not in relative[1:-1]:
                continue
            if any(part in ("", ".", "..") for part in relative) or PurePosixPath(member.name).is_absolute():
                raise ToolError(f"Refusing the archive entry {member.name!r}: it leaves the rules directory.")
            target = root.joinpath(*relative)
            if root not in target.resolve().parents:
                raise ToolError(f"Refusing the archive entry {member.name!r}: it leaves the rules directory.")
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_member(tf, member, target)
    count = sum(1 for _ in root.rglob("*.yaml"))
    if count < MIN_RULES:
        raise ToolError(f"Only {count} security rules found in the opengrep-rules archive; its layout changed.")
    # A language that lost its directory upstream would otherwise pass unnoticed in the total.
    empty = [language for language in RULE_LANGUAGES if not any((root / language).rglob("*.yaml"))]
    if empty:
        raise ToolError(f"No security rules for {', '.join(empty)} in the opengrep-rules archive; its layout changed.")
    if os.name == "posix":
        # Readable by any user: the scanner image runs under an arbitrary --user.
        for directory, _, files in os.walk(root):
            os.chmod(directory, 0o755)
            for name in files:
                os.chmod(os.path.join(directory, name), 0o644)
    return count


def _make_executable(path: Path, platform: str) -> None:
    if platform.startswith("windows") or os.name != "posix":
        return  # Windows has no executable bit; .exe is what makes it runnable
    os.chmod(path, 0o755)
    if sys.platform == "darwin":
        remove_quarantine(path)


def remove_quarantine(path: Path, run: Callable = subprocess.run) -> bool:
    """
    Gatekeeper refuses to start a binary carrying com.apple.quarantine. urllib does not set
    it, but a download tool or a managed Mac may; remove it only where it is present, and
    only on the file this module just wrote. Returns whether it was removed.
    """
    try:
        probe = run(["xattr", "-p", "com.apple.quarantine", str(path)], capture_output=True)  # nosec B603 B607
        if probe.returncode != 0:
            return False
        run(["xattr", "-d", "com.apple.quarantine", str(path)], capture_output=True, check=True)  # nosec B603 B607
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def check_opengrep(executable: Path) -> None:
    """`opengrep --version` must run and print the pinned version."""
    try:
        result = subprocess.run(  # nosec B603
            [str(executable), "--version"], capture_output=True, text=True, errors="replace", timeout=600
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ToolError(f"The downloaded opengrep does not run: {e}") from e
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0 or OPENGREP_VERSION not in output:
        raise ToolError(
            f"The downloaded opengrep does not run as expected (exit {result.returncode}): {output[-300:]}",
            "On Linux, check the C library: Opengrep has separate glibc (manylinux) and musl builds.",
        )


# --- maintenance ---


@dataclass
class Status:
    tool: Tool
    asset: Optional[Asset]
    path: Optional[Path]


def status(platform: str, root: Path) -> List[Status]:
    rows = []
    for tool in TOOLS.values():
        try:
            asset: Optional[Asset] = tool.asset_for(platform)
        except ToolError:
            asset = None
        rows.append(Status(tool, asset, installed(tool, platform, root) if asset else None))
    return rows


def clean(root: Path, unused_only: bool = False) -> List[Path]:
    """Removes the tools cache, or with unused_only the versions no longer pinned. Returns what went."""
    removed: List[Path] = []
    if not root.is_dir():
        return removed
    if not unused_only:
        shutil.rmtree(root)
        return [root]
    pinned = {(tool.name, tool.version) for tool in TOOLS.values()}
    for tool_directory in sorted(p for p in root.iterdir() if p.is_dir()):
        for version_directory in sorted(p for p in tool_directory.iterdir() if p.is_dir()):
            if (tool_directory.name, version_directory.name) not in pinned:
                shutil.rmtree(version_directory, ignore_errors=True)
                removed.append(version_directory)
    return removed


# --- python3 -m tdxguard.engine.tools: the Dockerfile's installer ---


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m tdxguard.engine.tools")
    sub = parser.add_subparsers(dest="command", required=True)
    install_parser = sub.add_parser("install", help="install the pinned tools")
    install_parser.add_argument("--platform", choices=sorted(PLATFORMS), help="default: this machine")
    install_parser.add_argument("--dir", help=f"tools directory (default: ${ENV_TOOLS_DIR} or the cache)")
    args = parser.parse_args(argv)

    root = Path(args.dir) if args.dir else tools_dir()
    target = args.platform or detect_platform()
    try:
        ensure(target, root, log=lambda message: print(message, file=sys.stderr, flush=True))
    except ToolError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
