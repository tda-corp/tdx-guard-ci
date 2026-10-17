"""
Builds the standalone `tdxguard` executable of this machine's platform with PyInstaller and
names it like the release asset: tdxguard-<version>-<os>-<arch>[.exe].

    python packaging/build.py [--expect-version X.Y.Z] [--out DIR]

Run it with an interpreter that has packaging/requirements-build.txt installed. The version
comes from tdxguard/__init__.py and must equal pyproject.toml's (and --expect-version, the
release tag, when given). In GitHub Actions the asset name and path are also written to
$GITHUB_OUTPUT as `asset` and `path`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path

CLI = Path(__file__).resolve().parents[1]
SPEC = CLI / "packaging" / "tdxguard.spec"

OPERATING_SYSTEMS = {"darwin": "darwin", "linux": "linux", "windows": "windows"}
ARCHITECTURES = {"x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}


def package_version() -> str:
    init = (CLI / "tdxguard" / "__init__.py").read_text(encoding="utf-8")
    pyproject = (CLI / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^__version__ = "([^"]+)"$', init, re.MULTILINE)
    project = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    if not version or not project:
        raise SystemExit("build: cannot read the version from tdxguard/__init__.py and pyproject.toml")
    if version.group(1) != project.group(1):
        raise SystemExit(
            f"build: tdxguard/__init__.py says {version.group(1)}, pyproject.toml says {project.group(1)}; " "bump both"
        )
    return version.group(1)


def asset_name(version: str) -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system not in OPERATING_SYSTEMS or machine not in ARCHITECTURES:
        raise SystemExit(f"build: no release asset for {system} {machine}")
    suffix = ".exe" if system == "windows" else ""
    return f"tdxguard-{version}-{OPERATING_SYSTEMS[system]}-{ARCHITECTURES[machine]}{suffix}"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--expect-version", help="fail unless the package has this version (the release tag's)")
    parser.add_argument("--out", default=str(CLI / "dist"), help="where the executable goes (default: cli/dist)")
    args = parser.parse_args()

    version = package_version()
    if args.expect_version and args.expect_version != version:
        raise SystemExit(f"build: the tag says {args.expect_version}, the package is {version}")
    name = asset_name(version)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    work = Path(tempfile.mkdtemp(prefix="tdxguard-build."))
    started = time.monotonic()
    try:
        subprocess.run(  # nosec B603
            [
                sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
                "--distpath", str(work / "dist"), "--workpath", str(work / "build"), str(SPEC),
            ],
            check=True,
            cwd=str(CLI),
        )  # fmt: skip
        built = work / "dist" / ("tdxguard.exe" if name.endswith(".exe") else "tdxguard")
        target = out / name
        shutil.copy2(built, target)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    size = target.stat().st_size
    print(f"{target}  {size / 1e6:.1f} MB  sha256 {sha256_of(target)}  ({time.monotonic() - started:.0f}s)")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"asset={name}\npath={target}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
