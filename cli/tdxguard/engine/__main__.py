"""
`python3 -m tdxguard.engine`: the scanner image's command line (its entrypoint
ci-templates/scanner/tdxguard-scan only sets the locale and calls this). The contract:

    docker run --rm -v <repo>:/src:ro -v <outdir>:/out \\
      [-v /var/run/docker.sock:/var/run/docker.sock] [-v <trivy-cache>:/cache] \\
      ghcr.io/tda-corp/tdxguard-scanner:v1 scan \\
      [--exclude <path>]... [--image <ref>=<slug>]... [--remote-image <ref>=<slug>]... \\
      [--skip betterleaks|opengrep|trivy|zizmor|image]... [--secrets-mode dir|git] [--log-opts <opts>]

Exit status: 0 the scans ran (findings are not an error), 1 at least one scanner failed
(listed in summary.json "errors"), 2 bad usage or an unusable /src or /out.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from tdxguard.engine import scan, tools
from tdxguard.errors import ToolError

SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

USAGE = """\
Usage:
  tdxguard-scan scan [options]   scan /src, write the reports and summary.json to /out
  tdxguard-scan --version        print the image and scanner versions
  tdxguard-scan --help           this text

Options of `scan`:
  --exclude <path>            exclude a path or glob, on top of the CI defaults
                              (node_modules, .venv, vendor, dist, build, *.md, *.example
                              for Opengrep; node_modules, .venv, vendor for Trivy).
                              Applies to Opengrep and Trivy fs. Repeatable.
  --image <ref>=<slug>        also scan this image through the mounted Docker socket and
                              write sbom-image-<slug>.cdx.json + trivy-image-<slug>.sarif.
                              Repeatable.
  --remote-image <ref>=<slug> the same for an image Trivy pulls from its registry
                              (--image-src remote); needs no Docker socket. Repeatable.
  --skip <scanner>            betterleaks, opengrep, trivy, zizmor or image. Repeatable.
  --secrets-mode dir|git      dir (default): the whole working tree;
                              git: the git history (CI scans only the new commits).
  --log-opts <git-log-opts>   with --secrets-mode git, limit the history the way CI does,
                              e.g. "origin/main..HEAD". Default: the whole history.

Mounts:
  /src    the repository, read-only is fine (required)
  /out    where the reports go, must be writable by the container user (required)
  /cache  Trivy's DB and checks cache; makes repeated scans fast (optional)
  /var/run/docker.sock   needed for --image with locally built images (optional)

Reports in /out: betterleaks.json, opengrep.sarif, trivy.sarif, sbom.cdx.json, zizmor.sarif,
sbom-image-<slug>.cdx.json, trivy-image-<slug>.sarif, summary.json.

Exit status: 0 the scans ran (findings are not an error), 1 a scanner failed (see
"errors" in summary.json), 2 bad usage or unusable mounts.
"""


class UsageError(Exception):
    pass


def print_version(version: str) -> None:
    print(f"tdxguard-scanner {version}")
    print(f"betterleaks {tools.BETTERLEAKS_VERSION}")
    print(f"opengrep {tools.OPENGREP_VERSION} (rules {tools.OPENGREP_RULES_SHA})")
    print(f"trivy {tools.TRIVY_VERSION}")


def parse(argv: Sequence[str]) -> Tuple[Dict[str, object], bool]:
    """
    Parses the options of `scan` exactly like the bash entrypoint did: `--opt value` and
    `--opt=value`, an empty value is an error, unknown options are errors. Returns the
    options and whether --help was asked for.
    """
    options: Dict[str, object] = {
        "excludes": [],
        "images": [],
        "skips": [],
        "secrets_mode": "dir",
        "log_opts": "",
    }
    excludes: List[str] = options["excludes"]  # type: ignore[assignment]
    images: List[scan.ImageTarget] = options["images"]  # type: ignore[assignment]
    skips: List[str] = options["skips"]  # type: ignore[assignment]
    arguments = list(argv)
    i = 0

    def value(name: str) -> str:
        nonlocal i
        argument = arguments[i]
        if argument.startswith(name + "="):
            i += 1
            return argument[len(name) + 1 :]
        if i + 1 >= len(arguments) or arguments[i + 1] == "":
            raise UsageError(f"{name} needs a value")
        i += 2
        return arguments[i - 1]

    while i < len(arguments):
        argument = arguments[i]
        name = argument.split("=", 1)[0]
        if name == "--exclude":
            excludes.append(value(name))
        elif name in ("--image", "--remote-image"):
            spec = value(name)
            if "=" not in spec:
                raise UsageError(f"{name} expects <ref>=<slug>, got: {spec}")
            ref, slug = spec.rsplit("=", 1)
            if not ref:
                raise UsageError(f"{name} has an empty reference: {spec}")
            # The slug becomes part of a file name; keep it to what the template's slugs are made of.
            if not SLUG.match(slug):
                raise UsageError(f"{name} slug must match [a-z0-9][a-z0-9._-]*, got: {slug}")
            images.append(scan.ImageTarget(ref, slug, remote=name == "--remote-image"))
        elif name == "--skip":
            scanner = value(name)
            if scanner not in scan.SCANNERS:
                raise UsageError(f"--skip expects betterleaks, opengrep, trivy, zizmor or image, got: {scanner}")
            skips.append(scanner)
        elif name == "--secrets-mode":
            mode = value(name)
            if mode not in scan.SECRETS_MODES:
                raise UsageError(f"--secrets-mode expects dir or git, got: {mode}")
            options["secrets_mode"] = mode
        elif name == "--log-opts":
            options["log_opts"] = value(name)
        elif argument in ("--help", "-h"):
            return options, True
        else:
            raise UsageError(f"unknown option: {argument}")
    return options, False


def container_environment(work: Path, uid: str) -> Dict[str, str]:
    """
    The image runs as UID 10001 by default but must work under any `--user`, so nothing may
    assume a home directory or a passwd entry.
    """
    environment = dict(os.environ)
    home = environment.get("HOME", "")
    if not home or not os.access(home, os.W_OK):
        home = str(work / "home")
        os.makedirs(home, exist_ok=True)
        environment["HOME"] = home
    environment.setdefault("XDG_CACHE_HOME", os.path.join(home, ".cache"))
    # /src belongs to the host user, not to the container's UID, and git refuses to read a
    # repository owned by someone else ("dubious ownership"). The environment form needs no
    # writable config file.
    environment.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"})
    # Trivy's DB and checks bundle: /cache when it is mounted and writable, else throwaway.
    if not environment.get("TRIVY_CACHE_DIR"):
        if os.path.isdir("/cache") and os.access("/cache", os.W_OK):
            environment["TRIVY_CACHE_DIR"] = "/cache"
        else:
            if os.path.isdir("/cache"):
                print(
                    f"==> /cache is mounted but not writable by UID {uid}; using a temporary Trivy cache",
                    file=sys.stderr,
                )
            environment["TRIVY_CACHE_DIR"] = str(work / "trivy-cache")
    return environment


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    version = os.environ.get("TDXGUARD_SCANNER_VERSION", "dev")
    command = argv[0] if argv else ""
    if command in ("--version", "version"):
        print_version(version)
        return scan.EXIT_OK
    if command in ("--help", "-h", "help", ""):
        print(USAGE, end="")
        return scan.EXIT_OK
    if command != "scan":
        return _usage_error(f"unknown command: {command}")
    try:
        parsed, wants_help = parse(argv[1:])
    except UsageError as e:
        return _usage_error(str(e))
    if wants_help:
        print(USAGE, end="")
        return scan.EXIT_OK

    src = Path(os.environ.get("TDXGUARD_SRC", "/src"))
    out = Path(os.environ.get("TDXGUARD_OUT", "/out"))
    uid = str(os.getuid()) if hasattr(os, "getuid") else "?"
    if not src.is_dir() or not os.access(src, os.R_OK | os.X_OK):
        print(f"tdxguard-scan: {src} is not a readable directory; mount the repository there.", file=sys.stderr)
        return scan.EXIT_USAGE
    if not out.is_dir() or not os.access(out, os.W_OK):
        print(
            f"tdxguard-scan: {out} is not writable by UID {uid}; mount a writable directory there "
            '(and run with --user "$(id -u):$(id -g)").',
            file=sys.stderr,
        )
        return scan.EXIT_USAGE

    try:
        platform = tools.detect_platform()
        toolset = tools.toolset(platform, tools.tools_dir())
    except ToolError as e:
        print(f"tdxguard-scan: {e.message}", file=sys.stderr)
        return scan.EXIT_USAGE

    try:
        home = Path(tempfile.mkdtemp(prefix="tdxguard-home."))
    except OSError:
        print(f"tdxguard-scan: cannot create a work directory under {tempfile.gettempdir()}", file=sys.stderr)
        return scan.EXIT_USAGE
    try:
        environment = container_environment(home, uid)
        options = scan.Options(
            src=src,
            out=out,
            excludes=parsed["excludes"],  # type: ignore[arg-type]
            images=parsed["images"],  # type: ignore[arg-type]
            skips=parsed["skips"],  # type: ignore[arg-type]
            secrets_mode=str(parsed["secrets_mode"]),
            log_opts=str(parsed["log_opts"]),
            engine="docker",
            version=version,
            check_docker_socket=True,
        )
        return scan.Scan(options, toolset, scan.scanner_environment(environment)).run()
    finally:
        shutil.rmtree(str(home), ignore_errors=True)


def _usage_error(message: str) -> int:
    print(f"tdxguard-scan: {message}\n", file=sys.stderr)
    print(USAGE, end="", file=sys.stderr)
    return scan.EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
