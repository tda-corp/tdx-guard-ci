"""
The standalone executable: `tdxguard` built with PyInstaller into one file (see
cli/packaging/), for machines without Python.

A frozen executable has no separate interpreter: `sys.executable` is the executable itself,
and there is no `python3` to run a script with. Everything that would start Python goes
through this module instead:

- the engine's helper scripts (tdxguard/engine/helpers/*.py, bundled as data files) run as
  `<executable> __helper <name> <args>`, a hidden command that executes the bundled script
  as `__main__` in a fresh process, exactly like `python3 -I -X utf8 <script> <args>` does
  for the package;
- TLS: the interpreter inside the executable was built on another machine, and its OpenSSL
  looks for CA certificates where that machine kept them, so the system's bundle is loaded
  explicitly.

Without PyInstaller, none of this changes anything: `is_frozen()` is false and the package
behaves as it always did.
"""

from __future__ import annotations

import os
import platform as platform_module
import runpy
import ssl
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from tdxguard.engine.helpers import OPENGREP_PRUNE_RULES, SARIF_ENRICH

HELPER_COMMAND = "__helper"
# The helpers by the name the CI templates give them.
HELPERS = {
    "sarif-enrich": SARIF_ENRICH,
    "opengrep-prune-rules": OPENGREP_PRUNE_RULES,
}

# Where Linux distributions and macOS keep the system CA bundle (Debian/Ubuntu/Alpine,
# Fedora/RHEL, openSUSE, macOS and the BSDs).
SYSTEM_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
)


def is_frozen() -> bool:
    """True inside the PyInstaller executable."""
    return bool(getattr(sys, "frozen", False))


def helper_command(script: Path, arguments: Sequence[str]) -> List[str]:
    """
    The command that runs a helper script with `arguments`. From the package: the current
    interpreter, isolated (-I: nothing in the scanned repository, the working directory, can
    shadow a module) and in UTF-8 mode (-X utf8: the rule files and reports are UTF-8
    whatever the locale). Frozen: the executable itself with the hidden helper command,
    which gives the same guarantees (see run_helper).
    """
    if not is_frozen():
        return [sys.executable, "-I", "-X", "utf8", str(script), *arguments]
    names = {path.name: name for name, path in HELPERS.items()}
    if script.name not in names:
        raise ValueError(f"not a bundled helper: {script}")
    return [sys.executable, HELPER_COMMAND, names[script.name], *arguments]


def run_helper(argv: Sequence[str]) -> int:
    """
    `tdxguard __helper <name> <args>`: runs a bundled helper script as `__main__`, with
    `sys.argv` as `python3 <script> <args>` would set it. Returns its exit status.

    Isolation: the executable's module path holds only the bundle, never the working
    directory, and `runpy.run_path` of a file adds nothing to it. UTF-8: the executable is
    built in UTF-8 mode (packaging/tdxguard.spec); a build without it is refused here rather
    than reading rule files in the Windows code page.
    """
    if not argv or argv[0] not in HELPERS:
        print(f"tdxguard {HELPER_COMMAND}: expected one of {', '.join(sorted(HELPERS))}", file=sys.stderr)
        return 2
    if is_frozen() and not sys.flags.utf8_mode:
        print(f"tdxguard {HELPER_COMMAND}: this executable was built without UTF-8 mode", file=sys.stderr)
        return 2
    script = HELPERS[argv[0]]
    cwd = os.getcwd()
    sys.path[:] = [entry for entry in sys.path if entry not in ("", ".", cwd)]
    saved_argv = sys.argv
    sys.argv = [str(script), *argv[1:]]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as e:
        return _exit_status(e.code)
    finally:
        sys.argv = saved_argv
    return 0


def _exit_status(code: object) -> int:
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    print(code, file=sys.stderr)
    return 1


def ssl_context(cafile: Optional[str] = None) -> Optional[ssl.SSLContext]:
    """
    The TLS context for downloads and API calls. An explicit CA bundle (TDXGUARD_CA_BUNDLE
    and friends, found by the caller) always wins. From the package, None: urllib's default,
    as before. Frozen on Linux and macOS: the default context plus the system's CA bundle,
    because the bundled OpenSSL's built-in certificate directory belongs to the build
    machine. Windows reads the system certificate store anyway.
    """
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    if not is_frozen() or os.name == "nt":
        return None
    context = ssl.create_default_context()
    for path in SYSTEM_CA_BUNDLES:
        if os.path.isfile(path):
            try:
                context.load_verify_locations(cafile=path)
            except (OSError, ssl.SSLError):
                continue
            break
    return context


def platform_label() -> str:
    """os-arch of this machine, for `tdxguard --version`."""
    system = platform_module.system().lower() or sys.platform
    machine = platform_module.machine().lower() or "unknown"
    machine = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return f"{system}-{machine}"


def version_line(version: str) -> str:
    """What `tdxguard --version` prints."""
    if is_frozen():
        runtime = "standalone"
    else:
        runtime = f"python {platform_module.python_version()}"
    return f"tdxguard {version} ({platform_label()}, {runtime})"
