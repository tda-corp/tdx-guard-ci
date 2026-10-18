"""
The PDF of the report: a Chromium-based browser already on the machine prints the HTML
headless. Nothing is downloaded; without a browser the user prints the HTML themselves.

The report's print CSS sets A4, the margins and the page numbers (@page margin boxes, which
Chrome supports since version 131); the browser's own header and footer (date, file URL) are
switched off.
"""

from __future__ import annotations

import ntpath
import os
import platform
import posixpath
import re
import shutil
import signal
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Mapping, Optional, Sequence, Tuple

from tdxguard.errors import CLIError, ConfigError

ENV_BROWSER = "TDXGUARD_BROWSER"
PRINT_TIMEOUT = 180

# (name, path below /Applications or ~/Applications)
MACOS_APPS: Sequence[Tuple[str, str]] = (
    ("Google Chrome", "Google Chrome.app/Contents/MacOS/Google Chrome"),
    ("Microsoft Edge", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    ("Chromium", "Chromium.app/Contents/MacOS/Chromium"),
    ("Brave", "Brave Browser.app/Contents/MacOS/Brave Browser"),
)
# (name, path below %ProgramFiles%, %ProgramFiles(x86)% or %LocalAppData%)
WINDOWS_APPS: Sequence[Tuple[str, str]] = (
    ("Google Chrome", r"Google\Chrome\Application\chrome.exe"),
    ("Microsoft Edge", r"Microsoft\Edge\Application\msedge.exe"),
    ("Chromium", r"Chromium\Application\chrome.exe"),
    ("Brave", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
)
WINDOWS_ROOTS = ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData")
# Programs looked up on PATH, per system, in this order.
PATH_NAMES = {
    "Darwin": (("Chromium", "chromium"), ("Google Chrome", "google-chrome")),
    "Windows": (("Google Chrome", "chrome"), ("Microsoft Edge", "msedge"), ("Chromium", "chromium")),
    "Linux": (
        ("Google Chrome", "google-chrome"),
        ("Google Chrome", "google-chrome-stable"),
        ("Chromium", "chromium"),
        ("Chromium", "chromium-browser"),
        ("Microsoft Edge", "microsoft-edge"),
        ("Microsoft Edge", "microsoft-edge-stable"),
        ("Brave", "brave-browser"),
    ),
}


@dataclass(frozen=True)
class Browser:
    name: str
    path: str


def candidates(system: str, environ: Mapping[str, str], home: str) -> List[Browser]:
    """The fixed install locations of the system, most common first."""
    if system == "Darwin":
        roots = ["/Applications", posixpath.join(home, "Applications")]
        return [Browser(name, posixpath.join(root, app)) for name, app in MACOS_APPS for root in roots]
    if system == "Windows":
        lowered = {key.lower(): value for key, value in environ.items()}
        roots = [lowered[name.lower()] for name in WINDOWS_ROOTS if lowered.get(name.lower())]
        return [Browser(name, ntpath.join(root, app)) for name, app in WINDOWS_APPS for root in roots]
    return []


def find_browser(
    environ: Optional[Mapping[str, str]] = None,
    system: Optional[str] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    is_file: Callable[[str], bool] = os.path.isfile,
    home: Optional[str] = None,
) -> Optional[Browser]:
    """TDXGUARD_BROWSER, else the usual install locations, else PATH; None when there is none."""
    environ = os.environ if environ is None else environ
    system = system or platform.system()
    chosen = (environ.get(ENV_BROWSER) or "").strip()
    if chosen:
        path = chosen if is_file(chosen) else which(chosen)
        if not path:
            raise ConfigError(
                f"{ENV_BROWSER} is {chosen}, which is not a file or a program on PATH.",
                "Set it to the path of Chrome, Chromium or Edge, or unset it.",
            )
        return Browser(Path(path).stem, path)
    for browser in candidates(system, environ, home or os.path.expanduser("~")):
        if is_file(browser.path):
            return browser
    for name, program in PATH_NAMES.get(system, PATH_NAMES["Linux"]):
        path = which(program)
        if path:
            return Browser(name, path)
    return None


def print_command(browser: Browser, html: Path, pdf: Path, profile: str, as_root: bool = False) -> List[str]:
    command = [
        browser.path,
        "--headless",
        "--disable-gpu",
        "--disable-extensions",
        "--no-first-run",
        "--no-default-browser-check",
        # A profile of its own: works while the user's browser is open, and leaves it alone.
        f"--user-data-dir={profile}",
        # Without the date, title and file URL Chrome would print on every page.
        "--no-pdf-header-footer",
        "--print-to-pdf-no-header",  # the same, before Chrome 120
        f"--print-to-pdf={pdf}",
    ]
    if as_root:
        # Chrome refuses to start its sandbox as root (containers, CI runners).
        command.append("--no-sandbox")
    command.append(html.resolve().as_uri())
    return command


def print_to_pdf(browser: Browser, html: Path, pdf: Path, timeout: float = PRINT_TIMEOUT) -> None:
    """Prints `html` to `pdf`; raises CLIError when the browser fails or takes too long."""
    try:
        pdf.unlink()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise CLIError(f"Cannot replace {pdf}: {error.strerror or error}") from error
    as_root = platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() == 0
    hint = f"Open {html} in a browser and print it to PDF (A4, no headers and footers)."
    profile = tempfile.mkdtemp(prefix="tdxguard-browser-")
    try:
        command = print_command(browser, html, pdf.resolve(), profile, as_root)
        code, output = _run(command, timeout, browser, hint)
    finally:
        # The browser may still hold files of its profile for a moment (Windows).
        shutil.rmtree(profile, ignore_errors=True)
    if code != 0 or not is_pdf(pdf):
        last = _last_line(output)
        raise CLIError(
            f"{browser.name} did not write the PDF (exit code {code}{': ' + last if last else ''}).",
            hint,
        )


def _run(command: List[str], timeout: float, browser: Browser, hint: str) -> Tuple[int, str]:
    # Its own process group, so that a timeout also stops the renderer processes.
    kwargs: dict = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **kwargs)  # nosec B603
    except OSError as error:
        raise CLIError(f"Cannot start {browser.name} ({browser.path}): {error.strerror or error}", hint) from error
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(process)
        raise CLIError(f"{browser.name} did not finish the PDF within {int(timeout)} s.", hint) from None
    return process.returncode, output.decode("utf-8", "replace")


def _kill(process: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(  # nosec B603 B607
                ["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def _last_line(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1][:200] if lines else ""


def is_pdf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(5) == b"%PDF-"
    except OSError:
        return False


_PAGE = re.compile(rb"/Type\s*/Page(?![a-zA-Z])")


def page_count(path: Path) -> int:
    """Pages of a PDF Chrome wrote (it keeps page objects uncompressed); 0 when unknown."""
    try:
        return len(_PAGE.findall(path.read_bytes()))
    except OSError:
        return 0
