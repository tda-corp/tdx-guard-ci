"""What the tool needs to know about the repository: root, remote, branch."""

from __future__ import annotations

import re
import subprocess  # nosec B404
from pathlib import Path
from typing import List, Optional, Tuple


def _git(args: List[str], cwd: Path) -> Optional[str]:
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def find_root(start: Optional[Path] = None) -> Optional[Path]:
    start = (start or Path.cwd()).resolve()
    top = _git(["rev-parse", "--show-toplevel"], start)
    return Path(top).resolve() if top else None


def remote_url(root: Path) -> Optional[str]:
    url = _git(["remote", "get-url", "origin"], root)
    if url:
        return url
    remotes = _git(["remote"], root)
    if remotes:
        return _git(["remote", "get-url", remotes.splitlines()[0]], root)
    return None


def current_branch(root: Path) -> str:
    branch = _git(["symbolic-ref", "--quiet", "--short", "HEAD"], root)
    if branch:
        return branch
    sha = _git(["rev-parse", "--short", "HEAD"], root)
    return f"detached-{sha}" if sha else "no-commit"


def parse_remote(url: str) -> Tuple[str, str]:
    """
    Returns (repository path, repository name) of a remote URL:
      git@github.com:tda-corp/tdx-scribe.git   -> ("tda-corp/tdx-scribe", "tdx-scribe")
      https://gitlab.example.com/a/b/c.git     -> ("a/b/c", "c")
    """
    url = (url or "").strip()
    match = re.match(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+:(.+)$", url)
    if match:
        path = match.group(1)
    else:
        path = re.sub(r"^[a-z+]+://", "", url)
        path = path.split("/", 1)[1] if "/" in path else ""
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    name = path.rsplit("/", 1)[-1] if path else ""
    return path, name
