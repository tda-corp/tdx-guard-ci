"""Docker: checks, image builds and the scanner container."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Deque, List, Optional, Sequence, Tuple

from tdxguard.errors import DockerError

CONTAINER_SOCKET = "/var/run/docker.sock"
DEFAULT_HOST_SOCKET = "/var/run/docker.sock"


def ensure_available() -> None:
    if not shutil.which("docker"):
        raise DockerError(
            "Docker is not installed or not on the PATH.",
            "Install Docker Desktop (macOS, Windows) or Docker Engine (Linux): https://docs.docker.com/get-docker/",
        )
    try:
        result = subprocess.run(  # nosec B603 B607
            ["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        raise DockerError("Docker does not answer.", "Is Docker Desktop starting up? Try again in a moment.") from None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        hint = "Start Docker Desktop, or the Docker service (sudo systemctl start docker)."
        if detail and "permission denied" in detail[-1].lower():
            hint = "Add your user to the docker group (sudo usermod -aG docker $USER) and log in again."
        raise DockerError("Docker is not running or not reachable" + (f": {detail[-1]}" if detail else "."), hint)


def is_available() -> bool:
    """Whether a Docker daemon answers: the `auto` engine's choice."""
    try:
        ensure_available()
        return True
    except DockerError:
        return False


def image_usable(image: str, timeout: int = 600) -> bool:
    """
    Whether the scanner image is on this machine or can be pulled. The `auto` engine uses
    Docker only then: a registry that refuses the pull (a private package, no `docker login`)
    used to end the scan with an error although the native engine would have worked.
    """
    try:
        present = subprocess.run(  # nosec B603 B607
            ["docker", "image", "inspect", image], capture_output=True, text=True, timeout=30
        )
        if present.returncode == 0:
            return True
        pulled = subprocess.run(  # nosec B603 B607
            ["docker", "pull", "-q", image], capture_output=True, text=True, timeout=timeout
        )
        return pulled.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@dataclass
class Socket:
    """The Docker socket as the daemon sees it (the -v source) and the group to add."""

    path: str
    group: Optional[int]


def detect_socket(
    platform: str = sys.platform,
    context_host: Optional[str] = None,
    environ: Optional[dict] = None,
    stat: Callable[[str], os.stat_result] = os.stat,
) -> Socket:
    """
    The -v source is resolved by the DAEMON, not by this machine. On Linux the daemon runs
    here, so the endpoint of the current Docker context is the right path (rootless Docker
    uses /run/user/<uid>/docker.sock). Docker Desktop, Colima and OrbStack run the daemon in
    a VM where the socket is /var/run/docker.sock, whatever the context on the Mac says.

    The socket is owned by root and a docker group, while the scanner runs as the
    invoking user: --group-add with the socket's group lets it in.
    """
    environ = os.environ if environ is None else environ
    override = environ.get("TDXGUARD_DOCKER_SOCKET")
    if override:
        return Socket(override, _group_of(override, stat))

    if platform.startswith("linux"):
        if context_host is None:
            context_host = current_context_host()
        if context_host and context_host.startswith("unix://"):
            path = context_host[len("unix://") :]
            return Socket(path, _group_of(path, stat))
        return Socket(DEFAULT_HOST_SOCKET, _group_of(DEFAULT_HOST_SOCKET, stat))

    # In the VM the socket belongs to root:root; group 0 is what gets the scanner in.
    return Socket(DEFAULT_HOST_SOCKET, 0)


def _group_of(path: str, stat: Callable[[str], os.stat_result]) -> Optional[int]:
    try:
        return stat(path).st_gid
    except OSError:
        return None


def current_context_host() -> Optional[str]:
    try:
        result = subprocess.run(  # nosec B603 B607
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    host = result.stdout.strip()
    return host if result.returncode == 0 and host else None


def build_command(dockerfile: str, context: str, ref: str) -> List[str]:
    return ["docker", "build", "-f", dockerfile, "-t", ref, context]


def scanner_command(
    *,
    image: str,
    src: str,
    out: str,
    cache: str,
    uid: Optional[int],
    gid: Optional[int],
    socket: Optional[Socket] = None,
    excludes: Sequence[str] = (),
    images: Sequence[Tuple[str, str]] = (),
    remote_images: Sequence[Tuple[str, str]] = (),
    skips: Sequence[str] = (),
    secrets_mode: Optional[str] = None,
    log_opts: Optional[str] = None,
) -> List[str]:
    """
    The scanner image's contract:
      docker run --rm -v <gitroot>:/src:ro -v <outdir>:/out [-v <socket>:/var/run/docker.sock]
        -v <cache>:/cache --user <uid>:<gid> [--group-add <gid>] <image> scan
        [--exclude <path>]... [--image <ref>=<slug>]... [--remote-image <ref>=<slug>]...
        [--skip <scanner>]... [--secrets-mode dir|git] [--log-opts=<git log options>]
    The socket is mounted only when locally built images are scanned; registry images
    (--remote-image) are pulled by Trivy itself. Exit codes: 0 the scans ran, 1 a
    scanner failed (summary.json is still written), 2 bad usage or unusable mounts.
    """
    scans_images = bool(images) and "image" not in skips
    scans_remote = bool(remote_images) and "image" not in skips
    command = ["docker", "run", "--rm", "-v", f"{src}:/src:ro", "-v", f"{out}:/out"]
    if scans_images and socket:
        command += ["-v", f"{socket.path}:{CONTAINER_SOCKET}"]
    command += ["-v", f"{cache}:/cache"]
    if uid is not None and gid is not None:
        command += ["--user", f"{uid}:{gid}"]
    if scans_images and socket and socket.group is not None and socket.group != gid:
        command += ["--group-add", str(socket.group)]
    command += [image, "scan"]
    for path in excludes:
        command += ["--exclude", path]
    if scans_images:
        for ref, slug in images:
            command += ["--image", f"{ref}={slug}"]
    if scans_remote:
        for ref, slug in remote_images:
            command += ["--remote-image", f"{ref}={slug}"]
    for scanner in skips:
        command += ["--skip", scanner]
    if secrets_mode:
        command += ["--secrets-mode", secrets_mode]
    if log_opts:
        # One argument with =, since git log options start with a dash themselves.
        command.append(f"--log-opts={log_opts}")
    return command


def run(command: Sequence[str], *, verbose: bool, cwd: Optional[Path] = None, tail: int = 40) -> Tuple[int, str]:
    """
    Runs a command. With verbose the output streams through; otherwise only the last
    lines are kept, to show when it fails. Returns (exit code, kept output).
    """
    try:
        process = subprocess.Popen(  # nosec B603
            list(command),
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except OSError as e:
        raise DockerError(f"Could not run {command[0]}: {e}") from e
    kept: Deque[str] = deque(maxlen=tail)
    assert process.stdout is not None  # nosec B101
    for line in process.stdout:
        kept.append(line.rstrip("\n"))
        if verbose:
            print("    " + line.rstrip("\n"), file=sys.stderr, flush=True)
    return process.wait(), "\n".join(kept)
