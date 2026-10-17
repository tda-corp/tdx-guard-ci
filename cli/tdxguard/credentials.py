"""Where the API token lives: ~/.config/tdxguard/credentials.json, or the environment."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Optional

from tdxguard import DEFAULT_SERVER
from tdxguard.errors import NotLoggedInError

ENV_TOKEN = "TDXGUARD_TOKEN"
ENV_SERVER = "TDXGUARD_SERVER"


@dataclass
class Credentials:
    server: str
    token: str
    name: str = ""
    username: str = ""
    expires: str = ""
    # Where the REST API lives; usually <server>/api.
    api_url: str = ""
    # "file" or "environment"; not stored.
    source: str = "file"

    @property
    def api(self) -> str:
        return (self.api_url or api_url_for(self.server)).rstrip("/")


def normalize_server(server: str) -> str:
    """https://guard.example.com/ and https://guard.example.com/api both mean the frontend base."""
    server = (server or "").strip().rstrip("/")
    if not server:
        return DEFAULT_SERVER
    if "://" not in server:
        server = "https://" + server
    if server.endswith("/api"):
        server = server[: -len("/api")]
    return server


def api_url_for(server: str) -> str:
    return normalize_server(server) + "/api"


def config_dir(environ: Optional[Mapping[str, str]] = None) -> Path:
    environ = os.environ if environ is None else environ
    base = environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "tdxguard"


def credentials_path(environ: Optional[Mapping[str, str]] = None) -> Path:
    return config_dir(environ) / "credentials.json"


def load_file(environ: Optional[Mapping[str, str]] = None) -> Optional[Credentials]:
    path = credentials_path(environ)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("token"):
        return None
    return Credentials(
        server=normalize_server(str(data.get("server", ""))),
        token=str(data["token"]),
        name=str(data.get("name", "")),
        username=str(data.get("username", "")),
        expires=str(data.get("expires", "")),
        api_url=str(data.get("api_url", "")),
        source="file",
    )


def load(environ: Optional[Mapping[str, str]] = None) -> Optional[Credentials]:
    """TDXGUARD_TOKEN (with TDXGUARD_SERVER) wins over the file."""
    environ = os.environ if environ is None else environ
    token = environ.get(ENV_TOKEN, "").strip()
    if token:
        return Credentials(server=normalize_server(environ.get(ENV_SERVER, "")), token=token, source="environment")
    return load_file(environ)


def require(environ: Optional[Mapping[str, str]] = None) -> Credentials:
    credentials = load(environ)
    if not credentials:
        raise NotLoggedInError()
    return credentials


def save(credentials: Credentials, environ: Optional[Mapping[str, str]] = None) -> Path:
    """Writes the file with mode 0600 in a directory with mode 0700, atomically."""
    directory = config_dir(environ)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)

    data = asdict(credentials)
    data.pop("source", None)

    # mkstemp creates the file with mode 0600, so the token is never readable by others,
    # not even for a moment.
    fd, tmp_path = tempfile.mkstemp(prefix=".credentials-", dir=str(directory))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        path = credentials_path(environ)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
        return path
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def delete(environ: Optional[Mapping[str, str]] = None) -> bool:
    try:
        credentials_path(environ).unlink()
        return True
    except FileNotFoundError:
        return False
