"""A small HTTP client on top of urllib: JSON, forms and multipart uploads."""

from __future__ import annotations

import json
import mimetypes
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from tdxguard import __version__, frozen
from tdxguard.errors import NetworkError

USER_AGENT = f"tdxguard-cli/{__version__}"
DEFAULT_TIMEOUT = 60


@dataclass
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8") or "null")
        except (UnicodeDecodeError, ValueError):
            return None

    def text(self, limit: int = 300) -> str:
        return self.body.decode("utf-8", errors="replace")[:limit]


def request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Response:
    """Sends a request. An HTTP error status is returned, not raised; a network failure raises."""
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    all_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=all_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:  # nosec B310
            return Response(resp.status, resp.read(), dict(resp.headers))
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b""
        return Response(e.code, body, dict(e.headers or {}))
    except urllib.error.URLError as e:
        raise NetworkError(f"Cannot reach {_origin(url)}: {e.reason}", "Check the address and your connection.") from e
    except (TimeoutError, OSError) as e:
        raise NetworkError(f"Cannot reach {_origin(url)}: {e}", "Check the address and your connection.") from e


def get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = DEFAULT_TIMEOUT) -> Response:
    return request("GET", url, headers=headers, timeout=timeout)


def post_json(url: str, payload: Any, headers: Optional[Dict[str, str]] = None) -> Response:
    all_headers = {"Content-Type": "application/json"}
    all_headers.update(headers or {})
    return request("POST", url, headers=all_headers, data=json.dumps(payload).encode("utf-8"))


def post_form(url: str, fields: Mapping[str, str], headers: Optional[Dict[str, str]] = None) -> Response:
    all_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    all_headers.update(headers or {})
    return request("POST", url, headers=all_headers, data=urllib.parse.urlencode(fields).encode("ascii"))


def post_multipart(
    url: str,
    fields: Mapping[str, str],
    files: Mapping[str, str],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 600,
) -> Response:
    """`files` maps the form field to a local path."""
    body, content_type = encode_multipart(fields, files)
    all_headers = {"Content-Type": content_type}
    all_headers.update(headers or {})
    return request("POST", url, headers=all_headers, data=body, timeout=timeout)


def encode_multipart(fields: Mapping[str, str], files: Mapping[str, str]) -> Tuple[bytes, str]:
    boundary = f"----tdxguard{uuid.uuid4().hex}"
    lines = []
    for name, value in fields.items():
        lines.append(f"--{boundary}".encode())
        lines.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        lines.append(b"")
        lines.append(str(value).encode("utf-8"))
    for name, path in files.items():
        filename = os.path.basename(path)
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        with open(path, "rb") as f:
            content = f.read()
        lines.append(f"--{boundary}".encode())
        lines.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode())
        lines.append(f"Content-Type: {mime}".encode())
        lines.append(b"")
        lines.append(content)
    lines.append(f"--{boundary}--".encode())
    lines.append(b"")
    return b"\r\n".join(lines), f"multipart/form-data; boundary={boundary}"


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else url


def _ssl_context() -> Optional[ssl.SSLContext]:
    # Respect a corporate CA bundle the same way curl and requests do.
    for variable in ("TDXGUARD_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        path = os.environ.get(variable)
        if path and os.path.isfile(path):
            return frozen.ssl_context(cafile=path)
    return frozen.ssl_context()
