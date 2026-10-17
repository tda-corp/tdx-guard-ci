"""OAuth 2.0 device authorization grant (RFC 8628) against the identity provider."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from tdxguard import http
from tdxguard.errors import LoginError

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SLOW_DOWN_STEP = 5  # seconds, RFC 8628 section 3.5


@dataclass
class Endpoints:
    device_authorization: str
    token: str


@dataclass
class DeviceAuthorization:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


def discover(authority: str) -> Endpoints:
    url = authority.rstrip("/") + "/.well-known/openid-configuration"
    response = http.get(url)
    data = response.json()
    if not response.ok or not isinstance(data, dict):
        raise LoginError(f"Could not read the identity provider's configuration at {url} (HTTP {response.status}).")
    device = data.get("device_authorization_endpoint")
    token = data.get("token_endpoint")
    if not device or not token:
        raise LoginError(f"The identity provider {authority} does not offer the device authorization grant.")
    return Endpoints(device_authorization=device, token=token)


def start(endpoints: Endpoints, client_id: str, scope: str) -> DeviceAuthorization:
    response = http.post_form(endpoints.device_authorization, {"client_id": client_id, "scope": scope})
    data = response.json()
    if not response.ok or not isinstance(data, dict) or not data.get("device_code"):
        raise LoginError(
            f"The identity provider refused to start the login (HTTP {response.status}): {_describe_error(data)}",
            "Is the client allowed to use the device flow? Check --client-id.",
        )
    verification_uri = data.get("verification_uri") or data.get("verification_url") or ""
    return DeviceAuthorization(
        device_code=data["device_code"],
        user_code=data.get("user_code", ""),
        verification_uri=verification_uri,
        verification_uri_complete=data.get("verification_uri_complete") or verification_uri,
        expires_in=int(data.get("expires_in") or 600),
        interval=int(data.get("interval") or 5),
    )


PostForm = Callable[[str, Mapping[str, str]], http.Response]


def poll(
    endpoints: Endpoints,
    client_id: str,
    authorization: DeviceAuthorization,
    *,
    post_form: Optional[PostForm] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    on_wait: Optional[Callable[[], None]] = None,
) -> Dict[str, Any]:
    """
    Polls the token endpoint until the user has confirmed (returns the token response),
    declined (access_denied) or the code expired (expired_token or our own deadline).
    """
    post_form = post_form or (lambda url, fields: http.post_form(url, fields))
    interval = max(1, authorization.interval)
    deadline = clock() + authorization.expires_in
    fields = {"grant_type": DEVICE_CODE_GRANT, "device_code": authorization.device_code, "client_id": client_id}

    while True:
        if clock() >= deadline:
            raise LoginError("The login code expired before it was confirmed.", "Run `tdxguard login` again.")
        sleep(interval)

        response = post_form(endpoints.token, fields)
        data = response.json()
        if response.ok and isinstance(data, dict) and (data.get("id_token") or data.get("access_token")):
            return data

        error = _error_code(data)
        if error == "authorization_pending":
            if on_wait:
                on_wait()
            continue
        if error == "slow_down":
            interval += SLOW_DOWN_STEP
            continue
        if error == "expired_token":
            raise LoginError("The login code expired before it was confirmed.", "Run `tdxguard login` again.")
        if error == "access_denied":
            raise LoginError("The login was declined in the browser.")
        raise LoginError(f"The identity provider answered HTTP {response.status}: {_describe_error(data)}")


KNOWN_ERRORS = ("authorization_pending", "slow_down", "expired_token", "access_denied")


def _error_code(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    error = str(data.get("error") or "")
    if error in KNOWN_ERRORS:
        return error
    # Some providers put the code into a message field only.
    text = " ".join(str(data.get(k) or "") for k in ("error", "error_description", "message")).lower()
    for code in KNOWN_ERRORS:
        if code in text:
            return code
    return error


def _describe_error(data: Any) -> str:
    if isinstance(data, dict):
        parts = [str(data.get(k)) for k in ("error", "error_description", "message") if data.get(k)]
        if parts:
            return ": ".join(parts)
    return "no details"
