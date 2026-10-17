"""The TDxGuard REST API, as far as the command line tool needs it."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, Mapping, Optional

from tdxguard import http
from tdxguard.credentials import normalize_server
from tdxguard.errors import ApiError, AuthenticationError

RUNTIME_CONFIG_PATTERN = re.compile(r"__RUNTIME_CONFIG__\s*=\s*(\{.*?\})\s*;?\s*$", re.DOTALL)


def fetch_runtime_config(server: str) -> Dict[str, str]:
    """
    The frontend learns OIDC_AUTHORITY, OIDC_CLIENT_ID, OIDC_SCOPE and API_BASE_URL from
    <server>/runtime-env.js. Reading the same file keeps the tool free of hard-coded
    identity provider settings. Returns {} when the file cannot be read.
    """
    response = http.get(normalize_server(server) + "/runtime-env.js", headers={"Accept": "*/*"}, timeout=15)
    if not response.ok:
        return {}
    return parse_runtime_config(response.body.decode("utf-8", errors="replace"))


def parse_runtime_config(text: str) -> Dict[str, str]:
    match = RUNTIME_CONFIG_PATTERN.search(text.strip())
    if not match:
        return {}
    try:
        data = json.loads(match.group(1))
    except ValueError:
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


class Client:
    def __init__(self, api_url: str, token: Optional[str] = None, bearer: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        if token:
            self.auth_header = {"Authorization": f"APIToken {token}"}
        elif bearer:
            self.auth_header = {"Authorization": f"Bearer {bearer}"}
        else:
            self.auth_header = {}

    def _url(self, path: str) -> str:
        return self.api_url + "/" + path.lstrip("/")

    def _check(self, response: http.Response, what: str) -> Any:
        if response.ok:
            return response.json()
        message = _server_message(response)
        if response.status == 401:
            raise AuthenticationError(f"TDxGuard rejected the token: {message}")
        raise ApiError(f"{what} failed (HTTP {response.status}): {message}", response.status)

    # --- authentication ---

    def create_cli_token(self, label: str) -> Dict[str, Any]:
        """Needs the client to be built with bearer=<id_token>."""
        response = http.post_json(self._url("authentication/cli_token/"), {"name": label}, self.auth_header)
        return self._check(response, "Creating the API token")

    def revoke_cli_token(self) -> None:
        response = http.request("POST", self._url("authentication/cli_token/revoke/"), headers=self.auth_header)
        self._check(response, "Revoking the API token")

    def me(self) -> Dict[str, Any]:
        response = http.get(self._url("users/me/"), self.auth_header)
        return self._check(response, "Reading the current user")

    # --- products ---

    def find_product(self, name: str) -> Optional[Dict[str, Any]]:
        """Exact match by name; the API's name filter is a substring match."""
        query = urllib.parse.urlencode({"name": name, "page_size": 1000})
        response = http.get(self._url(f"products/?{query}"), self.auth_header)
        data = self._check(response, "Looking up the product")
        results = data.get("results", data) if isinstance(data, dict) else data
        for product in results or []:
            if isinstance(product, dict) and product.get("name") == name:
                return product
        return None

    def onboard(self, name: str, repository: str) -> Dict[str, Any]:
        response = http.post_json(self._url("onboarding/"), {"name": name, "repository": repository}, self.auth_header)
        if response.status == 403:
            raise ApiError(
                f"You may not create the project {name} in TDxGuard: {_server_message(response)}",
                403,
                "External users can scan existing projects only. Ask a TDxGuard user to create it.",
            )
        return self._check(response, f"Creating the project {name}")

    # --- import ---

    def upload(self, path: str, fields: Mapping[str, str]) -> Dict[str, Any]:
        response = http.post_multipart(
            self._url("import/file_upload_observations_by_name/"), fields, {"file": path}, self.auth_header
        )
        return self._check(response, f"Uploading {path.rsplit('/', 1)[-1]}")


def _server_message(response: http.Response) -> str:
    data = response.json()
    if isinstance(data, dict):
        for key in ("message", "detail", "error"):
            if data.get(key):
                return str(data[key])
        return json.dumps(data)[:300]
    return response.text() or "no details"
