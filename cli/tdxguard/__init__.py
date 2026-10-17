"""tdxguard: scan a repository locally and send the results to TDxGuard."""

__version__ = "0.1.0"

DEFAULT_SERVER = "https://guard.tdadevelop.com"
# Fallbacks only: `tdxguard login` reads the OIDC settings from the server's runtime
# configuration (the one the frontend uses) and needs these only when that fails.
DEFAULT_OIDC_AUTHORITY = "https://sso.tdadevelop.com"
DEFAULT_OIDC_CLIENT_ID = "5148b93c-2952-4f73-887b-c5f4b1bd2288"
DEFAULT_OIDC_SCOPE = "openid profile email groups"
DEFAULT_SCANNER_IMAGE = "ghcr.io/tda-corp/tdxguard-scanner:v1"
