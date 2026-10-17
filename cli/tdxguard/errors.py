"""Exceptions that end a command with a message for the user instead of a traceback."""

# Exit codes
EXIT_OK = 0
EXIT_GATE = 1  # the quality gate of .tdxguard.yml was exceeded
EXIT_ERROR = 2  # the scan or the upload did not complete, or the tool could not run


class CLIError(Exception):
    """An error with a message meant for the user. `hint` says what to do about it."""

    exit_code = EXIT_ERROR

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint


class ConfigError(CLIError):
    pass


class NotLoggedInError(CLIError):
    def __init__(self, message: str = "You are not logged in to TDxGuard."):
        super().__init__(
            message,
            "Run `tdxguard login`, or set TDXGUARD_TOKEN (and TDXGUARD_SERVER) for CI and scripts.",
        )


class AuthenticationError(CLIError):
    """The server rejected the token: expired, revoked or wrong server."""

    def __init__(self, message: str = "TDxGuard rejected the token (expired or revoked)."):
        super().__init__(message, "Run `tdxguard login` to get a new one.")


class NetworkError(CLIError):
    pass


class ApiError(CLIError):
    def __init__(self, message: str, status: int = 0, hint: str = ""):
        super().__init__(message, hint)
        self.status = status


class DockerError(CLIError):
    pass


class ToolError(CLIError):
    """A scanner tool of the native engine cannot be downloaded, verified or run."""


class LoginError(CLIError):
    pass
