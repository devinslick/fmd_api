"""Typed exceptions for fmd_api v2."""


class FmdApiException(Exception):
    """Base exception for FMD API errors."""

    pass


class AuthenticationError(FmdApiException):
    """Raised when authentication fails."""

    pass


class DeviceNotFoundError(FmdApiException):
    """Raised when a requested device cannot be found."""

    pass


class RateLimitError(FmdApiException):
    """Raised when the server indicates rate limiting."""

    pass


class OperationError(FmdApiException):
    """Raised for failed operations (commands, downloads, etc)."""

    pass
