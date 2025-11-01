"""Exception types for FMD API."""


class FmdApiException(Exception):
    """Base exception for FMD API errors."""
    pass


class FmdAuthenticationError(FmdApiException):
    """Raised when authentication fails."""
    pass


class FmdDecryptionError(FmdApiException):
    """Raised when data decryption fails."""
    pass


class FmdApiRequestError(FmdApiException):
    """Raised when an API request fails."""
    pass


class FmdInvalidDataError(FmdApiException):
    """Raised when received data is invalid or corrupted."""
    pass
