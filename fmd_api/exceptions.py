"""Exception classes for the fmd_api package.

This module defines custom exceptions used throughout the fmd_api package
for better error handling and debugging.
"""


class FmdApiException(Exception):
    """Base exception for all FMD API errors.
    
    This is the base class for all exceptions raised by the fmd_api package.
    Catching this exception will catch all fmd_api-specific errors.
    """
    pass


class AuthenticationError(FmdApiException):
    """Raised when authentication with the FMD server fails.
    
    This can occur due to:
    - Invalid credentials (wrong device ID or password)
    - Expired session token
    - Network connectivity issues during authentication
    """
    pass


class DecryptionError(FmdApiException):
    """Raised when data blob decryption fails.
    
    This can occur due to:
    - Corrupted or invalid encrypted data from server
    - Wrong private key being used
    - Data blob too small or malformed
    """
    pass


class ApiRequestError(FmdApiException):
    """Raised when an API request to the FMD server fails.
    
    This can occur due to:
    - Network connectivity issues
    - Server errors (5xx status codes)
    - Invalid request parameters
    """
    pass


class CommandError(FmdApiException):
    """Raised when sending a command to the device fails.
    
    This can occur due to:
    - Invalid command format
    - Command signing failure
    - Device not responding
    """
    pass
