"""Helper functions for the fmd_api package.

This module contains utility functions used across the fmd_api package,
including base64 padding, encryption helpers, and data conversion utilities.
"""

import base64


def pad_base64(s: str) -> str:
    """Add padding to base64 strings that may be missing it.
    
    The FMD server sometimes returns base64 strings without proper padding.
    This function adds the necessary '=' padding characters.
    
    Args:
        s: Base64 string that may be missing padding
        
    Returns:
        Properly padded base64 string
        
    Example:
        >>> pad_base64("SGVsbG8")
        'SGVsbG8='
    """
    return s + '=' * (-len(s) % 4)


def decode_base64(s: str) -> bytes:
    """Decode a base64 string, adding padding if necessary.
    
    Args:
        s: Base64 string to decode (may be missing padding)
        
    Returns:
        Decoded bytes
        
    Example:
        >>> decode_base64("SGVsbG8")
        b'Hello'
    """
    return base64.b64decode(pad_base64(s))


def encode_base64(data: bytes, strip_padding: bool = True) -> str:
    """Encode bytes to base64 string.
    
    Args:
        data: Bytes to encode
        strip_padding: If True, remove trailing '=' padding (default: True)
        
    Returns:
        Base64 encoded string
        
    Example:
        >>> encode_base64(b'Hello')
        'SGVsbG8'
    """
    encoded = base64.b64encode(data).decode('utf-8')
    if strip_padding:
        encoded = encoded.rstrip('=')
    return encoded
