"""Small helper utilities for base64 handling."""

import base64


def _pad_base64(s: str) -> str:
    """Add padding to a base64 string if needed."""
    return s + "=" * (-len(s) % 4)


def b64_decode_padded(s: str) -> bytes:
    """Decode a base64 string, adding padding if necessary."""
    return base64.b64decode(_pad_base64(s))
