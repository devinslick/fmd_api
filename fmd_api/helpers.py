"""Small helper utilities."""

import base64


def _pad_base64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def b64_decode_padded(s: str) -> bytes:
    return base64.b64decode(_pad_base64(s))


# Placeholder for pagination helpers, parse helpers, etc.
