"""Helper utilities for FMD API."""
import base64


def pad_base64(s: str) -> str:
    """Add padding to base64 string if needed.
    
    Args:
        s: Base64 string that may be missing padding
        
    Returns:
        Properly padded base64 string
    """
    return s + '=' * (-len(s) % 4)


def decode_base64(s: str) -> bytes:
    """Decode base64 string, adding padding if needed.
    
    Args:
        s: Base64 string
        
    Returns:
        Decoded bytes
    """
    return base64.b64decode(pad_base64(s))


def encode_base64(data: bytes, strip_padding: bool = True) -> str:
    """Encode bytes to base64 string.
    
    Args:
        data: Bytes to encode
        strip_padding: If True, remove padding characters
        
    Returns:
        Base64 encoded string
    """
    encoded = base64.b64encode(data).decode('utf-8')
    if strip_padding:
        return encoded.rstrip('=')
    return encoded
