"""
Utility: read credentials from credentials.txt (KEY=VALUE lines)

Place credentials.txt in tests/utils/ or set environment variables.
"""

from pathlib import Path
from typing import Optional, Union, Dict
import os


def read_credentials(path: Optional[Union[str, Path]] = None) -> Dict[str, str]:
    """Return dict of credentials from the given file. Falls back to env vars if not present."""
    creds = {}
    if path is None:
        # Default to tests/utils/credentials.txt
        path = Path(__file__).parent / "credentials.txt"
    p = Path(path)
    if p.exists():
        for ln in p.read_text().splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if "=" in ln:
                k, v = ln.split("=", 1)
                creds[k.strip()] = v.strip()
    # Fallback to environment for keys not provided.
    # Only accept non-empty values to avoid silently using empty strings.
    for k in ("BASE_URL", "FMD_ID", "PASSWORD", "DEVICE_ID"):
        if k not in creds:
            val = os.getenv(k)
            if val:  # skip None and empty strings
                creds[k] = val
    return creds
