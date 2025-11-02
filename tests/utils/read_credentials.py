"""
Utility: read credentials from credentials.txt (KEY=VALUE lines)

Place credentials.txt in tests/utils/ or set environment variables.
"""
from pathlib import Path
import os


def read_credentials(path: str | Path = None) -> dict:
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
    # fallback to environment for keys not provided
    for k in ("BASE_URL", "FMD_ID", "PASSWORD", "DEVICE_ID"):
        if k not in creds and os.getenv(k):
            creds[k] = os.getenv(k)
    return creds
