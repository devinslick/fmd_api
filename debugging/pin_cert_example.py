"""
Quick TLS test for FmdClient with certificate pinning or insecure mode.

Security note:
- Avoid passing passwords on the command line (they can end up in history). This script supports env vars
    and secure prompt input so you can omit --password.

Usage (PowerShell):
    # 1) Export server cert to PEM using Python stdlib
    #    Replace host as needed
    python - << 'PY'
import ssl
host = "fmd.example.com"
pem = ssl.get_server_certificate((host, 443))
open("server-cert.pem", "w").write(pem)
print("Wrote server-cert.pem for", host)
PY

    # 2) Set env vars (recommended)
    $env:FMD_ID = "<FMD_ID>"
    $env:FMD_PASSWORD = "<PASSWORD>"  # Consider Read-Host -AsSecureString for interactive use

    # 3) Try connecting with pinned cert (preferred for self-signed)
    python debugging/pin_cert_example.py --base-url https://fmd.example.com --ca server-cert.pem

    # 4) Or try insecure mode (development only)
    python debugging/pin_cert_example.py --base-url https://fmd.example.com --insecure
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
from pathlib import Path
import os
import getpass

from fmd_api import FmdClient


async def run(base_url: str, fmd_id: str, password: str, ca_path: str | None, insecure: bool) -> int:
    ssl_arg: object | None
    if insecure:
        ssl_arg = False
    elif ca_path:
        ctx = ssl.create_default_context()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(cafile=ca_path)
        ssl_arg = ctx
    else:
        ssl_arg = None  # system default validation

    try:
        async with await FmdClient.create(
            base_url,
            fmd_id,
            password,
            ssl=ssl_arg,
        ) as client:
            # Minimal call that exercises the API with auth
            # This will call /api/v1/locationDataSize
            locs = await client.get_locations(num_to_get=0)
            print("TLS OK; auth OK; available locations:", len(locs))
            return 0
    except Exception as e:
        print("Failed:", e)
        return 2


def main() -> int:
    p = argparse.ArgumentParser(description="FmdClient TLS/pinning test")
    p.add_argument("--base-url", required=True, help="Base URL, must be https://...")
    p.add_argument("--id", help="FMD user ID (or set FMD_ID env var)")
    p.add_argument("--password", help="FMD password (or set FMD_PASSWORD env var, or omit to be prompted)")
    p.add_argument("--ca", dest="ca_path", help="Path to PEM file to trust (pinning or custom CA)")
    p.add_argument("--insecure", action="store_true", help="Disable certificate validation (development only)")
    args = p.parse_args()

    if args.base_url.lower().startswith("http://"):
        p.error("--base-url must be HTTPS (http:// is not allowed)")

    if args.ca_path and not Path(args.ca_path).exists():
        p.error(f"--ca file not found: {args.ca_path}")

    if args.insecure and args.ca_path:
        p.error("Use either --ca or --insecure, not both.")

    # Resolve credentials from args, env, or prompt
    fmd_id = args.id or os.environ.get("FMD_ID")
    if not fmd_id:
        fmd_id = input("FMD ID: ")

    password = args.password or os.environ.get("FMD_PASSWORD")
    if not password:
        # Prompt securely without echo
        password = getpass.getpass("Password: ")

    return asyncio.run(run(args.base_url, fmd_id, password, args.ca_path, args.insecure))


if __name__ == "__main__":
    raise SystemExit(main())
