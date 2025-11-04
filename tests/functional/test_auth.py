"""
Test: authenticate (FmdClient.create)
Usage:
  python tests/functional/test_auth.py
"""

import asyncio
import sys
from pathlib import Path

# Add repo root to path for package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.utils.read_credentials import read_credentials


async def main():
    creds = read_credentials()
    if not creds.get("BASE_URL") or not creds.get("FMD_ID") or not creds.get("PASSWORD"):
        print(
            "Missing credentials. Copy tests/utils/credentials.txt.example -> "
            "tests/utils/credentials.txt and fill in BASE_URL, FMD_ID, PASSWORD"
        )
        return
    from fmd_api import FmdClient

    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    print("Authenticated. access_token (first 12 chars):", (client.access_token or "")[:12])
    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
