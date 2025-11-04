"""
Test: request a new location command and then poll for the latest location.
Usage:
  python tests/functional/test_request_location.py [provider] [wait_seconds]
provider: one of all,gps,cell,last (default: all)
wait_seconds: seconds to wait for the device to respond (default: 30)
"""

import asyncio
import json
import sys
from pathlib import Path

# Add repo root to path for package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.utils.read_credentials import read_credentials


async def main():
    creds = read_credentials()
    if not creds.get("BASE_URL") or not creds.get("FMD_ID") or not creds.get("PASSWORD"):
        print("Missing credentials.")
        return
    provider = sys.argv[1] if len(sys.argv) > 1 else "all"
    wait = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    from fmd_api import FmdClient

    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    try:
        ok = await client.request_location(provider)
        print("Request location sent:", ok)
        if ok and wait > 0:
            print(f"Waiting {wait} seconds for device to upload...")
            await asyncio.sleep(wait)
        blobs = await client.get_locations(5)
        print("Recent blobs:", len(blobs))
        if blobs:
            dec = client.decrypt_data_blob(blobs[0])
            print("Newest decrypted:", json.dumps(json.loads(dec), indent=2))
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
