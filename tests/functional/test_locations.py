"""
Test: get_locations + decrypt_data_blob
Fetch most recent N blobs and decrypt each (prints parsed JSON).
Usage:
  python tests/functional/test_locations.py [N]
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
    num = -1
    if len(sys.argv) > 1:
        try:
            num = int(sys.argv[1])
        except (ValueError, TypeError):
            # Ignore invalid CLI value; keep default of -1 (fetch all)
            num = -1
    from fmd_api import FmdClient

    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    try:
        blobs = await client.get_locations(num_to_get=num if num != 0 else -1)
        print(f"Retrieved {len(blobs)} location blob(s)")
        for i, b in enumerate(blobs[:10]):
            try:
                dec = client.decrypt_data_blob(b)
                obj = json.loads(dec)
                print(f"Blob #{i}: {json.dumps(obj, indent=2)}")
            except Exception as e:
                print(f"Failed to decrypt/parse blob #{i}: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
