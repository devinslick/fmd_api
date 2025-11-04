"""
Test: get_pictures and download/decrypt the first picture found
Usage:
  python tests/functional/test_pictures.py
"""

import asyncio
import base64
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

    from fmd_api import FmdClient

    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    try:
        pics = await client.get_pictures(10)
        print("Pictures returned:", len(pics))
        if not pics:
            print("No pictures available.")
            return

        # Server sometimes returns list of dicts or list of base64 strings.
        # Try to extract a blob string:
        first = pics[0]
        blob = None
        if isinstance(first, dict):
            # try common keys
            for k in ("Data", "blob", "Blob", "data"):
                if k in first:
                    blob = first[k]
                    break
            # if picture metadata contains an encoded blob in a nested field, adjust as needed
        elif isinstance(first, str):
            blob = first

        if not blob:
            print("Could not find picture blob inside first picture entry. Showing entry:")
            print(first)
            return

        # decrypt to get inner base64 image string or bytes
        decrypted = client.decrypt_data_blob(blob)
        try:
            inner_b64 = decrypted.decode("utf-8").strip()
            img = base64.b64decode(inner_b64 + "=" * (-len(inner_b64) % 4))
            out = "picture_0.jpg"
            with open(out, "wb") as f:
                f.write(img)
            print("Saved picture to", out)
        except Exception:
            print("Decrypted payload not a base64 image string; saving raw bytes as picture_0.bin")
            with open("picture_0.bin", "wb") as f:
                f.write(decrypted)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
