"""
Test: Device class flows (refresh, get_location, get_pictures, get_picture)
Usage:
  python tests/functional/test_device.py
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
        print("Missing credentials.")
        return
    device_id = creds.get("DEVICE_ID", creds.get("FMD_ID"))

    from fmd_api import FmdClient
    from fmd_api.device import Device

    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    try:
        device = Device(client, device_id)
        print("Refreshing device (may return nothing if no data)...")
        await device.refresh()
        loc = await device.get_location()
        print("Cached location:", loc)
        # fetch pictures and attempt to download the first one
        pics = await device.get_picture_blobs(5)
        print("Pictures listed:", len(pics))
        if pics:
            try:
                photo = await device.decode_picture(pics[0])
                fn = "device_photo.jpg"
                with open(fn, "wb") as f:
                    f.write(photo.data)
                print("Saved device photo to", fn)
            except Exception as e:
                print("Failed to get picture:", e)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
