"""Minimal async example for FmdClient usage."""
import asyncio
import json
from fmd_api import FmdClient

async def main():
    client = await FmdClient.create("https://fmd.example.com", "alice", "secret")
    try:
        blobs = await client.get_locations(5)
        for b in blobs:
            data = client.decrypt_data_blob(b)
            print(json.loads(data))
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())