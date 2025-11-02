"""
Test: export_data_zip (downloads export ZIP to provided filename)
Usage:
  python tests/functional/test_export.py [output.zip]
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
    out = sys.argv[1] if len(sys.argv) > 1 else "export_test.zip"
    from fmd_api import FmdClient
    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    try:
        await client.export_data_zip(out)
        print("Export saved to", out)
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
