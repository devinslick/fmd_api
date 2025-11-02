"""
Test: send_command (ring, lock, camera, bluetooth)
Usage:
  python test_scripts/test_commands.py <command>
Examples:
  python test_scripts/test_commands.py ring
  python test_scripts/test_commands.py "camera front"
  python test_scripts/test_commands.py "bluetooth on"
"""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.read_credentials import read_credentials

async def main():
    creds = read_credentials()
    if not creds.get("BASE_URL") or not creds.get("FMD_ID") or not creds.get("PASSWORD"):
        print("Missing credentials.")
        return
    if len(sys.argv) < 2:
        print("Usage: test_commands.py <command>")
        return
    cmd = sys.argv[1]
    from fmd_api import FmdClient
    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])
    try:
        ok = await client.send_command(cmd)
        print(f"Sent '{cmd}': {ok}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())