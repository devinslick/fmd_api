"""
Test: Validated command methods (ring, lock, camera, bluetooth, etc.)
Usage:
  python tests/functional/test_commands.py <command> [args...]

Commands:
  ring                    - Make device ring
  lock                    - Lock device screen
  camera <front|back>     - Take picture (default: back)
  bluetooth <on|off>      - Set Bluetooth on/off
  dnd <on|off>           - Set Do Not Disturb on/off
  ringer <normal|vibrate|silent> - Set ringer mode
  stats                   - Get device network statistics
  locate [all|gps|cell|last] - Request location update (default: all)

Examples:
  python tests/functional/test_commands.py ring
  python tests/functional/test_commands.py camera front
  python tests/functional/test_commands.py bluetooth on
  python tests/functional/test_commands.py ringer vibrate
  python tests/functional/test_commands.py locate gps
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

    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1].lower()
    from fmd_api import FmdClient

    client = await FmdClient.create(creds["BASE_URL"], creds["FMD_ID"], creds["PASSWORD"])

    try:
        result = False

        if command == "ring":
            result = await client.send_command("ring")
            print(f"Ring command sent: {result}")

        elif command == "lock":
            result = await client.send_command("lock")
            print(f"Lock command sent: {result}")

        elif command == "camera":
            camera = sys.argv[2].lower() if len(sys.argv) > 2 else "back"
            result = await client.take_picture(camera)
            print(f"Camera '{camera}' command sent: {result}")

        elif command == "bluetooth":
            if len(sys.argv) < 3:
                print("Error: bluetooth requires on|off argument")
                return
            state = sys.argv[2].lower()
            if state not in ["on", "off"]:
                print("Error: bluetooth state must be 'on' or 'off'")
                return
            result = await client.set_bluetooth(state == "on")
            print(f"Bluetooth {state} command sent: {result}")

        elif command == "dnd":
            if len(sys.argv) < 3:
                print("Error: dnd requires on|off argument")
                return
            state = sys.argv[2].lower()
            if state not in ["on", "off"]:
                print("Error: dnd state must be 'on' or 'off'")
                return
            result = await client.set_do_not_disturb(state == "on")
            print(f"Do Not Disturb {state} command sent: {result}")

        elif command == "ringer":
            if len(sys.argv) < 3:
                print("Error: ringer requires normal|vibrate|silent argument")
                return
            mode = sys.argv[2].lower()
            result = await client.set_ringer_mode(mode)
            print(f"Ringer mode '{mode}' command sent: {result}")

        elif command == "stats":
            result = await client.get_device_stats()
            print(f"Device stats command sent: {result}")

        elif command == "locate":
            provider = sys.argv[2].lower() if len(sys.argv) > 2 else "all"
            result = await client.request_location(provider)
            print(f"Location request ({provider}) sent: {result}")

        else:
            print(f"Unknown command: {command}")
            print(__doc__)

    except ValueError as e:
        print(f"Error: {e}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
