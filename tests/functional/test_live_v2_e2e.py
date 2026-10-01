"""Live end-to-end probe: register a protocol-v2 account on the real server.

Full chain: register_v2 -> post_data_items(location) -> (fresh client)
login_v2 -> get_data_items -> decrypt_item -> JSON parse.

Run:  .venv-api/bin/python tests/functional/test_live_v2_e2e.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

sys.path.insert(0, ".")

from fmd_api import FmdClient  # noqa: E402
from fmd_api.api_v2 import ApiV2Error  # noqa: E402

BASE = "https://fmd.devinslick.com"
ACCOUNT = "devinslick-v2test"
PASSWORD = "e2e-test-account-2026"

TEST_LOCATION = {
    "lat": 32.8429,
    "lon": -96.9689,
    "time": time.strftime("%a %b %d %H:%M:%S %Z %Y"),
    "date": int(time.time() * 1000),
    "provider": "gps",
    "bat": 55,
    "accuracy": 8.2,
}


async def main() -> None:
    """Run the full v2 chain against the live server."""
    # --- 1. register (fresh account each run: salt differs, that's fine) ---
    client = FmdClient(BASE)
    try:
        registered = False
        try:
            await client.register_v2(ACCOUNT, PASSWORD)
            registered = True
            print(f"[1] registered protocol-v2 account '{ACCOUNT}'")
        except ApiV2Error as exc:
            if "not available" in str(exc).lower() or "409" in str(exc):
                print(f"[1] account already exists, logging in instead")
                await client.login_v2(ACCOUNT, PASSWORD, 3600)
            else:
                raise
        proto = await client.negotiate_protocol(ACCOUNT)
        print(f"[2] salt endpoint now reports protoVersion={proto}")
        assert proto == 2, "expected protocol 2 after v2 registration"

        # --- 2. upload a test location ---
        await client.post_data_items(
            "location", [json.dumps(TEST_LOCATION).encode()]
        )
        print("[3] uploaded 1 encrypted test location")

        # --- 3. fetch + decrypt with the SAME client ---
        items = await client.get_data_items("location")
        print(f"[4] fetched {len(items)} location item(s)")
        found = False
        for item in items:
            raw = client.decrypt_item("location", item)
            data = json.loads(raw)
            print(f"    item ts={item.unix_millis} -> lat={data.get('lat')} "
                  f"provider={data.get('provider')} bat={data.get('bat')}")
            if data.get("bat") == TEST_LOCATION["bat"]:
                found = True
        assert found, "uploaded test location not found in fetched items"
        print("[5] decrypt OK - round trip matches uploaded data")
    finally:
        await client.close()

    # --- 4. fresh client: login_v2 with password, fetch, decrypt ---
    client2 = FmdClient(BASE)
    try:
        await client2.login_v2(ACCOUNT, PASSWORD, 3600)
        print("[6] fresh client login_v2 OK (master key unwrapped)")
        items = await client2.get_data_items("location")
        assert items, "no items after fresh login"
        data = json.loads(client2.decrypt_item("location", items[0]))
        print(f"[7] fresh client decrypt OK: lat={data.get('lat')} "
              f"provider={data.get('provider')}")
        print("\nEND-TO-END v2: PASS")
    finally:
        await client2.close()


if __name__ == "__main__":
    asyncio.run(main())
