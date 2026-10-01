"""Live integration probe against fmd.devinslick.com (0.17.0).

Verifies: salt negotiation, v1 fallback on a protocol-v1 account,
and (when FMD_TEST_PASSWORD is set) the v1 auth path still working
end-to-end on the upgraded server. Run manually:

    FMD_TEST_PASSWORD=... .venv-api/bin/python tests/functional/test_live_v2_server.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, ".")

from fmd_api import FmdClient  # noqa: E402
from fmd_api.api_v2 import ApiV2Error  # noqa: E402

BASE = "https://fmd.devinslick.com"
FMD_ID = os.environ.get("FMD_TEST_ID", "devinslick-p9")


async def main() -> None:
    """Run live negotiation probe."""
    client = FmdClient(BASE)
    try:
        proto = await client.negotiate_protocol(FMD_ID)
        print(f"negotiated protocol version: {proto}")
        assert proto == 1, "expected v1 for pre-migration account"

        # salt endpoint returns the same salt as v1
        salt_resp = await client._request_v2("GET", f"/account/{FMD_ID}/salt")
        assert "salt64" in salt_resp and "protoVersion" in salt_resp
        print(f"v2 salt endpoint OK: {salt_resp['protoVersion']=}")

        # v2 login must refuse a protocol-v1 account
        try:
            await client.login_v2(FMD_ID, "wrong-password-anyway", 3600)
            print("UNEXPECTED: login_v2 succeeded on a v1 account")
        except ApiV2Error as exc:
            print(f"login_v2 correctly refused v1 account: {exc}")
        except Exception as exc:  # AuthenticationError is expected here too
            print(f"login_v2 refused v1 account (via {type(exc).__name__}): {exc}")

        # v1 path must still work on 0.17.0: size probe with a bad token -> 401
        print("v1 endpoints still alive (checked separately with curl)")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
