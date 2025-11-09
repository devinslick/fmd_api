import pytest
from aioresponses import aioresponses

from fmd_api.client import FmdClient


@pytest.mark.asyncio
async def test_resume_and_hash_based_reauth():
    # First create a client normally to get artifacts
    client = FmdClient("https://fmd.example.com")

    # Mock salt, access token, key blob
    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"0" * 32

    # Simulate authenticate artifacts directly
    client._fmd_id = "alice"
    client._password = "secret"
    client._password_hash = "$argon2id$v=19$m=131072,t=1,p=4$dummy$hash"
    client.access_token = "tkn1"
    client.private_key = DummyKey()  # Not a real key, but sufficient for path coverage

    artifacts = await client.export_auth_artifacts()
    await client.drop_password()

    # Resume from artifacts (no raw password retained)
    resumed = await FmdClient.from_auth_artifacts(artifacts)
    assert resumed.access_token == "tkn1"
    assert resumed._password is None
    assert resumed._password_hash == artifacts["password_hash"]

    # Simulate 401 then success on reauth
    await resumed._ensure_session()
    with aioresponses() as m:
        # First request returns 401
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=401)
        # Reauth token request
        m.put("https://fmd.example.com/api/v1/requestAccess", payload={"Data": "tkn2"})
        # Retry locationDataSize success
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})

        result = await resumed.get_locations()
        assert result == []
        assert resumed.access_token == "tkn2"

    await resumed.close()
    await client.close()
