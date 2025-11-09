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


@pytest.mark.asyncio
async def test_resume_with_der_key():
    """Test resume() with DER-encoded private key (fallback path)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate a real RSA key and encode as DER
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der_bytes = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Resume with DER bytes (should trigger ValueError in PEM load, then succeed with DER)
    client = await FmdClient.resume(
        "https://fmd.example.com",
        "alice",
        "token123",
        der_bytes,
        password_hash="$argon2id$v=19$m=131072,t=1,p=4$dummy$hash",
    )

    try:
        assert client.access_token == "token123"
        assert client.private_key is not None
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_401_without_password_or_hash():
    """Test 401 response when neither password nor hash available raises error."""
    from fmd_api.exceptions import FmdApiException

    client = FmdClient("https://fmd.example.com")
    client.access_token = "old_token"
    client._fmd_id = "alice"
    client._password = None
    client._password_hash = None

    await client._ensure_session()
    with aioresponses() as m:
        # Returns 401 and no password/hash available
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=401)

        try:
            with pytest.raises(FmdApiException, match="401"):
                await client.get_locations()
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_reauth_with_hash_missing_fields():
    """Test _reauth_with_hash raises when ID or hash missing."""
    from fmd_api.exceptions import FmdApiException

    client = FmdClient("https://fmd.example.com")
    client._fmd_id = None
    client._password_hash = None

    try:
        with pytest.raises(FmdApiException, match="Hash-based reauth not possible"):
            await client._reauth_with_hash()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_from_auth_artifacts_missing_fields():
    """Test from_auth_artifacts raises on missing required fields."""
    incomplete = {"base_url": "https://fmd.example.com", "fmd_id": "alice"}

    with pytest.raises(ValueError, match="Missing artifact fields"):
        await FmdClient.from_auth_artifacts(incomplete)


@pytest.mark.asyncio
async def test_export_artifacts_without_private_key():
    """Test export_auth_artifacts raises when private key not loaded."""
    from fmd_api.exceptions import FmdApiException

    client = FmdClient("https://fmd.example.com")
    client._fmd_id = "alice"
    client.access_token = "token"
    client.private_key = None

    try:
        with pytest.raises(FmdApiException, match="Cannot export artifacts"):
            await client.export_auth_artifacts()
    finally:
        await client.close()
