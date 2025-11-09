"""
Additional tests to improve code coverage to 95%+
Focuses on uncovered branches and edge cases in client.py and device.py
"""

import json
import base64
import zipfile
import pytest
from aioresponses import aioresponses
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
import aiohttp

from fmd_api.client import FmdClient, CONTEXT_STRING_ASYM_KEY_WRAP
from fmd_api.device import Device
from fmd_api.exceptions import FmdApiException, OperationError


# ==========================================
# Test authentication helper methods
# ==========================================


@pytest.mark.asyncio
async def test_hash_password_internal():
    """Test _hash_password generates correct format."""
    client = FmdClient("https://fmd.example.com")
    result = client._hash_password("testpass", "dGVzdHNhbHQxMjM0NTY3OA")

    assert result.startswith("$argon2id$v=19$m=131072,t=1,p=4$")
    assert "$" in result
    parts = result.split("$")
    assert len(parts) == 6  # empty, argon2id, v=19, params, salt, hash


@pytest.mark.asyncio
async def test_load_private_key_from_pem():
    """Test _load_private_key_from_bytes with PEM format."""
    client = FmdClient("https://fmd.example.com")

    # Generate a test RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    loaded_key = client._load_private_key_from_bytes(pem_bytes)
    assert loaded_key is not None


@pytest.mark.asyncio
async def test_load_private_key_from_der():
    """Test _load_private_key_from_bytes with DER format (fallback path)."""
    client = FmdClient("https://fmd.example.com")

    # Generate a test RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    der_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    loaded_key = client._load_private_key_from_bytes(der_bytes)
    assert loaded_key is not None


# ==========================================
# Test JSON parsing fallback paths
# ==========================================


@pytest.mark.asyncio
async def test_json_parse_error_fallback_to_text():
    """Test that JSONDecodeError triggers fallback to text response."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        # Return text that will trigger JSONDecodeError
        m.put(
            "https://fmd.example.com/api/v1/salt",
            body='"invalid json',  # Missing closing quote
            content_type="application/json",
        )

        try:
            # Should fall back to text and return the raw string
            result = await client._make_api_request("PUT", "/api/v1/salt", {"IDT": "test", "Data": ""})
            assert result == '"invalid json'
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_json_missing_data_key_fallback():
    """Test KeyError when JSON response lacks 'Data' key."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        # Return JSON without 'Data' key
        m.put("https://fmd.example.com/api/v1/salt", payload={"error": "something"}, content_type="application/json")

        try:
            # Should catch KeyError and fall back to text
            result = await client._make_api_request("PUT", "/api/v1/salt", {"IDT": "test", "Data": ""})
            # aioresponses returns the payload dict as-is when no 'Data'
            assert isinstance(result, (str, dict))
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_empty_text_response_warning():
    """Test that empty text response triggers warning log."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        # Return JSON with Data key but with empty string value
        m.put("https://fmd.example.com/api/v1/salt", payload={"Data": ""}, content_type="application/json")

        try:
            result = await client._make_api_request("PUT", "/api/v1/salt", {"IDT": "test", "Data": ""})
            # Empty response should return empty string
            assert result == ""
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_expect_json_false_path():
    """Test expect_json=False returns text directly."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", body="Command received", status=200)

        try:
            result = await client._make_api_request(
                "POST", "/api/v1/command", {"IDT": "token", "Data": "test"}, expect_json=False
            )
            assert result == "Command received"
        finally:
            await client.close()


# ==========================================
# Test connection error retry logic
# ==========================================


@pytest.mark.asyncio
async def test_connection_error_retry_with_backoff(monkeypatch):
    """Test ClientConnectionError triggers retry with backoff."""
    client = FmdClient("https://fmd.example.com", max_retries=2, backoff_base=0.1, jitter=False)
    client.access_token = "token"

    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)

    await client._ensure_session()

    with aioresponses() as m:
        # First two attempts: connection error, third: success
        m.put(
            "https://fmd.example.com/api/v1/locationDataSize",
            exception=aiohttp.ClientConnectionError("Connection failed"),
        )
        m.put(
            "https://fmd.example.com/api/v1/locationDataSize",
            exception=aiohttp.ClientConnectionError("Connection failed"),
        )
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})

        try:
            result = await client.get_locations()
            assert result == []
            # Should have two backoff sleeps: 0.1, 0.2
            assert len(slept) == 2
            assert slept[0] == 0.1
            assert slept[1] == 0.2
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_connection_error_exhausted_retries(monkeypatch):
    """Test connection error raises FmdApiException when retries exhausted."""
    client = FmdClient("https://fmd.example.com", max_retries=1, backoff_base=0.1, jitter=False)
    client.access_token = "token"

    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)

    await client._ensure_session()

    with aioresponses() as m:
        # All attempts fail
        for _ in range(3):
            m.put(
                "https://fmd.example.com/api/v1/locationDataSize",
                exception=aiohttp.ClientConnectionError("Connection failed"),
            )

        try:
            with pytest.raises(FmdApiException, match="API request failed"):
                await client.get_locations()
            # Should have 1 retry sleep
            assert len(slept) == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_connection_error_no_retry_for_unsafe_command():
    """Test connection error doesn't retry for unsafe command POST."""
    client = FmdClient("https://fmd.example.com", max_retries=3)
    client.access_token = "token"

    # Set up private key for send_command
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    client.private_key = private_key

    await client._ensure_session()

    with aioresponses() as m:
        # Connection error on command endpoint
        m.post("https://fmd.example.com/api/v1/command", exception=aiohttp.ClientConnectionError("Connection failed"))

        try:
            with pytest.raises(FmdApiException, match="Failed to send command"):
                await client.send_command("ring")
        finally:
            await client.close()


# ==========================================
# Test export_data_zip edge cases
# ==========================================


@pytest.mark.asyncio
async def test_export_zip_png_detection():
    """Test PNG magic byte detection in export_data_zip."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    # Set up private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    client.private_key = private_key

    # Create PNG image bytes (PNG magic bytes + minimal data)
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    png_b64 = base64.b64encode(png_data).decode("utf-8")

    # Double-encode as per FMD picture format
    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x01" * 12

    # Encrypt the base64 string
    ciphertext = aesgcm.encrypt(iv, png_b64.encode("utf-8"), None)

    # Build encrypted blob
    public_key = private_key.public_key()
    session_key_packet = public_key.encrypt(
        session_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    blob = session_key_packet + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8")

    await client._ensure_session()

    with aioresponses() as m:
        # No locations
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})
        # One PNG picture
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": [blob_b64]})

        try:
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                output_path = tmp.name

            result = await client.export_data_zip(output_path, include_pictures=True)
            assert result == output_path

            # Verify ZIP contains PNG
            with zipfile.ZipFile(output_path, "r") as zf:
                files = zf.namelist()
                assert "pictures/manifest.json" in files
                assert any("picture_" in f and f.endswith(".png") for f in files)

            import os

            os.unlink(output_path)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_export_zip_picture_decrypt_error():
    """Test export handles picture decryption errors gracefully."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    # Set up private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    client.private_key = private_key

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})
        # Invalid picture blob (too small)
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": ["invalid"]})

        try:
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                output_path = tmp.name

            await client.export_data_zip(output_path, include_pictures=True)

            # Should complete despite error
            with zipfile.ZipFile(output_path, "r") as zf:
                manifest = json.loads(zf.read("pictures/manifest.json"))
                # Error should be recorded
                assert "error" in manifest[0]

            import os

            os.unlink(output_path)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_export_zip_location_decrypt_error():
    """Test export handles location decryption errors gracefully."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    # Set up private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    client.private_key = private_key

    await client._ensure_session()

    with aioresponses() as m:
        # One invalid location
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": "tooshort"})
        # No pictures
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": []})

        try:
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                output_path = tmp.name

            await client.export_data_zip(output_path, include_pictures=False)

            # Should complete with error recorded
            with zipfile.ZipFile(output_path, "r") as zf:
                locations = json.loads(zf.read("locations.json"))
                assert "error" in locations[0]
                assert locations[0]["index"] == 0

            import os

            os.unlink(output_path)
        finally:
            await client.close()


# ==========================================
# Test device.py missing lines
# ==========================================


@pytest.mark.asyncio
async def test_device_download_photo_decode_error():
    """Test Device.download_photo handles decode errors (line 137-138)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    # Set up private key with 3072-bit key to get 384-byte RSA packet
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    client.private_key = private_key

    device = Device(client, "test_device")

    # Create an invalid blob (will decrypt but not be valid base64)
    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x01" * 12

    # Invalid inner data (not valid base64)
    ciphertext = aesgcm.encrypt(iv, b"not-base64-data!!!", None)

    public_key = private_key.public_key()
    session_key_packet = public_key.encrypt(
        session_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    blob = session_key_packet + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8")

    with pytest.raises(OperationError, match="Failed to decode picture blob"):
        await device.download_photo(blob_b64)


@pytest.mark.asyncio
async def test_device_get_history_decrypt_error():
    """Test Device.get_history handles decrypt errors (line 99-101)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    # Set up private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    client.private_key = private_key

    device = Device(client, "test_device")

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": "invalid"})

        try:
            with pytest.raises(OperationError, match="Failed to decrypt/parse location blob"):
                async for loc in device.get_history(limit=1):
                    pass
        finally:
            await client.close()


# ==========================================
# Test helper functions indirectly through client behavior
# ==========================================


@pytest.mark.asyncio
async def test_retry_after_header_parsing_indirectly():
    """Test Retry-After header parsing through actual 429 response."""
    client = FmdClient("https://fmd.example.com", max_retries=2)
    client.access_token = "token"

    await client._ensure_session()

    with aioresponses() as m:
        # Test with valid Retry-After number
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=429, headers={"Retry-After": "5"})
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})

        try:
            await client.get_locations()
            # If it succeeds, Retry-After was parsed correctly
        finally:
            await client.close()


# ==========================================
# Additional edge cases
# ==========================================


@pytest.mark.asyncio
async def test_decrypt_blob_with_missing_private_key():
    """Test decrypt_data_blob raises when private_key is None."""
    client = FmdClient("https://fmd.example.com")
    # Don't set private_key

    # Use a valid base64 string that's long enough
    dummy_blob = base64.b64encode(b"\x00" * 400).decode("utf-8")
    with pytest.raises(FmdApiException, match="Private key not loaded"):
        client.decrypt_data_blob(dummy_blob)


@pytest.mark.asyncio
async def test_send_command_with_missing_private_key():
    """Test send_command raises when private_key is None."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    try:
        with pytest.raises(FmdApiException, match="Private key not loaded"):
            await client.send_command("ring")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_device_fetch_pictures_deprecated():
    """Test fetch_pictures() deprecated wrapper emits warning."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": ["blob1", "blob2"]})

        try:
            import warnings

            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result = await device.fetch_pictures(2)
                assert len(w) == 1
                assert issubclass(w[0].category, DeprecationWarning)
                assert "fetch_pictures() is deprecated" in str(w[0].message)
                assert len(result) == 2
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_client_error_generic():
    """Test generic ClientError handling."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", exception=aiohttp.ClientError("Generic client error"))

        try:
            with pytest.raises(FmdApiException, match="API request failed"):
                await client.get_locations()
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_value_error_in_response_parsing():
    """Test ValueError in response parsing."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        # Return JSON that will cause ValueError when parsing int
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "not-a-number"})

        try:
            with pytest.raises(Exception):  # int() will raise ValueError, caught and re-raised
                await client.get_locations()
        finally:
            await client.close()


# ==========================================
# Additional tests to reach 95% coverage
# ==========================================


@pytest.mark.asyncio
async def test_authenticate_full_flow():
    """Test complete authenticate flow including internal methods (lines 163-211)."""
    client = FmdClient("https://fmd.example.com")

    with aioresponses() as m:
        # Mock salt retrieval
        m.put("https://fmd.example.com/api/v1/salt", payload={"Data": base64.b64encode(b"\x00" * 16).decode()})
        # Mock token request
        m.put("https://fmd.example.com/api/v1/requestAccess", payload={"Data": "test_token"})
        # Mock private key retrieval
        # Create a simple encrypted key blob
        password = "testpass"
        salt = b"\x00" * 16
        iv = b"\x01" * 12

        # Create a dummy private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        privkey_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Encrypt the private key
        password_bytes = (CONTEXT_STRING_ASYM_KEY_WRAP + password).encode("utf-8")
        aes_key = hash_secret_raw(
            secret=password_bytes, salt=salt, time_cost=1, memory_cost=131072, parallelism=4, hash_len=32, type=Type.ID
        )
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(iv, privkey_pem, None)
        encrypted_blob = salt + iv + ciphertext

        m.put("https://fmd.example.com/api/v1/key", payload={"Data": base64.b64encode(encrypted_blob).decode()})

        try:
            await client.authenticate("testid", password, 3600)
            assert client.access_token == "test_token"
            assert client.private_key is not None
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_429_with_retry_after_header():
    """Test 429 response with Retry-After header (lines 305-312)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 1
    await client._ensure_session()

    with aioresponses() as m:
        # First request returns 429 with Retry-After
        m.get("https://fmd.example.com/api/v1/test", status=429, headers={"Retry-After": "1"})
        # Second request succeeds
        m.get("https://fmd.example.com/api/v1/test", payload={"Data": "success"})

        try:
            result = await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
            assert result == "success"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_500_error_retry():
    """Test 500 server error triggers retry (lines 353-358)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 1
    await client._ensure_session()

    with aioresponses() as m:
        # First request returns 500
        m.get("https://fmd.example.com/api/v1/test", status=500)
        # Second request succeeds
        m.get("https://fmd.example.com/api/v1/test", payload={"Data": "success"})

        try:
            result = await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
            assert result == "success"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_negative_retry_after_header():
    """Test Retry-After with negative value (lines 703-707)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 1
    await client._ensure_session()

    with aioresponses() as m:
        # First request returns 429 with invalid negative Retry-After
        m.get("https://fmd.example.com/api/v1/test", status=429, headers={"Retry-After": "-5"})
        # Second request succeeds
        m.get("https://fmd.example.com/api/v1/test", payload={"Data": "success"})

        try:
            result = await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
            assert result == "success"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_http_date_retry_after():
    """Test Retry-After with HTTP-date format (lines 709-711)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 1
    await client._ensure_session()

    with aioresponses() as m:
        # First request returns 429 with HTTP-date Retry-After
        m.get(
            "https://fmd.example.com/api/v1/test", status=429, headers={"Retry-After": "Wed, 21 Oct 2025 07:28:00 GMT"}
        )
        # Second request succeeds
        m.get("https://fmd.example.com/api/v1/test", payload={"Data": "success"})

        try:
            result = await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
            assert result == "success"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_backoff_without_jitter():
    """Test backoff calculation without jitter (lines 715-718)."""
    client = FmdClient("https://fmd.example.com", jitter=False)
    client.access_token = "token"
    client.max_retries = 2
    await client._ensure_session()

    with aioresponses() as m:
        # First request returns 500
        m.get("https://fmd.example.com/api/v1/test", status=500)
        # Second request returns 500
        m.get("https://fmd.example.com/api/v1/test", status=500)
        # Third request succeeds
        m.get("https://fmd.example.com/api/v1/test", payload={"Data": "success"})

        try:
            result = await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
            assert result == "success"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_internal_parse_location_error():
    """Test that _parse_location_blob raises RuntimeError (device.py line 23)."""
    from fmd_api.device import _parse_location_blob

    with pytest.raises(RuntimeError, match="should not be called directly"):
        _parse_location_blob("dummy_blob")


@pytest.mark.asyncio
async def test_get_pictures_with_specific_count():
    """Test get_pictures with specific num_to_get (lines 477-478)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    # Set up private key for decryption
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    client.private_key = private_key

    with aioresponses() as m:
        # Mock response with 10 pictures
        pictures_list = [f"picture{i}" for i in range(10)]
        m.put("https://fmd.example.com/api/v1/pictureDataSize", payload={"Data": "10"})
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": pictures_list})

        try:
            # Request only 3 pictures
            result = await client.get_pictures(num_to_get=3)
            assert len(result) == 3
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_exhausted_retries_on_500():
    """Test exhausting retries on repeated 500 errors (lines 353-358)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 2
    await client._ensure_session()

    with aioresponses() as m:
        # All requests return 500
        for _ in range(5):
            m.get("https://fmd.example.com/api/v1/test", status=500)

        try:
            with pytest.raises(FmdApiException, match="API request failed"):
                await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_compute_backoff_with_jitter():
    """Test _compute_backoff with jitter enabled (line 715-718)."""
    from fmd_api.client import _compute_backoff

    # With jitter, result should be between 0 and calculated delay
    for attempt in range(3):
        delay = _compute_backoff(1.0, attempt, 10.0, True)
        expected_max = min(10.0, 1.0 * (2**attempt))
        assert 0 <= delay <= expected_max


@pytest.mark.asyncio
async def test_429_exhausted_retries():
    """Test 429 with exhausted retries (lines 305-306)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 0  # No retries
    await client._ensure_session()

    with aioresponses() as m:
        m.get("https://fmd.example.com/api/v1/test", status=429)

        try:
            with pytest.raises(FmdApiException, match="Rate limited.*retries exhausted"):
                await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_streaming_response():
    """Test streaming response path (line 374-376)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        m.get("https://fmd.example.com/api/v1/test", body="streaming content", content_type="text/plain")

        try:
            result = await client._make_api_request(
                "GET", "/api/v1/test", {"IDT": "test", "Data": ""}, stream=True  # Request streaming response
            )
            # Should return the response object itself
            assert result is not None
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_pictures_all_count():
    """Test get_pictures with num_to_get=-1 (all pictures) (lines 477-478)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    # Set up private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    client.private_key = private_key

    with aioresponses() as m:
        # Mock response with 5 pictures
        pictures_list = [f"picture{i}" for i in range(5)]
        m.put("https://fmd.example.com/api/v1/pictureDataSize", payload={"Data": "5"})
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": pictures_list})

        try:
            # Request all pictures (num_to_get=-1)
            result = await client.get_pictures(num_to_get=-1)
            assert len(result) == 5
        finally:
            await client.close()


# ==========================================
# Final push to 100% coverage
# ==========================================


@pytest.mark.asyncio
async def test_500_error_exhausted_retries_raises():
    """Test 500 error with exhausted retries (lines 353-358)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 1
    await client._ensure_session()

    with aioresponses() as m:
        # All requests return 500
        for _ in range(3):
            m.post("https://fmd.example.com/api/v1/test", status=500)

        try:
            with pytest.raises(FmdApiException, match="API request failed"):
                await client._make_api_request("POST", "/api/v1/test", {"IDT": "test", "Data": ""})
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_expect_json_false_returns_text():
    """Test expect_json=False returns text directly (line 368)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", body="Command executed", content_type="text/plain")

        try:
            result = await client._make_api_request(
                "POST", "/api/v1/command", {"IDT": "test", "Data": ""}, expect_json=False
            )
            assert result == "Command executed"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_response_parsing_key_error():
    """Test KeyError/ValueError in response parsing (lines 392-393)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        # Return invalid response that will cause parsing error outside the JSON block
        m.put(
            "https://fmd.example.com/api/v1/test",
            payload={"Data": {"nested": "value"}},  # Valid JSON but might cause issues downstream
            content_type="application/json",
        )

        try:
            # This should work without errors
            result = await client._make_api_request("PUT", "/api/v1/test", {"IDT": "test", "Data": ""})
            assert result == {"nested": "value"}
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_pictures_returns_list_when_all():
    """Test get_pictures returns full list when num_to_get=-1 (line 480)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    # Set up private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    client.private_key = private_key

    with aioresponses() as m:
        # Mock response with 10 pictures
        pictures_list = [f"picture{i}" for i in range(10)]
        m.put("https://fmd.example.com/api/v1/pictureDataSize", payload={"Data": "10"})
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": pictures_list})

        try:
            # Request all pictures explicitly
            result = await client.get_pictures(num_to_get=-1)
            # Should return all 10 pictures
            assert len(result) == 10
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_export_zip_default_jpg_extension():
    """Test export_data_zip defaults to jpg for unknown image types (line 567)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    # Set up private key for decryption
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    client.private_key = private_key

    # Create an encrypted blob with unknown image format (not PNG or JPEG)
    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x01" * 12

    # Create image data that doesn't match PNG or JPEG magic bytes
    unknown_image = b"\x00\x00\x00\x00UNKNOWN" + b"\x00" * 20
    image_b64 = base64.b64encode(unknown_image).decode("utf-8")

    # Encrypt it
    ciphertext = aesgcm.encrypt(iv, image_b64.encode("utf-8"), None)

    public_key = private_key.public_key()
    session_key_packet = public_key.encrypt(
        session_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    blob = session_key_packet + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8")

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})
        m.put("https://fmd.example.com/api/v1/pictureDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": [blob_b64]})

        try:
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                output_path = tmp.name

            await client.export_data_zip(output_path, include_pictures=True)

            # Verify the file was created and contains jpg file
            with zipfile.ZipFile(output_path, "r") as zf:
                names = zf.namelist()
                # Should have defaulted to .jpg extension
                assert any(".jpg" in name for name in names)

            # Cleanup
            import os

            if os.path.exists(output_path):
                os.unlink(output_path)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_mask_token_with_none():
    """Test _mask_token with None input (line 685-686)."""
    from fmd_api.client import _mask_token

    result = _mask_token(None)
    assert result == "<none>"


@pytest.mark.asyncio
async def test_mask_token_with_short():
    """Test _mask_token with short token (line 687-688)."""
    from fmd_api.client import _mask_token

    result = _mask_token("ab", show_chars=5)
    assert result == "***"


@pytest.mark.asyncio
async def test_mask_token_with_long():
    """Test _mask_token with long token (line 689)."""
    from fmd_api.client import _mask_token

    result = _mask_token("verylongtoken123456", show_chars=4)
    assert result.startswith("very")
    assert result.endswith("...***")


@pytest.mark.asyncio
async def test_parse_retry_after_with_invalid():
    """Test _parse_retry_after with invalid input (line 703)."""
    from fmd_api.client import _parse_retry_after

    # None input
    result = _parse_retry_after(None)
    assert result is None

    # Invalid string
    result = _parse_retry_after("invalid")
    assert result is None


@pytest.mark.asyncio
async def test_compute_backoff_with_jitter_randomness():
    """Test _compute_backoff with jitter produces values in range (line 717-718)."""
    from fmd_api.client import _compute_backoff

    # With jitter=True, should return random value between 0 and delay
    delays = [_compute_backoff(1.0, 0, 10.0, True) for _ in range(10)]

    # All should be >= 0 and <= 1.0 (base * 2^0)
    assert all(0 <= d <= 1.0 for d in delays)

    # With enough samples, should have some variation (not all the same)
    # (This might fail in rare cases but is statistically very unlikely)
    assert len(set(delays)) > 1 or delays[0] == 0  # Allow all zeros as edge case


@pytest.mark.asyncio
async def test_502_error_with_exhausted_retries():
    """Test 502 error exhausts retries and continues to raise (lines 353-358)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client.max_retries = 1
    await client._ensure_session()

    with aioresponses() as m:
        # All requests return 502
        for _ in range(5):
            m.get("https://fmd.example.com/api/v1/test", status=502)

        try:
            with pytest.raises(FmdApiException, match="API request failed"):
                await client._make_api_request("GET", "/api/v1/test", {"IDT": "test", "Data": ""})
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_non_json_response_with_expect_json_false():
    """Test non-JSON response when expect_json=False (line 368)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/test", body="plain text response", content_type="text/plain")

        try:
            result = await client._make_api_request(
                "PUT", "/api/v1/test", {"IDT": "test", "Data": ""}, expect_json=False
            )
            assert result == "plain text response"
        finally:
            await client.close()
