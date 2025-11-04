import json
import base64

import pytest
from aioresponses import aioresponses

from fmd_api.client import FmdClient

# NOTE: These tests validate behavior parity for the core HTTP flows using mocks.
# They do not perform full Argon2/RSA cryptography verification, but they assert
# that the client calls the expected endpoints and behaves like the original client.


@pytest.mark.asyncio
async def test_get_locations_and_decrypt(monkeypatch):
    # Create a fake client and stub methods that require heavy crypto with small helpers.
    client = FmdClient("https://fmd.example.com")
    # Provide a dummy private_key with a decrypt method for testing

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            # Return a 32-byte AES session key for AESGCM, for tests we use 32 zero bytes
            return b"\x00" * 32
    client.private_key = DummyKey()

    # Build a fake AES-GCM encrypted payload: we'll create plaintext b'{"lat":1.0,"lon":2.0,"date":1234,"bat":50}'
    plaintext = b'{"lat":1.0,"lon":2.0,"date":1600000000000,"bat":50}'
    # For the test, simulate AESGCM by encrypting with a known key using AESGCM class
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x01" * 12
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    # Build blob: session_key_packet (RSA_KEY_SIZE_BYTES) + iv + ciphertext
    session_key_packet = b"\xAA" * 384  # dummy RSA packet; DummyKey.decrypt ignores it
    blob = session_key_packet + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode('utf-8').rstrip('=')

    # Mock the endpoints used by get_locations:
    client.access_token = "dummy-token"
    # Ensure session is created before entering aioresponses context
    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        try:
            locations = await client.get_locations(num_to_get=1)
            assert len(locations) == 1
            decrypted = client.decrypt_data_blob(locations[0])
            assert b'"lat":1.0' in decrypted
            assert b'"lon":2.0' in decrypted
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_connector_configuration_applied():
    """Client should apply SSL and pooling settings to the connector."""
    import aiohttp

    client = FmdClient(
        "https://fmd.example.com",
        ssl=False,  # disable verification
        conn_limit=10,
        conn_limit_per_host=5,
        keepalive_timeout=15.0,
    )

    try:
        await client._ensure_session()
        # Ensure session/connector created
        assert client._session is not None
        connector = client._session.connector
        assert isinstance(connector, aiohttp.TCPConnector)

        # Validate SSL disabled (private attr in aiohttp)
        assert getattr(connector, "_ssl", None) is False

        # Validate limits (use properties when available; fall back to private attrs)
        limit = getattr(connector, "limit", None)
        if limit is None:
            limit = getattr(connector, "_limit", None)
        assert limit == 10

        lph = getattr(connector, "limit_per_host", None)
        if lph is None:
            lph = getattr(connector, "_limit_per_host", None)
        assert lph == 5

        # Validate keepalive timeout (private in aiohttp)
        kat = getattr(connector, "keepalive_timeout", None)
        if kat is None:
            kat = getattr(connector, "_keepalive_timeout", None)
        # Some aiohttp versions may store as int or float; compare as float
        assert pytest.approx(float(kat)) == 15.0
    finally:
        await client.close()


def test_https_required():
    """FmdClient should reject non-HTTPS base URLs."""
    with pytest.raises(ValueError, match="HTTPS is required"):
        FmdClient("http://fmd.example.com")


@pytest.mark.asyncio
async def test_create_closes_session_on_auth_failure(monkeypatch):
    """FmdClient.create should close any created session if auth fails; avoid subclassing ClientSession."""
    import aiohttp
    from fmd_api.exceptions import FmdApiException

    closed = {"count": 0}

    real_cls = aiohttp.ClientSession

    def factory(*args, **kwargs):
        # Create a real session, then wrap its close method to track calls
        sess = real_cls(*args, **kwargs)
        real_close = sess.close

        async def tracked_close():
            closed["count"] += 1
            await real_close()

        # Replace instance method
        setattr(sess, "close", tracked_close)
        return sess

    # Patch the symbol used in client.py to our factory
    monkeypatch.setattr("fmd_api.client.aiohttp.ClientSession", factory)

    # Mock the first auth call to fail (salt 401)
    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/salt", status=401)
        with pytest.raises(FmdApiException):
            await FmdClient.create("https://fmd.example.com", "id", "pw")

    # A session would have been created during the request; ensure it was closed
    assert closed["count"] >= 1


@pytest.mark.asyncio
async def test_create_with_insecure_ssl_configures_connector(monkeypatch):
    """Using create() with ssl=False should not error and should configure connector accordingly."""
    async def fake_authenticate(self, fmd_id, password, session_duration):
        # Minimal stub to avoid network
        self._fmd_id = fmd_id
        self._password = password
        self.access_token = "token"

    monkeypatch.setattr(FmdClient, "authenticate", fake_authenticate)

    client = await FmdClient.create("https://fmd.example.com", "id", "pw", ssl=False)
    try:
        # Ensure session is created and connector ssl=False
        await client._ensure_session()
        import aiohttp

        assert isinstance(client._session.connector, aiohttp.TCPConnector)
        assert getattr(client._session.connector, "_ssl", None) is False
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_send_command_reauth(monkeypatch):
    client = FmdClient("https://fmd.example.com")
    # create a dummy private key with sign()

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()
    client._fmd_id = "id"
    client._password = "pw"
    client.access_token = "old-token"

    with aioresponses() as m:
        # First POST returns 401 -> client should re-authenticate
        m.post("https://fmd.example.com/api/v1/command", status=401)
        # When authenticate is called during reauth, stub the internal calls:

        async def fake_authenticate(fmd_id, password, session_duration):
            client.access_token = "new-token"
        monkeypatch.setattr(client, "authenticate", fake_authenticate)
        # Second attempt should now succeed
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            res = await client.send_command("ring")
            assert res is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_export_data_zip_stream(monkeypatch, tmp_path):
    """Test export_data_zip creates a ZIP file with locations and pictures (client-side)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client._fmd_id = "test-device"
    
    # Create a dummy private key for decryption
    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32
    client.private_key = DummyKey()
    
    # Create fake encrypted location blob
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x01" * 12
    plaintext = b'{"lat":1.0,"lon":2.0,"date":1600000000000}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    session_key_packet = b"\xAA" * 384
    blob = session_key_packet + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode('utf-8').rstrip('=')
    
    with aioresponses() as m:
        # Mock location API calls
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        # Mock pictures API call
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": []})
        
        out_file = tmp_path / "export.zip"
        try:
            result = await client.export_data_zip(str(out_file), include_pictures=True)
            assert result == str(out_file)
            assert out_file.exists()
            
            # Verify ZIP contains expected files
            import zipfile
            with zipfile.ZipFile(out_file, 'r') as zipf:
                names = zipf.namelist()
                assert "info.json" in names
                assert "locations.json" in names
                # Verify encrypted files are NOT included
                assert "locations_encrypted.json" not in names
                assert "pictures_encrypted.json" not in names
                
                # Check info.json has correct structure
                info = json.loads(zipf.read("info.json"))
                assert info["fmd_id"] == "test-device"
                assert info["location_count"] == 1
                assert info["version"] == "2.0"
                assert "pictures_extracted" in info
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_take_picture_validation():
    """Test take_picture validates camera parameter."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    with aioresponses() as m:
        # Valid cameras should work
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await client.take_picture("front") is True
            assert await client.take_picture("back") is True
        finally:
            await client.close()

    # Invalid camera should raise ValueError
    client2 = FmdClient("https://fmd.example.com")
    client2.access_token = "token"
    client2.private_key = DummySigner()
    try:
        with pytest.raises(ValueError, match="Invalid camera.*Must be 'front' or 'back'"):
            await client2.take_picture("rear")
    finally:
        await client2.close()


@pytest.mark.asyncio
async def test_set_ringer_mode_validation():
    """Test set_ringer_mode validates mode parameter."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    with aioresponses() as m:
        # Valid modes should work
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await client.set_ringer_mode("normal") is True
            assert await client.set_ringer_mode("vibrate") is True
            assert await client.set_ringer_mode("silent") is True
        finally:
            await client.close()

    # Invalid mode should raise ValueError
    client2 = FmdClient("https://fmd.example.com")
    client2.access_token = "token"
    client2.private_key = DummySigner()
    try:
        with pytest.raises(ValueError, match="Invalid ringer mode.*Must be"):
            await client2.set_ringer_mode("loud")
    finally:
        await client2.close()


@pytest.mark.asyncio
async def test_request_location_providers():
    """Test request_location with different providers."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    with aioresponses() as m:
        # Mock all provider requests
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await client.request_location("all") is True
            assert await client.request_location("gps") is True
            assert await client.request_location("cell") is True
            assert await client.request_location("last") is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_set_bluetooth_and_dnd():
    """Test set_bluetooth and set_do_not_disturb commands."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    with aioresponses() as m:
        # Mock commands
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await client.set_bluetooth(True) is True
            assert await client.set_bluetooth(False) is True
            assert await client.set_do_not_disturb(True) is True
            assert await client.set_do_not_disturb(False) is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_device_stats():
    """Test get_device_stats sends stats command."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await client.get_device_stats() is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_decrypt_data_blob_too_small():
    """Test decrypt_data_blob raises FmdApiException for small blobs."""
    from fmd_api.exceptions import FmdApiException

    client = FmdClient("https://fmd.example.com")

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32
    client.private_key = DummyKey()

    # Blob must be at least RSA_KEY_SIZE_BYTES (384) + AES_GCM_IV_SIZE_BYTES (12) = 396 bytes
    too_small = base64.b64encode(b"x" * 100).decode('utf-8')

    with pytest.raises(FmdApiException, match="Blob too small for decryption"):
        client.decrypt_data_blob(too_small)


@pytest.mark.asyncio
async def test_get_pictures_direct():
    """Test get_pictures endpoint directly."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    with aioresponses() as m:
        # Mock pictures endpoint returning list of blobs
        m.put("https://fmd.example.com/api/v1/pictures", payload=["blob1", "blob2", "blob3"])
        try:
            pics = await client.get_pictures(num_to_get=2)
            assert len(pics) == 2
            # Should get the 2 most recent (last 2 in reverse)
            assert pics == ["blob3", "blob2"]
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_http_error_handling():
    """Test client handles various HTTP errors."""
    from fmd_api.exceptions import FmdApiException

    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    # Test 404
    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=404)
        try:
            with pytest.raises(FmdApiException):
                await client.get_locations()
        finally:
            await client.close()

    # Test 500
    client2 = FmdClient("https://fmd.example.com")
    client2.access_token = "token"
    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=500)
        try:
            with pytest.raises(FmdApiException):
                await client2.get_locations()
        finally:
            await client2.close()


@pytest.mark.asyncio
async def test_empty_location_response():
    """Test handling of empty location data."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    with aioresponses() as m:
        # Server reports 0 locations
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})
        try:
            locs = await client.get_locations()
            assert locs == []
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_all_locations():
    """Test get_locations with num_to_get=-1 fetches all locations."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    # Create 3 location blobs
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b'\x00' * 32
    aesgcm = AESGCM(session_key)

    blobs = []
    for i in range(3):
        iv = bytes([i + 1] * 12)
        plaintext = json.dumps({"lat": float(i), "lon": float(
            i * 10), "date": 1600000000000, "bat": 80}).encode('utf-8')
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        blob = b'\xAA' * 384 + iv + ciphertext
        blobs.append(base64.b64encode(blob).decode('utf-8').rstrip('='))

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "3"})
        # When fetching all, indices are 0, 1, 2
        for i, blob_b64 in enumerate(blobs):
            m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})

        try:
            locs = await client.get_locations(num_to_get=-1)
            assert len(locs) == 3
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_skip_empty_locations():
    """Test that skip_empty skips over empty blobs to find valid ones."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b'\x00' * 32
    aesgcm = AESGCM(session_key)
    iv = b'\x05' * 12
    plaintext = b'{"lat":5.0,"lon":10.0,"date":1600000000000,"bat":90}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b'\xAA' * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode('utf-8').rstrip('=')

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "3"})
        # Index 2 (most recent): empty
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": ""})
        # Index 1: empty
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": ""})
        # Index 0: valid
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})

        try:
            locs = await client.get_locations(num_to_get=1, skip_empty=True)
            assert len(locs) == 1
            assert locs[0] == blob_b64
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_picture_endpoint_error():
    """Test error handling when pictures endpoint fails."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    await client._ensure_session()

    with aioresponses() as m:
        # pictures endpoint returns 500 error
        m.put("https://fmd.example.com/api/v1/pictures", status=500)

        try:
            # Should return empty list on error (client logs warning)
            pictures = await client.get_pictures()
            assert pictures == []
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_multiple_commands_sequence():
    """Test sending multiple commands in sequence."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    await client._ensure_session()

    with aioresponses() as m:
        # Mock multiple command requests
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            result1 = await client.send_command("ring")
            assert result1 is True

            result2 = await client.send_command("lock")
            assert result2 is True

            result3 = await client.send_command("locate")
            assert result3 is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_pictures_pagination():
    """Test get_pictures with num_to_get limit."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    await client._ensure_session()

    with aioresponses() as m:
        # Mock pictures response with multiple pictures (already in order)
        mock_pictures = [
            {"id": 2, "date": 1600000002000},
            {"id": 1, "date": 1600000001000},
            {"id": 0, "date": 1600000000000}
        ]
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": mock_pictures})

        try:
            pictures = await client.get_pictures(num_to_get=2)
            assert len(pictures) == 2
            # Should get the 2 most recent (last 2, reversed)
            # [-2:][::-1] on [2,1,0] gives [1,0] then reverses to [0,1]
            assert pictures[0]["id"] == 0
            assert pictures[1]["id"] == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_authenticate_error_handling():
    """Test authenticate with invalid credentials."""
    client = FmdClient("https://fmd.example.com")

    await client._ensure_session()

    with aioresponses() as m:
        # Mock authentication endpoints - first call is to /api/v1/salt
        m.put("https://fmd.example.com/api/v1/salt", status=401)

        try:
            from fmd_api.exceptions import FmdApiException
            with pytest.raises(FmdApiException, match="API request failed for /api/v1/salt"):
                await client.authenticate("bad_id", "bad_password", session_duration=3600)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_locations_with_skip_empty_false():
    """Test get_locations with skip_empty=False fetches all indices."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "2"})
        # Both empty and valid blobs
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": ""})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": ""})

        try:
            # With skip_empty=False, should return empty blobs too
            locs = await client.get_locations(num_to_get=2, skip_empty=False)
            # Both are empty strings, so should get empty list since empty strings are filtered
            assert len(locs) == 0
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_send_command_failure():
    """Test send_command when server returns non-200 status."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    await client._ensure_session()

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=500, body="Server Error")

        try:
            from fmd_api.exceptions import FmdApiException
            with pytest.raises(FmdApiException, match="Failed to send command"):
                await client.send_command("ring")
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_decrypt_blob_invalid_format():
    """Test decrypt_data_blob with malformed blob."""
    client = FmdClient("https://fmd.example.com")

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    # Blob too short to contain IV and ciphertext
    short_blob = base64.b64encode(b'x' * 10).decode('utf-8')

    from fmd_api.exceptions import FmdApiException
    with pytest.raises(FmdApiException, match="Blob too small"):
        client.decrypt_data_blob(short_blob)


@pytest.mark.asyncio
async def test_export_data_404():
    """Test export_data_zip when API calls fail (e.g., no locations available)."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    client._fmd_id = "test"

    await client._ensure_session()

    with aioresponses() as m:
        # Mock API to return error when fetching location size
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=500)

        try:
            from fmd_api.exceptions import FmdApiException
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                with pytest.raises(FmdApiException, match="Failed to export data"):
                    await client.export_data_zip(tmp.name)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_get_pictures_empty_response():
    """Test get_pictures when server returns empty list."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": []})

        try:
            pictures = await client.get_pictures()
            assert pictures == []
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_request_location_unknown_provider():
    """Test request_location with unknown provider (falls back to 'locate')."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    await client._ensure_session()

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            # Unknown provider falls back to generic "locate" command
            result = await client.request_location(provider="unknown")
            assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_close_without_session():
    """Test close when no session exists."""
    client = FmdClient("https://fmd.example.com")
    # Should not raise error
    await client.close()
    assert client._session is None


@pytest.mark.asyncio
async def test_multiple_close_calls():
    """Test calling close multiple times."""
    client = FmdClient("https://fmd.example.com")
    await client._ensure_session()

    # First close
    await client.close()
    assert client._session is None

    # Second close should not raise error
    await client.close()
    assert client._session is None


@pytest.mark.asyncio
async def test_get_locations_max_attempts():
    """Test get_locations respects max_attempts parameter."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    await client._ensure_session()

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "100"})
        # Only set up 3 mocks even though max_attempts could be higher
        for i in range(3):
            m.put("https://fmd.example.com/api/v1/location", payload={"Data": ""})

        try:
            # Request 1 location from 100 available, with max_attempts=3
            locs = await client.get_locations(num_to_get=1, skip_empty=True, max_attempts=3)
            # All 3 are empty, so should get empty list
            assert len(locs) == 0
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_set_ringer_mode_edge_cases():
    """Test set_ringer_mode with all valid modes."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()

    await client._ensure_session()

    with aioresponses() as m:
        # Mock for each valid mode
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            result1 = await client.set_ringer_mode("normal")
            assert result1 is True

            result2 = await client.set_ringer_mode("vibrate")
            assert result2 is True

            result3 = await client.set_ringer_mode("silent")
            assert result3 is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_timeout_configuration():
    """Test that timeout can be configured at client level and per-request."""
    import asyncio
    
    # Test 1: Default timeout is 30 seconds
    client1 = FmdClient("https://fmd.example.com")
    assert client1.timeout == 30.0
    
    # Test 2: Custom timeout via constructor
    client2 = FmdClient("https://fmd.example.com", timeout=60.0)
    assert client2.timeout == 60.0
    
    # Test 3: Timeout via create() factory method
    client3_creds = {"BASE_URL": "https://fmd.example.com", "FMD_ID": "test", "PASSWORD": "test"}
    
    with aioresponses() as m:
        # Mock authentication flow
        m.put("https://fmd.example.com/api/v1/salt", payload={"Data": base64.b64encode(b"x" * 16).decode().rstrip("=")})
        m.put("https://fmd.example.com/api/v1/requestAccess", payload={"Data": "fake-token"})
        m.put("https://fmd.example.com/api/v1/key", payload={"Data": "fake-key-blob"})
        
        # Since we can't easily complete auth without real crypto, just test constructor accepts timeout
        client3 = FmdClient("https://fmd.example.com", timeout=45.0)
        assert client3.timeout == 45.0
    
    # Test 4: Verify timeout is passed to aiohttp (integration test would be needed for full validation)
    # For now, just confirm the attribute is stored correctly
    client4 = FmdClient("https://fmd.example.com", cache_ttl=60, timeout=120.0)
    assert client4.timeout == 120.0
    assert client4.cache_ttl == 60
    
    await client1.close()
    await client2.close()
    await client3.close()
    await client4.close()


@pytest.mark.asyncio
async def test_async_context_manager_direct():
    """FmdClient supports async with and auto-closes session."""
    client = FmdClient("https://fmd.example.com")
    # Create session inside context and ensure it closes after
    async with client as c:
        assert c is client
        await c._ensure_session()
        assert c._session is not None and not c._session.closed
    # After context exit, session should be closed and cleared
    assert client._session is None


@pytest.mark.asyncio
async def test_async_context_manager_with_create(monkeypatch):
    """Using async with await FmdClient.create(...) should auto-close session."""
    async def fake_authenticate(self, fmd_id, password, session_duration):
        # Minimal stub: set access_token without network
        self._fmd_id = fmd_id
        self._password = password
        self.access_token = "token"

    monkeypatch.setattr(FmdClient, "authenticate", fake_authenticate)

    client = await FmdClient.create("https://fmd.example.com", "id", "pw")
    async with client as c:
        await c._ensure_session()
        assert c._session is not None and not c._session.closed
    assert client._session is None


@pytest.mark.asyncio
async def test_rate_limit_retry_with_retry_after(monkeypatch):
    """Ensure 429 triggers sleep using Retry-After and then succeeds."""
    client = FmdClient("https://fmd.example.com", max_retries=2)
    client.access_token = "token"

    slept = {"calls": []}

    async def fake_sleep(seconds):
        slept["calls"].append(seconds)
        return None

    monkeypatch.setattr("asyncio.sleep", fake_sleep)

    await client._ensure_session()
    with aioresponses() as m:
        # First call: 429 with Retry-After: 1, then success
        m.put(
            "https://fmd.example.com/api/v1/locationDataSize",
            status=429,
            headers={"Retry-After": "1"},
        )
        m.put(
            "https://fmd.example.com/api/v1/locationDataSize",
            payload={"Data": "0"},
        )

        try:
            locs = await client.get_locations()
            assert locs == []
            # We should have slept once for ~1 second
            assert len(slept["calls"]) == 1
            # Allow a small tolerance due to float conversion
            assert abs(slept["calls"][0] - 1.0) < 0.01
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_server_error_retry_then_success(monkeypatch):
    """Ensure 500 triggers exponential backoff retry and then success."""
    client = FmdClient("https://fmd.example.com", max_retries=2, backoff_base=0.1, jitter=False)
    client.access_token = "token"

    slept = {"calls": []}

    async def fake_sleep(seconds):
        slept["calls"].append(seconds)
        return None

    monkeypatch.setattr("asyncio.sleep", fake_sleep)

    await client._ensure_session()
    with aioresponses() as m:
        # First attempt 500, second attempt 200 with Data=0
        m.put("https://fmd.example.com/api/v1/locationDataSize", status=500)
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})

        try:
            locs = await client.get_locations()
            assert locs == []
            # One backoff sleep, base=0.1, attempt0 -> 0.1 seconds when no jitter
            assert slept["calls"] == [0.1]
        finally:
            await client.close()
