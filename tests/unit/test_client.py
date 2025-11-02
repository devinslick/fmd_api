import asyncio
import json
import base64
from datetime import datetime, timezone

import pytest
import aiohttp
from aioresponses import aioresponses

from fmd_api.client import FmdClient
from fmd_api.helpers import _pad_base64

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
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    small_zip = b'PK\x03\x04' + b'\x00' * 100
    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/exportData", body=small_zip, status=200)
        out_file = tmp_path / "export.zip"
        try:
            await client.export_data_zip(str(out_file))
            assert out_file.exists()
            content = out_file.read_bytes()
            assert content.startswith(b'PK\x03\x04')
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
        iv = bytes([i+1] * 12)
        plaintext = json.dumps({"lat": float(i), "lon": float(i*10), "date": 1600000000000, "bat": 80}).encode('utf-8')
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
