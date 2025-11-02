import asyncio
import base64
import json
from datetime import datetime, timezone

import pytest
from aioresponses import aioresponses

from fmd_api.client import FmdClient
from fmd_api.device import Device

@pytest.mark.asyncio
async def test_device_refresh_and_get_location(monkeypatch):
    client = FmdClient("https://fmd.example.com")
    # Dummy private_key decrypt path (reuse approach from client tests)
    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    # Create a simple AES-GCM encrypted location blob (same scheme as client test)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b'\x00' * 32
    aesgcm = AESGCM(session_key)
    iv = b'\x02' * 12
    plaintext = b'{"lat":10.0,"lon":20.0,"date":1600000000000,"bat":80}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b'\xAA' * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode('utf-8').rstrip('=')

    client.access_token = "token"
    device = Device(client, "alice")
    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        try:
            await device.refresh()
            loc = await device.get_location()
            assert loc is not None
            assert abs(loc.lat - 10.0) < 1e-6
            assert abs(loc.lon - 20.0) < 1e-6
        finally:
            await client.close()

@pytest.mark.asyncio
async def test_device_fetch_and_download_picture(monkeypatch):
    client = FmdClient("https://fmd.example.com")
    # Provide dummy private key that decrypts session packet into all-zero key
    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    # Prepare an "encrypted blob" that after decrypt yields a base64 image string.
    # For test simplicity, we'll make decrypted payload the base64 of b'PNGDATA'
    inner_image = base64.b64encode(b'PNGDATA').decode('utf-8')
    # Encrypt inner_image using AESGCM with zero key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b'\x00' * 32
    aesgcm = AESGCM(session_key)
    iv = b'\x03' * 12
    ciphertext = aesgcm.encrypt(iv, inner_image.encode('utf-8'), None)
    blob = b'\xAA' * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode('utf-8').rstrip('=')

    with aioresponses() as m:
        # get_pictures endpoint returns a JSON list; emulate simple list containing our blob
        m.put("https://fmd.example.com/api/v1/pictures", payload=[blob_b64])
        client.access_token = "token"
        device = Device(client, "alice")
        try:
            pics = await device.fetch_pictures()
            assert len(pics) == 1
            # download the picture and verify we got PNGDATA bytes
            photo = await device.download_photo(pics[0])
            assert photo.data == b'PNGDATA'
            assert photo.mime_type.startswith("image/")
        finally:
            await client.close()

@pytest.mark.asyncio
async def test_device_command_wrappers():
    """Test Device command wrapper methods."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()
    
    device = Device(client, "test-device")
    
    with aioresponses() as m:
        # Mock all command endpoints
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await device.play_sound() is True
            assert await device.take_front_photo() is True
            assert await device.take_rear_photo() is True
            assert await device.lock() is True
        finally:
            await client.close()

@pytest.mark.asyncio
async def test_device_wipe_requires_confirm():
    """Test Device.wipe requires confirm=True."""
    from fmd_api.exceptions import OperationError
    
    client = FmdClient("https://fmd.example.com")
    device = Device(client, "test-device")
    
    # Should raise without confirm
    with pytest.raises(OperationError, match="wipe.*requires confirm=True"):
        await device.wipe()
    
    # Should work with confirm
    client.access_token = "token"
    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xAB" * 64
    client.private_key = DummySigner()
    
    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        try:
            assert await device.wipe(confirm=True) is True
        finally:
            await client.close()

@pytest.mark.asyncio
async def test_device_empty_location():
    """Test Device handles empty location gracefully."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()

    client.access_token = "token"
    device = Device(client, "test-device")

    with aioresponses() as m:
        # Server reports 0 locations
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "0"})
        try:
            loc = await device.get_location()
            assert loc is None
        finally:
            await client.close()

@pytest.mark.asyncio
async def test_device_get_history():
    """Test Device.get_history async iterator."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b'\x00' * 32
    client.private_key = DummyKey()
    
    # Create two location blobs
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    session_key = b'\x00' * 32
    aesgcm = AESGCM(session_key)
    
    blobs = []
    for i, (lat, lon) in enumerate([(10.0, 20.0), (11.0, 21.0)]):
        iv = bytes([i+1] * 12)
        plaintext = json.dumps({"lat": lat, "lon": lon, "date": 1600000000000 + i*1000, "bat": 80}).encode('utf-8')
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        blob = b'\xAA' * 384 + iv + ciphertext
        blobs.append(base64.b64encode(blob).decode('utf-8').rstrip('='))
    
    client.access_token = "token"
    device = Device(client, "test-device")
    
    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "2"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blobs[0]})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blobs[1]})
        try:
            locs = []
            async for loc in device.get_history(limit=2):
                locs.append(loc)
            
            assert len(locs) == 2
            assert abs(locs[0].lat - 10.0) < 1e-6
            assert abs(locs[1].lat - 11.0) < 1e-6
        finally:
            await client.close()

@pytest.mark.asyncio
async def test_device_force_refresh():
    """Test Device force refresh bypasses cache."""
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
    plaintext = b'{"lat":15.0,"lon":25.0,"date":1600000000000,"bat":90}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b'\xAA' * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode('utf-8').rstrip('=')
    
    client.access_token = "token"
    device = Device(client, "test-device")
    
    with aioresponses() as m:
        # First refresh
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        # Force refresh (should hit endpoints again)
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        try:
            await device.refresh()
            loc1 = await device.get_location()
            
            # Without force, should return cached
            loc2 = await device.get_location()
            assert loc1 is loc2  # Same object
            
            # With force, should fetch again
            loc3 = await device.get_location(force=True)
            assert abs(loc3.lat - 15.0) < 1e-6
        finally:
            await client.close()
