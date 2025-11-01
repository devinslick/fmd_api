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

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload=blob_b64)
        client.access_token = "token"
        device = Device(client, "alice")
        await device.refresh()
        loc = await device.get_location()
        assert loc is not None
        assert abs(loc.lat - 10.0) < 1e-6
        assert abs(loc.lon - 20.0) < 1e-6

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
        pics = await device.fetch_pictures()
        assert len(pics) == 1
        # download the picture and verify we got PNGDATA bytes
        photo = await device.download_photo(pics[0])
        assert photo.data == b'PNGDATA'
        assert photo.mime_type.startswith("image/")