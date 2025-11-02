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
    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        client.access_token = "dummy-token"
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
