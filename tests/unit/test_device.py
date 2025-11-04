import base64
import json

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
            return b"\x00" * 32

    client.private_key = DummyKey()

    # Create a simple AES-GCM encrypted location blob (same scheme as client test)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x02" * 12
    plaintext = b'{"lat":10.0,"lon":20.0,"date":1600000000000,"bat":80}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b"\xaa" * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8").rstrip("=")

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
            return b"\x00" * 32

    client.private_key = DummyKey()

    # Prepare an "encrypted blob" that after decrypt yields a base64 image string.
    # For test simplicity, we'll make decrypted payload the base64 of b'PNGDATA'
    inner_image = base64.b64encode(b"PNGDATA").decode("utf-8")
    # Encrypt inner_image using AESGCM with zero key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x03" * 12
    ciphertext = aesgcm.encrypt(iv, inner_image.encode("utf-8"), None)
    blob = b"\xaa" * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8").rstrip("=")

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
            assert photo.data == b"PNGDATA"
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
            return b"\xab" * 64

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
            return b"\xab" * 64

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
            return b"\x00" * 32

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
            return b"\x00" * 32

    client.private_key = DummyKey()

    # Create two location blobs
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)

    blobs = []
    for i, (lat, lon) in enumerate([(10.0, 20.0), (11.0, 21.0)]):
        iv = bytes([i + 1] * 12)
        plaintext = json.dumps({"lat": lat, "lon": lon, "date": 1600000000000 + i * 1000, "bat": 80}).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        blob = b"\xaa" * 384 + iv + ciphertext
        blobs.append(base64.b64encode(blob).decode("utf-8").rstrip("="))

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
            return b"\x00" * 32

    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x05" * 12
    plaintext = b'{"lat":15.0,"lon":25.0,"date":1600000000000,"bat":90}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b"\xaa" * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8").rstrip("=")

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


@pytest.mark.asyncio
async def test_device_cached_location_property():
    """Test Device.cached_location property access."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32

    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x06" * 12
    plaintext = b'{"lat":20.0,"lon":30.0,"date":1600000000000,"bat":75}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b"\xaa" * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8").rstrip("=")

    client.access_token = "token"
    device = Device(client, "test-device")

    # Initially None
    assert device.cached_location is None

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        try:
            await device.refresh()
            # Now should have cached location
            assert device.cached_location is not None
            assert abs(device.cached_location.lat - 20.0) < 1e-6
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_refresh_without_force():
    """Test Device.refresh with force=False doesn't re-fetch if cached."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32

    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)
    iv = b"\x07" * 12
    plaintext = b'{"lat":25.0,"lon":35.0,"date":1600000000000,"bat":85}'
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = b"\xaa" * 384 + iv + ciphertext
    blob_b64 = base64.b64encode(blob).decode("utf-8").rstrip("=")

    client.access_token = "token"
    device = Device(client, "test-device")

    with aioresponses() as m:
        # Only one set of mocks
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})
        try:
            await device.refresh()
            loc1 = device.cached_location

            # Second refresh without force should not make HTTP calls (mocks would fail if it did)
            await device.refresh(force=False)
            loc2 = device.cached_location

            assert loc1 is loc2  # Same cached object
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_picture_commands():
    """Test Device picture-related command shortcuts."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        # take_front_photo
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        # take_rear_photo
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            result1 = await device.take_front_photo()
            assert result1 is True

            result2 = await device.take_rear_photo()
            assert result2 is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_lock_with_message():
    """Test Device.lock with custom message."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            result = await device.lock("Please return this device")
            assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_multiple_history_calls():
    """Test Device.get_history can be called multiple times."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32

    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)

    blobs = []
    for i in range(2):
        iv = bytes([i + 10] * 12)
        plaintext = json.dumps(
            {"lat": float(30 + i), "lon": float(40 + i), "date": 1600000000000 + i * 1000, "bat": 80}
        ).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        blob = b"\xaa" * 384 + iv + ciphertext
        blobs.append(base64.b64encode(blob).decode("utf-8").rstrip("="))

    client.access_token = "token"
    device = Device(client, "test-device")

    with aioresponses() as m:
        # First call to get_history
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "2"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blobs[0]})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blobs[1]})

        # Second call to get_history
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "2"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blobs[0]})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blobs[1]})

        try:
            # First iteration
            locs1 = []
            async for loc in device.get_history(limit=2):
                locs1.append(loc)
            assert len(locs1) == 2

            # Second iteration (should work independently)
            locs2 = []
            async for loc in device.get_history(limit=2):
                locs2.append(loc)
            assert len(locs2) == 2

            # Both should have same data (different Location objects)
            assert abs(locs1[0].lat - locs2[0].lat) < 1e-6
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_name_property():
    """Test Device.name property from raw data."""
    client = FmdClient("https://fmd.example.com")
    device = Device(client, "my-phone-id", raw={"name": "My Phone"})

    assert device.name == "My Phone"
    assert device.id == "my-phone-id"
    await client.close()


@pytest.mark.asyncio
async def test_device_wipe_with_confirm():
    """Test Device.wipe when confirm=True actually sends command."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            result = await device.wipe(confirm=True)
            assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_ringer_via_client():
    """Test Device can use client's set_ringer_mode."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            # Device doesn't have set_ringer_mode, use client directly
            result = await device.client.set_ringer_mode("vibrate")
            assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_bluetooth_via_client():
    """Test Device can use client's set_bluetooth."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            # Device doesn't have set_bluetooth, use client directly
            result1 = await device.client.set_bluetooth(True)
            assert result1 is True

            result2 = await device.client.set_bluetooth(False)
            assert result2 is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_dnd_via_client():
    """Test Device can use client's set_do_not_disturb."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            # Device doesn't have set_do_not_disturb, use client directly
            result1 = await device.client.set_do_not_disturb(True)
            assert result1 is True

            result2 = await device.client.set_do_not_disturb(False)
            assert result2 is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_get_history_with_all_locations():
    """Test Device.get_history with limit=-1 fetches all."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32

    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)

    blobs = []
    for i in range(3):
        iv = bytes([i + 20] * 12)
        plaintext = json.dumps(
            {"lat": float(40 + i), "lon": float(50 + i), "date": 1600000000000 + i * 1000, "bat": 85}
        ).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        blob = b"\xaa" * 384 + iv + ciphertext
        blobs.append(base64.b64encode(blob).decode("utf-8").rstrip("="))

    client.access_token = "token"
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "3"})
        for blob_b64 in blobs:
            m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob_b64})

        try:
            locs = []
            async for loc in device.get_history(limit=-1):
                locs.append(loc)

            assert len(locs) == 3
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_fetch_pictures():
    """Test Device.fetch_pictures method."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        mock_pictures = [{"id": 0, "date": 1600000000000}]
        m.put("https://fmd.example.com/api/v1/pictures", payload={"Data": mock_pictures})

        try:
            pictures = await device.fetch_pictures(num_to_get=1)
            assert len(pictures) == 1
            assert pictures[0]["id"] == 0
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_request_location_via_client():
    """Test Device can use client's request_location."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            # Device doesn't have request_location, use client directly
            result = await device.client.request_location(provider="gps")
            assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_get_stats_via_client():
    """Test Device can use client's get_device_stats."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            # Device doesn't have get_stats, use client's get_device_stats
            result = await device.client.get_device_stats()
            assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_refresh_updates_cached_location():
    """Test that refresh() updates the cached location."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummyKey:
        def decrypt(self, packet, padding_obj):
            return b"\x00" * 32

    client.private_key = DummyKey()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = b"\x00" * 32
    aesgcm = AESGCM(session_key)

    # Create two different blobs
    iv1 = b"\x30" * 12
    plaintext1 = b'{"lat":50.0,"lon":60.0,"date":1600000000000,"bat":90}'
    ciphertext1 = aesgcm.encrypt(iv1, plaintext1, None)
    blob1 = b"\xaa" * 384 + iv1 + ciphertext1
    blob1_b64 = base64.b64encode(blob1).decode("utf-8").rstrip("=")

    iv2 = b"\x31" * 12
    plaintext2 = b'{"lat":55.0,"lon":65.0,"date":1600000001000,"bat":85}'
    ciphertext2 = aesgcm.encrypt(iv2, plaintext2, None)
    blob2 = b"\xaa" * 384 + iv2 + ciphertext2
    blob2_b64 = base64.b64encode(blob2).decode("utf-8").rstrip("=")

    client.access_token = "token"
    device = Device(client, "test-device")

    with aioresponses() as m:
        # First refresh
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob1_b64})

        # Second refresh with force=True
        m.put("https://fmd.example.com/api/v1/locationDataSize", payload={"Data": "1"})
        m.put("https://fmd.example.com/api/v1/location", payload={"Data": blob2_b64})

        try:
            await device.refresh()
            loc1 = device.cached_location
            assert abs(loc1.lat - 50.0) < 1e-6

            # Force refresh should get new data
            await device.refresh(force=True)
            loc2 = device.cached_location
            assert abs(loc2.lat - 55.0) < 1e-6
        finally:
            await client.close()
