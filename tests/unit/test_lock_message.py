import pytest
from aioresponses import aioresponses, CallbackResult

from fmd_api.client import FmdClient
from fmd_api.device import Device


@pytest.mark.asyncio
async def test_device_lock_without_message_sends_plain_lock():
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        # capture payload via callback
        captured = {}

        def cb(url, **kwargs):
            captured["json"] = kwargs.get("json")
            return CallbackResult(status=200, body="OK")

        m.post("https://fmd.example.com/api/v1/command", callback=cb)
        try:
            ok = await device.lock()
            assert ok is True
            assert captured["json"]["Data"] == "lock"
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_lock_with_message_sanitizes_and_sends():
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        captured = {}

        def cb(url, **kwargs):
            captured["json"] = kwargs.get("json")
            return CallbackResult(status=200, body="OK")

        m.post("https://fmd.example.com/api/v1/command", callback=cb)
        try:
            ok = await device.lock("  Hello   world; \n stay 'safe' \"pls\"  ")
            assert ok is True
            sent = captured["json"]["Data"]
            assert sent.startswith("lock ")
            # Ensure removed quotes/semicolons/newlines and collapsed spaces
            assert '"' not in sent and "'" not in sent and ";" not in sent and "\n" not in sent
            assert "  " not in sent
            assert sent.endswith("Hello world stay safe pls")
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_lock_truncates_long_message():
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        captured = {}

        def cb(url, **kwargs):
            captured["json"] = kwargs.get("json")
            return CallbackResult(status=200, body="OK")

        m.post("https://fmd.example.com/api/v1/command", callback=cb)
        try:
            # Create a message longer than 120 chars
            long_msg = "a" * 150
            ok = await device.lock(long_msg)
            assert ok is True
            sent = captured["json"]["Data"]
            assert sent.startswith("lock ")
            # "lock " is 5 chars, so the payload part is sent[5:]
            payload = sent[5:]
            assert len(payload) == 120
            assert payload == "a" * 120
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_device_lock_with_only_removed_chars_sends_plain_lock():
    """Test that a message with only removed characters results in plain 'lock' command."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()

    await client._ensure_session()
    device = Device(client, "test-device")

    with aioresponses() as m:
        captured = {}

        def cb(url, **kwargs):
            captured["json"] = kwargs.get("json")
            return CallbackResult(status=200, body="OK")

        m.post("https://fmd.example.com/api/v1/command", callback=cb)
        try:
            # Message consists only of chars that get removed (quotes, semicolons, backticks)
            ok = await device.lock("  ';\"` ;' \" `  ")
            assert ok is True
            # Should fall back to plain "lock" since sanitized message is empty
            assert captured["json"]["Data"] == "lock"
        finally:
            await client.close()
