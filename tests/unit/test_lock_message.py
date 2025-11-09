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
