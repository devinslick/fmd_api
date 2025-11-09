"""Tests for Device.wipe PIN validation."""

import pytest
from fmd_api import Device
from fmd_api.client import FmdClient
from fmd_api.exceptions import OperationError
from aioresponses import aioresponses


@pytest.mark.asyncio
async def test_wipe_accepts_alphanumeric_pins():
    """Test that wipe accepts various alphanumeric PINs."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()
    device = Device(client, "test-device")

    valid_pins = [
        "1234",  # Numeric only (short)
        "12",  # Very short numeric
        "123456789012345678901234567890",  # Long numeric
        "abc123",  # Alphanumeric lowercase
        "ABC123",  # Alphanumeric uppercase
        "MyPin2025",  # Mixed case alphanumeric
        "a",  # Single character
        "Z9",  # Two characters
    ]

    with aioresponses() as m:
        for pin in valid_pins:
            m.post("https://fmd.example.com/api/v1/command", status=200, body="OK")

        try:
            for pin in valid_pins:
                result = await device.wipe(pin=pin, confirm=True)
                assert result is True
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_wipe_rejects_invalid_pins():
    """Test that wipe rejects PINs with invalid characters."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"

    class DummySigner:
        def sign(self, message_bytes, pad, algo):
            return b"\xab" * 64

    client.private_key = DummySigner()
    device = Device(client, "test-device")

    invalid_pins = [
        "123 456",  # Contains space
        "hello world",  # Contains space
        "pin!",  # Special character
        "test@123",  # Special character
        "pin#code",  # Special character
        "émoji",  # Non-ASCII
        "測試",  # Non-ASCII
        "test-pin",  # Hyphen
        "pin_code",  # Underscore
        "test.pin",  # Period
    ]

    try:
        for pin in invalid_pins:
            with pytest.raises(OperationError, match="alphanumeric ASCII|spaces"):
                await device.wipe(pin=pin, confirm=True)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_wipe_spaces_specific_error():
    """Test that spaces in PIN trigger the alphanumeric error message."""
    client = FmdClient("https://fmd.example.com")
    device = Device(client, "test-device")

    try:
        # Space causes isalnum() to fail, hitting the alphanumeric check first
        with pytest.raises(OperationError, match="alphanumeric ASCII"):
            await device.wipe(pin="my pin", confirm=True)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_wipe_rejects_empty_pin():
    """Test that wipe rejects empty PIN."""
    client = FmdClient("https://fmd.example.com")
    device = Device(client, "test-device")

    try:
        with pytest.raises(OperationError, match="requires a PIN"):
            await device.wipe(pin=None, confirm=True)

        with pytest.raises(OperationError, match="requires a PIN"):
            await device.wipe(pin="", confirm=True)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_wipe_requires_confirm():
    """Test that wipe requires confirm=True."""
    client = FmdClient("https://fmd.example.com")
    device = Device(client, "test-device")

    try:
        with pytest.raises(OperationError, match="requires confirm=True"):
            await device.wipe(pin="abc123", confirm=False)

        with pytest.raises(OperationError, match="requires confirm=True"):
            await device.wipe(pin="abc123")
    finally:
        await client.close()
