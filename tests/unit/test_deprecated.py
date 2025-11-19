import pytest
from unittest.mock import AsyncMock, MagicMock
from fmd_api.device import Device
from fmd_api.client import FmdClient


@pytest.mark.asyncio
async def test_deprecated_take_front_photo():
    client = MagicMock(spec=FmdClient)
    device = Device(client, "test-device")
    device.take_front_picture = AsyncMock(return_value=True)

    with pytest.warns(DeprecationWarning, match="take_front_photo.*deprecated"):
        result = await device.take_front_photo()

    assert result is True
    device.take_front_picture.assert_awaited_once()


@pytest.mark.asyncio
async def test_deprecated_take_rear_photo():
    client = MagicMock(spec=FmdClient)
    device = Device(client, "test-device")
    device.take_rear_picture = AsyncMock(return_value=True)

    with pytest.warns(DeprecationWarning, match="take_rear_photo.*deprecated"):
        result = await device.take_rear_photo()

    assert result is True
    device.take_rear_picture.assert_awaited_once()


@pytest.mark.asyncio
async def test_deprecated_fetch_pictures():
    client = MagicMock(spec=FmdClient)
    device = Device(client, "test-device")
    expected = [{"id": "123"}]
    device.get_picture_blobs = AsyncMock(return_value=expected)

    with pytest.warns(DeprecationWarning, match="fetch_pictures.*deprecated"):
        result = await device.fetch_pictures(num_to_get=5)

    assert result == expected
    device.get_picture_blobs.assert_awaited_once_with(num_to_get=5)


@pytest.mark.asyncio
async def test_deprecated_get_pictures():
    client = MagicMock(spec=FmdClient)
    device = Device(client, "test-device")
    expected = [{"id": "123"}]
    device.get_picture_blobs = AsyncMock(return_value=expected)

    with pytest.warns(DeprecationWarning, match="get_pictures.*deprecated"):
        result = await device.get_pictures(num_to_get=5)

    assert result == expected
    device.get_picture_blobs.assert_awaited_once_with(num_to_get=5)


@pytest.mark.asyncio
async def test_deprecated_download_photo():
    client = MagicMock(spec=FmdClient)
    device = Device(client, "test-device")
    expected = MagicMock()  # PhotoResult
    device.decode_picture = AsyncMock(return_value=expected)

    with pytest.warns(DeprecationWarning, match="download_photo.*deprecated"):
        result = await device.download_photo("blob")

    assert result == expected
    device.decode_picture.assert_awaited_once_with("blob")


@pytest.mark.asyncio
async def test_deprecated_get_picture():
    client = MagicMock(spec=FmdClient)
    device = Device(client, "test-device")
    expected = MagicMock()  # PhotoResult
    device.decode_picture = AsyncMock(return_value=expected)

    with pytest.warns(DeprecationWarning, match="get_picture.*deprecated"):
        result = await device.get_picture("blob")

    assert result == expected
    device.decode_picture.assert_awaited_once_with("blob")
