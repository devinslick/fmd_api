"""Tests for Device class."""
import json
import pytest
from unittest.mock import Mock, AsyncMock, patch
from io import BytesIO

from fmd_api import Device, Location, PhotoResult
from fmd_api.client import FmdClient
from fmd_api.helpers import encode_base64


@pytest.fixture
def mock_client():
    """Mock FmdClient."""
    client = Mock(spec=FmdClient)
    client.get_locations = AsyncMock()
    client.get_pictures = AsyncMock()
    client.send_command = AsyncMock(return_value=True)
    client.request_location = AsyncMock(return_value=True)
    client.take_picture = AsyncMock(return_value=True)
    client.decrypt_data_blob = Mock()
    return client


@pytest.mark.asyncio
async def test_device_get_location(mock_client):
    """Test getting current location."""
    device = Device(mock_client)
    
    # Mock location data
    location_data = {
        'time': 'Mon Jan 1 12:00:00 UTC 2024',
        'date': 1704110400000,
        'provider': 'gps',
        'bat': 75,
        'lat': 37.7749,
        'lon': -122.4194,
        'accuracy': 10.5,
        'speed': 1.2
    }
    
    mock_client.get_locations.return_value = ['encrypted_blob']
    mock_client.decrypt_data_blob.return_value = json.dumps(location_data).encode()
    
    location = await device.get_location()
    
    assert location is not None
    assert location.latitude == 37.7749
    assert location.longitude == -122.4194
    assert location.battery == 75
    assert location.provider == 'gps'
    assert location.accuracy == 10.5
    assert location.speed == 1.2
    
    mock_client.get_locations.assert_called_once_with(num_to_get=1)


@pytest.mark.asyncio
async def test_device_get_location_no_data(mock_client):
    """Test getting location when no data available."""
    device = Device(mock_client)
    
    mock_client.get_locations.return_value = []
    
    location = await device.get_location()
    
    assert location is None


@pytest.mark.asyncio
async def test_device_get_location_cached(mock_client):
    """Test getting cached location."""
    device = Device(mock_client)
    
    # Set a cached location
    cached_location = Location(
        time='Mon Jan 1 12:00:00 UTC 2024',
        date=1704110400000,
        provider='gps',
        battery=75,
        latitude=37.7749,
        longitude=-122.4194
    )
    device._cached_location = cached_location
    
    location = await device.get_location(use_cached=True)
    
    assert location == cached_location
    mock_client.get_locations.assert_not_called()


@pytest.mark.asyncio
async def test_device_get_history(mock_client):
    """Test getting location history."""
    device = Device(mock_client)
    
    location_data_1 = {
        'time': 'Mon Jan 1 12:00:00 UTC 2024',
        'date': 1704110400000,
        'provider': 'gps',
        'bat': 75,
        'lat': 37.7749,
        'lon': -122.4194
    }
    
    location_data_2 = {
        'time': 'Mon Jan 1 13:00:00 UTC 2024',
        'date': 1704114000000,
        'provider': 'network',
        'bat': 70,
        'lat': 37.7750,
        'lon': -122.4195
    }
    
    mock_client.get_locations.return_value = ['blob1', 'blob2']
    mock_client.decrypt_data_blob.side_effect = [
        json.dumps(location_data_1).encode(),
        json.dumps(location_data_2).encode()
    ]
    
    history = await device.get_history(count=2)
    
    assert len(history) == 2
    assert history[0].latitude == 37.7749
    assert history[1].latitude == 37.7750
    assert history[0].battery == 75
    assert history[1].battery == 70
    
    mock_client.get_locations.assert_called_once_with(num_to_get=2)


@pytest.mark.asyncio
async def test_device_refresh(mock_client):
    """Test refreshing device location."""
    device = Device(mock_client)
    
    result = await device.refresh(provider='gps')
    
    assert result is True
    mock_client.request_location.assert_called_once_with('gps')


@pytest.mark.asyncio
async def test_device_play_sound(mock_client):
    """Test making device ring."""
    device = Device(mock_client)
    
    result = await device.play_sound()
    
    assert result is True
    mock_client.send_command.assert_called_once_with('ring')


@pytest.mark.asyncio
async def test_device_take_photo(mock_client):
    """Test taking a photo."""
    device = Device(mock_client)
    
    result = await device.take_photo(camera='front')
    
    assert result is True
    mock_client.take_picture.assert_called_once_with('front')


@pytest.mark.asyncio
async def test_device_fetch_pictures(mock_client):
    """Test fetching pictures."""
    device = Device(mock_client)
    
    mock_client.get_pictures.return_value = [
        {'timestamp': 1000, 'camera': 'back', 'data': 'blob1'},
        {'timestamp': 2000, 'camera': 'front', 'data': 'blob2'}
    ]
    
    pictures = await device.fetch_pictures(count=2)
    
    assert len(pictures) == 2
    assert pictures[0].timestamp == 1000
    assert pictures[0].camera == 'back'
    assert pictures[1].timestamp == 2000
    assert pictures[1].camera == 'front'
    
    mock_client.get_pictures.assert_called_once_with(num_to_get=2)


@pytest.mark.asyncio
async def test_device_download_photo(mock_client):
    """Test downloading and decrypting a photo."""
    device = Device(mock_client)
    
    photo = PhotoResult(
        timestamp=1000,
        camera='back',
        encrypted_data='encrypted_blob'
    )
    
    # Mock decryption to return base64-encoded image data
    photo_bytes = b'FAKE_IMAGE_DATA'
    photo_b64 = encode_base64(photo_bytes, strip_padding=False)
    mock_client.decrypt_data_blob.return_value = photo_b64.encode()
    
    output = BytesIO()
    result = await device.download_photo(photo, output)
    
    assert result is True
    assert output.getvalue() == photo_bytes
    mock_client.decrypt_data_blob.assert_called_once_with('encrypted_blob')


@pytest.mark.asyncio
async def test_device_lock(mock_client):
    """Test locking device."""
    device = Device(mock_client)
    
    result = await device.lock()
    
    assert result is True
    mock_client.send_command.assert_called_once_with('lock')


@pytest.mark.asyncio
async def test_device_wipe(mock_client):
    """Test wiping device."""
    device = Device(mock_client)
    
    result = await device.wipe()
    
    assert result is True
    mock_client.send_command.assert_called_once_with('delete')


@pytest.mark.asyncio
async def test_device_create():
    """Test Device.create factory method."""
    with patch('fmd_api.device.FmdClient.create') as mock_create:
        mock_client = Mock(spec=FmdClient)
        mock_create.return_value = mock_client
        
        device = await Device.create('https://fmd.test', 'device-id', 'password')
        
        assert device.client == mock_client
        mock_create.assert_called_once_with('https://fmd.test', 'device-id', 'password', 3600)
