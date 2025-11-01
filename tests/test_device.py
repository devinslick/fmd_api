"""Unit tests for Device class.

These tests validate the high-level Device interface and its interaction
with the underlying FmdClient.
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from fmd_api import Device, Location, Picture
from fmd_api.client import FmdClient


class TestDevice:
    """Test suite for Device class."""
    
    @pytest.fixture
    def mock_client(self):
        """Create a mock FmdClient."""
        client = MagicMock(spec=FmdClient)
        client.get_locations = AsyncMock()
        client.get_pictures = AsyncMock()
        client.decrypt_data_blob = MagicMock()
        client.send_command = AsyncMock()
        client.play_sound = AsyncMock()
        client.lock_device = AsyncMock()
        client.wipe_device = AsyncMock()
        client.take_picture = AsyncMock()
        return client
    
    @pytest.fixture
    def device(self, mock_client):
        """Create a Device instance with mock client."""
        return Device(mock_client)
    
    @pytest.fixture
    def sample_location_data(self):
        """Sample location data for testing."""
        return {
            "lat": 37.7749,
            "lon": -122.4194,
            "time": "Mon Jan 1 12:00:00 PST 2024",
            "date": 1704135600000,
            "provider": "gps",
            "bat": 75,
            "accuracy": 10.5,
            "altitude": 52.0,
            "speed": 0.0,
            "heading": None
        }
    
    @pytest.mark.asyncio
    async def test_create(self):
        """Test Device.create() factory method."""
        with patch.object(FmdClient, 'create', new_callable=AsyncMock) as mock_create:
            mock_client = MagicMock(spec=FmdClient)
            mock_create.return_value = mock_client
            
            device = await Device.create(
                "https://test.example.com",
                "test-device",
                "test-password",
                session_duration=7200
            )
            
            assert isinstance(device, Device)
            assert device.client == mock_client
            
            mock_create.assert_called_once_with(
                "https://test.example.com",
                "test-device",
                "test-password",
                7200
            )
    
    @pytest.mark.asyncio
    async def test_refresh(self, device, mock_client, sample_location_data):
        """Test refresh() updates cached location."""
        # Mock client to return location blob
        location_json = json.dumps(sample_location_data).encode('utf-8')
        mock_client.get_locations.return_value = ["encrypted_blob"]
        mock_client.decrypt_data_blob.return_value = location_json
        
        await device.refresh()
        
        # Verify location was fetched and cached
        assert device._cached_location is not None
        assert device._cached_location.latitude == 37.7749
        assert device._cached_location.longitude == -122.4194
        assert device._cached_location.battery == 75
        
        mock_client.get_locations.assert_called_once_with(num=1)
        mock_client.decrypt_data_blob.assert_called_once_with("encrypted_blob")
    
    @pytest.mark.asyncio
    async def test_refresh_no_data(self, device, mock_client):
        """Test refresh() when no location data available."""
        mock_client.get_locations.return_value = []
        
        await device.refresh()
        
        # Verify cached location is None
        assert device._cached_location is None
    
    @pytest.mark.asyncio
    async def test_get_location_no_cache(self, device, mock_client, sample_location_data):
        """Test get_location() without cache."""
        location_json = json.dumps(sample_location_data).encode('utf-8')
        mock_client.get_locations.return_value = ["encrypted_blob"]
        mock_client.decrypt_data_blob.return_value = location_json
        
        location = await device.get_location(use_cache=False)
        
        assert location is not None
        assert location.latitude == 37.7749
        assert location.longitude == -122.4194
        
        mock_client.get_locations.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_location_use_cache(self, device, mock_client, sample_location_data):
        """Test get_location() using cache."""
        # Set up cached location
        device._cached_location = Location.from_dict(sample_location_data)
        
        location = await device.get_location(use_cache=True)
        
        assert location == device._cached_location
        # Verify no API call was made
        mock_client.get_locations.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_get_location_cache_miss(self, device, mock_client, sample_location_data):
        """Test get_location() with use_cache=True but no cache."""
        location_json = json.dumps(sample_location_data).encode('utf-8')
        mock_client.get_locations.return_value = ["encrypted_blob"]
        mock_client.decrypt_data_blob.return_value = location_json
        
        location = await device.get_location(use_cache=True)
        
        assert location is not None
        # Verify API call was made since cache was empty
        mock_client.get_locations.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_history(self, device, mock_client, sample_location_data):
        """Test get_history() returns multiple locations."""
        # Create 3 location blobs
        location_json = json.dumps(sample_location_data).encode('utf-8')
        mock_client.get_locations.return_value = ["blob1", "blob2", "blob3"]
        mock_client.decrypt_data_blob.return_value = location_json
        
        history = await device.get_history(limit=3)
        
        assert len(history) == 3
        assert all(isinstance(loc, Location) for loc in history)
        assert all(loc.latitude == 37.7749 for loc in history)
        
        mock_client.get_locations.assert_called_once_with(num=3)
    
    @pytest.mark.asyncio
    async def test_get_history_skip_invalid(self, device, mock_client, sample_location_data):
        """Test get_history() skips invalid blobs."""
        location_json = json.dumps(sample_location_data).encode('utf-8')
        mock_client.get_locations.return_value = ["blob1", "blob2", "blob3"]
        
        # Make second blob fail to decrypt
        def decrypt_side_effect(blob):
            if blob == "blob2":
                raise Exception("Decryption failed")
            return location_json
        
        mock_client.decrypt_data_blob.side_effect = decrypt_side_effect
        
        history = await device.get_history(limit=3)
        
        # Should only get 2 locations (blob2 failed)
        assert len(history) == 2
    
    @pytest.mark.asyncio
    async def test_play_sound(self, device, mock_client):
        """Test play_sound() command."""
        mock_client.play_sound.return_value = True
        
        result = await device.play_sound()
        
        assert result is True
        mock_client.play_sound.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_lock(self, device, mock_client):
        """Test lock() command."""
        mock_client.lock_device.return_value = True
        
        result = await device.lock()
        
        assert result is True
        mock_client.lock_device.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_wipe(self, device, mock_client):
        """Test wipe() command."""
        mock_client.wipe_device.return_value = True
        
        result = await device.wipe()
        
        assert result is True
        mock_client.wipe_device.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_take_front_photo(self, device, mock_client):
        """Test take_front_photo() command."""
        mock_client.take_picture.return_value = True
        
        result = await device.take_front_photo()
        
        assert result is True
        mock_client.take_picture.assert_called_once_with("front")
    
    @pytest.mark.asyncio
    async def test_take_rear_photo(self, device, mock_client):
        """Test take_rear_photo() command."""
        mock_client.take_picture.return_value = True
        
        result = await device.take_rear_photo()
        
        assert result is True
        mock_client.take_picture.assert_called_once_with("back")
    
    @pytest.mark.asyncio
    async def test_fetch_pictures(self, device, mock_client):
        """Test fetch_pictures() retrieves and decrypts pictures."""
        # Mock picture data
        mock_client.get_pictures.return_value = [
            {"data": "encrypted_blob1"},
            {"data": "encrypted_blob2"}
        ]
        
        # Mock decryption to return base64-encoded image data
        import base64
        fake_image = b"fake_image_data"
        fake_image_b64 = base64.b64encode(fake_image)
        mock_client.decrypt_data_blob.return_value = fake_image_b64
        
        pictures = await device.fetch_pictures(limit=2)
        
        assert len(pictures) == 2
        assert all(isinstance(pic, Picture) for pic in pictures)
        assert all(pic.data == fake_image for pic in pictures)
        
        mock_client.get_pictures.assert_called_once_with(num=2)
    
    @pytest.mark.asyncio
    async def test_fetch_pictures_skip_empty(self, device, mock_client):
        """Test fetch_pictures() skips empty picture data."""
        mock_client.get_pictures.return_value = [
            {"data": "encrypted_blob1"},
            {"data": ""},  # Empty data
            {"data": "encrypted_blob3"}
        ]
        
        import base64
        fake_image = b"fake_image_data"
        fake_image_b64 = base64.b64encode(fake_image)
        mock_client.decrypt_data_blob.return_value = fake_image_b64
        
        pictures = await device.fetch_pictures()
        
        # Should only get 2 pictures (skipped empty one)
        assert len(pictures) == 2
    
    @pytest.mark.asyncio
    async def test_download_photo(self, device, tmp_path):
        """Test download_photo() saves picture to file."""
        picture = Picture(data=b"test_image_data")
        output_path = tmp_path / "test_photo.jpg"
        
        await device.download_photo(picture, str(output_path))
        
        # Verify file was created with correct content
        assert output_path.exists()
        assert output_path.read_bytes() == b"test_image_data"
    
    def test_last_known_location_property(self, device, sample_location_data):
        """Test last_known_location property."""
        # Initially None
        assert device.last_known_location is None
        
        # Set cached location
        location = Location.from_dict(sample_location_data)
        device._cached_location = location
        
        # Verify property returns cached location
        assert device.last_known_location == location
        assert device.last_known_location.latitude == 37.7749


class TestLocation:
    """Test suite for Location type."""
    
    def test_from_dict(self):
        """Test Location.from_dict() creates instance correctly."""
        data = {
            "lat": 37.7749,
            "lon": -122.4194,
            "time": "Mon Jan 1 12:00:00 PST 2024",
            "date": 1704135600000,
            "provider": "gps",
            "bat": 75,
            "accuracy": 10.5,
            "altitude": 52.0,
            "speed": 1.5,
            "heading": 180.0
        }
        
        location = Location.from_dict(data)
        
        assert location.latitude == 37.7749
        assert location.longitude == -122.4194
        assert location.timestamp == "Mon Jan 1 12:00:00 PST 2024"
        assert location.date_ms == 1704135600000
        assert location.provider == "gps"
        assert location.battery == 75
        assert location.accuracy == 10.5
        assert location.altitude == 52.0
        assert location.speed == 1.5
        assert location.heading == 180.0
    
    def test_from_dict_optional_fields(self):
        """Test Location.from_dict() handles missing optional fields."""
        data = {
            "lat": 37.7749,
            "lon": -122.4194,
            "time": "Mon Jan 1 12:00:00 PST 2024",
            "date": 1704135600000,
            "provider": "network",
            "bat": 50
        }
        
        location = Location.from_dict(data)
        
        assert location.latitude == 37.7749
        assert location.longitude == -122.4194
        assert location.accuracy is None
        assert location.altitude is None
        assert location.speed is None
        assert location.heading is None
    
    def test_to_dict(self):
        """Test Location.to_dict() creates correct dictionary."""
        location = Location(
            latitude=37.7749,
            longitude=-122.4194,
            timestamp="Mon Jan 1 12:00:00 PST 2024",
            date_ms=1704135600000,
            provider="gps",
            battery=75,
            accuracy=10.5,
            altitude=52.0,
            speed=1.5,
            heading=180.0
        )
        
        data = location.to_dict()
        
        assert data["lat"] == 37.7749
        assert data["lon"] == -122.4194
        assert data["time"] == "Mon Jan 1 12:00:00 PST 2024"
        assert data["date"] == 1704135600000
        assert data["provider"] == "gps"
        assert data["bat"] == 75
        assert data["accuracy"] == 10.5
        assert data["altitude"] == 52.0
        assert data["speed"] == 1.5
        assert data["heading"] == 180.0
    
    def test_to_dict_excludes_none(self):
        """Test Location.to_dict() excludes None values."""
        location = Location(
            latitude=37.7749,
            longitude=-122.4194,
            timestamp="Mon Jan 1 12:00:00 PST 2024",
            date_ms=1704135600000,
            provider="network",
            battery=50
        )
        
        data = location.to_dict()
        
        assert "accuracy" not in data
        assert "altitude" not in data
        assert "speed" not in data
        assert "heading" not in data
