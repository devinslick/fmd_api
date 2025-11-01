"""Unit tests for FmdClient class.

These tests validate the core functionality of the FmdClient class,
including authentication, encryption/decryption, and API operations.
"""

import pytest
import json
import base64
from unittest.mock import AsyncMock, MagicMock, patch

from fmd_api import FmdClient, FmdCommands
from fmd_api.exceptions import (
    AuthenticationError,
    DecryptionError,
    ApiRequestError,
    CommandError
)
from fmd_api.helpers import encode_base64


class TestFmdClient:
    """Test suite for FmdClient class."""
    
    @pytest.fixture
    def mock_client(self):
        """Create a mock FmdClient instance."""
        client = FmdClient("https://test.example.com", session_duration=3600)
        client.access_token = "test-token"
        client._fmd_id = "test-device"
        client._password = "test-password"
        return client
    
    def test_init(self):
        """Test FmdClient initialization."""
        client = FmdClient("https://test.example.com", session_duration=7200)
        assert client.base_url == "https://test.example.com"
        assert client.session_duration == 7200
        assert client.access_token is None
        assert client.private_key is None
    
    def test_base_url_stripping(self):
        """Test that trailing slashes are removed from base URL."""
        client = FmdClient("https://test.example.com/")
        assert client.base_url == "https://test.example.com"
        
        client = FmdClient("https://test.example.com///")
        assert client.base_url == "https://test.example.com"
    
    @pytest.mark.asyncio
    async def test_create_success(self):
        """Test successful client creation and authentication."""
        with patch.object(FmdClient, 'authenticate', new_callable=AsyncMock) as mock_auth:
            client = await FmdClient.create(
                "https://test.example.com",
                "test-device",
                "test-password",
                session_duration=3600
            )
            
            assert client.base_url == "https://test.example.com"
            assert client._fmd_id == "test-device"
            assert client._password == "test-password"
            assert client.session_duration == 3600
            
            mock_auth.assert_called_once_with("test-device", "test-password", 3600)
    
    def test_hash_password(self, mock_client):
        """Test password hashing with Argon2id."""
        salt = encode_base64(b"0" * 16)  # 16-byte salt
        password_hash = mock_client._hash_password("test-password", salt)
        
        # Verify hash format
        assert password_hash.startswith("$argon2id$v=19$m=131072,t=1,p=4$")
        assert salt in password_hash
        
        # Verify hash is deterministic
        password_hash2 = mock_client._hash_password("test-password", salt)
        assert password_hash == password_hash2
        
        # Verify different passwords produce different hashes
        password_hash3 = mock_client._hash_password("different-password", salt)
        assert password_hash != password_hash3
    
    @pytest.mark.asyncio
    async def test_get_locations_all(self, mock_client):
        """Test fetching all locations."""
        with patch.object(mock_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            # Mock responses
            mock_request.side_effect = [
                "3",  # locationDataSize
                "blob1", "blob2", "blob3"  # location blobs
            ]
            
            locations = await mock_client.get_locations(num=-1)
            
            assert len(locations) == 3
            assert locations == ["blob1", "blob2", "blob3"]
            assert mock_request.call_count == 4  # 1 size + 3 locations
    
    @pytest.mark.asyncio
    async def test_get_locations_limited(self, mock_client):
        """Test fetching limited number of locations."""
        with patch.object(mock_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            # Mock responses
            mock_request.side_effect = [
                "5",  # locationDataSize (5 available)
                "blob5", "blob4"  # Most recent 2 locations (indices 4, 3)
            ]
            
            locations = await mock_client.get_locations(num=2)
            
            assert len(locations) == 2
            assert locations == ["blob5", "blob4"]
    
    @pytest.mark.asyncio
    async def test_get_locations_empty(self, mock_client):
        """Test fetching locations when none available."""
        with patch.object(mock_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = "0"  # No locations
            
            locations = await mock_client.get_locations()
            
            assert len(locations) == 0
    
    @pytest.mark.asyncio
    async def test_get_locations_skip_empty(self, mock_client):
        """Test skipping empty location blobs."""
        with patch.object(mock_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            # Mock responses with some empty blobs
            mock_request.side_effect = [
                "5",  # locationDataSize
                "",  # Empty blob at index 4
                "blob3",  # Valid blob at index 3
            ]
            
            locations = await mock_client.get_locations(num=1, skip_empty=True)
            
            assert len(locations) == 1
            assert locations[0] == "blob3"
    
    @pytest.mark.asyncio
    async def test_send_command_success(self, mock_client):
        """Test sending a command successfully."""
        # Create a mock private key with sign method
        mock_private_key = MagicMock()
        mock_private_key.sign.return_value = b"signature"
        mock_client.private_key = mock_private_key
        
        with patch.object(mock_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = "OK"
            
            result = await mock_client.send_command("ring")
            
            assert result is True
            mock_private_key.sign.assert_called_once()
            mock_request.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_command_failure(self, mock_client):
        """Test command sending failure."""
        mock_private_key = MagicMock()
        mock_private_key.sign.return_value = b"signature"
        mock_client.private_key = mock_private_key
        
        with patch.object(mock_client, '_make_api_request', new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("Network error")
            
            with pytest.raises(CommandError):
                await mock_client.send_command("ring")
    
    @pytest.mark.asyncio
    async def test_request_location_providers(self, mock_client):
        """Test request_location with different providers."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            # Test all providers
            await mock_client.request_location("all")
            mock_send.assert_called_with(FmdCommands.LOCATE_ALL)
            
            await mock_client.request_location("gps")
            mock_send.assert_called_with(FmdCommands.LOCATE_GPS)
            
            await mock_client.request_location("cell")
            mock_send.assert_called_with(FmdCommands.LOCATE_CELL)
            
            await mock_client.request_location("network")
            mock_send.assert_called_with(FmdCommands.LOCATE_CELL)
            
            await mock_client.request_location("last")
            mock_send.assert_called_with(FmdCommands.LOCATE_LAST)
    
    @pytest.mark.asyncio
    async def test_play_sound(self, mock_client):
        """Test play_sound command."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.play_sound()
            mock_send.assert_called_once_with(FmdCommands.RING)
    
    @pytest.mark.asyncio
    async def test_lock_device(self, mock_client):
        """Test lock_device command."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.lock_device()
            mock_send.assert_called_once_with(FmdCommands.LOCK)
    
    @pytest.mark.asyncio
    async def test_take_picture_cameras(self, mock_client):
        """Test take_picture with different cameras."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.take_picture("front")
            mock_send.assert_called_with(FmdCommands.CAMERA_FRONT)
            
            await mock_client.take_picture("back")
            mock_send.assert_called_with(FmdCommands.CAMERA_BACK)
    
    @pytest.mark.asyncio
    async def test_take_picture_invalid_camera(self, mock_client):
        """Test take_picture with invalid camera."""
        with pytest.raises(ValueError, match="Invalid camera"):
            await mock_client.take_picture("invalid")
    
    @pytest.mark.asyncio
    async def test_toggle_bluetooth(self, mock_client):
        """Test Bluetooth toggle commands."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.toggle_bluetooth(True)
            mock_send.assert_called_with(FmdCommands.BLUETOOTH_ON)
            
            await mock_client.toggle_bluetooth(False)
            mock_send.assert_called_with(FmdCommands.BLUETOOTH_OFF)
    
    @pytest.mark.asyncio
    async def test_toggle_do_not_disturb(self, mock_client):
        """Test Do Not Disturb toggle commands."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.toggle_do_not_disturb(True)
            mock_send.assert_called_with(FmdCommands.NODISTURB_ON)
            
            await mock_client.toggle_do_not_disturb(False)
            mock_send.assert_called_with(FmdCommands.NODISTURB_OFF)
    
    @pytest.mark.asyncio
    async def test_set_ringer_mode(self, mock_client):
        """Test ringer mode setting."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.set_ringer_mode("normal")
            mock_send.assert_called_with(FmdCommands.RINGERMODE_NORMAL)
            
            await mock_client.set_ringer_mode("vibrate")
            mock_send.assert_called_with(FmdCommands.RINGERMODE_VIBRATE)
            
            await mock_client.set_ringer_mode("silent")
            mock_send.assert_called_with(FmdCommands.RINGERMODE_SILENT)
    
    @pytest.mark.asyncio
    async def test_set_ringer_mode_invalid(self, mock_client):
        """Test ringer mode with invalid value."""
        with pytest.raises(ValueError, match="Invalid ringer mode"):
            await mock_client.set_ringer_mode("invalid")
    
    @pytest.mark.asyncio
    async def test_get_device_stats(self, mock_client):
        """Test get_device_stats command."""
        with patch.object(mock_client, 'send_command', new_callable=AsyncMock) as mock_send:
            await mock_client.get_device_stats()
            mock_send.assert_called_once_with(FmdCommands.STATS)


class TestFmdCommands:
    """Test suite for FmdCommands constants."""
    
    def test_location_commands(self):
        """Test location command constants."""
        assert FmdCommands.LOCATE_ALL == "locate"
        assert FmdCommands.LOCATE_GPS == "locate gps"
        assert FmdCommands.LOCATE_CELL == "locate cell"
        assert FmdCommands.LOCATE_LAST == "locate last"
    
    def test_control_commands(self):
        """Test control command constants."""
        assert FmdCommands.RING == "ring"
        assert FmdCommands.LOCK == "lock"
        assert FmdCommands.DELETE == "delete"
    
    def test_camera_commands(self):
        """Test camera command constants."""
        assert FmdCommands.CAMERA_FRONT == "camera front"
        assert FmdCommands.CAMERA_BACK == "camera back"
    
    def test_bluetooth_commands(self):
        """Test Bluetooth command constants."""
        assert FmdCommands.BLUETOOTH_ON == "bluetooth on"
        assert FmdCommands.BLUETOOTH_OFF == "bluetooth off"
    
    def test_dnd_commands(self):
        """Test Do Not Disturb command constants."""
        assert FmdCommands.NODISTURB_ON == "nodisturb on"
        assert FmdCommands.NODISTURB_OFF == "nodisturb off"
    
    def test_ringer_commands(self):
        """Test ringer mode command constants."""
        assert FmdCommands.RINGERMODE_NORMAL == "ringermode normal"
        assert FmdCommands.RINGERMODE_VIBRATE == "ringermode vibrate"
        assert FmdCommands.RINGERMODE_SILENT == "ringermode silent"
    
    def test_info_commands(self):
        """Test information command constants."""
        assert FmdCommands.STATS == "stats"
        assert FmdCommands.GPS == "gps"
