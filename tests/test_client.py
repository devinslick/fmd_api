"""Tests for FmdClient class."""
import pytest
from unittest.mock import Mock, patch
from aioresponses import aioresponses

from fmd_api import FmdClient, FmdCommands
from fmd_api.exceptions import FmdAuthenticationError, FmdInvalidDataError
from fmd_api.helpers import encode_base64


@pytest.fixture
def mock_private_key():
    """Mock RSA private key."""
    mock_key = Mock()
    mock_key.decrypt.return_value = b'0' * 32  # 32-byte AES key
    mock_key.sign.return_value = b'0' * 384  # Mock signature
    return mock_key


@pytest.mark.asyncio
async def test_create_and_authenticate():
    """Test FmdClient creation and authentication."""
    with aioresponses() as m:
        # Mock salt request
        m.put('https://fmd.test/api/v1/salt', payload={'Data': 'dGVzdHNhbHQxMjM0NTY='})
        
        # Mock access token request
        m.put('https://fmd.test/api/v1/requestAccess', payload={'Data': 'test-token-123'})
        
        # Mock private key blob request
        m.put('https://fmd.test/api/v1/key', payload={'Data': encode_base64(b'0' * 500)})
        
        with patch('fmd_api.client.FmdClient._decrypt_private_key_blob') as mock_decrypt, \
             patch('fmd_api.client.FmdClient._load_private_key_from_bytes') as mock_load:
            mock_decrypt.return_value = b'fake_key_bytes'
            mock_load.return_value = Mock()
            
            client = await FmdClient.create('https://fmd.test', 'test-device', 'test-pass')
            
            assert client.access_token == 'test-token-123'
            assert client._fmd_id == 'test-device'
            assert client.private_key is not None


@pytest.mark.asyncio
async def test_get_locations_all():
    """Test getting all locations."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'test-token'
    
    with aioresponses() as m:
        # Mock location size request
        m.put('https://fmd.test/api/v1/locationDataSize', payload={'Data': '3'})
        
        # Mock location requests
        m.put('https://fmd.test/api/v1/location', payload={'Data': 'blob1'})
        m.put('https://fmd.test/api/v1/location', payload={'Data': 'blob2'})
        m.put('https://fmd.test/api/v1/location', payload={'Data': 'blob3'})
        
        locations = await client.get_locations(num_to_get=-1)
        
        assert len(locations) == 3
        assert locations[0] == 'blob1'
        assert locations[1] == 'blob2'
        assert locations[2] == 'blob3'


@pytest.mark.asyncio
async def test_get_locations_recent():
    """Test getting N most recent locations."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'test-token'
    
    with aioresponses() as m:
        # Mock location size request
        m.put('https://fmd.test/api/v1/locationDataSize', payload={'Data': '10'})
        
        # Mock location requests for last 2
        m.put('https://fmd.test/api/v1/location', payload={'Data': 'blob9'})
        m.put('https://fmd.test/api/v1/location', payload={'Data': 'blob8'})
        
        locations = await client.get_locations(num_to_get=2, skip_empty=False)
        
        assert len(locations) == 2


@pytest.mark.asyncio
async def test_decrypt_data_blob(mock_private_key):
    """Test decrypting a data blob."""
    client = FmdClient('https://fmd.test')
    client.private_key = mock_private_key
    
    # Create a minimal valid blob (RSA key packet + IV + ciphertext)
    rsa_packet = b'R' * 384  # 384 bytes RSA packet
    iv = b'I' * 12  # 12 bytes IV
    ciphertext = b'C' * 50  # Some ciphertext
    
    blob = rsa_packet + iv + ciphertext
    blob_b64 = encode_base64(blob, strip_padding=False)
    
    with patch('fmd_api.client.AESGCM') as mock_aesgcm:
        mock_aesgcm.return_value.decrypt.return_value = b'{"test": "data"}'
        
        result = client.decrypt_data_blob(blob_b64)
        
        assert result == b'{"test": "data"}'
        mock_private_key.decrypt.assert_called_once()


@pytest.mark.asyncio
async def test_decrypt_data_blob_too_small(mock_private_key):
    """Test decrypting a blob that is too small."""
    client = FmdClient('https://fmd.test')
    client.private_key = mock_private_key
    
    # Create a blob that's too small
    small_blob = encode_base64(b'x' * 100, strip_padding=False)
    
    with pytest.raises(FmdInvalidDataError):
        client.decrypt_data_blob(small_blob)


@pytest.mark.asyncio
async def test_send_command(mock_private_key):
    """Test sending a command."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'test-token'
    client.private_key = mock_private_key
    
    with aioresponses() as m:
        m.post('https://fmd.test/api/v1/command', status=200, body='OK')
        
        result = await client.send_command(FmdCommands.RING)
        
        assert result is True


@pytest.mark.asyncio
async def test_reauth_on_401():
    """Test automatic re-authentication on 401."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'old-token'
    client._fmd_id = 'test-device'
    client._password = 'test-pass'
    
    with aioresponses() as m:
        # First request returns 401
        m.put('https://fmd.test/api/v1/locationDataSize', status=401)
        
        # Re-auth sequence
        m.put('https://fmd.test/api/v1/salt', payload={'Data': 'dGVzdHNhbHQxMjM0NTY='})
        m.put('https://fmd.test/api/v1/requestAccess', payload={'Data': 'new-token-456'})
        m.put('https://fmd.test/api/v1/key', payload={'Data': encode_base64(b'0' * 500)})
        
        # Retry with new token succeeds
        m.put('https://fmd.test/api/v1/locationDataSize', payload={'Data': '5'})
        
        with patch('fmd_api.client.FmdClient._decrypt_private_key_blob') as mock_decrypt, \
             patch('fmd_api.client.FmdClient._load_private_key_from_bytes') as mock_load:
            mock_decrypt.return_value = b'fake_key_bytes'
            mock_load.return_value = Mock()
            
            result = await client._make_api_request(
                'PUT', '/api/v1/locationDataSize', 
                {'IDT': client.access_token, 'Data': 'unused'}
            )
            
            assert result == '5'
            assert client.access_token == 'new-token-456'


@pytest.mark.asyncio
async def test_export_data_zip(tmp_path):
    """Test exporting data to zip file."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'test-token'
    
    output_file = tmp_path / 'export.zip'
    
    with aioresponses() as m:
        # Mock zip file download
        m.post('https://fmd.test/api/v1/exportData', status=200, body=b'ZIPDATA123')
        
        await client.export_data_zip(str(output_file))
        
        assert output_file.exists()
        assert output_file.read_bytes() == b'ZIPDATA123'


@pytest.mark.asyncio
async def test_convenience_methods(mock_private_key):
    """Test convenience wrapper methods."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'test-token'
    client.private_key = mock_private_key
    
    with aioresponses() as m:
        m.post('https://fmd.test/api/v1/command', status=200, body='OK')
        m.post('https://fmd.test/api/v1/command', status=200, body='OK')
        m.post('https://fmd.test/api/v1/command', status=200, body='OK')
        m.post('https://fmd.test/api/v1/command', status=200, body='OK')
        m.post('https://fmd.test/api/v1/command', status=200, body='OK')
        
        # Test request_location
        assert await client.request_location('gps') is True
        
        # Test take_picture
        assert await client.take_picture('front') is True
        
        # Test toggle_bluetooth
        assert await client.toggle_bluetooth(True) is True
        
        # Test toggle_do_not_disturb
        assert await client.toggle_do_not_disturb(False) is True
        
        # Test set_ringer_mode
        assert await client.set_ringer_mode('vibrate') is True


@pytest.mark.asyncio
async def test_get_pictures():
    """Test getting pictures."""
    client = FmdClient('https://fmd.test')
    client.access_token = 'test-token'
    
    with aioresponses() as m:
        m.put('https://fmd.test/api/v1/pictures', payload=[
            {'timestamp': 1000, 'camera': 'back', 'data': 'blob1'},
            {'timestamp': 2000, 'camera': 'front', 'data': 'blob2'},
        ])
        
        pictures = await client.get_pictures(num_to_get=-1)
        
        assert len(pictures) == 2
        assert pictures[0]['timestamp'] == 1000
        assert pictures[1]['camera'] == 'front'
