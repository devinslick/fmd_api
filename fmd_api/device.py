"""Device class for FMD API.

This module provides the Device class which wraps FmdClient
and provides higher-level device-oriented operations.
"""
import json
import logging
from typing import List, Optional, BinaryIO

from .client import FmdClient
from .types import Location, PhotoResult
from .helpers import decode_base64

log = logging.getLogger(__name__)


class Device:
    """Represents an FMD device with high-level operations.
    
    This class wraps FmdClient to provide device-centric methods
    that automatically handle decryption and data parsing.
    """
    
    def __init__(self, client: FmdClient):
        """Initialize Device with an FmdClient.
        
        Args:
            client: Authenticated FmdClient instance
        """
        self.client = client
        self._cached_location: Optional[Location] = None
    
    @classmethod
    async def create(cls, base_url: str, fmd_id: str, password: str,
                    session_duration: int = 3600) -> "Device":
        """Create a Device instance with authentication.
        
        Args:
            base_url: Base URL of the FMD server
            fmd_id: Device ID
            password: Device password
            session_duration: Session duration in seconds
            
        Returns:
            Device instance with authenticated client
        """
        client = await FmdClient.create(base_url, fmd_id, password, session_duration)
        return cls(client)
    
    async def refresh(self, provider: str = "all") -> bool:
        """Request a new location update from the device.
        
        Args:
            provider: Location provider ("all", "gps", "cell", "last")
            
        Returns:
            True if request was sent successfully
        """
        log.info(f"Refreshing device location with provider: {provider}")
        return await self.client.request_location(provider)
    
    async def get_location(self, use_cached: bool = False) -> Optional[Location]:
        """Get the most recent location from the device.
        
        Args:
            use_cached: If True and cache exists, return cached location
            
        Returns:
            Location object or None if no location available
        """
        if use_cached and self._cached_location:
            log.debug("Returning cached location")
            return self._cached_location
        
        log.info("Fetching latest location from server")
        blobs = await self.client.get_locations(num_to_get=1)
        
        if not blobs:
            log.warning("No location data available")
            return None
        
        try:
            decrypted = self.client.decrypt_data_blob(blobs[0])
            location_data = json.loads(decrypted)
            location = Location.from_dict(location_data)
            self._cached_location = location
            log.info(f"Retrieved location: ({location.latitude}, {location.longitude})")
            return location
        except Exception as e:
            log.error(f"Failed to parse location: {e}")
            return None
    
    async def get_history(self, count: int = 10) -> List[Location]:
        """Get location history.
        
        Args:
            count: Number of historical locations to retrieve (-1 for all)
            
        Returns:
            List of Location objects
        """
        log.info(f"Fetching {count if count != -1 else 'all'} historical locations")
        blobs = await self.client.get_locations(num_to_get=count)
        
        locations = []
        for i, blob in enumerate(blobs):
            try:
                decrypted = self.client.decrypt_data_blob(blob)
                location_data = json.loads(decrypted)
                location = Location.from_dict(location_data)
                locations.append(location)
            except Exception as e:
                log.warning(f"Failed to parse location {i}: {e}")
        
        log.info(f"Retrieved {len(locations)} location(s) from history")
        return locations
    
    async def play_sound(self) -> bool:
        """Make the device ring.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Sending ring command to device")
        return await self.client.send_command("ring")
    
    async def take_photo(self, camera: str = "back") -> bool:
        """Take a photo with the device camera.
        
        Args:
            camera: Which camera to use ("front" or "back")
            
        Returns:
            True if command was sent successfully
        """
        log.info(f"Requesting photo from {camera} camera")
        return await self.client.take_picture(camera)
    
    async def fetch_pictures(self, count: int = -1) -> List[PhotoResult]:
        """Fetch picture metadata from the server.
        
        Args:
            count: Number of pictures to fetch (-1 for all)
            
        Returns:
            List of PhotoResult objects
        """
        log.info(f"Fetching {count if count != -1 else 'all'} picture(s)")
        pictures = await self.client.get_pictures(num_to_get=count)
        
        results = []
        for pic_data in pictures:
            try:
                result = PhotoResult.from_dict(pic_data)
                results.append(result)
            except Exception as e:
                log.warning(f"Failed to parse picture metadata: {e}")
        
        log.info(f"Retrieved {len(results)} picture(s)")
        return results
    
    async def download_photo(self, photo: PhotoResult, output: BinaryIO) -> bool:
        """Download and decrypt a photo.
        
        Args:
            photo: PhotoResult object with encrypted data
            output: Binary file-like object to write decrypted photo
            
        Returns:
            True if download and decryption successful
        """
        try:
            log.info(f"Decrypting photo from {photo.camera} camera")
            # Decrypt the photo data blob
            decrypted = self.client.decrypt_data_blob(photo.encrypted_data)
            
            # Photo data is base64 encoded after decryption
            photo_bytes = decode_base64(decrypted.decode('utf-8'))
            
            output.write(photo_bytes)
            log.info(f"Photo downloaded successfully ({len(photo_bytes)} bytes)")
            return True
        except Exception as e:
            log.error(f"Failed to download photo: {e}")
            return False
    
    async def lock(self) -> bool:
        """Lock the device screen.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Sending lock command to device")
        return await self.client.send_command("lock")
    
    async def wipe(self) -> bool:
        """Wipe device data (factory reset).
        
        WARNING: This is a destructive operation that will erase all data!
        
        Returns:
            True if command was sent successfully
        """
        log.warning("Sending WIPE command to device - this will erase all data!")
        return await self.client.send_command("delete")
