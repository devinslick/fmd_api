"""High-level Device interface for FMD API.

This module provides the Device class, which wraps FmdClient with a more
user-friendly, object-oriented interface for device management.
"""

import json
import base64
import logging
from typing import Optional, List
from datetime import datetime

from .client import FmdClient
from .types import Location, Picture
from .helpers import decode_base64

log = logging.getLogger(__name__)


class Device:
    """High-level interface for managing an FMD device.
    
    The Device class wraps FmdClient to provide a more intuitive,
    object-oriented API for common device operations.
    
    Example:
        # Create device instance
        device = await Device.create(
            'https://fmd.example.com',
            'device-id',
            'password'
        )
        
        # Get current location
        location = await device.get_location()
        print(f"Device at: {location.latitude}, {location.longitude}")
        
        # Get location history
        history = await device.get_history(limit=10)
        for loc in history:
            print(f"{loc.timestamp}: {loc.latitude}, {loc.longitude}")
        
        # Device control
        await device.play_sound()
        await device.lock()
        
        # Take pictures
        await device.take_front_photo()
        await device.take_rear_photo()
        
        # Get pictures
        pictures = await device.fetch_pictures(limit=5)
    """
    
    def __init__(self, client: FmdClient):
        """Initialize Device with an FmdClient.
        
        Args:
            client: Authenticated FmdClient instance
        """
        self.client = client
        self._cached_location: Optional[Location] = None
    
    @classmethod
    async def create(
        cls,
        base_url: str,
        device_id: str,
        password: str,
        session_duration: int = 3600
    ) -> 'Device':
        """Create and authenticate a Device instance.
        
        Args:
            base_url: Base URL of the FMD server
            device_id: Device ID for authentication
            password: Device password
            session_duration: Session duration in seconds (default: 3600)
            
        Returns:
            Authenticated Device instance
        """
        client = await FmdClient.create(base_url, device_id, password, session_duration)
        return cls(client)
    
    async def refresh(self):
        """Refresh device data by fetching the latest location.
        
        This updates the cached location with the most recent data
        from the server.
        """
        log.info("Refreshing device data")
        location_blobs = await self.client.get_locations(num=1)
        
        if location_blobs:
            decrypted = self.client.decrypt_data_blob(location_blobs[0])
            location_data = json.loads(decrypted)
            self._cached_location = Location.from_dict(location_data)
            log.info(f"Location refreshed: {self._cached_location.latitude}, {self._cached_location.longitude}")
        else:
            log.warning("No location data available")
            self._cached_location = None
    
    async def get_location(self, use_cache: bool = False) -> Optional[Location]:
        """Get the current device location.
        
        Args:
            use_cache: If True and cache is available, return cached location
                      without making a new API request
            
        Returns:
            Location object or None if no location data available
        """
        if use_cache and self._cached_location:
            log.debug("Returning cached location")
            return self._cached_location
        
        await self.refresh()
        return self._cached_location
    
    async def get_history(self, limit: int = 10) -> List[Location]:
        """Get device location history.
        
        Args:
            limit: Maximum number of locations to retrieve (default: 10)
                  Use -1 to get all available locations
            
        Returns:
            List of Location objects, most recent first
        """
        log.info(f"Fetching location history (limit={limit})")
        location_blobs = await self.client.get_locations(num=limit)
        
        locations = []
        for blob in location_blobs:
            try:
                decrypted = self.client.decrypt_data_blob(blob)
                location_data = json.loads(decrypted)
                location = Location.from_dict(location_data)
                locations.append(location)
            except Exception as e:
                log.warning(f"Failed to decrypt/parse location blob: {e}")
                continue
        
        log.info(f"Retrieved {len(locations)} locations")
        return locations
    
    async def play_sound(self) -> bool:
        """Make the device ring at full volume.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Playing sound on device")
        return await self.client.play_sound()
    
    async def lock(self) -> bool:
        """Lock the device screen.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Locking device")
        return await self.client.lock_device()
    
    async def wipe(self) -> bool:
        """Wipe all device data (factory reset).
        
        WARNING: This is destructive and cannot be undone!
        All data on the device will be permanently erased.
        
        Returns:
            True if command was sent successfully
        """
        log.warning("Wiping device - this will erase ALL data!")
        return await self.client.wipe_device()
    
    async def take_front_photo(self) -> bool:
        """Take a photo with the front camera.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Taking front camera photo")
        return await self.client.take_picture("front")
    
    async def take_rear_photo(self) -> bool:
        """Take a photo with the rear camera.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Taking rear camera photo")
        return await self.client.take_picture("back")
    
    async def fetch_pictures(self, limit: int = -1) -> List[Picture]:
        """Fetch pictures from the device.
        
        Args:
            limit: Maximum number of pictures to retrieve (default: -1 for all)
            
        Returns:
            List of Picture objects
        """
        log.info(f"Fetching pictures (limit={limit})")
        picture_dicts = await self.client.get_pictures(num=limit)
        
        pictures = []
        for pic_dict in picture_dicts:
            try:
                # Picture data is double-encoded: encrypted blob → base64 string → image bytes
                encrypted_blob = pic_dict.get('data', '')
                if not encrypted_blob:
                    log.warning("Empty picture data in response")
                    continue
                
                decrypted_b64 = self.client.decrypt_data_blob(encrypted_blob)
                image_data = base64.b64decode(decrypted_b64)
                
                # Create Picture object
                picture = Picture(
                    data=image_data,
                    timestamp=None,  # FMD doesn't provide timestamp in picture metadata
                    camera=None      # FMD doesn't provide camera info in picture metadata
                )
                pictures.append(picture)
                
            except Exception as e:
                log.warning(f"Failed to decrypt/parse picture: {e}")
                continue
        
        log.info(f"Retrieved {len(pictures)} pictures")
        return pictures
    
    async def download_photo(self, picture: Picture, output_path: str):
        """Download a photo to a file.
        
        Args:
            picture: Picture object to download
            output_path: Path where to save the photo
        """
        log.info(f"Saving photo to {output_path}")
        with open(output_path, 'wb') as f:
            f.write(picture.data)
        log.info(f"Photo saved successfully")
    
    @property
    def last_known_location(self) -> Optional[Location]:
        """Get the last known location from cache.
        
        Returns:
            Cached Location object or None if not available
        """
        return self._cached_location
