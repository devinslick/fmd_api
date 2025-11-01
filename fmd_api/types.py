"""Type definitions and data classes for the fmd_api package.

This module defines type hints and data structures used throughout the
fmd_api package for better type safety and code clarity.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Location:
    """Represents a device location with all available fields.
    
    Attributes:
        latitude: Latitude in degrees (-90 to 90)
        longitude: Longitude in degrees (-180 to 180)
        timestamp: Human-readable timestamp string
        date_ms: Unix timestamp in milliseconds
        provider: Location provider ("gps", "network", "fused", or "BeaconDB")
        battery: Battery percentage (0-100)
        accuracy: Optional GPS accuracy radius in meters
        altitude: Optional altitude above sea level in meters
        speed: Optional speed in meters per second (only when moving)
        heading: Optional direction in degrees 0-360 (only when moving with direction)
    """
    latitude: float
    longitude: float
    timestamp: str
    date_ms: int
    provider: str
    battery: int
    accuracy: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Location':
        """Create a Location instance from a dictionary.
        
        Args:
            data: Dictionary containing location data from decrypted JSON
            
        Returns:
            Location instance with all available fields populated
        """
        return cls(
            latitude=data['lat'],
            longitude=data['lon'],
            timestamp=data['time'],
            date_ms=data['date'],
            provider=data['provider'],
            battery=data['bat'],
            accuracy=data.get('accuracy'),
            altitude=data.get('altitude'),
            speed=data.get('speed'),
            heading=data.get('heading')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Location to a dictionary.
        
        Returns:
            Dictionary with all non-None fields
        """
        result = {
            'lat': self.latitude,
            'lon': self.longitude,
            'time': self.timestamp,
            'date': self.date_ms,
            'provider': self.provider,
            'bat': self.battery
        }
        
        if self.accuracy is not None:
            result['accuracy'] = self.accuracy
        if self.altitude is not None:
            result['altitude'] = self.altitude
        if self.speed is not None:
            result['speed'] = self.speed
        if self.heading is not None:
            result['heading'] = self.heading
            
        return result


@dataclass
class Picture:
    """Represents a picture taken by the device.
    
    Attributes:
        data: Raw image data as bytes
        timestamp: When the picture was taken (if available)
        camera: Which camera was used ("front" or "back", if available)
    """
    data: bytes
    timestamp: Optional[datetime] = None
    camera: Optional[str] = None


class LocationProvider:
    """Constants for location provider types."""
    ALL = "all"
    GPS = "gps"
    CELL = "cell"
    NETWORK = "network"
    LAST = "last"


class Camera:
    """Constants for camera selection."""
    FRONT = "front"
    BACK = "back"


class RingerMode:
    """Constants for device ringer modes."""
    NORMAL = "normal"
    VIBRATE = "vibrate"
    SILENT = "silent"
