"""Data types for FMD API."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Location:
    """Represents a device location."""
    
    # Always present fields
    time: str  # Human-readable timestamp
    date: int  # Unix timestamp in milliseconds
    provider: str  # "gps", "network", "fused", or "BeaconDB"
    battery: int  # Battery percentage (0-100)
    latitude: float  # Latitude in degrees
    longitude: float  # Longitude in degrees
    
    # Optional fields (GPS/movement dependent)
    accuracy: Optional[float] = None  # GPS accuracy in meters
    altitude: Optional[float] = None  # Altitude in meters
    speed: Optional[float] = None  # Speed in meters/second
    heading: Optional[float] = None  # Direction in degrees 0-360
    
    @classmethod
    def from_dict(cls, data: dict) -> "Location":
        """Create Location from dictionary.
        
        Args:
            data: Location data dictionary from decrypted blob
            
        Returns:
            Location instance
        """
        return cls(
            time=data['time'],
            date=data['date'],
            provider=data['provider'],
            battery=data['bat'],
            latitude=data['lat'],
            longitude=data['lon'],
            accuracy=data.get('accuracy'),
            altitude=data.get('altitude'),
            speed=data.get('speed'),
            heading=data.get('heading')
        )


@dataclass
class PhotoResult:
    """Represents a device photo result."""
    
    timestamp: int  # Unix timestamp in milliseconds
    camera: str  # "front" or "back"
    encrypted_data: str  # Base64 encrypted photo data
    
    @classmethod
    def from_dict(cls, data: dict) -> "PhotoResult":
        """Create PhotoResult from dictionary.
        
        Args:
            data: Photo data dictionary
            
        Returns:
            PhotoResult instance
        """
        return cls(
            timestamp=data.get('timestamp', 0),
            camera=data.get('camera', 'unknown'),
            encrypted_data=data.get('data', '')
        )
