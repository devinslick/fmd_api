"""FMD API Client Package.

This package provides a Python client for interacting with FMD (Find My Device)
servers. It includes both a low-level client (FmdClient) and a high-level
device interface (Device).

FMD Project Attribution:
    - FMD (Find My Device): https://fmd-foss.org
    - Created by Nulide (http://nulide.de)
    - Maintained by Thore (https://thore.io) and the FMD-FOSS team
    - FMD Server: https://gitlab.com/fmd-foss/fmd-server (AGPL-3.0)
    - FMD Android: https://gitlab.com/fmd-foss/fmd-android (GPL-3.0)

This Client Implementation:
    - MIT License - Copyright (c) 2025 Devin Slick
    - Independent client implementation for FMD API
    - Follows FMD's RSA-3072 + AES-GCM encryption protocol
    - Compatible with FMD server v012.0 API

Example Usage:
    # High-level Device API (recommended)
    from fmd_api import Device
    
    device = await Device.create(
        'https://fmd.example.com',
        'device-id',
        'password'
    )
    
    # Get current location
    location = await device.get_location()
    print(f"Device at: {location.latitude}, {location.longitude}")
    
    # Control device
    await device.play_sound()
    await device.lock()
    
    # Low-level Client API (for advanced use)
    from fmd_api import FmdClient
    
    client = await FmdClient.create(
        'https://fmd.example.com',
        'device-id',
        'password'
    )
    
    # Get encrypted location blobs
    blobs = await client.get_locations(num=10)
    
    # Decrypt and parse
    decrypted = client.decrypt_data_blob(blobs[0])
    location = json.loads(decrypted)
"""

from ._version import __version__, __version_info__
from .exceptions import (
    FmdApiException,
    AuthenticationError,
    DecryptionError,
    ApiRequestError,
    CommandError
)
from .types import (
    Location,
    Picture,
    LocationProvider,
    Camera,
    RingerMode
)
from .client import FmdClient, FmdCommands
from .device import Device

__all__ = [
    # Version
    '__version__',
    '__version_info__',
    
    # Main classes
    'Device',
    'FmdClient',
    
    # Exceptions
    'FmdApiException',
    'AuthenticationError',
    'DecryptionError',
    'ApiRequestError',
    'CommandError',
    
    # Types
    'Location',
    'Picture',
    'LocationProvider',
    'Camera',
    'RingerMode',
    
    # Constants
    'FmdCommands',
]
