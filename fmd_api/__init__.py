"""FMD API v2 - Python client for FMD (Find My Device) servers.

This package provides a client implementation for the FMD server API,
supporting authentication, encrypted communication, and device control.

Basic Usage:
    from fmd_api import FmdClient, Device
    
    # Using FmdClient directly
    client = await FmdClient.create('https://fmd.example.com', 'device-id', 'password')
    locations = await client.get_locations(10)
    
    # Using Device wrapper
    device = await Device.create('https://fmd.example.com', 'device-id', 'password')
    location = await device.get_location()
    await device.play_sound()
"""

from ._version import __version__
from .client import FmdClient, FmdCommands
from .device import Device
from .types import Location, PhotoResult
from .exceptions import (
    FmdApiException,
    FmdAuthenticationError,
    FmdDecryptionError,
    FmdApiRequestError,
    FmdInvalidDataError,
)

__all__ = [
    "__version__",
    "FmdClient",
    "FmdCommands",
    "Device",
    "Location",
    "PhotoResult",
    "FmdApiException",
    "FmdAuthenticationError",
    "FmdDecryptionError",
    "FmdApiRequestError",
    "FmdInvalidDataError",
]
