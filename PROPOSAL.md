# Proposal: FMD API v2 - Device/Client Architecture

## Overview

This proposal outlines the v2 architecture for the `fmd_api` Python client library, introducing a package-based structure with both high-level and low-level APIs for interacting with FMD (Find My Device) servers.

## Motivation

The v1 implementation (`fmd_api.py`) provides a functional interface but has several limitations:

1. **Flat module structure**: All code in a single file makes maintenance difficult
2. **No type safety**: Raw dictionary access without structured types
3. **Limited abstraction**: Users must handle encryption/decryption manually
4. **Inconsistent API**: Mix of low-level and convenience methods
5. **Poor testability**: No separation of concerns

## Goals

1. **Improved Developer Experience**: Provide intuitive, easy-to-use APIs
2. **Type Safety**: Structured data types for locations and pictures
3. **Better Maintainability**: Modular package structure
4. **Comprehensive Testing**: Full unit test coverage
5. **Backward Compatibility**: Preserve v1 functionality while adding v2

## Architecture

### Package Structure

```
fmd_api/
├── __init__.py          # Package exports
├── _version.py          # Version information
├── exceptions.py        # Custom exceptions
├── types.py            # Data structures (Location, Picture)
├── helpers.py          # Utility functions
├── client.py           # FmdClient (low-level API)
└── device.py           # Device (high-level API)
```

### Two-Tier API Design

#### High-Level API: Device Class

**Purpose**: Intuitive, object-oriented interface for common operations

**Features**:
- Automatic decryption and parsing
- Structured `Location` and `Picture` objects
- Simple method names (`play_sound()`, `lock()`, `take_photo()`)
- Cached location data
- Simplified picture handling

**Example**:
```python
from fmd_api import Device

device = await Device.create(url, device_id, password)

# Get current location (auto-decrypted)
location = await device.get_location()
print(f"At: {location.latitude}, {location.longitude}")

# Control device
await device.play_sound()
await device.lock()

# Get pictures
pictures = await device.fetch_pictures(limit=5)
```

#### Low-Level API: FmdClient Class

**Purpose**: Direct access to FMD server operations (similar to v1)

**Features**:
- Full control over encryption/decryption
- Access to raw encrypted blobs
- All v1 FmdApi functionality preserved
- Convenience methods for common commands

**Example**:
```python
from fmd_api import FmdClient

client = await FmdClient.create(url, device_id, password)

# Get encrypted blobs
blobs = await client.get_locations(num=10)

# Manual decryption
decrypted = client.decrypt_data_blob(blobs[0])

# Send commands
await client.send_command(FmdCommands.RING)
```

## Key Components

### 1. Type System

**Location Class**:
```python
@dataclass
class Location:
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
```

**Picture Class**:
```python
@dataclass
class Picture:
    data: bytes
    timestamp: Optional[datetime] = None
    camera: Optional[str] = None
```

### 2. Exception Hierarchy

```python
FmdApiException (base)
├── AuthenticationError
├── DecryptionError
├── ApiRequestError
└── CommandError
```

### 3. Helper Functions

- `pad_base64()`: Handle server's inconsistent base64 padding
- `encode_base64()` / `decode_base64()`: Convenient encoding/decoding

## API Comparison

| Operation | v1 | v2 High-level | v2 Low-level |
|-----------|-----|---------------|--------------|
| Create client | `FmdApi.create()` | `Device.create()` | `FmdClient.create()` |
| Get location | Manual decrypt + parse | `device.get_location()` | `client.get_locations()` |
| Location history | Loop + decrypt | `device.get_history(N)` | Loop + decrypt |
| Ring device | `send_command('ring')` | `device.play_sound()` | `client.play_sound()` |
| Take photo | `take_picture('front')` | `device.take_front_photo()` | `client.take_picture('front')` |
| Get pictures | Manual decrypt | `device.fetch_pictures()` | `client.get_pictures()` |

## Implementation Details

### FmdClient (Port of FmdApi)

The `FmdClient` class ports all functionality from v1's `FmdApi`:

✅ **Authentication**:
- Salt retrieval
- Argon2id password hashing
- Access token management
- Private key decryption

✅ **Encryption/Decryption**:
- RSA-OAEP session key unwrapping
- AES-GCM data decryption
- Command signing with RSA-PSS

✅ **API Operations**:
- `get_locations()` - Fetch location blobs
- `get_pictures()` - Fetch picture data
- `export_data_zip()` - Download export archive
- `send_command()` - Send device commands

✅ **Convenience Methods**:
- `request_location()` - Request location updates
- `play_sound()` - Make device ring
- `lock_device()` - Lock screen
- `take_picture()` - Capture photos
- `toggle_bluetooth()` - Control Bluetooth
- `toggle_do_not_disturb()` - Control DND mode
- `set_ringer_mode()` - Set ringer mode
- `get_device_stats()` - Get device info

### Device (High-Level Wrapper)

The `Device` class wraps `FmdClient` with simplified operations:

✅ **Location Management**:
- `get_location()` - Get current location (structured)
- `get_history()` - Get location history (list of Location objects)
- `refresh()` - Update cached location
- `last_known_location` - Property for cached data

✅ **Device Control**:
- `play_sound()` - Ring device
- `lock()` - Lock screen
- `wipe()` - Factory reset (destructive!)

✅ **Camera**:
- `take_front_photo()` - Front camera
- `take_rear_photo()` - Rear camera
- `fetch_pictures()` - Get Picture objects
- `download_photo()` - Save to file

## Testing Strategy

### Unit Tests

**test_client.py** - FmdClient functionality:
- Authentication flow
- Password hashing
- Location retrieval (all, limited, empty)
- Command sending
- Convenience methods
- Error handling

**test_device.py** - Device functionality:
- Device creation
- Location caching
- History retrieval
- Device control commands
- Picture handling
- Error scenarios

### Test Coverage Goals

- ✅ Core authentication and encryption
- ✅ All API operations
- ✅ Convenience methods
- ✅ Error handling and exceptions
- ✅ Type conversions (dict ↔ Location)

## Migration Path

### For New Projects

**Recommended**: Use high-level Device API

```python
from fmd_api import Device

device = await Device.create(url, id, password)
location = await device.get_location()
```

### For Existing v1 Users

**Option 1**: Minimal changes with FmdClient (low-level)
- Import `FmdClient` instead of `FmdApi`
- Minor method name changes (`get_all_locations` → `get_locations`)

**Option 2**: Migrate to Device API (recommended)
- More significant changes but cleaner code
- See migration guide in `docs/MIGRATE_FROM_V1.md`

### Backward Compatibility

The v1 `fmd_api.py` module remains in the repository, so existing code continues to work. Users can migrate at their own pace.

## Documentation

### Included Documentation

1. **Migration Guide** (`docs/MIGRATE_FROM_V1.md`):
   - Step-by-step migration instructions
   - Code comparison tables
   - Breaking changes list

2. **Example Code** (`examples/async_example.py`):
   - High-level Device API usage
   - Low-level FmdClient API usage
   - Common operations demonstrated

3. **API Documentation**:
   - Comprehensive docstrings
   - Type hints throughout
   - Usage examples in docstrings

## Benefits

### For Users

✅ **Simpler Code**: High-level API reduces boilerplate  
✅ **Type Safety**: Structured types prevent errors  
✅ **Better Errors**: Specific exceptions aid debugging  
✅ **Flexibility**: Choose high-level or low-level API  

### For Maintainers

✅ **Modular Structure**: Easier to maintain and extend  
✅ **Test Coverage**: Comprehensive unit tests  
✅ **Clear Separation**: Distinct layers (client, device, types)  
✅ **Documentation**: Self-documenting code with type hints  

## Security Considerations

All v1 security features are preserved:

- ✅ Argon2id password hashing
- ✅ RSA-3072 + AES-GCM encryption
- ✅ Command signing with RSA-PSS
- ✅ Session token management
- ✅ Automatic re-authentication on 401

## Future Enhancements

Possible additions for future releases:

1. **Async Context Manager**: `async with Device(...) as device:`
2. **Streaming Location Updates**: Real-time location monitoring
3. **Command Queuing**: Batch command operations
4. **Rate Limiting**: Built-in request throttling
5. **Caching Layer**: Redis/memcached for multi-process apps
6. **CLI Tool**: Command-line interface using the library

## Conclusion

The v2 architecture provides a modern, maintainable, and user-friendly interface for FMD API interactions while preserving all v1 functionality. The two-tier API design allows users to choose the right level of abstraction for their needs.

## Implementation Checklist

- [x] Package structure created
- [x] Core modules implemented:
  - [x] `_version.py` - Version info
  - [x] `exceptions.py` - Custom exceptions
  - [x] `types.py` - Data structures
  - [x] `helpers.py` - Utility functions
  - [x] `client.py` - FmdClient class
  - [x] `device.py` - Device class
  - [x] `__init__.py` - Package exports
- [x] Tests implemented:
  - [x] `test_client.py` - FmdClient tests
  - [x] `test_device.py` - Device tests
- [x] Documentation:
  - [x] `docs/MIGRATE_FROM_V1.md` - Migration guide
  - [x] `PROPOSAL.md` - This document
- [x] Examples:
  - [x] `examples/async_example.py` - Usage examples
- [x] Project configuration:
  - [x] Update `pyproject.toml` for package structure
  - [x] Update `.gitignore` for v2 artifacts

## References

- FMD Project: https://fmd-foss.org
- FMD Server: https://gitlab.com/fmd-foss/fmd-server
- FMD Android: https://gitlab.com/fmd-foss/fmd-android
