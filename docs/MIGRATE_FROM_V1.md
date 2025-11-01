# Migration Guide: v1 to v2

This guide helps you migrate from the v1 `fmd_api.py` module to the v2 `fmd_api` package.

## Overview of Changes

### v2 Architecture

The v2 release restructures the codebase into a proper Python package with:

- **Package structure**: `fmd_api/` directory with organized modules
- **High-level Device API**: Object-oriented interface for device management
- **Low-level Client API**: Direct access to FMD server operations (similar to v1)
- **Type-safe data structures**: `Location` and `Picture` classes
- **Improved error handling**: Specific exception types
- **Better testing**: Comprehensive unit tests

### What's New in v2

1. **Device Class**: High-level interface for common operations
2. **Structured Types**: `Location` and `Picture` dataclasses
3. **Better Exceptions**: Specific error types (`AuthenticationError`, `DecryptionError`, etc.)
4. **Improved Documentation**: Type hints, docstrings, and examples
5. **Unit Tests**: Full test coverage for reliability

## Migration Steps

### 1. Update Imports

**v1:**
```python
from fmd_api import FmdApi, FmdCommands
```

**v2 (High-level API - Recommended):**
```python
from fmd_api import Device
```

**v2 (Low-level API - Similar to v1):**
```python
from fmd_api import FmdClient, FmdCommands
```

### 2. Client Creation

**v1:**
```python
api = await FmdApi.create(
    'https://fmd.example.com',
    'device-id',
    'password'
)
```

**v2 High-level:**
```python
device = await Device.create(
    'https://fmd.example.com',
    'device-id',
    'password'
)
```

**v2 Low-level:**
```python
client = await FmdClient.create(
    'https://fmd.example.com',
    'device-id',
    'password'
)
```

### 3. Getting Locations

**v1:**
```python
import json

# Get location blobs
location_blobs = await api.get_all_locations(num_to_get=10)

# Decrypt and parse
for blob in location_blobs:
    decrypted = api.decrypt_data_blob(blob)
    location = json.loads(decrypted)
    
    lat = location['lat']
    lon = location['lon']
    battery = location['bat']
    accuracy = location.get('accuracy')
```

**v2 High-level (Recommended):**
```python
# Get current location
location = await device.get_location()
print(f"At: {location.latitude}, {location.longitude}")
print(f"Battery: {location.battery}%")
print(f"Accuracy: {location.accuracy}m")

# Get history
history = await device.get_history(limit=10)
for loc in history:
    print(f"{loc.timestamp}: {loc.latitude}, {loc.longitude}")
```

**v2 Low-level (Similar to v1):**
```python
import json

# Get location blobs
location_blobs = await client.get_locations(num=10)

# Decrypt and parse
for blob in location_blobs:
    decrypted = client.decrypt_data_blob(blob)
    location_data = json.loads(decrypted)
    
    # Or use Location type for structured access
    from fmd_api import Location
    location = Location.from_dict(location_data)
    
    print(f"At: {location.latitude}, {location.longitude}")
```

### 4. Sending Commands

**v1:**
```python
# Using string commands
await api.send_command('ring')
await api.send_command('locate gps')

# Using constants
await api.send_command(FmdCommands.RING)
await api.send_command(FmdCommands.LOCATE_GPS)

# Using convenience methods
await api.request_location('gps')
await api.take_picture('front')
await api.toggle_bluetooth(True)
```

**v2 High-level (Recommended):**
```python
# Simple, descriptive methods
await device.play_sound()
await device.lock()
await device.take_front_photo()
await device.take_rear_photo()

# Request new location (still available)
await device.client.request_location('gps')
```

**v2 Low-level (Similar to v1):**
```python
# Same as v1
await client.send_command('ring')
await client.send_command(FmdCommands.RING)
await client.request_location('gps')
await client.take_picture('front')
await client.toggle_bluetooth(True)
```

### 5. Working with Pictures

**v1:**
```python
import base64

pictures = await api.get_pictures(num_to_get=5)

for pic_dict in pictures:
    encrypted = pic_dict.get('data', '')
    decrypted_b64 = api.decrypt_data_blob(encrypted)
    image_data = base64.b64decode(decrypted_b64)
    
    with open(f'photo.jpg', 'wb') as f:
        f.write(image_data)
```

**v2 High-level (Recommended):**
```python
# Fetch pictures
pictures = await device.fetch_pictures(limit=5)

# Save to file
for i, picture in enumerate(pictures):
    await device.download_photo(picture, f'photo_{i}.jpg')
```

**v2 Low-level:**
```python
import base64

picture_dicts = await client.get_pictures(num=5)

for pic_dict in picture_dicts:
    encrypted = pic_dict.get('data', '')
    decrypted_b64 = client.decrypt_data_blob(encrypted)
    image_data = base64.b64decode(decrypted_b64)
    
    with open('photo.jpg', 'wb') as f:
        f.write(image_data)
```

### 6. Error Handling

**v1:**
```python
from fmd_api import FmdApiException

try:
    await api.authenticate(device_id, password)
except FmdApiException as e:
    print(f"Error: {e}")
```

**v2 (More Specific Exceptions):**
```python
from fmd_api import (
    FmdApiException,
    AuthenticationError,
    DecryptionError,
    ApiRequestError,
    CommandError
)

try:
    device = await Device.create(base_url, device_id, password)
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except ApiRequestError as e:
    print(f"API request failed: {e}")
except FmdApiException as e:
    print(f"General error: {e}")
```

## API Comparison Table

| Operation | v1 | v2 High-level | v2 Low-level |
|-----------|-----|---------------|--------------|
| Create client | `FmdApi.create()` | `Device.create()` | `FmdClient.create()` |
| Get location | `get_all_locations()` + decrypt | `get_location()` | `get_locations()` + decrypt |
| Location history | `get_all_locations(N)` + decrypt | `get_history(limit=N)` | `get_locations(num=N)` + decrypt |
| Ring device | `send_command('ring')` | `play_sound()` | `play_sound()` |
| Lock device | `send_command('lock')` | `lock()` | `lock_device()` |
| Take photo | `take_picture('front')` | `take_front_photo()` | `take_picture('front')` |
| Get pictures | `get_pictures()` + decrypt | `fetch_pictures()` | `get_pictures()` + decrypt |
| Request location | `request_location('gps')` | `client.request_location('gps')` | `request_location('gps')` |

## Choosing Between High-level and Low-level APIs

### Use High-level Device API when:
- Building applications with straightforward requirements
- You want clean, readable code
- You prefer object-oriented interfaces
- You don't need fine-grained control over encryption/decryption

### Use Low-level FmdClient API when:
- You need direct access to encrypted blobs
- You're building custom tools or integrations
- You want maximum control over API operations
- You're migrating from v1 and want minimal changes

## Breaking Changes

1. **Module structure**: `fmd_api.py` → `fmd_api/` package
2. **Class names**: `FmdApi` → `FmdClient` (low-level) or `Device` (high-level)
3. **Method names**:
   - `get_all_locations()` → `get_locations()` (low-level) or `get_history()` (high-level)
   - `get_pictures()` → `get_pictures()` (low-level) or `fetch_pictures()` (high-level)
4. **Return types**: Raw dictionaries → structured `Location` and `Picture` objects (high-level)
5. **Exception types**: Generic `FmdApiException` → specific exception types

## Compatibility Note

The v1 `fmd_api.py` module will continue to work alongside v2. However, we recommend
migrating to v2 for better maintainability, type safety, and improved features.

## Need Help?

- See `examples/async_example.py` for a complete v2 example
- Check the API documentation in docstrings
- Open an issue on GitHub if you encounter problems

## Summary

The v2 release provides a better developer experience with:
- ✅ Cleaner, more intuitive APIs
- ✅ Type-safe data structures
- ✅ Better error handling
- ✅ Comprehensive documentation
- ✅ Full test coverage

We recommend using the **high-level Device API** for new projects, as it provides
the most user-friendly interface while maintaining full functionality.
