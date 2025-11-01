# Migration Guide: V1 to V2

This guide helps you migrate from the old `fmd_api.py` module to the new v2 package structure with `FmdClient` and `Device` classes.

## Overview of Changes

V2 introduces:
- Structured package (`fmd_api/`) instead of single module
- Separate `FmdClient` (low-level) and `Device` (high-level) classes
- Typed exceptions for better error handling
- Type-annotated dataclasses for locations and photos
- More Pythonic API design

## Quick Migration Reference

### Imports

**V1:**
```python
from fmd_api import FmdApi, FmdCommands
```

**V2:**
```python
from fmd_api import FmdClient, Device, FmdCommands
```

### Creating a Client

**V1:**
```python
api = await FmdApi.create('https://fmd.example.com', 'device-id', 'password')
```

**V2 (Low-level client):**
```python
client = await FmdClient.create('https://fmd.example.com', 'device-id', 'password')
```

**V2 (High-level device wrapper):**
```python
device = await Device.create('https://fmd.example.com', 'device-id', 'password')
```

## API Mapping

### Location Operations

| V1 Method | V2 FmdClient Method | V2 Device Method |
|-----------|---------------------|------------------|
| `api.get_all_locations(num_to_get=10)` | `client.get_locations(num_to_get=10)` | `device.get_history(count=10)` |
| `api.decrypt_data_blob(blob)` | `client.decrypt_data_blob(blob)` | *(automatic in Device)* |
| `api.request_location('gps')` | `client.request_location('gps')` | `device.refresh('gps')` |

**V1 Example:**
```python
api = await FmdApi.create('https://fmd.example.com', 'device-id', 'password')
location_blobs = await api.get_all_locations(num_to_get=10)

for blob in location_blobs:
    decrypted_bytes = api.decrypt_data_blob(blob)
    location = json.loads(decrypted_bytes)
    print(f"Location: {location['lat']}, {location['lon']}")
```

**V2 FmdClient Example:**
```python
from fmd_api import FmdClient
import json

client = await FmdClient.create('https://fmd.example.com', 'device-id', 'password')
location_blobs = await client.get_locations(num_to_get=10)

for blob in location_blobs:
    decrypted_bytes = client.decrypt_data_blob(blob)
    location = json.loads(decrypted_bytes)
    print(f"Location: {location['lat']}, {location['lon']}")
```

**V2 Device Example (Recommended):**
```python
from fmd_api import Device

device = await Device.create('https://fmd.example.com', 'device-id', 'password')
locations = await device.get_history(count=10)

for location in locations:
    print(f"Location: {location.latitude}, {location.longitude}")
    print(f"  Battery: {location.battery}%")
    print(f"  Provider: {location.provider}")
    if location.speed:
        print(f"  Speed: {location.speed} m/s")
```

### Command Operations

| V1 Method | V2 FmdClient Method | V2 Device Method |
|-----------|---------------------|------------------|
| `api.send_command('ring')` | `client.send_command('ring')` | `device.play_sound()` |
| `api.send_command('lock')` | `client.send_command('lock')` | `device.lock()` |
| `api.send_command('delete')` | `client.send_command('delete')` | `device.wipe()` |
| `api.take_picture('back')` | `client.take_picture('back')` | `device.take_photo('back')` |
| `api.toggle_bluetooth(True)` | `client.toggle_bluetooth(True)` | *(use client)* |
| `api.toggle_do_not_disturb(True)` | `client.toggle_do_not_disturb(True)` | *(use client)* |
| `api.set_ringer_mode('vibrate')` | `client.set_ringer_mode('vibrate')` | *(use client)* |
| `api.get_device_stats()` | `client.get_device_stats()` | *(use client)* |

**V1 Example:**
```python
await api.send_command('ring')
await api.take_picture('front')
await api.toggle_bluetooth(True)
```

**V2 Device Example:**
```python
await device.play_sound()
await device.take_photo('front')
await device.client.toggle_bluetooth(True)  # Access client for advanced commands
```

### Picture Operations

| V1 Method | V2 FmdClient Method | V2 Device Method |
|-----------|---------------------|------------------|
| `api.get_pictures(num_to_get=5)` | `client.get_pictures(num_to_get=5)` | `device.fetch_pictures(count=5)` |

**V1 Example:**
```python
pictures = await api.get_pictures(num_to_get=5)
for pic in pictures:
    decrypted = api.decrypt_data_blob(pic['data'])
    photo_b64 = decrypted.decode('utf-8')
    photo_bytes = base64.b64decode(photo_b64)
    with open(f'photo_{pic["timestamp"]}.jpg', 'wb') as f:
        f.write(photo_bytes)
```

**V2 Device Example:**
```python
pictures = await device.fetch_pictures(count=5)
for pic in pictures:
    with open(f'photo_{pic.timestamp}.jpg', 'wb') as f:
        await device.download_photo(pic, f)
```

### Export Operations

| V1 Method | V2 FmdClient Method | V2 Device Method |
|-----------|---------------------|------------------|
| `api.export_data_zip('export.zip')` | `client.export_data_zip('export.zip')` | `device.client.export_data_zip('export.zip')` |

**No changes needed - same API.**

## Exception Handling

**V1:**
```python
from fmd_api import FmdApiException

try:
    api = await FmdApi.create(url, fmd_id, password)
except FmdApiException as e:
    print(f"Error: {e}")
```

**V2:**
```python
from fmd_api import (
    FmdApiException,
    FmdAuthenticationError,
    FmdDecryptionError,
    FmdApiRequestError,
    FmdInvalidDataError,
)

try:
    client = await FmdClient.create(url, fmd_id, password)
except FmdAuthenticationError as e:
    print(f"Authentication failed: {e}")
except FmdApiException as e:
    print(f"General error: {e}")
```

## Data Types

### Location Data

**V1:**
```python
location = json.loads(decrypted_bytes)
lat = location['lat']
lon = location['lon']
speed = location.get('speed')  # Optional field
```

**V2:**
```python
from fmd_api import Location

location = await device.get_location()
lat = location.latitude
lon = location.longitude
speed = location.speed  # None if not available
```

### Photo Data

**V1:**
```python
pic = pictures[0]  # Dictionary
timestamp = pic.get('timestamp', 0)
camera = pic.get('camera', 'unknown')
data = pic.get('data', '')
```

**V2:**
```python
from fmd_api import PhotoResult

pic = pictures[0]  # PhotoResult object
timestamp = pic.timestamp
camera = pic.camera
data = pic.encrypted_data
```

## Choosing Between FmdClient and Device

### Use `FmdClient` when:
- You need low-level control over API requests
- You want to handle decryption and parsing manually
- You're building custom tooling or integrations
- You need access to all API endpoints

### Use `Device` when:
- You want simple, high-level device operations
- You prefer automatic decryption and parsing
- You're building end-user applications
- You want type-safe data structures

### Combining Both

The `Device` class wraps `FmdClient`, so you can use both:

```python
device = await Device.create(url, fmd_id, password)

# High-level operations
location = await device.get_location()
await device.play_sound()

# Access client for advanced features
await device.client.toggle_bluetooth(True)
await device.client.set_ringer_mode('vibrate')
```

## Summary

The v2 API maintains backward compatibility at the client level while providing:
- Better structure and organization
- Typed data classes for improved IDE support
- More granular exception types
- High-level `Device` wrapper for common operations
- Same underlying protocol and encryption

For most applications, we recommend using the `Device` class for its convenience and type safety.
