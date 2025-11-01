# Proposal: fmd_api v2 — Device-centric async interface

Status: Draft  
Author: devinslick (proposal by Copilot Space)  
Date: 2025-11-01

## Goals

- Replace the current functional-style API with a small object model that exposes a Device class representing a single tracked device.
- Keep all existing behavior and business logic of the current implementation, but convert operations to awaitable async methods to satisfy Home Assistant integration requirements.
- Provide an idiomatic, easy-to-test, and extensible interface:
  - Device objects that encapsulate identifiers, state, and operations (refresh, play_sound, locate, take photos, etc).
  - A lightweight Client that handles authentication, session management, rate limiting, and discovery of devices.
- Keep the migration path simple: do NOT provide an in-code legacy compatibility layer. Instead include a short migration README that helps developers move from the old API to the new device-centric API.
- Include unit-test and integration-test guidance and examples.

## Overview of the new design

Top-level components:
- FmdClient: an async client that manages session, authentication tokens, request throttling, and device discovery.
- Device: represents a single device and exposes async methods to interact with it (async refresh(), async play_sound(), async get_location(), async take_front_photo(), async take_rear_photo(), async lock_device(), async wipe_device(), etc).
- Exceptions: typed exceptions for common error cases (AuthenticationError, DeviceNotFoundError, FmdApiError, RateLimitError).
- Utilities: small helpers for caching, TTL-based per-device caches, retry/backoff, JSON parsing.

Rationale:
- Home Assistant requires async-enabled integrations to avoid blocking the event loop. Converting to async lets this library integrate smoothly.
- Representing a device as an object makes the API easier to reason about, test, and extend.
- Centralized client manages authentication and rate-limiting across multiple Device instances.
- Avoiding a built-in legacy shim keeps the code simple and encourages direct migration.

## Public API

Example usage:

```python
from fmd_api import FmdClient

async def example():
    client = FmdClient(username="me@example.com", password="hunter2")
    await client.authenticate()

    devices = await client.get_devices()  # list[Device]
    device = devices[0]

    # Get latest known location (from cache or backend)
    loc = await device.get_location()

    # Force a refresh from backend
    await device.refresh(force=True)

    # Trigger play sound
    await device.play_sound()

    # Take front and rear photos
    front = await device.take_front_photo()
    rear = await device.take_rear_photo()

    # Lock device with message
    await device.lock_device(message="Lost phone — call me")

    # Wipe device (dangerous)
    # await device.wipe_device(confirm=True)

    # Close client when finished
    await client.close()
```

Core classes and signatures (proposal):

- FmdClient
  - __init__(self, username: str, password: str, session: Optional[aiohttp.ClientSession] = None, *, base_url: Optional[str] = None, request_timeout: int = 10, rate_limiter: Optional[RateLimiter] = None, cache_ttl: int = 30)
  - async authenticate(self) -> None
  - async get_devices(self) -> list["Device"]
  - async get_device(self, device_id: str) -> "Device"
  - async close(self) -> None
  - properties:
    - auth_token (read-only)
    - is_authenticated: bool
    - cache_ttl: int

- Device
  - Attributes:
    - client: FmdClient (back-reference)
    - id: str
    - name: str
    - model: Optional[str]
    - battery: Optional[int]
    - is_online: Optional[bool]
    - last_seen: Optional[datetime]
    - cached_location: Optional[Location]
    - raw: dict
  - Methods (async):
    - async refresh(self, *, force: bool = False) -> None
      - Updates device state and location from backend. Honor per-device cache TTL when force=False.
    - async get_location(self, *, force: bool = False) -> Optional[Location]
      - Returns last known location (calls refresh if expired or force=True)
    - async play_sound(self, *, volume: Optional[int] = None) -> None
    - async take_front_photo(self) -> Optional[bytes]
      - Requests a front-facing photo; returns raw bytes of image if available.
    - async take_rear_photo(self) -> Optional[bytes]
      - Requests a rear-facing photo; returns raw bytes of image if available.
    - async lock_device(self, *, passcode: Optional[str] = None, message: Optional[str] = None) -> None
    - async wipe_device(self, *, confirm: bool = False) -> None
    - async set_label(self, label: str) -> None
    - to_dict(self) -> dict
    - __repr__/__str__ helper for debugging

- Location (dataclass)
  - lat: float
  - lon: float
  - accuracy_m: Optional[float]
  - timestamp: datetime
  - raw: dict

- PhotoResult (dataclass)
  - bytes: bytes
  - mime_type: str
  - timestamp: datetime
  - raw: dict

- Exceptions
  - FmdApiError(Exception)
  - AuthenticationError(FmdApiError)
  - DeviceNotFoundError(FmdApiError)
  - RateLimitError(FmdApiError)
  - OperationError(FmdApiError)

## Behavior details & compatibility with current logic

- All request payloads, parsing, and business rules will reuse the logic currently implemented in the repository (parsing of responses, mapping fields to device properties, handling of play sound semantics, etc.). No functional changes to endpoints or command behavior are intended.
- Where current code uses synchronous HTTP (requests), the new client will use asyncio/aiohttp to make non-blocking calls. Helpers will be introduced to convert existing request/response handling functions to async easily.
- Device.refresh() mirrors current "get devices" and "refresh device" flows: fetch the device status endpoint, parse location, battery, and update fields.
- Photo functions: take_front_photo() and take_rear_photo() call the corresponding FMD endpoints (if supported). They should return either a PhotoResult object (preferred) or None if not supported by the device/account. Implementations should include sensible timeouts and handle partial results gracefully.
- Caching: to avoid hitting rate limits and reduce backend load, a per-device TTL cache will be implemented (configurable; default 30 seconds). get_location() uses cached data unless force=True or stale.
- Rate limiting: a shared RateLimiter object will enforce a maximum requests-per-second or requests-per-minute per client instance. Simple token-bucket or asyncio.Semaphore + sleep-backoff will be sufficient.
- Retries: transient HTTP errors will be retried with an exponential backoff (configurable; default 3 retries).
- Error handling: HTTP 401 triggers AuthenticationError; 404 for device endpoints raises DeviceNotFoundError; 429 triggers RateLimitError.

## Async design considerations

- Use aiohttp.ClientSession for requests. The session can be provided by a caller (for reuse) or created by the client.
- All public methods are async and return without blocking the event loop.
- Methods that call multiple network endpoints (for example, refresh that fetches multiple resources) should gather coroutines where parallelism is safe, using asyncio.gather.
- Allow integration with Home Assistant through the standard pattern: construct client during integration setup, call client.authenticate() in async_setup_entry(), create entities that hold Device references, and use DataUpdateCoordinator(s).

## Migration notes (from current repo)

- We will NOT ship an in-code legacy compatibility adapter. Instead, include a short README (docs/MIGRATE_FROM_V1.md) with:
  - A mapping table of old function names to the new FmdClient/Device equivalents.
  - Short code snippets showing how to migrate common flows (list devices, refresh, ring, take photos).
  - Notes about switching to async and recommended patterns for calling from synchronous scripts (e.g., using asyncio.run or running inside an existing loop).
- Example migration snippet:

Old v1 (sync):
```python
d = get_device("device-id")
location = d["location"]
ring_device("device-id")
```

New v2 (async):
```python
client = FmdClient(username="u", password="p")
await client.authenticate()
device = await client.get_device("device-id")
location = await device.get_location()
await device.play_sound()
```

## Testing

- Unit tests:
  - Mock aiohttp responses using aioresponses or pytest-aiohttp.
  - Test Device.refresh, Device.get_location caching behavior, play_sound, take_front_photo/take_rear_photo, lock_device, wipe_device, error mappings, and retry logic.
- Integration tests:
  - Optionally include an integration test suite that can run against a staging backend or recorded responses (VCR-like fixture).
- Linting:
  - Enforce mypy typing for public API and add tests that ensure Device methods are awaitable.

## Implementation plan (phased)

1. Agree on method names and shapes in this proposal.
2. Implement FmdClient and Device classes with core methods: authenticate, get_devices, get_device, Device.refresh, Device.get_location, Device.play_sound, Device.take_front_photo, Device.take_rear_photo.
3. Port parsing logic from current code into async request handlers.
4. Implement caching, rate limiting, and retries.
5. Add docs/MIGRATE_FROM_V1.md migration guide and examples.
6. Add Home Assistant integration notes and an example integration using DataUpdateCoordinator.
7. Add unit/integration tests and CI (GitHub Actions).
8. Release v2.0.0 with upgrade notes.

Estimated effort:
- Core async client + Device, basic tests: 1–2 days
- Full feature parity (all endpoints + play/lock/wipe/photos): 2–3 days
- Tests + CI + HA docs: 1–2 days

## File layout proposal

- fmd_api/
  - __init__.py              # exports FmdClient, Device, exceptions
  - client.py                # FmdClient implementation
  - device.py                # Device model & methods
  - types.py                 # dataclasses: Location, PhotoResult, DeviceInfo
  - exceptions.py            # typed exceptions
  - rate_limiter.py          # simple rate limiter utilities
  - cache.py                 # TTL cache helpers
  - helpers.py               # utility functions, parsers
  - tests/
    - test_client.py
    - test_device.py
    - fixtures/
- docs/
  - ha_integration.md
  - MIGRATE_FROM_V1.md      # short migration guide from existing repo
- examples/
  - async_example.py

## Home Assistant integration notes

- Use FmdClient in the integration's async_setup_entry() method.
- Create a DataUpdateCoordinator per entry or a single coordinator that manages all devices:
  - Coordinator calls client.get_devices() periodically and updates entities.
  - Entities keep a reference to their Device object and read properties directly.
- Expose device actions (play_sound, take_front_photo, take_rear_photo, lock, wipe) through Home Assistant services that call the corresponding async Device methods.

Example HA pattern:
- On setup:
  - client = FmdClient(...)
  - await client.authenticate()
  - devices = await client.get_devices()
  - coordinator = DataUpdateCoordinator(..., update_method=client.get_devices)
  - create entities that hold Device references

## Example Device class (sketch)

```python
class Device:
    def __init__(self, client: FmdClient, raw: dict):
        self.client = client
        self.id = raw["id"]
        self.name = raw.get("name")
        self.raw = raw
        self.cached_location: Optional[Location] = None
        self._last_refresh = datetime.min

    async def refresh(self, *, force: bool = False) -> None:
        if not force and (utcnow() - self._last_refresh).total_seconds() < self.client.cache_ttl:
            return
        data = await self.client._request("GET", f"/devices/{self.id}")
        self._update_from_raw(data)
        self._last_refresh = utcnow()

    async def get_location(self, *, force: bool = False) -> Optional[Location]:
        await self.refresh(force=force)
        return self.cached_location

    async def play_sound(self, *, volume: Optional[int] = None) -> None:
        await self.client._request("POST", f"/devices/{self.id}/play_sound", json={"volume": volume} if volume else None)

    async def take_front_photo(self) -> Optional[PhotoResult]:
        resp = await self.client._request("POST", f"/devices/{self.id}/take_photo", json={"camera": "front"})
        return parse_photo_result(resp)

    async def take_rear_photo(self) -> Optional[PhotoResult]:
        resp = await self.client._request("POST", f"/devices/{self.id}/take_photo", json={"camera": "rear"})
        return parse_photo_result(resp)
```

## Security considerations

- Store tokens securely; do not log secrets. Client will redact token values from debug logs.
- Encourage the use of per-integration API keys if the backend supports them.
- Provide options to scope rate limits and avoid accidental account lockouts via aggressive command usage.

## API docs & examples

- Add README sections showing:
  - Basic usage (authenticate, list devices, one-liners)
  - Example usage inside Home Assistant
  - Migration guide from v1 to v2 (docs/MIGRATE_FROM_V1.md)
  - How to run tests

## Closing

This proposal updates the earlier draft to:
- Use the more concise FmdClient name (no Async prefix).
- Include explicit methods for taking front and rear photos.
- Drop an in-code legacy compatibility layer and instead provide a small migration README.

If you approve, I will create a branch and a PR that implements the core FmdClient and Device class with the initial methods (authenticate, get_devices, get_device, Device.refresh, Device.get_location, Device.play_sound, Device.take_front_photo, Device.take_rear_photo), plus tests and example usage.