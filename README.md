# fmd_api: Python client for FMD (Find My Device)

[![Tests](https://github.com/devinslick/fmd_api/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/devinslick/fmd_api/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/devinslick/fmd_api/branch/main/graph/badge.svg?token=8WA2TKXIOW)](https://codecov.io/gh/devinslick/fmd_api)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/fmd-api)](https://pypi.org/project/fmd-api/)

Modern, async Python client for the open‑source FMD (Find My Device) server. It handles authentication, key management, encrypted data decryption, location/picture retrieval, and common device commands with safe, validated helpers.

## Install

- Requires Python 3.8+
- Stable (PyPI):
  ```bash
  pip install fmd_api
  ```
<!-- Pre-release via TestPyPI removed. Use stable releases from PyPI or GitHub Releases for pre-release artifacts -->

## Quickstart

```python
import asyncio, json
from fmd_api import FmdClient

async def main():
  # Recommended: async context manager auto-closes session
  async with await FmdClient.create("https://fmd.example.com", "alice", "secret", drop_password=True) as client:
    # Request a fresh GPS fix and wait a bit on your side
    await client.request_location("gps")

    # Fetch most recent locations and decrypt the latest
    blobs = await client.get_locations(num_to_get=1)
    # decrypt_data_blob() returns raw bytes — decode then parse JSON for clarity
    decrypted = client.decrypt_data_blob(blobs[0])
    loc = json.loads(decrypted.decode("utf-8"))
    print(loc["lat"], loc["lon"], loc.get("accuracy"))

    # Take a picture (validated helper)
    await client.take_picture("front")

asyncio.run(main())
```

### TLS and self-signed certificates

HTTPS is strongly recommended for all connections to FMD server. HTTP is permitted for local development or trusted private networks, but should not be used in production. If you need to connect to a server with a self-signed certificate, you have two options:

- Preferred (secure): provide a custom SSLContext that trusts your CA or certificate
- Last resort (not for production): disable certificate validation explicitly

Examples:

```python
import ssl
from fmd_api import FmdClient

# 1) Custom CA bundle / pinned cert (recommended)
ctx = ssl.create_default_context()
ctx.load_verify_locations(cafile="/path/to/your/ca.pem")

# Via constructor
client = FmdClient("https://fmd.example.com", ssl=ctx)

# Or via factory
# async with await FmdClient.create("https://fmd.example.com", "user", "pass", ssl=ctx) as client:

# 2) Disable verification (development only)
insecure_client = FmdClient("https://fmd.example.com", ssl=False)
```

Notes:
- HTTPS is strongly recommended. Use HTTP only on trusted local networks or for development.
- Prefer a custom SSLContext over disabling verification.
- For higher security, consider pinning the server cert in your context.

> Warning
>
> Passing `ssl=False` disables TLS certificate validation and should only be used in development. For production, use a custom `ssl.SSLContext` that trusts your CA/certificate or pin the server certificate. Using `http://` URLs sends credentials and data in plaintext — only use HTTP on trusted local networks or for development purposes.

#### Pinning the exact server certificate (recommended for self-signed)

If you're using a self-signed certificate and want to pin to that exact cert, load the server's PEM (or DER) directly into an SSLContext. This ensures only that certificate (or its CA) is trusted.

```python
import ssl
from fmd_api import FmdClient

# Export your server's certificate to PEM (e.g., server-cert.pem)
ctx = ssl.create_default_context()
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = True  # keep hostname verification when possible
ctx.load_verify_locations(cafile="/path/to/server-cert.pem")

client = FmdClient("https://fmd.example.com", ssl=ctx)
# async with await FmdClient.create("https://fmd.example.com", "user", "pass", ssl=ctx) as client:
```

Tips:
- If the server cert changes, pinning will fail until you update the PEM.
- For intermediate/CA signing chains, prefer pinning a private CA instead of the leaf.

## What’s in the box

- `FmdClient` (primary API)
  - Auth and key retrieval (salt → Argon2id → access token → private key retrieval and decryption)
  - Decrypt blobs (RSA‑OAEP wrapped AES‑GCM)
  - Fetch data: `get_locations`, `get_pictures`
  - Export: `export_data_zip(out_path)` — client-side packaging of all locations/pictures into ZIP (mimics web UI, no server endpoint)
  - Validated command helpers:
    - `request_location("all|gps|cell|last")`
    - `take_picture("front|back")`
    - `set_bluetooth(enable: bool)` — True = on, False = off
    - `set_do_not_disturb(enable: bool)` — True = on, False = off
    - `set_ringer_mode("normal|vibrate|silent")`

  > **Note:** Device statistics functionality (`get_device_stats()`) has been temporarily removed and will be restored when the FMD server supports it (see [fmd-server#74](https://gitlab.com/fmd-foss/fmd-server/-/issues/74)).

  - Low‑level: `decrypt_data_blob(b64_blob)`

- `Device` helper (per‑device convenience)
  - `await device.refresh()` → hydrate cached state
  - `await device.get_location()` → parsed last location
  - `await device.get_picture_blobs(n)` + `await device.decode_picture(blob)`
  - `await device.get_picture_metadata(n)` -> returns only metadata dicts (if the server exposes them)

  IMPORTANT (breaking change in v2.0.5): legacy compatibility wrappers were removed.
  The following legacy methods were removed from the `Device` API: `fetch_pictures`,
  `get_pictures`, `download_photo`, `get_picture`, `take_front_photo`, and `take_rear_photo`.
  Update your code to use `get_picture_blobs()`, `decode_picture()`, `take_front_picture()`
  and `take_rear_picture()` instead.
  - Commands: `await device.play_sound()`, `await device.take_front_picture()`,
    `await device.take_rear_picture()`, `await device.lock(message=None)`,
    `await device.wipe(pin="YourSecurePIN", confirm=True)`
    Note: wipe requires the FMD PIN (alphanumeric ASCII, no spaces) and must be enabled in the Android app's General settings.
    Future versions may enforce a 16+ character PIN length ([fmd-android#379](https://gitlab.com/fmd-foss/fmd-android/-/merge_requests/379)).

### Example: Lock device with a message

```python
import asyncio
from fmd_api import FmdClient, Device

async def main():
  client = await FmdClient.create("https://fmd.example.com", "alice", "secret")
  device = Device(client, "alice")
  # Optional message is sanitized (quotes/newlines removed, whitespace collapsed)
  await device.lock(message="Lost phone. Please call +1-555-555-1234")
  await client.close()

asyncio.run(main())
```

### Example: Inspect pictures metadata (when available)

Use `get_picture_blobs()` to fetch the raw server responses (strings or dicts). If you want a
strongly-typed list of picture metadata objects (where the server provides metadata as JSON
objects), use `get_picture_metadata()`, which filters for dict entries and returns only those.

```python
from fmd_api import FmdClient, Device

async def inspect_metadata():
  client = await FmdClient.create("https://fmd.example.com", "alice", "secret")
  device = Device(client, "alice")

  # Raw values may be strings (base64 blobs) or dicts (metadata). Keep raw when you need
  # to decode or handle both forms yourself.
  raw = await device.get_picture_blobs(10)

  # If you want only metadata entries returned by the server, use get_picture_metadata().
  # This returns a list of dict-like metadata objects (e.g. id/date/filename) and filters
  # out any raw string blobs.
  metadata = await device.get_picture_metadata(10)
  for m in metadata:
    print(m.get("id"), m.get("date"))

  await client.close()

asyncio.run(inspect_metadata())
```

## Testing

### Functional tests

Runnable scripts under `tests/functional/`:

- `test_auth.py` – basic auth smoke test
- `test_locations.py` – list and decrypt recent locations
- `test_pictures.py` – list and download/decrypt a photo
- `test_device.py` – device helper flows
- `test_commands.py` – validated command wrappers (no raw strings)
- `test_export.py` – export data to ZIP
- `test_request_location.py` – request location and poll for results

Put credentials in `tests/utils/credentials.txt` (copy from `credentials.txt.example`).

### Unit tests

Located in `tests/unit/`:
- `test_client.py` – client HTTP flows with mocked responses
- `test_device.py` – device wrapper logic

Run with pytest:
```bash
pip install -e ".[dev]"
pytest tests/unit/
```

## API highlights

- Encryption compatible with FMD web client
  - RSA‑3072 OAEP (SHA‑256) wrapping AES‑GCM session key
  - AES‑GCM IV: 12 bytes; RSA packet size: 384 bytes
- Password/key derivation with Argon2id
- Robust HTTP JSON/text fallback and 401 re‑auth
  - Supports password-free resume via exported auth artifacts (hash + token + private key)

### Advanced: Password-Free Resume

You can onboard once with a raw password, optionally discard it immediately using `drop_password=True`, export authentication artifacts, and later resume without storing the raw secret:

```python
client = await FmdClient.create(url, fmd_id, password, drop_password=True)
artifacts = await client.export_auth_artifacts()

# Persist `artifacts` securely (contains hash, token, private key)

# Later / after restart
client2 = await FmdClient.from_auth_artifacts(artifacts)
locations = await client2.get_locations(1)
```

On a 401, the client will transparently reauthenticate using the stored Argon2id `password_hash` if available. When `drop_password=True`, the raw password is never retained after initial onboarding.

## Troubleshooting

- "Blob too small for decryption": server returned empty/placeholder data. Skip and continue.
- Pictures may be double‑encoded (encrypted blob → base64 image string). The examples show how to decode safely.

## Credits

This client targets the FMD ecosystem:

- https://fmd-foss.org/
- https://gitlab.com/fmd-foss
- Public community instance: https://server.fmd-foss.org/
 - Listed on the official FMD community page: https://fmd-foss.org/docs/fmd-server/community

MIT © 2025 Devin Slick
