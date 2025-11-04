# fmd_api: Python client for FMD (Find My Device)

Modern, async Python client for the open‑source FMD (Find My Device) server. It handles authentication, key management, encrypted data decryption, location/picture retrieval, and common device commands with safe, validated helpers.

This is the v2 rewrite. The legacy, single‑file module (FmdApi in fmd_api.py) has been replaced by a proper package with clear classes and typed methods.

## Install

- Requires Python 3.8+
- Stable (PyPI):
  ```bash
  pip install fmd_api
  ```
- Pre‑release (Test PyPI):
  ```bash
  pip install --pre --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ fmd_api
  ```

## Quickstart

```python
import asyncio, json
from fmd_api import FmdClient

async def main():
  # Recommended: async context manager auto-closes session
  async with await FmdClient.create("https://fmd.example.com", "alice", "secret") as client:
    # Request a fresh GPS fix and wait a bit on your side
    await client.request_location("gps")

    # Fetch most recent locations and decrypt the latest
    blobs = await client.get_locations(num_to_get=1)
    loc = json.loads(client.decrypt_data_blob(blobs[0]))
    print(loc["lat"], loc["lon"], loc.get("accuracy"))

    # Take a picture (validated helper)
    await client.take_picture("front")

asyncio.run(main())
```

## What’s in the box

- `FmdClient` (primary API)
  - Auth and key retrieval (salt → Argon2id → access token → private key decrypt)
  - Decrypt blobs (RSA‑OAEP wrapped AES‑GCM)
  - Fetch data: `get_locations`, `get_pictures`
  - Export: `export_data_zip(out_path)` — client-side packaging of all locations/pictures into ZIP (mimics web UI, no server endpoint)
  - Validated command helpers:
    - `request_location("all|gps|cell|last")`
    - `take_picture("front|back")`
    - `set_bluetooth(enable: bool)` — True = on, False = off
    - `set_do_not_disturb(enable: bool)` — True = on, False = off
    - `set_ringer_mode("normal|vibrate|silent")`
    - `get_device_stats()`

  
  - Low‑level: `decrypt_data_blob(b64_blob)`

- `Device` helper (per‑device convenience)
  - `await device.refresh()` → hydrate cached state
  - `await device.get_location()` → parsed last location
  - `await device.fetch_pictures(n)` + `await device.download_photo(item)`

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

## Troubleshooting

- "Blob too small for decryption": server returned empty/placeholder data. Skip and continue.
- Pictures may be double‑encoded (encrypted blob → base64 image string). The examples show how to decode safely.

## Credits

This client targets the FMD ecosystem:

- https://fmd-foss.org/
- https://gitlab.com/fmd-foss
- Public community instance: https://fmd.nulide.de/

MIT © 2025 Devin Slick