"""Device class representing a single tracked device.

Device implements small helpers that call into FmdClient to perform the same
operations available in the original module (get locations, take pictures, send commands).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, AsyncIterator, List

from .types import Location, PhotoResult
from .exceptions import OperationError
from .helpers import b64_decode_padded
from .client import FmdClient

def _parse_location_blob(blob_b64: str) -> Location:
    """Helper to decrypt and parse a location blob into Location dataclass."""
    # This function expects the caller to pass in a client to decrypt; kept here
    # for signature clarity in Device methods.
    raise RuntimeError("Internal: _parse_location_blob should not be called directly")

class Device:
    def __init__(self, client: FmdClient, fmd_id: str, raw: dict = None):
        self.client = client
        self.id = fmd_id
        self.raw = raw or {}
        self.name = self.raw.get("name")
        self.cached_location: Optional[Location] = None
        self._last_refresh = None

    async def refresh(self, *, force: bool = False):
        """Refresh the device's most recent location (uses client.get_locations(1))."""
        if not force and self.cached_location is not None:
            return

        blobs = await self.client.get_locations(num_to_get=1)
        if not blobs:
            self.cached_location = None
            return

        # decrypt and parse JSON
        decrypted = self.client.decrypt_data_blob(blobs[0])
        loc = json.loads(decrypted)
        # Build Location object with fields from README / fmd_api.py
        timestamp_ms = loc.get("date")
        ts = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc) if timestamp_ms else None
        self.cached_location = Location(
            lat=loc["lat"],
            lon=loc["lon"],
            timestamp=ts,
            accuracy_m=loc.get("accuracy"),
            altitude_m=loc.get("altitude"),
            speed_m_s=loc.get("speed"),
            heading_deg=loc.get("heading"),
            battery_pct=loc.get("bat"),
            provider=loc.get("provider"),
            raw=loc
        )

    async def get_location(self, *, force: bool = False) -> Optional[Location]:
        if force or self.cached_location is None:
            await self.refresh(force=force)
        return self.cached_location

    async def get_history(self, start=None, end=None, limit: int = -1) -> AsyncIterator[Location]:
        """
        Iterate historical locations. Uses client.get_locations() under the hood.
        Yields decrypted Location objects newest-first (matches get_all_locations when requesting N recent).
        """
        # For parity with original behavior, we request num_to_get=limit when limit!=-1,
        # otherwise request all and stream.
        if limit == -1:
            blobs = await self.client.get_locations(-1)
        else:
            blobs = await self.client.get_locations(limit, skip_empty=True)

        for b in blobs:
            try:
                decrypted = self.client.decrypt_data_blob(b)
                loc = json.loads(decrypted)
                timestamp_ms = loc.get("date")
                ts = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc) if timestamp_ms else None
                yield Location(
                    lat=loc["lat"],
                    lon=loc["lon"],
                    timestamp=ts,
                    accuracy_m=loc.get("accuracy"),
                    altitude_m=loc.get("altitude"),
                    speed_m_s=loc.get("speed"),
                    heading_deg=loc.get("heading"),
                    battery_pct=loc.get("bat"),
                    provider=loc.get("provider"),
                    raw=loc
                )
            except Exception as e:
                # skip invalid blobs but log
                raise OperationError(f"Failed to decrypt/parse location blob: {e}") from e

    async def play_sound(self) -> bool:
        return await self.client.send_command("ring")

    async def take_front_photo(self) -> bool:
        return await self.client.take_picture("front")

    async def take_rear_photo(self) -> bool:
        return await self.client.take_picture("back")

    async def fetch_pictures(self, num_to_get: int = -1) -> List[dict]:
        return await self.client.get_pictures(num_to_get=num_to_get)

    async def download_photo(self, picture_blob_b64: str) -> PhotoResult:
        """
        Decrypt a picture blob and return binary PhotoResult.

        The fmd README says picture data is double-encoded: encrypted blob -> base64 string -> image bytes.
        We decrypt the blob to get a base64-encoded image string; decode that to bytes and return.
        """
        decrypted = self.client.decrypt_data_blob(picture_blob_b64)
        # decrypted is bytes, often containing a base64-encoded image (as text)
        try:
            inner_b64 = decrypted.decode('utf-8').strip()
            image_bytes = b64_decode_padded(inner_b64)
            # timestamp is not standardized in picture payload; attempt to parse JSON if present
            raw_meta = None
            try:
                raw_meta = json.loads(decrypted)
            except Exception:
                raw_meta = {"note": "binary image or base64 string; no JSON metadata"}
            # Build PhotoResult; mime type not provided by server so default to image/jpeg
            return PhotoResult(data=image_bytes, mime_type="image/jpeg", timestamp=datetime.now(timezone.utc), raw=raw_meta)
        except Exception as e:
            raise OperationError(f"Failed to decode picture blob: {e}") from e

    async def lock(self, message: Optional[str] = None, passcode: Optional[str] = None) -> bool:
        # The original API supports "lock" command; it does not carry message/passcode in the current client
        # Implementation preserves original behavior (sends "lock" command). Extensions can append data if server supports it.
        return await self.client.send_command("lock")

    async def wipe(self, confirm: bool = False) -> bool:
        if not confirm:
            raise OperationError("wipe() requires confirm=True to proceed (destructive action)")
        return await self.client.send_command("delete")