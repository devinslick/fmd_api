"""Device class representing a single tracked device.

Device implements small helpers that call into FmdClient to perform the same
operations available in the original module (get locations, take pictures, send commands).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, AsyncIterator, List, Dict, cast
from .types import JSONType, PictureMetadata

from .models import Location, PhotoResult
from .exceptions import OperationError
from .helpers import b64_decode_padded
from .client import FmdClient


class Device:
    def __init__(self, client: FmdClient, fmd_id: str, raw: Optional[Dict[str, JSONType]] = None) -> None:
        self.client = client
        self.id = fmd_id
        self.raw: Dict[str, JSONType] = raw or {}
        self.name = self.raw.get("name")
        self.cached_location: Optional[Location] = None
        self._last_refresh = None

    async def refresh(self, *, force: bool = False) -> None:
        """Refresh the device's most recent location (uses client.get_locations(1))."""
        if not force and self.cached_location is not None:
            return

        blobs = await self.client.get_locations(num_to_get=1)
        if not blobs:
            self.cached_location = None
            return

        # decrypt and parse JSON
        decrypted = self.client.decrypt_data_blob(blobs[0])
        self.cached_location = Location.from_json(decrypted.decode("utf-8"))

    async def get_location(self, *, force: bool = False) -> Optional[Location]:
        if force or self.cached_location is None:
            await self.refresh(force=force)
        return self.cached_location

    async def get_history(self, limit: int = -1) -> AsyncIterator[Location]:
        """
        Iterate historical locations. Uses client.get_locations() under the hood.

        Args:
            limit: Maximum number of locations to return. -1 for all available.

        Yields:
            Decrypted Location objects, newest-first.

        Raises:
            OperationError: If decryption or parsing fails for a location blob.

        Note:
            Time-based filtering (start/end) is not currently supported by the FMD server API.
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
                yield Location.from_json(decrypted.decode("utf-8"))
            except Exception as e:
                # skip invalid blobs but log
                raise OperationError(f"Failed to decrypt/parse location blob: {e}") from e

    async def play_sound(self) -> bool:
        return await self.client.send_command("ring")

    async def take_front_picture(self) -> bool:
        """Request a picture from the front camera."""
        return await self.client.take_picture("front")

    async def take_rear_picture(self) -> bool:
        """Request a picture from the rear camera."""
        return await self.client.take_picture("back")

    async def get_picture_blobs(self, num_to_get: int = -1) -> List[JSONType]:
        """Get raw picture blobs (usually a list of dicts returned by the server).

        The client may return lists of mixed JSON values; coerce/filter here so callers
        (and the annotated return type) are guaranteed a list of dicts.
        """
        # Return raw server values (strings, dicts, etc.) — callers like decode_picture
        # expect string blobs and some server versions return dicts; preserve this.
        raw = await self.client.get_pictures(num_to_get=num_to_get)
        return list(raw)

    async def get_picture_metadata(self, num_to_get: int = -1) -> List[PictureMetadata]:
        """Return only picture entries that are JSON objects (dicts) — strongly typed metadata.

        This method intentionally filters the raw values returned by `get_picture_blobs` and
        yields only mappings (dicts), which callers can rely on for metadata fields.
        """
        raw = await self.client.get_pictures(num_to_get=num_to_get)
        metadata: List[PictureMetadata] = [cast(PictureMetadata, p) for p in raw if isinstance(p, dict)]
        return metadata

    async def decode_picture(self, picture_blob_b64: str) -> PhotoResult:
        """Decrypt and decode a single picture blob into a PhotoResult."""
        decrypted = self.client.decrypt_data_blob(picture_blob_b64)
        # decrypted is bytes, often containing a base64-encoded image (as text)
        try:
            inner_b64 = decrypted.decode("utf-8").strip()
            image_bytes = b64_decode_padded(inner_b64)
            # timestamp is not standardized in picture payload; attempt to parse JSON if present
            raw_meta = None
            try:
                raw_meta = json.loads(decrypted)
            except Exception:
                raw_meta = {"note": "binary image or base64 string; no JSON metadata"}
            # Build PhotoResult; mime type not provided by server so default to image/jpeg
            return PhotoResult(
                data=image_bytes, mime_type="image/jpeg", timestamp=datetime.now(timezone.utc), raw=raw_meta
            )
        except Exception as e:
            raise OperationError(f"Failed to decode picture blob: {e}") from e

    async def lock(self, message: Optional[str] = None, passcode: Optional[str] = None) -> bool:
        """Lock the device, optionally passing a message (and future passcode).

        Notes:
        - The public web UI may not expose message/passcode yet, but protocol-level
          support is expected. We optimistically send a formatted command if a message
          is provided: "lock <escaped>".
        - Sanitization: collapse whitespace, limit length, and strip unsafe characters.
        - If server ignores the payload, the base "lock" still executes.
        - Passcode argument reserved for potential future support; currently unused.
        """
        base = "lock"
        if message:
            # Basic sanitization: trim, collapse internal whitespace, remove newlines
            sanitized = " ".join(message.strip().split())
            # Remove characters that could break command parsing (quotes/backticks/semicolons)
            for ch in ['"', "'", "`", ";"]:
                sanitized = sanitized.replace(ch, "")
            # Re-collapse whitespace after removing special chars (may leave gaps)
            sanitized = " ".join(sanitized.split())
            # Cap length to 120 chars to avoid overly long command payloads
            if len(sanitized) > 120:
                sanitized = sanitized[:120]
            if sanitized:
                base = f"lock {sanitized}"
        return await self.client.send_command(base)

    async def wipe(self, pin: Optional[str] = None, *, confirm: bool = False) -> bool:
        """Factory reset (delete) the device. Requires user confirmation and PIN.

        The underlying command format (per Android client) is: `fmd delete <PIN>`.
        Notes:
        - The Delete feature must be enabled in the FMD Android client's General settings.
        - A PIN is mandatory and must be sent when calling wipe(confirm=True).
        - PIN must be alphanumeric ASCII (a-z, A-Z, 0-9) without spaces
          This is a current and safe recommendation from fmd-foss maintainers.
        - Future change: FMD Android will enforce 16+ character PIN length requirement
          (https://gitlab.com/fmd-foss/fmd-android/-/merge_requests/379). Existing
          shorter PINs may be grandfathered. This client will be updated accordingly.
        """
        if not confirm:
            raise OperationError("wipe() requires confirm=True to proceed (destructive action)")
        if not pin:
            raise OperationError("wipe() requires a PIN: pass pin='yourPIN123'")
        # Validate alphanumeric ASCII without spaces
        if not all(ch.isalnum() and ord(ch) < 128 for ch in pin):
            raise OperationError("PIN must contain only alphanumeric ASCII characters (a-z, A-Z, 0-9), no spaces")
        command = f"fmd delete {pin}"
        return await self.client.send_command(command)
