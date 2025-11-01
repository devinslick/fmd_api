"""
FmdClient: port of the original fmd_api.FmdApi into an async client class.

This module implements:
 - authenticate (salt -> argon2 -> requestAccess -> get private key blob -> decrypt)
 - decrypt_data_blob (RSA session key + AES-GCM)
 - _make_api_request (aiohttp wrapper with re-auth on 401, JSON/text fallback, streaming)
 - get_locations (port of get_all_locations)
 - get_pictures (port of get_pictures)
 - export_data_zip (streamed download)
 - send_command (RSA-PSS signing and POST to /api/v1/command)
 - convenience wrappers: request_location, toggle_bluetooth, toggle_do_not_disturb,
   set_ringer_mode, get_device_stats, take_picture
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Optional, List, Any

import aiohttp
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .helpers import b64_decode_padded, _pad_base64
from .exceptions import FmdApiException, AuthenticationError
from .models import PhotoResult, Location

# Constants copied from original module to ensure parity
CONTEXT_STRING_LOGIN = "context:loginAuthentication"
CONTEXT_STRING_ASYM_KEY_WRAP = "context:asymmetricKeyWrap"
ARGON2_SALT_LENGTH = 16
AES_GCM_IV_SIZE_BYTES = 12
RSA_KEY_SIZE_BYTES = 384  # 3072 bits / 8

log = logging.getLogger(__name__)


class FmdClient:
    def __init__(self, base_url: str, session_duration: int = 3600, *, cache_ttl: int = 30):
        self.base_url = base_url.rstrip('/')
        self.session_duration = session_duration
        self.cache_ttl = cache_ttl

        self._fmd_id: Optional[str] = None
        self._password: Optional[str] = None
        self.access_token: Optional[str] = None
        self.private_key = None  # cryptography private key object

        self._session: Optional[aiohttp.ClientSession] = None

    @classmethod
    async def create(cls, base_url: str, fmd_id: str, password: str, session_duration: int = 3600):
        inst = cls(base_url, session_duration)
        inst._fmd_id = fmd_id
        inst._password = password
        await inst.authenticate(fmd_id, password, session_duration)
        return inst

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # -------------------------
    # Authentication helpers
    # -------------------------
    async def authenticate(self, fmd_id: str, password: str, session_duration: int) -> None:
        """
        Performs the full authentication and private key retrieval workflow.
        Mirrors the behavior in the original fmd_api.FmdApi.
        """
        log.info("[1] Requesting salt...")
        salt = await self._get_salt(fmd_id)
        log.info("[2] Hashing password with salt...")
        password_hash = self._hash_password(password, salt)
        log.info("[3] Requesting access token...")
        self._fmd_id = fmd_id
        self._password = password
        self.access_token = await self._get_access_token(fmd_id, password_hash, session_duration)

        log.info("[3a] Retrieving encrypted private key...")
        privkey_blob = await self._get_private_key_blob()
        log.info("[3b] Decrypting private key...")
        privkey_bytes = self._decrypt_private_key_blob(privkey_blob, password)
        self.private_key = self._load_private_key_from_bytes(privkey_bytes)

    def _hash_password(self, password: str, salt: str) -> str:
        salt_bytes = base64.b64decode(_pad_base64(salt))
        password_bytes = (CONTEXT_STRING_LOGIN + password).encode('utf-8')
        hash_bytes = hash_secret_raw(
            secret=password_bytes, salt=salt_bytes, time_cost=1,
            memory_cost=131072, parallelism=4, hash_len=32, type=Type.ID
        )
        hash_b64 = base64.b64encode(hash_bytes).decode('utf-8').rstrip('=')
        return f"$argon2id$v=19$m=131072,t=1,p=4${salt}${hash_b64}"

    async def _get_salt(self, fmd_id: str) -> str:
        return await self._make_api_request("PUT", "/api/v1/salt", {"IDT": fmd_id, "Data": ""})

    async def _get_access_token(self, fmd_id: str, password_hash: str, session_duration: int) -> str:
        payload = {
            "IDT": fmd_id, "Data": password_hash,
            "SessionDurationSeconds": session_duration
        }
        return await self._make_api_request("PUT", "/api/v1/requestAccess", payload)

    async def _get_private_key_blob(self) -> str:
        return await self._make_api_request("PUT", "/api/v1/key", {"IDT": self.access_token, "Data": "unused"})

    def _decrypt_private_key_blob(self, key_b64: str, password: str) -> bytes:
        key_bytes = base64.b64decode(_pad_base64(key_b64))
        salt = key_bytes[:ARGON2_SALT_LENGTH]
        iv = key_bytes[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES]
        ciphertext = key_bytes[ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES:]
        password_bytes = (CONTEXT_STRING_ASYM_KEY_WRAP + password).encode('utf-8')
        aes_key = hash_secret_raw(
            secret=password_bytes, salt=salt, time_cost=1, memory_cost=131072,
            parallelism=4, hash_len=32, type=Type.ID
        )
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(iv, ciphertext, None)

    def _load_private_key_from_bytes(self, privkey_bytes: bytes):
        try:
            return serialization.load_pem_private_key(privkey_bytes, password=None)
        except ValueError:
            return serialization.load_der_private_key(privkey_bytes, password=None)

    # -------------------------
    # Decryption
    # -------------------------
    def decrypt_data_blob(self, data_b64: str) -> bytes:
        """
        Decrypts a location or picture data blob using the instance's private key.

        Raises FmdApiException on problems (matches original behavior).
        """
        blob = base64.b64decode(_pad_base64(data_b64))

        # Check for minimum size (RSA packet + IV)
        min_size = RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES
        if len(blob) < min_size:
            raise FmdApiException(
                f"Blob too small for decryption: {len(blob)} bytes (expected at least {min_size} bytes). "
                f"This may indicate empty/invalid data from the server."
            )

        session_key_packet = blob[:RSA_KEY_SIZE_BYTES]
        iv = blob[RSA_KEY_SIZE_BYTES:RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES]
        ciphertext = blob[RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES:]
        session_key = self.private_key.decrypt(
            session_key_packet,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(), label=None
            )
        )
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(iv, ciphertext, None)

    # -------------------------
    # HTTP helper
    # -------------------------
    async def _make_api_request(self, method: str, endpoint: str, payload: Any,
                                stream: bool = False, expect_json: bool = True, retry_auth: bool = True):
        """
        Makes an API request and returns Data or text depending on expect_json/stream.
        Mirrors get_all_locations/_make_api_request logic from original file (including 401 re-auth).
        """
        url = self.base_url + endpoint
        await self._ensure_session()
        try:
            async with self._session.request(method, url, json=payload) as resp:
                # Handle 401 -> re-authenticate once
                if resp.status == 401 and retry_auth and self._fmd_id and self._password:
                    log.info("Received 401 Unauthorized, re-authenticating...")
                    await self.authenticate(self._fmd_id, self._password, self.session_duration)
                    payload["IDT"] = self.access_token
                    return await self._make_api_request(method, endpoint, payload, stream, expect_json, retry_auth=False)

                resp.raise_for_status()
                log.debug(f"{endpoint} response - status: {resp.status}, content-type: {resp.content_type}, content-length: {resp.content_length}")

                if not stream:
                    if expect_json:
                        # server sometimes reports wrong content-type -> force JSON parse
                        try:
                            json_data = await resp.json(content_type=None)
                            log.debug(f"{endpoint} JSON response: {json_data}")
                            return json_data["Data"]
                        except (KeyError, ValueError, json.JSONDecodeError) as e:
                            # fall back to text
                            log.debug(f"{endpoint} JSON parsing failed ({e}), trying as text")
                            text_data = await resp.text()
                            if text_data:
                                log.debug(f"{endpoint} first 200 chars: {text_data[:200]}")
                            else:
                                log.warning(f"{endpoint} returned EMPTY response body")
                            return text_data
                    else:
                        text_data = await resp.text()
                        log.debug(f"{endpoint} text response length: {len(text_data)}")
                        return text_data
                else:
                    # Return the aiohttp response for streaming consumers
                    return resp
        except aiohttp.ClientError as e:
            log.error(f"API request failed for {endpoint}: {e}")
            raise FmdApiException(f"API request failed for {endpoint}: {e}") from e
        except (KeyError, ValueError) as e:
            log.error(f"Failed to parse server response for {endpoint}: {e}")
            raise FmdApiException(f"Failed to parse server response for {endpoint}: {e}") from e

    # -------------------------
    # Location / picture access
    # -------------------------
    async def get_locations(self, num_to_get: int = -1, skip_empty: bool = True, max_attempts: int = 10) -> List[str]:
        """
        Fetches all or the N most recent location blobs.
        Returns list of base64-encoded blobs (strings), same as original get_all_locations.
        """
        log.debug(f"Getting locations, num_to_get={num_to_get}, skip_empty={skip_empty}")
        size_str = await self._make_api_request("PUT", "/api/v1/locationDataSize", {"IDT": self.access_token, "Data": ""})
        size = int(size_str)
        log.debug(f"Server reports {size} locations available")
        if size == 0:
            log.info("No locations found to download.")
            return []

        locations: List[str] = []
        if num_to_get == -1:
            log.info(f"Found {size} locations to download.")
            indices = range(size)
            for i in indices:
                log.info(f"  - Downloading location at index {i}...")
                blob = await self._make_api_request("PUT", "/api/v1/location", {"IDT": self.access_token, "Data": str(i)})
                locations.append(blob)
            return locations
        else:
            num_to_download = min(num_to_get, size)
            log.info(f"Found {size} locations. Downloading the {num_to_download} most recent.")
            start_index = size - 1

            if skip_empty:
                indices = range(start_index, max(0, start_index - max_attempts), -1)
                log.info(f"Will search for {num_to_download} non-empty location(s) starting from index {start_index}")
            else:
                end_index = size - num_to_download
                indices = range(start_index, end_index - 1, -1)
                log.info(f"Will fetch indices: {list(indices)}")

        for i in indices:
            log.info(f"  - Downloading location at index {i}...")
            blob = await self._make_api_request("PUT", "/api/v1/location", {"IDT": self.access_token, "Data": str(i)})
            log.debug(f"Received blob type: {type(blob)}, length: {len(blob) if blob else 0}")
            if blob and isinstance(blob, str) and blob.strip():
                log.debug(f"First 100 chars: {blob[:100]}")
                locations.append(blob)
                log.info(f"Found valid location at index {i}")
                if len(locations) >= num_to_get and num_to_get != -1:
                    break
            else:
                log.warning(f"Empty blob received for location index {i}, repr: {repr(blob[:50] if blob else blob)}")

        if not locations and num_to_get != -1:
            log.warning(f"No valid locations found after checking {min(max_attempts, size)} indices")

        return locations

    async def get_pictures(self, num_to_get: int = -1) -> List[Any]:
        """Fetches all or the N most recent picture metadata blobs (raw server response)."""
        try:
            await self._ensure_session()
            async with self._session.put(f"{self.base_url}/api/v1/pictures", json={"IDT": self.access_token, "Data": ""}) as resp:
                resp.raise_for_status()
                all_pictures = await resp.json()
        except aiohttp.ClientError as e:
            log.warning(f"Failed to get pictures: {e}. The endpoint may not exist or requires a different method.")
            return []

        if num_to_get == -1:
            log.info(f"Found {len(all_pictures)} pictures to download.")
            return all_pictures
        else:
            num_to_download = min(num_to_get, len(all_pictures))
            log.info(f"Found {len(all_pictures)} pictures. Selecting the {num_to_download} most recent.")
            return all_pictures[-num_to_download:][::-1]

    async def export_data_zip(self, output_file: str) -> None:
        """Downloads the pre-packaged export data zip file from /api/v1/exportData."""
        try:
            await self._ensure_session()
            async with self._session.post(f"{self.base_url}/api/v1/exportData", json={"IDT": self.access_token, "Data": "unused"}) as resp:
                resp.raise_for_status()
                with open(output_file, 'wb') as f:
                    while True:
                        chunk = await resp.content.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
            log.info(f"Exported data saved to {output_file}")
        except aiohttp.ClientError as e:
            log.error(f"Failed to export data: {e}")
            raise FmdApiException(f"Failed to export data: {e}") from e

    # -------------------------
    # Commands
    # -------------------------
    async def send_command(self, command: str) -> bool:
        """Sends a signed command to the server. Returns True on success."""
        log.info(f"Sending command to device: {command}")
        unix_time_ms = int(time.time() * 1000)
        message_to_sign = f"{unix_time_ms}:{command}"
        message_bytes = message_to_sign.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode('utf-8').rstrip('=')

        try:
            await self._make_api_request(
                "POST",
                "/api/v1/command",
                {
                    "IDT": self.access_token,
                    "Data": command,
                    "UnixTime": unix_time_ms,
                    "CmdSig": signature_b64
                },
                expect_json=False
            )
            log.info(f"Command sent successfully: {command}")
            return True
        except Exception as e:
            log.error(f"Failed to send command '{command}': {e}")
            raise FmdApiException(f"Failed to send command '{command}': {e}") from e

    async def request_location(self, provider: str = "all") -> bool:
        provider_map = {
            "all": "locate",
            "gps": "locate gps",
            "cell": "locate cell",
            "network": "locate cell",
            "last": "locate last"
        }
        command = provider_map.get(provider.lower(), "locate")
        log.info(f"Requesting location update with provider: {provider} (command: {command})")
        return await self.send_command(command)

    async def toggle_bluetooth(self, enable: bool) -> bool:
        command = "bluetooth on" if enable else "bluetooth off"
        log.info(f"{'Enabling' if enable else 'Disabling'} Bluetooth")
        return await self.send_command(command)

    async def toggle_do_not_disturb(self, enable: bool) -> bool:
        command = "nodisturb on" if enable else "nodisturb off"
        log.info(f"{'Enabling' if enable else 'Disabling'} Do Not Disturb mode")
        return await self.send_command(command)

    async def set_ringer_mode(self, mode: str) -> bool:
        mode = mode.lower()
        mode_map = {
            "normal": "ringermode normal",
            "vibrate": "ringermode vibrate",
            "silent": "ringermode silent"
        }
        if mode not in mode_map:
            raise ValueError(f"Invalid ringer mode '{mode}'. Must be 'normal', 'vibrate', or 'silent'")
        command = mode_map[mode]
        log.info(f"Setting ringer mode to: {mode}")
        return await self.send_command(command)

    async def get_device_stats(self) -> bool:
        log.info("Requesting device network statistics")
        return await self.send_command("stats")

    async def take_picture(self, camera: str = "back") -> bool:
        camera = camera.lower()
        if camera not in ["front", "back"]:
            raise ValueError(f"Invalid camera '{camera}'. Must be 'front' or 'back'")
        command = "camera front" if camera == "front" else "camera back"
        log.info(f"Requesting picture from {camera} camera")
        return await self.send_command(command)