"""FMD API Client implementation.

This module provides the FmdClient class that handles authentication,
encryption/decryption, and communication with the FMD server.
"""
import base64
import json
import logging
import time
from typing import List, Optional, Any

import aiohttp
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import (
    FmdApiException,
    FmdAuthenticationError,
    FmdDecryptionError,
    FmdApiRequestError,
    FmdInvalidDataError,
)
from .helpers import decode_base64, encode_base64
from .types import Location, PhotoResult

# --- Constants ---
CONTEXT_STRING_LOGIN = "context:loginAuthentication"
CONTEXT_STRING_ASYM_KEY_WRAP = "context:asymmetricKeyWrap"
ARGON2_SALT_LENGTH = 16
AES_GCM_IV_SIZE_BYTES = 12
RSA_KEY_SIZE_BYTES = 384  # 3072 bits / 8

log = logging.getLogger(__name__)


class FmdCommands:
    """Constants for available FMD device commands."""
    
    # Location requests
    LOCATE_ALL = "locate"
    LOCATE_GPS = "locate gps"
    LOCATE_CELL = "locate cell"
    LOCATE_LAST = "locate last"
    
    # Device control
    RING = "ring"
    LOCK = "lock"
    DELETE = "delete"
    
    # Camera
    CAMERA_FRONT = "camera front"
    CAMERA_BACK = "camera back"
    
    # Bluetooth
    BLUETOOTH_ON = "bluetooth on"
    BLUETOOTH_OFF = "bluetooth off"
    
    # Do Not Disturb
    NODISTURB_ON = "nodisturb on"
    NODISTURB_OFF = "nodisturb off"
    
    # Ringer Mode
    RINGERMODE_NORMAL = "ringermode normal"
    RINGERMODE_VIBRATE = "ringermode vibrate"
    RINGERMODE_SILENT = "ringermode silent"
    
    # Information/Status
    STATS = "stats"
    GPS = "gps"


class FmdClient:
    """Client for the FMD server API.
    
    This class handles authentication, key management, and encrypted
    communication with an FMD server.
    """
    
    def __init__(self, base_url: str, session_duration: int = 3600):
        """Initialize FMD client.
        
        Args:
            base_url: Base URL of the FMD server
            session_duration: Session duration in seconds (default: 3600)
        """
        self.base_url = base_url.rstrip('/')
        self.session_duration = session_duration
        self.access_token: Optional[str] = None
        self.private_key = None
        self._fmd_id: Optional[str] = None
        self._password: Optional[str] = None
    
    @classmethod
    async def create(cls, base_url: str, fmd_id: str, password: str, 
                     session_duration: int = 3600) -> "FmdClient":
        """Create and authenticate an FmdClient instance.
        
        Args:
            base_url: Base URL of the FMD server
            fmd_id: Device ID
            password: Device password
            session_duration: Session duration in seconds
            
        Returns:
            Authenticated FmdClient instance
            
        Raises:
            FmdAuthenticationError: If authentication fails
        """
        instance = cls(base_url, session_duration)
        instance._fmd_id = fmd_id
        instance._password = password
        await instance.authenticate(fmd_id, password, session_duration)
        return instance
    
    async def authenticate(self, fmd_id: str, password: str, session_duration: int):
        """Perform full authentication and key retrieval workflow.
        
        Args:
            fmd_id: Device ID
            password: Device password
            session_duration: Session duration in seconds
            
        Raises:
            FmdAuthenticationError: If authentication fails
        """
        try:
            log.info("[1] Requesting salt...")
            salt = await self._get_salt(fmd_id)
            
            log.info("[2] Hashing password with salt...")
            password_hash = self._hash_password(password, salt)
            
            log.info("[3] Requesting access token...")
            self._fmd_id = fmd_id
            self.access_token = await self._get_access_token(fmd_id, password_hash, session_duration)
            
            log.info("[3a] Retrieving encrypted private key...")
            privkey_blob = await self._get_private_key_blob()
            
            log.info("[3b] Decrypting private key...")
            privkey_bytes = self._decrypt_private_key_blob(privkey_blob, password)
            self.private_key = self._load_private_key_from_bytes(privkey_bytes)
        except Exception as e:
            log.error(f"Authentication failed: {e}")
            raise FmdAuthenticationError(f"Authentication failed: {e}") from e
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password using Argon2id.
        
        Args:
            password: Plain text password
            salt: Base64-encoded salt
            
        Returns:
            Argon2id hash string
        """
        salt_bytes = decode_base64(salt)
        password_bytes = (CONTEXT_STRING_LOGIN + password).encode('utf-8')
        hash_bytes = hash_secret_raw(
            secret=password_bytes,
            salt=salt_bytes,
            time_cost=1,
            memory_cost=131072,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        hash_b64 = encode_base64(hash_bytes)
        return f"$argon2id$v=19$m=131072,t=1,p=4${salt}${hash_b64}"
    
    async def _get_salt(self, fmd_id: str) -> str:
        """Get salt for password hashing."""
        return await self._make_api_request("PUT", "/api/v1/salt", {"IDT": fmd_id, "Data": ""})
    
    async def _get_access_token(self, fmd_id: str, password_hash: str, session_duration: int) -> str:
        """Get access token."""
        payload = {
            "IDT": fmd_id,
            "Data": password_hash,
            "SessionDurationSeconds": session_duration
        }
        return await self._make_api_request("PUT", "/api/v1/requestAccess", payload)
    
    async def _get_private_key_blob(self) -> str:
        """Get encrypted private key blob."""
        return await self._make_api_request("PUT", "/api/v1/key", {"IDT": self.access_token, "Data": "unused"})
    
    def _decrypt_private_key_blob(self, key_b64: str, password: str) -> bytes:
        """Decrypt private key blob using password-derived key.
        
        Args:
            key_b64: Base64-encoded encrypted key blob
            password: Device password
            
        Returns:
            Decrypted private key bytes
            
        Raises:
            FmdDecryptionError: If decryption fails
        """
        try:
            key_bytes = decode_base64(key_b64)
            salt = key_bytes[:ARGON2_SALT_LENGTH]
            iv = key_bytes[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES]
            ciphertext = key_bytes[ARGON2_SALT_LENGTH + AES_GCM_IV_SIZE_BYTES:]
            
            password_bytes = (CONTEXT_STRING_ASYM_KEY_WRAP + password).encode('utf-8')
            aes_key = hash_secret_raw(
                secret=password_bytes,
                salt=salt,
                time_cost=1,
                memory_cost=131072,
                parallelism=4,
                hash_len=32,
                type=Type.ID
            )
            
            aesgcm = AESGCM(aes_key)
            return aesgcm.decrypt(iv, ciphertext, None)
        except Exception as e:
            raise FmdDecryptionError(f"Failed to decrypt private key: {e}") from e
    
    def _load_private_key_from_bytes(self, privkey_bytes: bytes):
        """Load private key from bytes (PEM or DER format).
        
        Args:
            privkey_bytes: Private key bytes
            
        Returns:
            Private key object
        """
        try:
            return serialization.load_pem_private_key(privkey_bytes, password=None)
        except ValueError:
            return serialization.load_der_private_key(privkey_bytes, password=None)
    
    def decrypt_data_blob(self, data_b64: str) -> bytes:
        """Decrypt a data blob using the instance's private key.
        
        Args:
            data_b64: Base64-encoded encrypted blob
            
        Returns:
            Decrypted data bytes
            
        Raises:
            FmdDecryptionError: If decryption fails
            FmdInvalidDataError: If blob is too small
        """
        try:
            blob = decode_base64(data_b64)
            
            # Check if blob is large enough
            min_size = RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES
            if len(blob) < min_size:
                raise FmdInvalidDataError(
                    f"Blob too small for decryption: {len(blob)} bytes "
                    f"(expected at least {min_size} bytes)"
                )
            
            session_key_packet = blob[:RSA_KEY_SIZE_BYTES]
            iv = blob[RSA_KEY_SIZE_BYTES:RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES]
            ciphertext = blob[RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES:]
            
            # Decrypt session key with RSA
            session_key = self.private_key.decrypt(
                session_key_packet,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES-GCM
            aesgcm = AESGCM(session_key)
            return aesgcm.decrypt(iv, ciphertext, None)
        except (FmdInvalidDataError, FmdDecryptionError):
            raise
        except Exception as e:
            raise FmdDecryptionError(f"Failed to decrypt data blob: {e}") from e
    
    async def _make_api_request(self, method: str, endpoint: str, payload: dict,
                                stream: bool = False, expect_json: bool = True,
                                retry_auth: bool = True) -> Any:
        """Make an API request with automatic retry on 401.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            payload: Request payload
            stream: If True, return response object for streaming
            expect_json: If True, parse response as JSON
            retry_auth: If True, retry once with new auth on 401
            
        Returns:
            Response data or response object if streaming
            
        Raises:
            FmdApiRequestError: If request fails
        """
        url = self.base_url + endpoint
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, json=payload) as resp:
                    # Handle 401 Unauthorized by re-authenticating
                    if resp.status == 401 and retry_auth and self._fmd_id and self._password:
                        log.info("Received 401 Unauthorized, re-authenticating...")
                        await self.authenticate(self._fmd_id, self._password, self.session_duration)
                        # Retry with new token
                        payload["IDT"] = self.access_token
                        return await self._make_api_request(method, endpoint, payload, stream, expect_json, retry_auth=False)
                    
                    resp.raise_for_status()
                    
                    log.debug(f"{endpoint} response - status: {resp.status}, content-type: {resp.content_type}")
                    
                    if not stream:
                        if expect_json:
                            # FMD server sometimes returns wrong content-type
                            # Use content_type=None to force JSON parsing
                            try:
                                json_data = await resp.json(content_type=None)
                                log.debug(f"{endpoint} JSON response: {json_data}")
                                return json_data["Data"]
                            except (KeyError, ValueError, json.JSONDecodeError) as e:
                                # Fall back to text
                                log.debug(f"{endpoint} JSON parsing failed ({e}), trying as text")
                                text_data = await resp.text()
                                log.debug(f"{endpoint} returned text length: {len(text_data)}")
                                if not text_data:
                                    log.warning(f"{endpoint} returned EMPTY response body")
                                return text_data
                        else:
                            text_data = await resp.text()
                            log.debug(f"{endpoint} text response length: {len(text_data)}")
                            return text_data
                    else:
                        return resp
        except aiohttp.ClientError as e:
            log.error(f"API request failed for {endpoint}: {e}")
            raise FmdApiRequestError(f"API request failed for {endpoint}: {e}") from e
        except (KeyError, ValueError) as e:
            log.error(f"Failed to parse server response for {endpoint}: {e}")
            raise FmdApiRequestError(f"Failed to parse server response for {endpoint}: {e}") from e
    
    async def get_locations(self, num_to_get: int = -1, skip_empty: bool = True,
                          max_attempts: int = 10) -> List[str]:
        """Fetch location blobs from the server.
        
        Args:
            num_to_get: Number of locations to get (-1 for all)
            skip_empty: If True, skip empty blobs and search backwards
            max_attempts: Maximum indices to try when skip_empty is True
            
        Returns:
            List of encrypted location blobs
        """
        log.debug(f"Getting locations, num_to_get={num_to_get}, skip_empty={skip_empty}")
        size_str = await self._make_api_request("PUT", "/api/v1/locationDataSize", 
                                                {"IDT": self.access_token, "Data": "unused"})
        size = int(size_str)
        log.debug(f"Server reports {size} locations available")
        
        if size == 0:
            log.info("No locations found to download.")
            return []
        
        locations = []
        if num_to_get == -1:  # Download all
            log.info(f"Found {size} locations to download.")
            for i in range(size):
                log.info(f"  - Downloading location at index {i}...")
                blob = await self._make_api_request("PUT", "/api/v1/location", 
                                                   {"IDT": self.access_token, "Data": str(i)})
                locations.append(blob)
            return locations
        else:  # Download N most recent
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
                blob = await self._make_api_request("PUT", "/api/v1/location", 
                                                   {"IDT": self.access_token, "Data": str(i)})
                log.debug(f"Received blob type: {type(blob)}, length: {len(blob) if blob else 0}")
                
                if blob and blob.strip():
                    log.debug(f"First 100 chars: {blob[:100]}")
                    locations.append(blob)
                    log.info(f"Found valid location at index {i}")
                    if len(locations) >= num_to_get and num_to_get != -1:
                        break
                else:
                    log.warning(f"Empty blob received for location index {i}")
            
            if not locations and num_to_get != -1:
                log.warning(f"No valid locations found after checking {min(max_attempts, size)} indices")
        
        return locations
    
    async def get_pictures(self, num_to_get: int = -1) -> List[dict]:
        """Fetch picture metadata from the server.
        
        Args:
            num_to_get: Number of pictures to get (-1 for all)
            
        Returns:
            List of picture metadata dictionaries
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.put(f"{self.base_url}/api/v1/pictures", 
                                      json={"IDT": self.access_token, "Data": ""}) as resp:
                    resp.raise_for_status()
                    all_pictures = await resp.json()
        except aiohttp.ClientError as e:
            log.warning(f"Failed to get pictures: {e}")
            return []
        
        if num_to_get == -1:
            log.info(f"Found {len(all_pictures)} pictures to download.")
            return all_pictures
        else:
            num_to_download = min(num_to_get, len(all_pictures))
            log.info(f"Found {len(all_pictures)} pictures. Selecting the {num_to_download} most recent.")
            return all_pictures[-num_to_download:][::-1]
    
    async def export_data_zip(self, output_file: str):
        """Download the pre-packaged export data zip file.
        
        Args:
            output_file: Path to save the zip file
            
        Raises:
            FmdApiRequestError: If export fails
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.base_url}/api/v1/exportData", 
                                       json={"IDT": self.access_token, "Data": "unused"}) as resp:
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
            raise FmdApiRequestError(f"Failed to export data: {e}") from e
    
    async def send_command(self, command: str) -> bool:
        """Send a command to the device.
        
        Args:
            command: Command string (use FmdCommands constants)
            
        Returns:
            True if command was sent successfully
            
        Raises:
            FmdApiRequestError: If command sending fails
        """
        log.info(f"Sending command to device: {command}")
        
        # Get current Unix time in milliseconds
        unix_time_ms = int(time.time() * 1000)
        
        # Sign the command using RSA-PSS
        # IMPORTANT: Sign "timestamp:command", not just the command
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
        signature_b64 = encode_base64(signature)
        
        try:
            result = await self._make_api_request(
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
            raise FmdApiRequestError(f"Failed to send command '{command}': {e}") from e
    
    # Convenience methods
    
    async def request_location(self, provider: str = "all") -> bool:
        """Request a new location update from the device.
        
        Args:
            provider: Location provider ("all", "gps", "cell", "last")
            
        Returns:
            True if request was sent successfully
        """
        provider_map = {
            "all": FmdCommands.LOCATE_ALL,
            "gps": FmdCommands.LOCATE_GPS,
            "cell": FmdCommands.LOCATE_CELL,
            "network": FmdCommands.LOCATE_CELL,
            "last": FmdCommands.LOCATE_LAST
        }
        command = provider_map.get(provider.lower(), FmdCommands.LOCATE_ALL)
        log.info(f"Requesting location update with provider: {provider} (command: {command})")
        return await self.send_command(command)
    
    async def take_picture(self, camera: str = "back") -> bool:
        """Request the device to take a picture.
        
        Args:
            camera: Which camera to use ("front" or "back")
            
        Returns:
            True if command was sent successfully
            
        Raises:
            ValueError: If camera is not "front" or "back"
        """
        camera = camera.lower()
        if camera not in ["front", "back"]:
            raise ValueError(f"Invalid camera '{camera}'. Must be 'front' or 'back'")
        
        command = FmdCommands.CAMERA_FRONT if camera == "front" else FmdCommands.CAMERA_BACK
        log.info(f"Requesting picture from {camera} camera")
        return await self.send_command(command)
    
    async def toggle_bluetooth(self, enable: bool) -> bool:
        """Enable or disable Bluetooth on the device.
        
        Args:
            enable: True to enable, False to disable
            
        Returns:
            True if command was sent successfully
        """
        command = FmdCommands.BLUETOOTH_ON if enable else FmdCommands.BLUETOOTH_OFF
        log.info(f"{'Enabling' if enable else 'Disabling'} Bluetooth")
        return await self.send_command(command)
    
    async def toggle_do_not_disturb(self, enable: bool) -> bool:
        """Enable or disable Do Not Disturb mode.
        
        Args:
            enable: True to enable, False to disable
            
        Returns:
            True if command was sent successfully
        """
        command = FmdCommands.NODISTURB_ON if enable else FmdCommands.NODISTURB_OFF
        log.info(f"{'Enabling' if enable else 'Disabling'} Do Not Disturb mode")
        return await self.send_command(command)
    
    async def set_ringer_mode(self, mode: str) -> bool:
        """Set the device ringer mode.
        
        Args:
            mode: Ringer mode ("normal", "vibrate", "silent")
            
        Returns:
            True if command was sent successfully
            
        Raises:
            ValueError: If mode is invalid
        """
        mode = mode.lower()
        mode_map = {
            "normal": FmdCommands.RINGERMODE_NORMAL,
            "vibrate": FmdCommands.RINGERMODE_VIBRATE,
            "silent": FmdCommands.RINGERMODE_SILENT
        }
        
        if mode not in mode_map:
            raise ValueError(f"Invalid ringer mode '{mode}'. Must be 'normal', 'vibrate', or 'silent'")
        
        command = mode_map[mode]
        log.info(f"Setting ringer mode to: {mode}")
        return await self.send_command(command)
    
    async def get_device_stats(self) -> bool:
        """Request device network statistics.
        
        Returns:
            True if command was sent successfully
        """
        log.info("Requesting device network statistics")
        return await self.send_command(FmdCommands.STATS)
