"""FMD API client implementation.

This module provides the FmdClient class, which handles authentication,
encryption/decryption, and communication with the FMD server.

This is a port of the original fmd_api.FmdApi class with improved structure
and error handling.
"""

import base64
import json
import logging
import time
from typing import Optional, List, Dict, Any

import aiohttp
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import (
    AuthenticationError,
    DecryptionError,
    ApiRequestError,
    CommandError
)
from .helpers import pad_base64, decode_base64, encode_base64

# --- Constants ---
CONTEXT_STRING_LOGIN = "context:loginAuthentication"
CONTEXT_STRING_ASYM_KEY_WRAP = "context:asymmetricKeyWrap"
ARGON2_SALT_LENGTH = 16
AES_GCM_IV_SIZE_BYTES = 12
RSA_KEY_SIZE_BYTES = 384  # 3072 bits / 8

log = logging.getLogger(__name__)


class FmdCommands:
    """Constants for available FMD device commands.
    
    These commands are supported by the FMD Android app and can be sent
    via the send_command() method.
    """
    # Location requests
    LOCATE_ALL = "locate"
    LOCATE_GPS = "locate gps"
    LOCATE_CELL = "locate cell"
    LOCATE_LAST = "locate last"
    
    # Device control
    RING = "ring"
    LOCK = "lock"
    DELETE = "delete"  # Wipes device data (destructive!)
    
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
    STATS = "stats"  # Network info (IP addresses, WiFi networks)
    GPS = "gps"      # Battery and GPS status


class FmdClient:
    """Client for interacting with the FMD server API.
    
    This class handles authentication, key management, encryption/decryption,
    and all API operations for communicating with an FMD server.
    
    Example:
        # Create and authenticate client
        client = await FmdClient.create(
            'https://fmd.example.com',
            'device-id',
            'password'
        )
        
        # Get locations
        location_blobs = await client.get_locations(num=10)
        
        # Decrypt location data
        decrypted = client.decrypt_data_blob(location_blobs[0])
        location = json.loads(decrypted)
        
        # Send command
        await client.send_command('ring')
    """
    
    def __init__(self, base_url: str, session_duration: int = 3600):
        """Initialize FmdClient.
        
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
    async def create(
        cls,
        base_url: str,
        fmd_id: str,
        password: str,
        session_duration: int = 3600
    ) -> 'FmdClient':
        """Create and authenticate an FmdClient instance.
        
        Args:
            base_url: Base URL of the FMD server
            fmd_id: Device ID for authentication
            password: Device password
            session_duration: Session duration in seconds (default: 3600)
            
        Returns:
            Authenticated FmdClient instance
            
        Raises:
            AuthenticationError: If authentication fails
        """
        instance = cls(base_url, session_duration)
        instance._fmd_id = fmd_id
        instance._password = password
        await instance.authenticate(fmd_id, password, session_duration)
        return instance
    
    async def authenticate(self, fmd_id: str, password: str, session_duration: int):
        """Perform full authentication and key retrieval workflow.
        
        Args:
            fmd_id: Device ID for authentication
            password: Device password
            session_duration: Session duration in seconds
            
        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            log.info("[1] Requesting salt...")
            salt = await self._get_salt(fmd_id)
            
            log.info("[2] Hashing password with salt...")
            password_hash = self._hash_password(password, salt)
            
            log.info("[3] Requesting access token...")
            self.fmd_id = fmd_id
            self.access_token = await self._get_access_token(fmd_id, password_hash, session_duration)
            
            log.info("[3a] Retrieving encrypted private key...")
            privkey_blob = await self._get_private_key_blob()
            
            log.info("[3b] Decrypting private key...")
            privkey_bytes = self._decrypt_private_key_blob(privkey_blob, password)
            self.private_key = self._load_private_key_from_bytes(privkey_bytes)
            
            log.info("Authentication successful")
        except Exception as e:
            log.error(f"Authentication failed: {e}")
            raise AuthenticationError(f"Authentication failed: {e}") from e
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password using Argon2id.
        
        Args:
            password: Plain text password
            salt: Base64-encoded salt from server
            
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
        """Retrieve salt from server.
        
        Args:
            fmd_id: Device ID
            
        Returns:
            Base64-encoded salt
        """
        return await self._make_api_request("PUT", "/api/v1/salt", {"IDT": fmd_id, "Data": ""})
    
    async def _get_access_token(self, fmd_id: str, password_hash: str, session_duration: int) -> str:
        """Request access token from server.
        
        Args:
            fmd_id: Device ID
            password_hash: Hashed password
            session_duration: Session duration in seconds
            
        Returns:
            Access token
        """
        payload = {
            "IDT": fmd_id,
            "Data": password_hash,
            "SessionDurationSeconds": session_duration
        }
        return await self._make_api_request("PUT", "/api/v1/requestAccess", payload)
    
    async def _get_private_key_blob(self) -> str:
        """Retrieve encrypted private key from server.
        
        Returns:
            Base64-encoded encrypted private key blob
        """
        return await self._make_api_request(
            "PUT",
            "/api/v1/key",
            {"IDT": self.access_token, "Data": "unused"}
        )
    
    def _decrypt_private_key_blob(self, key_b64: str, password: str) -> bytes:
        """Decrypt private key blob using password.
        
        Args:
            key_b64: Base64-encoded encrypted private key
            password: User's password
            
        Returns:
            Decrypted private key bytes
        """
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
    
    def _load_private_key_from_bytes(self, privkey_bytes: bytes):
        """Load RSA private key from bytes.
        
        Args:
            privkey_bytes: Private key bytes (PEM or DER format)
            
        Returns:
            RSA private key object
        """
        try:
            return serialization.load_pem_private_key(privkey_bytes, password=None)
        except ValueError:
            return serialization.load_der_private_key(privkey_bytes, password=None)
    
    def decrypt_data_blob(self, data_b64: str) -> bytes:
        """Decrypt a data blob using RSA-OAEP + AES-GCM.
        
        Args:
            data_b64: Base64-encoded encrypted blob from server
            
        Returns:
            Decrypted data as bytes
            
        Raises:
            DecryptionError: If decryption fails or blob is invalid
        """
        try:
            blob = decode_base64(data_b64)
            
            # Check if blob is large enough
            min_size = RSA_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES
            if len(blob) < min_size:
                raise DecryptionError(
                    f"Blob too small for decryption: {len(blob)} bytes "
                    f"(expected at least {min_size} bytes)"
                )
            
            # Extract components
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
            
        except Exception as e:
            log.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt data blob: {e}") from e
    
    async def _make_api_request(
        self,
        method: str,
        endpoint: str,
        payload: Dict[str, Any],
        stream: bool = False,
        expect_json: bool = True,
        retry_auth: bool = True
    ) -> Any:
        """Make an API request to the FMD server.
        
        Args:
            method: HTTP method (GET, PUT, POST, etc.)
            endpoint: API endpoint path
            payload: Request payload
            stream: If True, return response object for streaming
            expect_json: If True, parse response as JSON
            retry_auth: If True, retry once with re-authentication on 401
            
        Returns:
            Response data (parsed or raw depending on parameters)
            
        Raises:
            ApiRequestError: If request fails
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
                        return await self._make_api_request(
                            method, endpoint, payload, stream, expect_json, retry_auth=False
                        )
                    
                    resp.raise_for_status()
                    
                    # Log response details
                    log.debug(
                        f"{endpoint} response - status: {resp.status}, "
                        f"content-type: {resp.content_type}, "
                        f"content-length: {resp.content_length}"
                    )
                    
                    if stream:
                        return resp
                    
                    if expect_json:
                        try:
                            # Force JSON parsing regardless of Content-Type header
                            json_data = await resp.json(content_type=None)
                            log.debug(f"{endpoint} JSON response: {json_data}")
                            return json_data["Data"]
                        except (KeyError, ValueError, json.JSONDecodeError) as e:
                            # Fall back to text if JSON parsing fails
                            log.debug(f"{endpoint} JSON parsing failed ({e}), trying as text")
                            text_data = await resp.text()
                            if not text_data:
                                log.warning(f"{endpoint} returned EMPTY response body")
                            return text_data
                    else:
                        text_data = await resp.text()
                        log.debug(f"{endpoint} text response length: {len(text_data)}")
                        return text_data
                        
        except aiohttp.ClientError as e:
            log.error(f"API request failed for {endpoint}: {e}")
            raise ApiRequestError(f"API request failed for {endpoint}: {e}") from e
        except (KeyError, ValueError) as e:
            log.error(f"Failed to parse server response for {endpoint}: {e}")
            raise ApiRequestError(f"Failed to parse server response for {endpoint}: {e}") from e
    
    async def get_locations(
        self,
        num: int = -1,
        skip_empty: bool = True,
        max_attempts: int = 10
    ) -> List[str]:
        """Fetch location blobs from the server.
        
        Args:
            num: Number of locations to get (-1 for all)
            skip_empty: If True, skip empty blobs and search backwards
            max_attempts: Maximum indices to try when skip_empty is True
            
        Returns:
            List of base64-encoded encrypted location blobs
        """
        log.debug(f"Getting locations, num={num}, skip_empty={skip_empty}")
        
        # Get total number of locations
        size_str = await self._make_api_request(
            "PUT",
            "/api/v1/locationDataSize",
            {"IDT": self.access_token, "Data": "unused"}
        )
        size = int(size_str)
        log.debug(f"Server reports {size} locations available")
        
        if size == 0:
            log.info("No locations found")
            return []
        
        locations = []
        
        if num == -1:  # Download all
            log.info(f"Downloading all {size} locations")
            for i in range(size):
                blob = await self._make_api_request(
                    "PUT",
                    "/api/v1/location",
                    {"IDT": self.access_token, "Data": str(i)}
                )
                locations.append(blob)
            return locations
        
        # Download N most recent
        num_to_download = min(num, size)
        log.info(f"Downloading {num_to_download} most recent locations")
        start_index = size - 1
        
        if skip_empty:
            # Try indices one at a time starting from most recent
            indices = range(start_index, max(0, start_index - max_attempts), -1)
        else:
            end_index = size - num_to_download
            indices = range(start_index, end_index - 1, -1)
        
        for i in indices:
            blob = await self._make_api_request(
                "PUT",
                "/api/v1/location",
                {"IDT": self.access_token, "Data": str(i)}
            )
            
            if blob and blob.strip():
                locations.append(blob)
                if len(locations) >= num and num != -1:
                    break
            else:
                log.warning(f"Empty blob at index {i}")
        
        return locations
    
    async def get_pictures(self, num: int = -1) -> List[Dict[str, Any]]:
        """Fetch picture data from the server.
        
        Args:
            num: Number of pictures to get (-1 for all)
            
        Returns:
            List of picture data dictionaries
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    f"{self.base_url}/api/v1/pictures",
                    json={"IDT": self.access_token, "Data": ""}
                ) as resp:
                    resp.raise_for_status()
                    all_pictures = await resp.json()
        except aiohttp.ClientError as e:
            log.warning(f"Failed to get pictures: {e}")
            return []
        
        if num == -1:
            log.info(f"Found {len(all_pictures)} pictures")
            return all_pictures
        
        num_to_download = min(num, len(all_pictures))
        log.info(f"Selecting {num_to_download} most recent pictures")
        return all_pictures[-num_to_download:][::-1]
    
    async def export_data_zip(self, output_file: str):
        """Download pre-packaged export data zip file.
        
        Args:
            output_file: Path to save the zip file
            
        Raises:
            ApiRequestError: If export fails
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/v1/exportData",
                    json={"IDT": self.access_token, "Data": "unused"}
                ) as resp:
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
            raise ApiRequestError(f"Failed to export data: {e}") from e
    
    async def send_command(self, command: str) -> bool:
        """Send a command to the device.
        
        Args:
            command: Command string to send (see FmdCommands for constants)
            
        Returns:
            True if command was sent successfully
            
        Raises:
            CommandError: If command sending fails
        """
        log.info(f"Sending command: {command}")
        
        try:
            # Get current Unix time in milliseconds
            unix_time_ms = int(time.time() * 1000)
            
            # Sign the command using RSA-PSS
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
            raise CommandError(f"Failed to send command '{command}': {e}") from e
    
    # --- Convenience Methods ---
    
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
        return await self.send_command(command)
    
    async def play_sound(self) -> bool:
        """Make the device ring at full volume.
        
        Returns:
            True if command was sent successfully
        """
        return await self.send_command(FmdCommands.RING)
    
    async def lock_device(self) -> bool:
        """Lock the device screen.
        
        Returns:
            True if command was sent successfully
        """
        return await self.send_command(FmdCommands.LOCK)
    
    async def wipe_device(self) -> bool:
        """Wipe all device data (factory reset).
        
        WARNING: This is destructive and cannot be undone!
        
        Returns:
            True if command was sent successfully
        """
        log.warning("Sending WIPE command - this will erase all device data!")
        return await self.send_command(FmdCommands.DELETE)
    
    async def take_picture(self, camera: str = "back") -> bool:
        """Request the device to take a picture.
        
        Args:
            camera: Camera to use ("front" or "back")
            
        Returns:
            True if command was sent successfully
            
        Raises:
            ValueError: If camera is not "front" or "back"
        """
        camera = camera.lower()
        if camera not in ["front", "back"]:
            raise ValueError(f"Invalid camera '{camera}'. Must be 'front' or 'back'")
        
        command = FmdCommands.CAMERA_FRONT if camera == "front" else FmdCommands.CAMERA_BACK
        return await self.send_command(command)
    
    async def toggle_bluetooth(self, enable: bool) -> bool:
        """Enable or disable Bluetooth.
        
        Args:
            enable: True to enable, False to disable
            
        Returns:
            True if command was sent successfully
        """
        command = FmdCommands.BLUETOOTH_ON if enable else FmdCommands.BLUETOOTH_OFF
        return await self.send_command(command)
    
    async def toggle_do_not_disturb(self, enable: bool) -> bool:
        """Enable or disable Do Not Disturb mode.
        
        Args:
            enable: True to enable, False to disable
            
        Returns:
            True if command was sent successfully
        """
        command = FmdCommands.NODISTURB_ON if enable else FmdCommands.NODISTURB_OFF
        return await self.send_command(command)
    
    async def set_ringer_mode(self, mode: str) -> bool:
        """Set device ringer mode.
        
        Args:
            mode: Ringer mode ("normal", "vibrate", or "silent")
            
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
            raise ValueError(
                f"Invalid ringer mode '{mode}'. Must be 'normal', 'vibrate', or 'silent'"
            )
        
        return await self.send_command(mode_map[mode])
    
    async def get_device_stats(self) -> bool:
        """Request device network statistics.
        
        Returns:
            True if command was sent successfully
        """
        return await self.send_command(FmdCommands.STATS)
