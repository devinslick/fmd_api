"""API v2 / Protocol v2 client plumbing for FmdClient.

Negotiates the protocol version via the v2 salt endpoint (falling back to
API v1 for older servers), performs protocol-v2 login (Argon2id +
HKDF-derived K_auth, master-key unwrap), and fetches encrypted data
envelopes from GET /api/v2/data/{type}.

The public surface mirrors the v1 behaviour so callers (the Home
Assistant integration) do not change shape.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Optional

from .exceptions import AuthenticationError, FmdApiException
from .protocol_v2 import (
    LongTermKeys,
    ProtocolError,
    TYPE_LOCATION,
    derive_password_key,
    decrypt_master_key,
    encrypt_master_key,
    generate_master_key,
)

V2_BASE: Final = "/api/v2"

_PROTO_VERSION_FIELD: Final = "protoVersion"
_SALT_FIELD: Final = "salt64"
_ACCESS_TOKEN_FIELD: Final = "accessToken"
_ENC_MASTER_KEY_FIELD: Final = "encMasterKey64"


class ApiV2Error(FmdApiException):
    """Raised for API v2 transport/response errors."""


@dataclass(frozen=True)
class EncryptedItem:
    """One encrypted data envelope as returned by GET /data/{type}."""

    item_id: bytes  # 16 raw bytes (hex on the wire)
    unix_millis: int
    ciphertext: bytes  # [iv|dek|tag][iv|data|tag]


@dataclass
class V2Session:
    """State of an authenticated protocol-v2 session."""

    access_token: str
    long_term_keys: LongTermKeys
    token_issued_at: float
    auth_key: Optional[bytes] = None  # K_auth; enables re-login on 401


def _pad_b64(s: str) -> str:
    """Fix unpadded base64 from the server."""
    return s + "=" * (-len(s) % 4)


class ApiV2Mixin:
    """Protocol-v2 methods mixed into FmdClient.

    The host class (FmdClient) provides the attributes declared here;
    they are annotated so type checkers accept the mixin.
    """

    if TYPE_CHECKING:
        base_url: str
        session_duration: int
        _fmd_id: Optional[str]
        _session: Optional[Any]

        def _ensure_session(self) -> Any: ...

    # populated by FmdClient.__init__
    protocol_version: int = 1
    _v2_session: Optional[V2Session] = None

    async def negotiate_protocol(self, fmd_id: str) -> int:
        """Ask the server which protocol version the account uses.

        Uses the unauthenticated v2 salt endpoint; a server that does not
        expose it (pre-0.17.0) means protocol v1.
        """
        try:
            resp = await self._request_v2("GET", f"/account/{fmd_id}/salt")
        except ApiV2Error:
            self.protocol_version = 1
            return 1
        proto = int(resp.get(_PROTO_VERSION_FIELD, 1))
        self.protocol_version = proto
        return proto

    async def login_v2(
        self, fmd_id: str, password: str, session_duration: int
    ) -> None:
        """Perform protocol-v2 login and establish the session keys."""
        salt_resp = await self._request_v2("GET", f"/account/{fmd_id}/salt")
        salt = base64.b64decode(_pad_b64(salt_resp[_SALT_FIELD]))
        loop = asyncio.get_running_loop()
        k_auth, k_pmk = await loop.run_in_executor(
            None, lambda: derive_password_key(fmd_id, password, salt)
        )

        resp = await self._request_v2(
            "POST",
            "/account/login",
            {
                "username": fmd_id,
                "passwordHash64": base64.b64encode(k_auth).decode("ascii"),
                "sessionDurationSeconds": session_duration,
            },
        )
        access_token = resp[_ACCESS_TOKEN_FIELD]
        enc_master_key = resp.get(_ENC_MASTER_KEY_FIELD, "")
        if not enc_master_key:
            # Protocol-v1 account on a v2-capable server
            raise ApiV2Error(
                "Account uses protocol v1 (no encMasterKey64); use the v1 path"
            )
        master_key = decrypt_master_key(
            fmd_id, k_pmk, base64.b64decode(_pad_b64(enc_master_key))
        )
        self.protocol_version = 2
        self.access_token = access_token
        self._fmd_id = fmd_id
        self._v2_session = V2Session(
            access_token=access_token,
            long_term_keys=LongTermKeys(fmd_id, master_key),
            token_issued_at=time.time(),
            auth_key=k_auth,
        )

    async def _relogin_v2(self) -> None:
        """Re-login with the stored K_auth after a 401 (token expiry)."""
        if self._v2_session is None or self._v2_session.auth_key is None:
            raise AuthenticationError(
                "Access token expired and no v2 auth key stored for re-login"
            )
        resp = await self._request_v2(
            "POST",
            "/account/login",
            {
                "username": self._fmd_id,
                "passwordHash64": base64.b64encode(
                    self._v2_session.auth_key
                ).decode("ascii"),
                "sessionDurationSeconds": self.session_duration,
            },
            _relogin=False,
        )
        self.access_token = resp[_ACCESS_TOKEN_FIELD]
        self._v2_session.access_token = self.access_token
        self._v2_session.token_issued_at = time.time()

    async def register_v2(
        self,
        fmd_id: str,
        password: str,
        session_duration: int = 3600,
        registration_token: str = "",
    ) -> str:
        """Register a new protocol-v2 account and log in.

        The client picks the salt, derives K_auth/K_pmk, generates the
        master key and uploads encMasterKey64. Returns the access token.
        """
        import base64 as _b64
        import os as _os

        salt = _os.urandom(16)
        loop = asyncio.get_running_loop()
        k_auth, k_pmk = await loop.run_in_executor(
            None, lambda: derive_password_key(fmd_id, password, salt)
        )
        master_key = generate_master_key()
        enc_master_key = encrypt_master_key(fmd_id, k_pmk, master_key)

        resp = await self._request_v2(
            "POST",
            "/account/register",
            {
                "username": fmd_id,
                "salt64": _b64.b64encode(salt).decode("ascii"),
                "passwordHash64": _b64.b64encode(k_auth).decode("ascii"),
                "protoVersion": 2,
                "encMasterKey64": _b64.b64encode(enc_master_key).decode("ascii"),
                "registrationToken": registration_token,
            },
        )
        access_token = str(resp[_ACCESS_TOKEN_FIELD])
        self.protocol_version = 2
        self.access_token = access_token
        self._fmd_id = fmd_id
        self._v2_session = V2Session(
            access_token=access_token,
            long_term_keys=LongTermKeys(fmd_id, master_key),
            token_issued_at=time.time(),
            auth_key=k_auth,
        )
        return access_token

    async def post_data_items(
        self, data_type: str, raw_items: list[bytes]
    ) -> None:
        """Upload encrypted data items (testing/migration helper)."""
        import base64 as _b64

        if self._v2_session is None:
            msg = "Not logged in with protocol v2"
            raise ApiV2Error(msg)
        items = []
        for raw in raw_items:
            item_id, unix_millis, ciphertext = (
                self._v2_session.long_term_keys.encrypt_data_blob(raw, data_type)
            )
            items.append(
                {
                    "clientItemIdHex": item_id.hex(),
                    "unixMillis": unix_millis,
                    "ciphertext64": _b64.b64encode(ciphertext).decode("ascii"),
                }
            )
        await self._request_v2("POST", f"/data/{data_type}", {"items": items})

    async def get_data_items(self, data_type: str) -> list[EncryptedItem]:
        """Fetch all encrypted items of a data type (locations, pictures...)."""
        if self._v2_session is None:
            msg = "Not logged in with protocol v2"
            raise ApiV2Error(msg)
        resp = await self._request_v2("GET", f"/data/{data_type}")
        items: list[EncryptedItem] = []
        for raw in resp.get("items", []):
            items.append(
                EncryptedItem(
                    item_id=bytes.fromhex(raw["clientItemIdHex"]),
                    unix_millis=int(raw["unixMillis"]),
                    ciphertext=base64.b64decode(_pad_b64(raw["ciphertext64"])),
                )
            )
        # Most recent first (matches the v1 client's newest-first behaviour)
        items.sort(key=lambda i: i.unix_millis, reverse=True)
        return items

    def decrypt_item(self, data_type: str, item: EncryptedItem) -> bytes:
        """Decrypt one data item with the session's long-term keys."""
        if self._v2_session is None:
            msg = "Not logged in with protocol v2"
            raise ApiV2Error(msg)
        try:
            return self._v2_session.long_term_keys.decrypt_data_blob(
                item.item_id, item.unix_millis, data_type, item.ciphertext
            )
        except ProtocolError as exc:
            raise ApiV2Error(str(exc)) from exc

    async def _get_locations_v2(self, num_to_get: int) -> list[str]:
        """v2 branch of get_locations: return base64 ciphertext envelopes.

        Encodes each EncryptedItem back to a transport string so the
        v1-shaped public surface (List[str] blobs) is preserved; the
        decrypt side recognises v2 envelopes via decrypt_data_blob.
        """
        import base64 as _b64

        items = await self.get_data_items(TYPE_LOCATION)
        if num_to_get != -1:
            items = items[:num_to_get]
        return [
            i.item_id.hex() + ":" + str(i.unix_millis) + ":" + _b64.b64encode(i.ciphertext).decode("ascii")
            for i in items
        ]

    def _decode_v2_blob(self, blob: str) -> tuple[bytes, int] | None:
        """Parse an id:ts:ciphertext envelope produced by _get_locations_v2."""
        parts = blob.split(":", 2)
        if len(parts) != 3 or len(parts[0]) != 32:
            return None
        try:
            return bytes.fromhex(parts[0]), int(parts[1])
        except ValueError:
            return None

    async def _request_v2(
        self, method: str, path: str, body: Any = None, _relogin: bool = True
    ) -> Any:
        """JSON request against /api/v2 with bearer auth when logged in."""
        import aiohttp

        url = self.base_url + V2_BASE + path
        await self._ensure_session()
        session = self._session
        assert session is not None
        headers = {}
        if self._v2_session is not None:
            headers["Authorization"] = f"Bearer {self._v2_session.access_token}"
        try:
            async with session.request(
                method, url, json=body, headers=headers
            ) as resp:
                if resp.status == 401:
                    if _relogin and self._v2_session is not None:
                        await self._relogin_v2()
                        return await self._request_v2(
                            method, path, body, _relogin=False
                        )
                    raise AuthenticationError("401 Unauthorized (v2)")
                if resp.status == 403:
                    from .exceptions import AuthenticationError

                    raise AuthenticationError("Access denied (403)")
                if resp.status == 404:
                    raise ApiV2Error("404 Not Found")
                if resp.status >= 400:
                    text = await resp.text()
                    raise ApiV2Error(f"HTTP {resp.status}: {text[:200]}")
                if resp.status == 200:
                    body = await resp.read()
                    if not body:
                        return None
                    try:
                        return json.loads(body)
                    except ValueError:
                        return body.decode("utf-8", errors="replace")
                return None
        except aiohttp.ClientError as exc:
            raise ApiV2Error(f"Request failed: {exc}") from exc
