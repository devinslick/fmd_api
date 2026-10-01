"""API v2 / Protocol v2 client plumbing for FmdClient.

Negotiates the protocol version via the v2 salt endpoint (falling back to
API v1 for older servers), performs protocol-v2 login (Argon2id +
HKDF-derived K_auth, master-key unwrap), and fetches encrypted data
envelopes from GET /api/v2/data/{type}.

The public surface mirrors the v1 behaviour so callers (the Home
Assistant integration) do not change shape.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any, Final, Optional

from .protocol_v2 import (
    LongTermKeys,
    ProtocolError,
    TYPE_LOCATION,
    derive_password_key,
    decrypt_master_key,
)

V2_BASE: Final = "/api/v2"

_PROTO_VERSION_FIELD: Final = "protoVersion"
_SALT_FIELD: Final = "salt64"
_ACCESS_TOKEN_FIELD: Final = "accessToken"
_ENC_MASTER_KEY_FIELD: Final = "encMasterKey64"


class ApiV2Error(Exception):
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


def _pad_b64(s: str) -> str:
    """Fix unpadded base64 from the server."""
    return s + "=" * (-len(s) % 4)


class ApiV2Mixin:
    """Protocol-v2 methods mixed into FmdClient.

    The host class must provide ``_make_api_request_v2`` (simple JSON
    request helper with bearer auth) plus the v1 helpers it falls back
    to. Kept as a mixin so the diff against the v1 client stays small.
    """

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
        k_auth, k_pmk = derive_password_key(fmd_id, password, salt)

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
        )

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

    async def _request_v2(self, method: str, path: str, body: Any = None) -> Any:
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
                    raise ApiV2Error("401 Unauthorized")
                if resp.status == 403:
                    from .exceptions import AuthenticationError

                    raise AuthenticationError("Access denied (403)")
                if resp.status == 404:
                    raise ApiV2Error("404 Not Found")
                if resp.status >= 400:
                    text = await resp.text()
                    raise ApiV2Error(f"HTTP {resp.status}: {text[:200]}")
                if resp.status == 200:
                    return await resp.json()
                return None
        except aiohttp.ClientError as exc:
            raise ApiV2Error(f"Request failed: {exc}") from exc
