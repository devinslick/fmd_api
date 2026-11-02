"""Unit tests for _request_v2 HTTP error mapping.

Regression tests for the 401 path: a function-local
``from .exceptions import AuthenticationError`` inside the 403 branch made
``AuthenticationError`` a function-scoped local, so the 401 branch raised
``UnboundLocalError`` instead of ``AuthenticationError`` whenever the 403
branch had not executed first (rejected re-logins, 401 with no session).
The local import is gone; the module-level import is the only binding.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock

import pytest
from aioresponses import aioresponses

from fmd_api import FmdClient
from fmd_api.api_v2 import V2Session
from fmd_api.exceptions import AuthenticationError
from fmd_api.protocol_v2 import LongTermKeys

BASE = "https://fmd.example.com"
PING = f"{BASE}/api/v2/ping"

USERNAME = "v2-auth-user"
MASTER_KEY = os.urandom(32)


def _make_v2_client(access_token: str | None = "token-v2") -> FmdClient:
    client = FmdClient(BASE)
    client._fmd_id = USERNAME
    client.protocol_version = 2
    client._v2_session = None
    if access_token is not None:
        client._v2_session = V2Session(
            access_token=access_token,
            long_term_keys=LongTermKeys(USERNAME, MASTER_KEY),
            token_issued_at=0.0,
            auth_key=os.urandom(32),
        )
    return client


def test_401_without_session_raises_authentication_error() -> None:
    """401 with no v2 session raises AuthenticationError, not UnboundLocalError."""
    client = _make_v2_client(access_token=None)
    try:
        with aioresponses() as m:
            m.get(PING, status=401)
            with pytest.raises(AuthenticationError, match="401 Unauthorized"):
                asyncio.run(client._request_v2("GET", "/ping"))
    finally:
        asyncio.run(client.close())


def test_401_relogin_retried_then_401_raises_authentication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 401 that survives re-login raises AuthenticationError on the retry."""
    client = _make_v2_client()
    relogin = AsyncMock()
    monkeypatch.setattr(client, "_relogin_v2", relogin)
    try:
        with aioresponses() as m:
            m.get(PING, status=401)
            m.get(PING, status=401)
            with pytest.raises(AuthenticationError, match="401 Unauthorized"):
                asyncio.run(client._request_v2("GET", "/ping"))
        assert relogin.await_count == 1
    finally:
        asyncio.run(client.close())


def test_401_relogin_success_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401 that re-login fixes is retried once and returns the fresh payload."""

    async def fresh_relogin() -> None:
        assert client._v2_session is not None
        client._v2_session.access_token = "token-fresh"

    client = _make_v2_client()
    monkeypatch.setattr(client, "_relogin_v2", fresh_relogin)
    try:
        with aioresponses() as m:
            m.get(PING, status=401)
            m.get(PING, payload={"ok": 1})
            result = asyncio.run(client._request_v2("GET", "/ping"))
        assert result == {"ok": 1}
        assert client._v2_session is not None
        assert client._v2_session.access_token == "token-fresh"
    finally:
        asyncio.run(client.close())


def test_403_raises_authentication_error() -> None:
    """403 (wrong password) raises AuthenticationError as before."""
    client = _make_v2_client(access_token=None)
    try:
        with aioresponses() as m:
            m.get(PING, status=403)
            with pytest.raises(AuthenticationError, match="Access denied"):
                asyncio.run(client._request_v2("GET", "/ping"))
    finally:
        asyncio.run(client.close())
