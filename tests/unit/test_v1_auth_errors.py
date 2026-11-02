"""Unit tests for protocol-v1 auth-error mapping and event-loop offloading.

Regression tests for the Copilot-reviewed findings on 3.2.1:

1. A 401 on the token requests (``/api/v1/requestAccess``, ``/api/v1/key``)
   recursively re-entered ``authenticate()`` because the requests kept the
   default ``retry_auth=True``; now they disable re-auth and raise
   ``AuthenticationError``.
2. A 403 (rejected credentials) surfaced as a generic ``FmdApiException``
   (Home Assistant: ``cannot_connect``); now it raises
   ``AuthenticationError`` (``invalid_auth``).
3. RSA private-key load/serialize calls ran synchronously on the event loop
   in ``authenticate``, ``resume``, and ``export_auth_artifacts``; they now
   run in the executor.
"""

from __future__ import annotations

import asyncio

import pytest
from aioresponses import aioresponses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fmd_api import FmdClient
from fmd_api.exceptions import AuthenticationError, FmdApiException

BASE = "https://fmd.example.com"
REQUEST_ACCESS = f"{BASE}/api/v1/requestAccess"
KEY_BLOB = f"{BASE}/api/v1/key"

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _RSA_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)


def _make_client() -> FmdClient:
    client = FmdClient(BASE)
    client._fmd_id = "alice"
    return client


def test_403_on_request_access_raises_authentication_error() -> None:
    """Rejected credentials (403) raise AuthenticationError, not FmdApiException."""
    client = _make_client()
    try:
        with aioresponses() as m:
            m.put(REQUEST_ACCESS, status=403)
            with pytest.raises(AuthenticationError, match="Access denied"):
                asyncio.run(client._get_access_token("alice", "hash", 3600))
    finally:
        asyncio.run(client.close())


def test_401_on_request_access_does_not_recurse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 401 on the token request raises instead of re-entering authenticate()."""
    client = _make_client()
    client._password = "secret"

    async def explode(*args: object) -> None:
        raise AssertionError("authenticate must not be re-entered from a token request")

    monkeypatch.setattr(client, "authenticate", explode)
    try:
        with aioresponses() as m:
            m.put(REQUEST_ACCESS, status=401)
            with pytest.raises(AuthenticationError, match="401"):
                asyncio.run(client._get_access_token("alice", "hash", 3600))
    finally:
        asyncio.run(client.close())


def test_401_on_key_blob_does_not_recurse(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401 on the private-key blob request raises instead of re-authing."""
    client = _make_client()
    client.access_token = "tkn"

    async def explode(*args: object) -> None:
        raise AssertionError("authenticate must not be re-entered from a token request")

    monkeypatch.setattr(client, "authenticate", explode)
    try:
        with aioresponses() as m:
            m.put(KEY_BLOB, status=401)
            with pytest.raises(AuthenticationError, match="401"):
                asyncio.run(client._get_private_key_blob())
    finally:
        asyncio.run(client.close())


def test_401_without_credentials_raises_authentication_error() -> None:
    """401 with no stored password/hash raises AuthenticationError (typed)."""
    client = FmdClient(BASE)
    client.access_token = "old_token"
    client._fmd_id = "alice"
    client._password = None
    client._password_hash = None
    try:
        with aioresponses() as m:
            m.put(f"{BASE}/api/v1/locationDataSize", status=401)
            with pytest.raises(AuthenticationError, match="no credentials"):
                asyncio.run(client.get_locations())
    finally:
        asyncio.run(client.close())


def test_resume_roundtrip_and_export_use_executor() -> None:
    """resume() loads the key and export_auth_artifacts() serializes it.

    Functional coverage for the executor-offloaded paths: PEM in -> key
    loaded -> PEM out, matching the original bytes.
    """
    async def run() -> None:
        client = await FmdClient.resume(BASE, "alice", "tkn", _PEM.decode("utf-8"))
        try:
            assert client.private_key is not None
            artifacts = await client.export_auth_artifacts()
            assert artifacts.get("private_key") == _PEM.decode("utf-8")
        finally:
            await client.close()

    asyncio.run(run())


def test_export_fallback_generates_key_for_test_doubles() -> None:
    """The export fallback (key without private_bytes) still produces PEM."""

    class FakeKey:
        """Stand-in lacking cryptography's private_bytes."""

    async def run() -> None:
        client = await FmdClient.resume(BASE, "alice", "tkn", _PEM.decode("utf-8"))
        client.private_key = FakeKey()  # type: ignore[assignment]
        try:
            artifacts = await client.export_auth_artifacts()
            pem = artifacts.get("private_key")
            assert pem is not None
            assert "BEGIN PRIVATE KEY" in pem
            # The generated key must be a usable RSA key.
            serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        finally:
            await client.close()

    asyncio.run(run())


def test_authentication_error_is_fmd_api_exception() -> None:
    """Callers catching FmdApiException keep working (subclass contract)."""
    assert issubclass(AuthenticationError, FmdApiException)
