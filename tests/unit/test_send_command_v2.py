"""Unit tests for protocol-v2 command sending (send_command v2 branch).

Regression tests for the v2 command channel: protocol-v2 accounts have no
RSA keypair, so send_command must upload the command as an encrypted data
item (POST /api/v2/data/command) instead of RSA-PSS signing /api/v1/command.
"""

from __future__ import annotations

import asyncio
import base64
import os

import pytest

from fmd_api import FmdClient
from fmd_api.api_v2 import ApiV2Error, V2Session
from fmd_api.protocol_v2 import LongTermKeys, TYPE_COMMAND
from fmd_api.exceptions import FmdApiException

USERNAME = "cmd-user"
MASTER_KEY = os.urandom(32)


def _make_v2_client() -> FmdClient:
    """Build a client with a protocol-v2 session (no RSA private key)."""
    client = FmdClient("https://fmd.example.com")
    client._fmd_id = USERNAME
    client.protocol_version = 2
    client.access_token = "token-v2"
    client._v2_session = V2Session(
        access_token="token-v2",
        long_term_keys=LongTermKeys(USERNAME, MASTER_KEY),
        token_issued_at=0.0,
        auth_key=os.urandom(32),
    )
    return client


def test_send_command_v2_uploads_encrypted_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """v2 send_command encrypts with the command KEK and posts to /data/command."""
    client = _make_v2_client()
    captured: dict[str, object] = {}

    async def fake_post_data_items(data_type: str, raw_items: list[bytes]) -> None:
        captured["data_type"] = data_type
        captured["raw_items"] = raw_items

    monkeypatch.setattr(client, "post_data_items", fake_post_data_items)

    try:
        assert asyncio.run(client.send_command("ring")) is True
    finally:
        asyncio.run(client.close())

    assert captured["data_type"] == TYPE_COMMAND
    raw_items = captured["raw_items"]
    assert isinstance(raw_items, list) and len(raw_items) == 1
    assert raw_items[0] == b"ring"


def test_send_command_v2_ciphertext_uses_command_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The posted ciphertext decrypts with the command-type KEK, not the location KEK."""
    client = _make_v2_client()
    envelopes: list[tuple[bytes, int, bytes]] = []

    async def fake_post_data_items(data_type: str, raw_items: list[bytes]) -> None:
        for raw in raw_items:
            item_id, unix_millis, ciphertext = client._v2_session.long_term_keys.encrypt_data_blob(
                raw, data_type
            )
            envelopes.append((item_id, unix_millis, ciphertext))

    monkeypatch.setattr(client, "post_data_items", fake_post_data_items)

    try:
        assert asyncio.run(client.send_command("locate gps")) is True
    finally:
        asyncio.run(client.close())

    item_id, unix_millis, ciphertext = envelopes[0]
    decrypted = client._v2_session.long_term_keys.decrypt_data_blob(
        item_id, unix_millis, TYPE_COMMAND, ciphertext
    )
    assert decrypted == b"locate gps"


def test_send_command_v2_wraps_api_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ApiV2Error from the transport is re-raised as FmdApiException."""
    client = _make_v2_client()

    async def fake_post_data_items(data_type: str, raw_items: list[bytes]) -> None:
        raise ApiV2Error("HTTP 500: boom")

    monkeypatch.setattr(client, "post_data_items", fake_post_data_items)

    try:
        with pytest.raises(FmdApiException, match="Failed to send command 'ring'"):
            asyncio.run(client.send_command("ring"))
    finally:
        asyncio.run(client.close())


def test_send_command_v1_without_private_key_message_mentions_v2() -> None:
    """v1 path with no private key still fails, with a message pointing at v2."""
    client = FmdClient("https://fmd.example.com")
    client.access_token = "token"
    try:
        with pytest.raises(FmdApiException, match="Private key not loaded"):
            asyncio.run(client.send_command("ring"))
    finally:
        asyncio.run(client.close())


def test_export_artifacts_v2_roundtrip_preserves_command_capability() -> None:
    """Artifacts exported from a v2 session resume into a client able to send commands."""
    client = _make_v2_client()
    artifacts = asyncio.run(client.export_auth_artifacts())
    asyncio.run(client.close())
    assert artifacts["protocol_version"] == 2
    assert artifacts["master_key"] == base64.b64encode(MASTER_KEY).decode("ascii")
