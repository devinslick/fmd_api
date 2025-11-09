import time
import pytest
from fmd_api.client import FmdClient


@pytest.mark.asyncio
async def test_create_with_drop_password(monkeypatch):
    # Stub authenticate to avoid network & crypto
    async def fake_auth(self, fmd_id, password, session_duration):
        self._fmd_id = fmd_id
        self._password = password
        self.access_token = "tok123"
        # Simulate resulting password_hash + token time
        self._password_hash = "$argon2id$v=19$m=131072,t=1,p=4$dummy$hash"
        self._token_issued_at = time.time()

        # Provide dummy private_key with required interface for later operations
        class DummyKey:
            def decrypt(self, packet, padding_obj):
                return b"0" * 32

            def sign(self, msg, pad, algo):
                return b"sig"

        self.private_key = DummyKey()

    monkeypatch.setattr(FmdClient, "authenticate", fake_auth)

    client = await FmdClient.create("https://fmd.example.com", "alice", "secret", drop_password=True)
    try:
        # Raw password should be purged; hash retained for reauth
        assert client._password is None
        assert client._password_hash is not None
        assert client.access_token == "tok123"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_create_without_drop_password(monkeypatch):
    async def fake_auth(self, fmd_id, password, session_duration):
        self._fmd_id = fmd_id
        self._password = password
        self.access_token = "tokABC"
        self._password_hash = "$argon2id$v=19$m=131072,t=1,p=4$dummy$hash"
        self._token_issued_at = time.time()

        class DummyKey:
            def decrypt(self, packet, padding_obj):
                return b"0" * 32

        self.private_key = DummyKey()

    monkeypatch.setattr(FmdClient, "authenticate", fake_auth)

    client = await FmdClient.create("https://fmd.example.com", "bob", "hunter2", drop_password=False)
    try:
        assert client._password == "hunter2"
        assert client._password_hash is not None
        assert client.access_token == "tokABC"
    finally:
        await client.close()
