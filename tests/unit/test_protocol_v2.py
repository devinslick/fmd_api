"""Round-trip tests for fmd_api.protocol_v2 against the fmd-android wire format."""

from __future__ import annotations

import base64
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fmd_api.protocol_v2 import (
    CTX_DATA,
    CTX_DEK,
    AES_GCM_IV_SIZE,
    LongTermKeys,
    derive_password_key,
    decrypt_master_key,
)

USERNAME = "test-user"
PASSWORD = "correct horse battery staple"
SALT = os.urandom(16)
MASTER_KEY = os.urandom(32)



def test_password_key_derivation_deterministic() -> None:
    k1 = derive_password_key(USERNAME, PASSWORD, SALT)
    k2 = derive_password_key(USERNAME, PASSWORD, SALT)
    assert k1 == k2
    assert k1[0] != k1[1]  # K_auth != K_pmk
    assert len(k1[0]) == 32 and len(k1[1]) == 32


def test_password_key_different_salt() -> None:
    k1 = derive_password_key(USERNAME, PASSWORD, SALT)
    k2 = derive_password_key(USERNAME, PASSWORD, os.urandom(16))
    assert k1 != k2


def test_master_key_roundtrip() -> None:
    import hashlib

    ad = b"fmd_v2_master" + hashlib.sha256(USERNAME.encode()).digest()
    _, k_pmk = derive_password_key(USERNAME, PASSWORD, SALT)
    iv = os.urandom(12)
    enc = iv + AESGCM(k_pmk).encrypt(iv, MASTER_KEY, ad)
    assert decrypt_master_key(USERNAME, k_pmk, enc) == MASTER_KEY


def test_data_blob_roundtrip_against_android_format() -> None:
    ltk = LongTermKeys(USERNAME, MASTER_KEY)
    plaintext = b'{"lat": 32.83, "lon": -96.96, "provider": "gps"}'

    # reference encrypt (android format)
    import hashlib

    item_id = os.urandom(16)
    unix_millis = 1790600000000
    user_hash = hashlib.sha256(USERNAME.encode()).digest()
    ad_suffix = (
        b"location" + user_hash + item_id + struct.pack(">q", unix_millis)
    )
    dek = os.urandom(32)
    iv1 = os.urandom(12)
    iv2 = os.urandom(12)
    enc_dek = iv1 + AESGCM(ltk.location_key).encrypt(iv1, dek, CTX_DEK + ad_suffix)
    enc_data = iv2 + AESGCM(dek).encrypt(iv2, plaintext, CTX_DATA + ad_suffix)
    ciphertext = enc_dek + enc_data

    # our decrypt
    out = ltk.decrypt_data_blob(item_id, unix_millis, "location", ciphertext)
    assert out == plaintext


def test_data_blob_wrong_type_fails() -> None:
    ltk = LongTermKeys(USERNAME, MASTER_KEY)
    plaintext = b"x"
    import hashlib

    item_id = os.urandom(16)
    unix_millis = 1790600000000
    user_hash = hashlib.sha256(USERNAME.encode()).digest()
    ad_suffix = b"picture" + user_hash + item_id + struct.pack(">q", unix_millis)
    dek = os.urandom(32)
    iv1 = os.urandom(12)
    iv2 = os.urandom(12)
    enc_dek = iv1 + AESGCM(ltk.picture_key).encrypt(iv1, dek, CTX_DEK + ad_suffix)
    enc_data = iv2 + AESGCM(dek).encrypt(iv2, plaintext, CTX_DATA + ad_suffix)

    from fmd_api.protocol_v2 import ProtocolError

    import pytest

    with pytest.raises(ProtocolError):
        ltk.decrypt_data_blob(item_id, unix_millis, "location", enc_dek + enc_data)
