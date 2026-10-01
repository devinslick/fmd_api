"""FMD Server Protocol v2 cryptography.

Implements the key schedule and data-envelope format specified in
https://gitlab.com/fmd-foss/server-protocol (main.tex), mirroring the
reference implementation in fmd-android (CryptoV2.kt, LongTermKeys.kt,
CypherUtils.java).

All AES-GCM calls use 256-bit keys, 96-bit IVs and 128-bit tags.
Wire format of an encrypted data item's ciphertext::

    encrypted_dek = iv(12) || ct(key=32) || tag(16)   # AES-GCM under K_tau
    encrypted_data = iv(12) || ct(data) || tag(16)     # AES-GCM under DEK
    ciphertext64 = base64( encrypted_dek || encrypted_data )

Associated-data context strings bind every operation to the username,
data type, per-item 128-bit id and the Unix-millisecond timestamp,
exactly as in the protocol spec ("Context strings" section).
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from typing import Final

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Context strings (protocol v2) -----------------------------------------
CTX_PASSWORD: Final = b"fmd_v2_password"
CTX_AUTH: Final = b"fmd_v2_auth"
CTX_PREMASTER: Final = b"fmd_v2_premaster"
CTX_MASTER: Final = b"fmd_v2_master"

# KEK contexts, one per data type
CTX_KEK_COMMAND: Final = b"fmd_v2_kek_command"
CTX_KEK_LOCATION: Final = b"fmd_v2_kek_location"
CTX_KEK_PICTURE: Final = b"fmd_v2_kek_picture"

# Data envelope contexts; suffixed with the data-type label
CTX_DEK: Final = b"fmd_v2_dek_"
CTX_DATA: Final = b"fmd_v2_data_"

# --- Sizes (bytes) ----------------------------------------------------------
AES_GCM_IV_SIZE: Final = 12
AES_GCM_KEY_SIZE: Final = 32
AES_GCM_TAG_SIZE: Final = 16
CLIENT_ITEM_ID_SIZE: Final = 16  # 128-bit id chosen by the client

# Argon2id parameters (protocol spec table "Argon2id parameters for
# client-side hashing")
ARGON2_TIME_COST: Final = 1
ARGON2_PARALLELISM: Final = 4
ARGON2_MEMORY_KIB: Final = 131072  # 2**17 KiB = 128 MiB
ARGON2_HASH_LENGTH: Final = 32

# Data-type labels
TYPE_LOCATION: Final = "location"
TYPE_PICTURE: Final = "picture"
TYPE_COMMAND: Final = "command"

_KEK_CONTEXTS: Final[dict[str, bytes]] = {
    TYPE_LOCATION: CTX_KEK_LOCATION,
    TYPE_PICTURE: CTX_KEK_PICTURE,
    TYPE_COMMAND: CTX_KEK_COMMAND,
}


class ProtocolError(Exception):
    """Raised when a protocol-v2 operation fails (bad ciphertext, AD)."""


def _hash_username(username: str) -> bytes:
    """SHA-256 of the UTF-8 username, as required for context binding."""
    return hashlib.sha256(username.encode("utf-8")).digest()


def hkdf_derive(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 extract-and-expand (salt is empty per the spec)."""
    # Expand-only would also be spec-conformant (salt empty => PRK = HMAC
    # of ikm), but full extract+expand matches the reference implementation
    # (BouncyCastle HKDFBytesGenerator with HKDFParameters(ikm, null, info)).
    import cryptography.hazmat.primitives.hashes as _hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=_hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


def derive_password_key(
    username: str, password: str, salt: bytes
) -> tuple[bytes, bytes]:
    """Derive (K_auth, K_pmk) from the passphrase.

    K_pwk = Argon2id("fmd_v2_password" || SHA256(U) || P, salt)
    K_auth = HKDF(K_pwk, info="fmd_v2_auth" || SHA256(U))
    K_pmk  = HKDF(K_pwk, info="fmd_v2_premaster" || SHA256(U))
    """
    pwk = hash_secret_raw(
        secret=CTX_PASSWORD + _hash_username(username) + password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        parallelism=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_KIB,
        hash_len=ARGON2_HASH_LENGTH,
        type=Type.ID,
    )
    user_hash = _hash_username(username)
    k_auth = hkdf_derive(pwk, CTX_AUTH + user_hash)
    k_pmk = hkdf_derive(pwk, CTX_PREMASTER + user_hash)
    return k_auth, k_pmk


def decrypt_master_key(
    username: str, pre_master_key: bytes, encrypted_master_key: bytes
) -> bytes:
    """Decrypt the account master key (login's encMasterKey64 payload).

    The server returns ``encMasterKey64`` = base64( iv || ct || tag )
    encrypted under K_pmk with AD = "fmd_v2_master" || SHA256(U).
    """
    blob = encrypted_master_key
    ad = CTX_MASTER + _hash_username(username)
    try:
        return AESGCM(pre_master_key).decrypt(blob[:AES_GCM_IV_SIZE], blob[AES_GCM_IV_SIZE:], ad)
    except Exception as exc:  # noqa: BLE001
        msg = "Failed to decrypt account master key"
        raise ProtocolError(msg) from exc


def generate_master_key() -> bytes:
    """Generate a fresh 256-bit account master key (registration)."""
    return os.urandom(AES_GCM_KEY_SIZE)


def encrypt_master_key(
    username: str, pre_master_key: bytes, master_key: bytes
) -> bytes:
    """Encrypt the master key under K_pmk (registration/passphrase rotation).

    Returns iv || ct || tag, the payload for encMasterKey64.
    """
    ad = CTX_MASTER + _hash_username(username)
    iv = os.urandom(AES_GCM_IV_SIZE)
    return iv + AESGCM(pre_master_key).encrypt(iv, master_key, ad)


def derive_kek(master_key: bytes, username: str, data_type: str) -> bytes:
    """Derive the per-type key-encryption key K_tau."""
    context = _KEK_CONTEXTS.get(data_type)
    if context is None:
        msg = f"Unknown data type: {data_type!r}"
        raise ProtocolError(msg)
    return hkdf_derive(master_key, context + _hash_username(username))


class LongTermKeys:
    """Per-type KEKs derived from the account master key."""

    def __init__(self, username: str, master_key: bytes) -> None:
        """Initialize keys for a user."""
        self.username = username
        self.master_key = master_key
        self.location_key = derive_kek(master_key, username, TYPE_LOCATION)
        self.picture_key = derive_kek(master_key, username, TYPE_PICTURE)
        self.command_key = derive_kek(master_key, username, TYPE_COMMAND)

    def _kek(self, data_type: str) -> bytes:
        return {
            TYPE_LOCATION: self.location_key,
            TYPE_PICTURE: self.picture_key,
            TYPE_COMMAND: self.command_key,
        }[data_type]

    def encrypt_data_blob(self, raw: bytes, data_type: str) -> tuple[bytes, int, bytes]:
        """Encrypt one data item; returns (item_id, unix_millis, ciphertext).

        Mirror of decrypt_data_blob: fresh 128-bit item id, fresh DEK,
        AES-GCM twice (DEK under the type KEK, data under the DEK) with
        the same context-bound ADs.
        """
        item_id = os.urandom(CLIENT_ITEM_ID_SIZE)
        unix_millis = int(time.time() * 1000)
        ad_suffix = (
            data_type.encode("utf-8")
            + _hash_username(self.username)
            + item_id
            + struct.pack(">q", unix_millis)
        )
        dek = os.urandom(AES_GCM_KEY_SIZE)
        iv_dek = os.urandom(AES_GCM_IV_SIZE)
        iv_data = os.urandom(AES_GCM_IV_SIZE)
        encrypted_dek = iv_dek + AESGCM(self._kek(data_type)).encrypt(
            iv_dek, dek, CTX_DEK + ad_suffix
        )
        encrypted_data = iv_data + AESGCM(dek).encrypt(
            iv_data, raw, CTX_DATA + ad_suffix
        )
        return item_id, unix_millis, encrypted_dek + encrypted_data

    def decrypt_data_blob(
        self, item_id: bytes, unix_millis: int, data_type: str, ciphertext: bytes
    ) -> bytes:
        """Decrypt one EncryptedItem ciphertext (see module docstring).

        Does NOT validate the timestamp or item id (mirrors the Android
        reference behaviour); callers apply command freshness rules.
        """
        dek_end = AES_GCM_IV_SIZE + AES_GCM_KEY_SIZE + AES_GCM_TAG_SIZE
        if len(ciphertext) <= dek_end:
            msg = "Ciphertext too short for protocol v2 envelope"
            raise ProtocolError(msg)
        encrypted_dek = ciphertext[:dek_end]
        encrypted_data = ciphertext[dek_end:]

        ad_suffix = (
            data_type.encode("utf-8")
            + _hash_username(self.username)
            + item_id
            + struct.pack(">q", unix_millis)
        )
        try:
            dek = AESGCM(self._kek(data_type)).decrypt(
                encrypted_dek[:AES_GCM_IV_SIZE],
                encrypted_dek[AES_GCM_IV_SIZE:],
                CTX_DEK + ad_suffix,
            )
            return AESGCM(dek).decrypt(
                encrypted_data[:AES_GCM_IV_SIZE],
                encrypted_data[AES_GCM_IV_SIZE:],
                CTX_DATA + ad_suffix,
            )
        except Exception as exc:  # noqa: BLE001
            msg = "Failed to decrypt protocol v2 data blob"
            raise ProtocolError(msg) from exc
