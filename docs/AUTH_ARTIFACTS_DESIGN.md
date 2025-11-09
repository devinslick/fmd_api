# Authentication Artifacts Design (Password-Free Runtime)

This document proposes and specifies an artifact-based authentication flow for `fmd_api` that avoids storing the raw user password in long-running integrations (e.g., Home Assistant), while preserving the ability to decrypt data and reauthenticate when tokens expire.

## Goals

- Do not retain the user's raw password in memory/storage after onboarding.
- Support seamless reauthentication (401 → new token) without prompting the user again.
- Keep the local RSA private key as a long-lived client secret to avoid re-fetching/decrypting each session.
- Provide clear import/export and resume flows for integrations.

## Terms

- `fmd_id`: The FMD identity (username-like identifier).
- `password_hash`: The full Argon2id string expected by the server when calling `/api/v1/requestAccess` (includes salt and parameters).
- `access_token`: The current session token used in API requests; expires after the requested duration.
- `private_key`: The RSA private key used to decrypt location/picture blobs and sign commands. Long-lived, stored client-side.
- `session_duration`: Seconds requested when creating tokens (client default: 3600).
- `token_issued_at`: Local timestamp to optionally preempt expiry.

## Overview

Two operating modes:

1. Password mode (existing): Onboard with raw password; derive `password_hash`, request `access_token`, download and decrypt `private_key`. After success, the client may optionally discard the raw password.
2. Artifact mode (new): Resume using stored artifacts (no raw password). On 401 Unauthorized, the client uses `password_hash` to request a fresh `access_token`. The `private_key` is already local.

## API Additions

### Constructor/Factory

- `@classmethod async def resume(cls, base_url: str, fmd_id: str, access_token: str, private_key_bytes: bytes | str, *, password_hash: str | None = None, session_duration: int = 3600, **opts) -> FmdClient`
  - Loads the provided private key (PEM/DER) and sets runtime fields.
  - If a 401 occurs and `password_hash` is provided, requests a new token with `/api/v1/requestAccess`.
  - If `password_hash` is not provided, 401 bubbles as an error (caller can re-onboard or supply a callback).

- `@classmethod async def from_auth_artifacts(cls, artifacts: dict, **opts) -> FmdClient`
  - Convenience around `resume()`. Expects keys: `base_url`, `fmd_id`, `access_token`, `private_key` (PEM or base64 DER), optional `password_hash`, `session_duration`.

- `async def export_auth_artifacts(self) -> dict`
  - Returns a serializable dict containing: `base_url`, `fmd_id`, `access_token`, `private_key` (PEM), `password_hash` (if available), `session_duration`, `token_issued_at`.

- `async def drop_password(self) -> None`
  - Immediately discards any stored raw password. Recommended once artifacts have been persisted by the caller.

- `@classmethod async def create(..., drop_password: bool = False)`
  - After successful onboarding, if `drop_password=True`, clears the in-memory `_password` attribute.

### Internal Helpers

- `async def _reauth_with_hash(self) -> None`
  - Calls `/api/v1/requestAccess` with stored `password_hash` and `session_duration`. Updates `access_token` on success.

- `_make_api_request` changes
  - On 401: if `_password` is present, behave as today (reauth using raw password).
  - Otherwise, if `password_hash` is present, call `_reauth_with_hash()` once and retry.
  - Else: raise.

## Data Handling

- `private_key` must be loadable from PEM or DER. `export_auth_artifacts()` will prefer PEM for portability.
- `password_hash` is an online-equivalent secret for token requests. It is preferable to raw password, but should still be stored carefully (consider HA secrets storage if available).
- No raw password is stored or exported by default.

## Failure Modes

- User changes password or server salt/params: stored `password_hash` becomes invalid. Reauth fails; caller should prompt the user once, produce a new `password_hash`, and update artifacts.
- Server caps or rejects long `session_duration`: token would expire earlier than requested; client handles 401 via reauth.
- Private key rotation: if the server issues a new private key (unlikely in normal flow), onboarding should refresh artifacts.

## Example Flows

### Onboarding (password mode)

```python
client = await FmdClient.create(base_url, fmd_id, password, session_duration=3600)
artifacts = await client.export_auth_artifacts()
await client.drop_password()  # optional hardening
# Persist artifacts in HA storage
```

### Resume (artifact mode)

```python
client = await FmdClient.from_auth_artifacts(artifacts)
# Use client normally; on 401 it will reauth using password_hash if present
```

## Backward Compatibility

- Existing behavior is preserved.
- New APIs are additive.
- Deprecation of retaining raw `_password` by default is not proposed; instead provide `drop_password=True` knob and a `drop_password()` method.

## Security Considerations

- Storing `password_hash` is strictly better than storing the raw password, but still sensitive.
- If the host supports keyrings or encrypted secret storage, prefer it for both `password_hash` and `private_key`.
- Consider file permissions and in-memory zeroization when feasible.

## Open Questions

- Should `drop_password=True` become the default in a future major version?
- Should we provide a pluggable secret provider interface for HA to implement platform-specific secure storage?
