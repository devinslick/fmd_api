# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- HTTP URLs (`http://`) are now permitted; HTTPS is strongly recommended but no longer enforced. Use HTTP only on trusted local networks or for development.

## [2.0.8] - 2025-02-01

### Added
- `decrypt_data_blob_async()` method for non-blocking decryption in async contexts
- Exported `Location`, `PhotoResult`, and `RateLimitError` from package root
- `CHANGELOG.md` following Keep a Changelog format
- Comprehensive exception documentation (Raises sections) for all public API methods

### Changed
- Improved lock message sanitization to re-collapse whitespace after removing special characters
- Simplified `get_history()` signature by removing unused `start`/`end` parameters
- Improved docstrings for helpers.py functions

### Removed
- Dead code: `_parse_location_blob()` function that was never called
- Placeholder comment from helpers.py

### Fixed
- Lock messages containing only special characters now correctly fall back to plain "lock" command

## [2.0.7] - 2025-01-15

### Changed
- Cleanup release to trigger new PyPI deployment
- No functional changes from 2.0.6

## [2.0.6] - 2025-01-10

### Added
- 100% test coverage achieved

### Changed
- Full type safety with strict mypy checks
- Improved method signatures with precise return types

## [2.0.5] - 2025-01-08

### Added
- Strict typing enforcement (Phase 1)
- Comprehensive edge case tests for `Location` parsing
- `docs/strict_typing_enforcement_plan.md` roadmap

### Changed
- Updated community instance URL to https://server.fmd-foss.org/

## [2.0.4] - 2024-11-09

### Added
- Password-free authentication via `export_auth_artifacts()` and `from_auth_artifacts()`
- `drop_password=True` option to discard raw password after onboarding
- `Device.get_picture_blobs()` and `Device.decode_picture()` methods
- `Device.lock(message=...)` with sanitization (quotes, backticks, semicolons removed)
- Wipe PIN validation (alphanumeric ASCII only, no spaces)
- PNG detection via magic bytes in `export_data_zip()`

### Changed
- 401 handling now supports hash-based token refresh
- Private key loading supports both PEM and DER formats
- Test coverage increased to ~98%

### Deprecated
- `Device.take_front_photo()` - use `take_front_picture()`
- `Device.take_rear_photo()` - use `take_rear_picture()`
- `Device.fetch_pictures()` - use `get_picture_blobs()`
- `Device.download_photo()` - use `decode_picture()`

## [2.0.0] - 2024-10-01

### Added
- Async client with `FmdClient.create()` factory method
- Async context manager support (`async with`)
- HTTPS enforcement (plain HTTP rejected)
- Configurable SSL validation (`ssl=False` for dev, custom `SSLContext` for production)
- Request timeouts on all HTTP calls
- Retry logic with exponential backoff and jitter for 5xx errors
- 429 rate-limit handling with Retry-After support
- Client-side ZIP export (locations + pictures)
- `Device` helper class for convenience actions
- `py.typed` marker for PEP 561 compliance
- GitHub Actions CI (lint, type-check, tests, coverage)
- Codecov integration with badges

### Changed
- Complete rewrite from sync to async API
- Python 3.8+ required (3.7 dropped)

### Removed
- Legacy synchronous `FmdApi` class

### Security
- Sanitized logging (no sensitive payloads exposed)
- Token masking in debug output

## [1.x] - Legacy

Previous synchronous implementation. See git history for details.

[Unreleased]: https://github.com/devinslick/fmd_api/compare/v2.0.8...HEAD
[2.0.8]: https://github.com/devinslick/fmd_api/compare/v2.0.7...v2.0.8
[2.0.7]: https://github.com/devinslick/fmd_api/compare/v2.0.6...v2.0.7
[2.0.6]: https://github.com/devinslick/fmd_api/compare/v2.0.5...v2.0.6
[2.0.5]: https://github.com/devinslick/fmd_api/compare/v2.0.4...v2.0.5
[2.0.4]: https://github.com/devinslick/fmd_api/compare/v2.0.0...v2.0.4
[2.0.0]: https://github.com/devinslick/fmd_api/releases/tag/v2.0.0
