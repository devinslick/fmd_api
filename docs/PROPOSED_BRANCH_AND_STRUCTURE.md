```markdown
Branch: feature/v2-device-client

This document proposes the initial branch and repository layout for fmd_api v2
(FmdClient + Device). The branch name above is the suggested feature branch
to create in the repository.

Goals for the branch:
- Add package layout and initial skeleton modules that port the current
  fmd_api.py behavior into a FmdClient class and a Device class while
  preserving the decryption, auth, and command semantics.
- Provide minimal, well-typed skeletons and README + migration doc to guide
  further work and make it easy to add tests incrementally.

Top-level layout (files to add in feature branch)
- fmd_api/
  - __init__.py
  - client.py
  - device.py
  - types.py
  - exceptions.py
  - helpers.py
  - _version.py
  - tests/
    - __init__.py
    - test_client.py
    - test_device.py
- docs/
  - MIGRATE_FROM_V1.md
  - ha_integration.md
- examples/
  - async_example.py
- PROPOSAL.md  # updated proposal (keeps current proposal but with final details)
- pyproject.toml (skeleton)
- tox.ini / .github/workflows/ci.yml (placeholders)

Next steps after branch creation:
1. Implement FmdClient.create() by porting fmd_api.FmdApi.create and its helper methods.
2. Implement decrypt_data_blob unchanged and expose as FmdClient.decrypt_data_blob.
3. Add Device wrappers (take_picture, request_location, get_locations -> get_history/get_location).
4. Add tests that assert parity for authentication and decrypt_data_blob (using recorded values or mocks).
5. Iterate on rate-limiter/cache and add streaming helpers for export_data_zip.

If you'd like, I can now generate the initial skeleton files for this branch (client.py, device.py, types.py, exceptions.py, helpers.py, docs/MIGRATE_FROM_V1.md, examples/async_example.py, PROPOSAL.md). Which files would you like me to create first?
```