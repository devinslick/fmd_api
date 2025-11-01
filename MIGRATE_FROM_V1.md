```markdown
# Migrating from fmd_api v1 (module style) to v2 (FmdClient + Device)

This short guide shows common v1 usages (from fmd_api.py) and how to perform the
equivalent actions using the new FmdClient and Device classes.

Authenticate
v1:
```python
api = await FmdApi.create("https://fmd.example.com", "alice", "secret")