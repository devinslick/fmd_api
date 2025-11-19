# MyPy Strict Typing Errors - Baseline Assessment

This document captures the initial mypy errors found during Phase 1 of the strict typing enforcement plan.

Run command: `mypy fmd_api/ --strict --show-error-codes`

Date: November 18, 2025

## Summary
- Total errors: 12
- Files affected: client.py (9 errors), device.py (3 errors)
- Checked files: 7 source files

## Errors by File

### fmd_api/client.py
1. Line 99: Function is missing a type annotation for one or more arguments [no-untyped-def]
2. Line 103: Function is missing a return type annotation [no-untyped-def]
3. Line 202: Returning Any from function declared to return "str" [no-any-return]
4. Line 206: Returning Any from function declared to return "str" [no-any-return]
5. Line 209: Returning Any from function declared to return "str" [no-any-return]
6. Line 372: Function is missing a return type annotation [no-untyped-def]
7. Line 821: Returning Any from function declared to return "float" [no-any-return]

### fmd_api/device.py
1. Line 36: Function is missing a return type annotation [no-untyped-def]
2. Line 55: Function is missing a type annotation for one or more arguments [no-untyped-def]
3. Line 94: Missing type parameters for generic type "dict" [type-arg]
4. Line 124: Missing type parameters for generic type "dict" [type-arg]
5. Line 142: Missing type parameters for generic type "dict" [type-arg]

## Next Steps
These errors will be addressed in Phase 2 (Core Module Typing). Priority order:
1. Add missing type annotations to functions
2. Replace Any returns with proper types
3. Add type parameters to generic types

## Configuration
- Python version: 3.9
- Strict mode: enabled
- Tests excluded: yes (ignore_errors = true)
