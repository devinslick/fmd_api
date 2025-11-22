"""Shared typing helpers used across the fmd_api package.

This module centralizes JSON-like typings and commonly used typed dictionaries so
other modules in the package can import concrete types rather than using
unstructured Any in many places.
"""
from __future__ import annotations

from typing import Dict, List, Union, TypedDict, Optional


# Recursive JSON-ish type used for payloads / returned JSON values
JSONType = Union[Dict[str, "JSONType"], List["JSONType"], str, int, float, bool, None]


class AuthArtifacts(TypedDict, total=False):
    base_url: str
    fmd_id: Optional[str]
    access_token: Optional[str]
    private_key: str
    password_hash: Optional[str]
    session_duration: int
    token_issued_at: Optional[float]


class PictureMetadata(TypedDict, total=False):
    """Common picture metadata fields returned by server endpoints.

    The server returns varying shapes; this TypedDict captures common fields.
    Fields are optional because older/newer server versions may differ.
    """
    id: int
    date: int
    filename: str
    size: int
    index: int
