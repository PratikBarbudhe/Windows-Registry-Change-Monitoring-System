"""Hashing helpers for registry integrity checks."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def sha256_hash(content: str) -> str:
    """Generate a SHA-256 hash from a UTF-8 string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def hash_registry_value(path: str, value_name: str, data: Any, reg_type: Any) -> str:
    """Create a stable hash for a single key-value pair."""
    canonical = json.dumps(
        {
            "path": path,
            "value_name": value_name,
            "data": data,
            "type": reg_type,
        },
        sort_keys=True,
        default=str,
    )
    return sha256_hash(canonical)


def add_hashes_to_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Attach per-value hashes to every registry value in a snapshot."""
    hashed_snapshot: Dict[str, Any] = {}

    for path, key_data in snapshot.items():
        cloned = {
            "exists": key_data.get("exists", False),
            "error": key_data.get("error"),
            "values": {},
        }

        for value_name, value_info in key_data.get("values", {}).items():
            value_data = value_info.get("data")
            reg_type = value_info.get("type")
            cloned["values"][value_name] = {
                "data": value_data,
                "type": reg_type,
                "hash": hash_registry_value(path, value_name, value_data, reg_type),
            }

        hashed_snapshot[path] = cloned

    return hashed_snapshot

