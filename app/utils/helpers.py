"""Helper functions for reading and normalizing Windows registry data."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

winreg: Any
try:
    import winreg
except ImportError:  # Non-Windows runtime (e.g., Streamlit Cloud Linux)
    winreg = None

HIVE_MAP = (
    {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }
    if winreg is not None
    else {}
)


def normalize_registry_data(data: Any) -> Any:
    """Convert registry value data into JSON-serializable, stable output."""
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        return [normalize_registry_data(item) for item in data]
    return data


def parse_registry_path(path: str) -> Tuple[Optional[int], str]:
    """Split a registry path into hive constant and sub-key path."""
    if not path or "\\" not in path:
        return None, ""

    hive_name, sub_key = path.split("\\", 1)
    hive = HIVE_MAP.get(hive_name.upper())
    return hive, sub_key


def list_registry_values(path: str) -> Dict[str, Any]:
    """Enumerate all value names/data/types in a registry key with safe errors."""
    if winreg is None:
        return {
            "path": path,
            "exists": False,
            "values": {},
            "error": "Windows registry access is only available on Windows.",
        }

    hive, sub_key = parse_registry_path(path)
    if hive is None:
        return {
            "path": path,
            "exists": False,
            "values": {},
            "error": "Invalid registry hive prefix.",
        }

    result: Dict[str, Any] = {
        "path": path,
        "exists": True,
        "values": {},
        "error": None,
    }

    try:
        with winreg.OpenKey(hive, sub_key, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, index)
                    value_name = name if name else "(Default)"
                    result["values"][value_name] = {
                        "data": normalize_registry_data(data),
                        "type": reg_type,
                    }
                    index += 1
                except OSError:
                    break
    except FileNotFoundError:
        result["exists"] = False
        result["error"] = "Key does not exist."
    except PermissionError:
        result["exists"] = False
        result["error"] = "Access denied."
    except OSError as exc:
        result["exists"] = False
        result["error"] = f"Registry read error: {exc}"

    return result


def flatten_registry_paths(registry_paths: Dict[str, Any]) -> List[str]:
    """Flatten the nested registry path config into one unique ordered list."""
    flattened: List[str] = []

    for item in registry_paths.get("autorun_keys", []):
        if item not in flattened:
            flattened.append(item)

    for group in registry_paths.get("security_keys", {}).values():
        for item in group:
            if item not in flattened:
                flattened.append(item)

    for group in registry_paths.get("system_behavior_keys", {}).values():
        for item in group:
            if item not in flattened:
                flattened.append(item)

    return flattened
