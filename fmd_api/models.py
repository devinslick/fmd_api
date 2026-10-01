from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Optional, Dict, Union
from .types import JSONType
import json as _json


def _validate_coordinate(value: object, name: str, limit: float) -> float:
    """Validate and normalize a coordinate value.

    Accepts ints/floats (not bools) that are finite and within +/- limit;
    raises ValueError otherwise. Strings and other non-numeric types are
    rejected so they can never reach downstream distance calculations.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"'{name}' must be a number, got {type(value).__name__}")
    if not math.isfinite(value):
        raise ValueError(f"'{name}' must be finite, got {value!r}")
    if abs(value) > limit:
        raise ValueError(f"'{name}' must be within +/-{limit}, got {value!r}")
    return float(value)


def _optional_float(data: Dict[str, JSONType], key: str) -> Optional[float]:
    """Leniently coerce an optional numeric field; None if absent/invalid."""
    value = data.get(key)
    if value is None:
        return None
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


@dataclass
class Location:
    lat: float
    lon: float
    timestamp: Optional[datetime]
    accuracy_m: Optional[float] = None
    altitude_m: Optional[float] = None
    speed_m_s: Optional[float] = None
    heading_deg: Optional[float] = None
    battery_pct: Optional[int] = None
    provider: Optional[str] = None
    raw: Optional[Dict[str, JSONType]] = None

    @classmethod
    def from_json(cls, json: Union[str, Dict[str, JSONType]]) -> "Location":
        """Construct a Location from a JSON dict or JSON string.

        Expected fields (from server payloads):
        - lat (float, required, finite, within +/-90)
        - lon (float, required, finite, within +/-180)
        - date (int milliseconds since epoch)
        - Optional: accuracy, altitude, speed, heading, bat, provider

        Raises ValueError for invalid JSON, non-object payloads, or
        missing/invalid required fields. Optional numeric fields are
        coerced leniently: unusable values become None instead of
        discarding an otherwise valid fix.
        """
        # Accept either a JSON string or a dict
        if isinstance(json, str):
            try:
                data = _json.loads(json)
            except Exception as e:
                raise ValueError(f"Invalid JSON string for Location: {e}") from e
        elif isinstance(json, dict):
            data = json
        else:
            raise TypeError("Location.from_json expects a dict or JSON string")

        if not isinstance(data, dict):
            raise ValueError(f"Location JSON must be an object, got {type(data).__name__}")

        if "lat" not in data or "lon" not in data:
            raise ValueError("Location JSON must include 'lat' and 'lon'")

        lat = _validate_coordinate(data["lat"], "lat", 90)
        lon = _validate_coordinate(data["lon"], "lon", 180)

        # Convert date (ms since epoch) to aware datetime in UTC if present
        ts = None
        if data.get("date") is not None:
            try:
                ts = datetime.fromtimestamp(float(data["date"]) / 1000.0, tz=timezone.utc)
            except Exception as e:
                raise ValueError(f"Invalid 'date' field for Location: {e}") from e

        battery: Optional[int] = None
        if data.get("bat") is not None:
            try:
                battery = int(float(data["bat"]))
            except (TypeError, ValueError):
                battery = None

        return cls(
            lat=lat,
            lon=lon,
            timestamp=ts,
            accuracy_m=_optional_float(data, "accuracy"),
            altitude_m=_optional_float(data, "altitude"),
            speed_m_s=_optional_float(data, "speed"),
            heading_deg=_optional_float(data, "heading"),
            battery_pct=battery,
            provider=(str(data["provider"]) if data.get("provider") is not None else None),
            raw=data,
        )


@dataclass
class PhotoResult:
    data: bytes
    mime_type: str
    timestamp: datetime
    raw: Optional[Dict[str, JSONType]] = None
