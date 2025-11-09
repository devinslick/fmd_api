from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union
import json as _json


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
    raw: Optional[Dict[str, Any]] = None

    @classmethod
    def from_json(cls, json: Union[str, Dict[str, Any]]) -> "Location":
        """Construct a Location from a JSON dict or JSON string.

        Expected fields (from server payloads):
        - lat (float)
        - lon (float)
        - date (int milliseconds since epoch)
        - Optional: accuracy, altitude, speed, heading, bat, provider
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

        if "lat" not in data or "lon" not in data:
            raise ValueError("Location JSON must include 'lat' and 'lon'")

        # Convert date (ms since epoch) to aware datetime in UTC if present
        ts = None
        if data.get("date") is not None:
            try:
                ts = datetime.fromtimestamp(float(data["date"]) / 1000.0, tz=timezone.utc)
            except Exception as e:
                raise ValueError(f"Invalid 'date' field for Location: {e}") from e

        return cls(
            lat=float(data["lat"]),
            lon=float(data["lon"]),
            timestamp=ts,
            accuracy_m=(float(data["accuracy"]) if data.get("accuracy") is not None else None),
            altitude_m=(float(data["altitude"]) if data.get("altitude") is not None else None),
            speed_m_s=(float(data["speed"]) if data.get("speed") is not None else None),
            heading_deg=(float(data["heading"]) if data.get("heading") is not None else None),
            battery_pct=(int(data["bat"]) if data.get("bat") is not None else None),
            provider=(str(data["provider"]) if data.get("provider") is not None else None),
            raw=data,
        )


@dataclass
class PhotoResult:
    data: bytes
    mime_type: str
    timestamp: datetime
    raw: Optional[Dict[str, Any]] = None
