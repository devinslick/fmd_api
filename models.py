from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

@dataclass
class Location:
    lat: float
    lon: float
    timestamp: datetime
    accuracy_m: Optional[float] = None
    altitude_m: Optional[float] = None
    speed_m_s: Optional[float] = None
    heading_deg: Optional[float] = None
    battery_pct: Optional[int] = None
    provider: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None

@dataclass
class PhotoResult:
    data: bytes
    mime_type: str
    timestamp: datetime
    raw: Optional[Dict[str, Any]] = None