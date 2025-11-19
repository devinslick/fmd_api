import json
from datetime import timezone
from typing import Dict, Any

import pytest

from fmd_api.models import Location


def test_location_from_json_dict_basic() -> None:
    data: Dict[str, Any] = {
        "lat": 10.5,
        "lon": 20.25,
        "date": 1600000000000,  # ms since epoch
        "accuracy": 5.0,
        "altitude": 100.0,
        "speed": 1.5,
        "heading": 180.0,
        "bat": 75,
        "provider": "gps",
    }
    loc = Location.from_json(data)
    assert loc.lat == 10.5
    assert loc.lon == 20.25
    assert loc.timestamp is not None
    assert loc.timestamp.tzinfo == timezone.utc
    assert loc.accuracy_m == 5.0
    assert loc.altitude_m == 100.0
    assert loc.speed_m_s == 1.5
    assert loc.heading_deg == 180.0
    assert loc.battery_pct == 75
    assert loc.provider == "gps"
    assert loc.raw == data


def test_location_from_json_string_basic() -> None:
    payload: Dict[str, Any] = {
        "lat": 1.0,
        "lon": 2.0,
        "date": 1600000000000,
    }
    loc = Location.from_json(json.dumps(payload))
    assert loc.lat == 1.0
    assert loc.lon == 2.0
    assert loc.timestamp is not None
    assert loc.timestamp.tzinfo == timezone.utc


def test_location_from_json_missing_optional_fields() -> None:
    payload: Dict[str, Any] = {"lat": 0.0, "lon": 0.0, "date": 1600000000000}
    loc = Location.from_json(payload)
    assert loc.accuracy_m is None
    assert loc.altitude_m is None
    assert loc.speed_m_s is None
    assert loc.heading_deg is None
    assert loc.battery_pct is None
    assert loc.provider is None


def test_location_from_json_no_date() -> None:
    payload: Dict[str, Any] = {"lat": 1.0, "lon": 2.0}
    loc = Location.from_json(payload)
    assert loc.lat == 1.0
    assert loc.lon == 2.0
    assert loc.timestamp is None


def test_location_from_json_invalid_inputs() -> None:
    with pytest.raises(TypeError):
        Location.from_json(123)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        Location.from_json("not json")

    with pytest.raises(ValueError):
        Location.from_json({"lat": 1.0})  # missing lon

    with pytest.raises(ValueError):
        Location.from_json({"lat": 1.0, "lon": 2.0, "date": "abc"})
