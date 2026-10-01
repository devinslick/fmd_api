import json
import math
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


# --- Coordinate validation (3.1.0) ---


def test_location_from_json_rejects_non_numeric_coordinates() -> None:
    """String/None coordinates raise ValueError instead of flowing downstream."""
    with pytest.raises(ValueError):
        Location.from_json({"provider": "gps", "lat": "bad", "lon": "bad"})
    with pytest.raises(ValueError):
        Location.from_json({"provider": "gps", "lat": None, "lon": None})


def test_location_from_json_rejects_out_of_range_coordinates() -> None:
    with pytest.raises(ValueError):
        Location.from_json({"lat": 91, "lon": 0})
    with pytest.raises(ValueError):
        Location.from_json({"lat": 0, "lon": -181})


def test_location_from_json_rejects_non_finite_coordinates() -> None:
    with pytest.raises(ValueError):
        Location.from_json({"lat": float("inf"), "lon": 0})
    with pytest.raises(ValueError):
        Location.from_json({"lat": 0, "lon": math.nan})


def test_location_from_json_rejects_bool_coordinates() -> None:
    with pytest.raises(ValueError):
        Location.from_json({"lat": True, "lon": False})


def test_location_from_json_rejects_non_object_payload() -> None:
    with pytest.raises(ValueError):
        Location.from_json("[1, 2, 3]")
    with pytest.raises(ValueError):
        Location.from_json('"a string"')


def test_location_from_json_lenient_optional_fields() -> None:
    """Unusable optional values become None without discarding the fix."""
    loc = Location.from_json(
        {
            "lat": 1.0,
            "lon": 2.0,
            "accuracy": "garbage",
            "altitude": math.nan,
            "speed": "fast",
            "heading": None,
            "bat": "not-a-number",
            "provider": 7,
        }
    )
    assert loc.lat == 1.0
    assert loc.lon == 2.0
    assert loc.accuracy_m is None
    assert loc.altitude_m is None
    testspeed = loc.speed_m_s
    assert testspeed is None
    assert loc.heading_deg is None
    assert loc.battery_pct is None
    assert loc.provider == "7"


def test_location_from_json_accepts_integer_coordinates() -> None:
    loc = Location.from_json({"lat": 41, "lon": -87})
    assert loc.lat == 41.0
    assert loc.lon == -87.0


# --- Accuracy sign validation (3.1.1) ---


def test_location_accuracy_rejects_negative_and_non_finite() -> None:
    """Accuracy is a radius: negatives/inf/NaN become None."""
    for bad in (-1, -0.1, math.inf, -math.inf, math.nan):
        loc = Location.from_json({"lat": 1.0, "lon": 2.0, "accuracy": bad})
        assert loc.accuracy_m is None, bad
    loc = Location.from_json({"lat": 1.0, "lon": 2.0, "accuracy": 0})
    assert loc.accuracy_m == 0.0


def test_location_altitude_allows_negative() -> None:
    """Altitude below sea level is legitimate and must survive."""
    loc = Location.from_json({"lat": 1.0, "lon": 2.0, "altitude": -430.5})
    assert loc.altitude_m == -430.5


def test_location_speed_and_heading_still_lenient() -> None:
    """Only finite check applies to speed/heading (signed/>360 kept)."""
    loc = Location.from_json(
        {"lat": 1.0, "lon": 2.0, "speed": -3.0, "heading": 400.0}
    )
    assert loc.speed_m_s == -3.0
    assert loc.heading_deg == 400.0
