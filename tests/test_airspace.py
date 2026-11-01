import math

from toolkit.airspace import (
    EARTH_RADIUS_M,
    Incursion,
    check_incursions,
    load_zones,
    point_in_zone,
)


CIRCLE_ZONE = {
    "name": "Test Circle",
    "type": "circle",
    "category": "test",
    "source_note": "test fixture",
    "center_lat": 40.0,
    "center_lon": -73.0,
    "radius_m": 1000.0,
}

CONVEX_POLYGON_ZONE = {
    "name": "Convex Test Zone",
    "type": "polygon",
    "category": "test",
    "source_note": "test fixture",
    "points": [
        [0.0, 0.0],
        [0.0, 2.0],
        [2.0, 2.0],
        [2.0, 0.0],
    ],
}

# Classic concave "notch cut into the top edge" polygon: (lat, lon) pairs
# tracing bottom-left -> top-left -> notch (pulled inward) -> top-right ->
# bottom-right -> close.
CONCAVE_POLYGON_ZONE = {
    "name": "Concave Test Zone",
    "type": "polygon",
    "category": "test",
    "source_note": "test fixture",
    "points": [
        [0.0, 0.0],
        [4.0, 0.0],
        [2.0, 2.0],
        [4.0, 4.0],
        [0.0, 4.0],
    ],
}


def _ts(point):
    return {"latitude": point[0], "longitude": point[1], "altitude_m": 100, "timestamp_utc": point[2]}


# --- point-in-circle ---

def test_point_in_circle_inside():
    assert point_in_zone(40.001, -73.0, CIRCLE_ZONE) is True


def test_point_in_circle_outside():
    assert point_in_zone(41.0, -73.0, CIRCLE_ZONE) is False


def test_point_in_circle_on_boundary():
    # Move exactly radius_m due north of center — for a pure north-south
    # displacement the haversine formula reduces to an exact angular
    # distance, so this lands (up to float rounding) exactly on radius_m.
    delta_deg = math.degrees(CIRCLE_ZONE["radius_m"] / EARTH_RADIUS_M)
    lat = CIRCLE_ZONE["center_lat"] + delta_deg
    assert point_in_zone(lat, CIRCLE_ZONE["center_lon"], CIRCLE_ZONE) is True


# --- point-in-polygon (ray casting) ---

def test_point_in_polygon_convex_inside():
    assert point_in_zone(1.0, 1.0, CONVEX_POLYGON_ZONE) is True


def test_point_in_polygon_convex_outside():
    assert point_in_zone(3.0, 3.0, CONVEX_POLYGON_ZONE) is False


def test_point_in_polygon_concave_inside_main_body():
    # Well inside the bulk of the shape, below the notch.
    assert point_in_zone(1.0, 2.0, CONCAVE_POLYGON_ZONE) is True


def test_point_in_polygon_concave_notch_excluded():
    # In the region the notch carves out of the top — must be outside.
    assert point_in_zone(3.5, 2.0, CONCAVE_POLYGON_ZONE) is False


def test_point_in_polygon_concave_lobe_inside():
    # Inside the right-hand lobe past the notch.
    assert point_in_zone(3.0, 3.5, CONCAVE_POLYGON_ZONE) is True


# --- check_incursions: coalescing ---

def test_single_crossing_coalesced_into_one_interval():
    path = [
        _ts((39.0, -73.0, "2026-01-01T00:00:00Z")),   # outside
        _ts((40.0, -73.0, "2026-01-01T00:00:01Z")),    # inside (entry)
        _ts((40.001, -73.0, "2026-01-01T00:00:02Z")),  # inside
        _ts((40.002, -73.0, "2026-01-01T00:00:03Z")),  # inside (exit)
        _ts((41.0, -73.0, "2026-01-01T00:00:04Z")),    # outside
    ]
    result = check_incursions(path, [CIRCLE_ZONE])
    assert result == [
        Incursion(
            zone_name="Test Circle",
            entry_ts="2026-01-01T00:00:01Z",
            exit_ts="2026-01-01T00:00:03Z",
            point_count=3,
        )
    ]


def test_two_separate_crossings_with_gap_not_merged():
    path = [
        _ts((40.0, -73.0, "t0")),  # inside (1st interval)
        _ts((41.0, -73.0, "t1")),  # outside (gap)
        _ts((42.0, -73.0, "t2")),  # outside (gap)
        _ts((40.0, -73.0, "t3")),  # inside (2nd interval)
    ]
    result = check_incursions(path, [CIRCLE_ZONE])
    assert result == [
        Incursion(zone_name="Test Circle", entry_ts="t0", exit_ts="t0", point_count=1),
        Incursion(zone_name="Test Circle", entry_ts="t3", exit_ts="t3", point_count=1),
    ]


def test_no_incursions_returns_empty_list():
    path = [
        _ts((10.0, 10.0, "t0")),
        _ts((11.0, 11.0, "t1")),
    ]
    assert check_incursions(path, [CIRCLE_ZONE, CONVEX_POLYGON_ZONE]) == []


def test_incursion_still_open_at_end_of_path_is_flushed():
    path = [
        _ts((39.0, -73.0, "t0")),  # outside
        _ts((40.0, -73.0, "t1")),  # inside (entry, never exits)
    ]
    result = check_incursions(path, [CIRCLE_ZONE])
    assert result == [
        Incursion(zone_name="Test Circle", entry_ts="t1", exit_ts="t1", point_count=1),
    ]


# --- load_zones / bundled dataset ---

def test_load_zones_returns_well_formed_real_dataset():
    zones = load_zones()
    assert len(zones) >= 4

    names = [z["name"] for z in zones]
    assert len(names) == len(set(names))

    has_circle = has_polygon = False
    for zone in zones:
        assert zone["type"] in ("circle", "polygon")
        assert zone.get("source_note")
        assert zone.get("category")
        if zone["type"] == "circle":
            has_circle = True
            assert isinstance(zone["center_lat"], (int, float))
            assert isinstance(zone["center_lon"], (int, float))
            assert zone["radius_m"] > 0
        else:
            has_polygon = True
            assert len(zone["points"]) >= 3

    assert has_circle
    assert has_polygon
