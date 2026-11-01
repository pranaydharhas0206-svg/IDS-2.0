"""Restricted-airspace / no-fly-zone incursion detection.

Zone dict schema (see toolkit/data/no_fly_zones.json):
    {
        "name": str,
        "type": "circle" | "polygon",
        "category": str,          # e.g. "airport_atz", "airport_boundary"
        "source_note": str,       # provenance/licensing note
        # type == "circle":
        "center_lat": float,
        "center_lon": float,
        "radius_m": float,
        # type == "polygon":
        "points": [[lat, lon], ...]   # ring of >= 3 vertices, need not be
                                       # explicitly closed (first != last ok)
    }

Flight path entries are dicts shaped {timestamp_utc, latitude, longitude,
altitude_m, ...} matching what toolkit.parsers.* actually populate on
ParserResult.flight_path (see toolkit/geo.py's export helpers, which read
the same "latitude"/"longitude" keys).

v1 scope: horizontal (2D) containment only, no altitude/ceiling handling.
Polygon containment treats lat/lon as a flat 2D plane (fine for the small,
airport-scale footprints bundled here; not geodesically exact for large
polygons). Circle containment uses a haversine great-circle distance from
the center point vs. radius_m, consistent with the style of
toolkit/parsers/ardupilot.py's _haversine_m helper.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

EARTH_RADIUS_M = 6371000.0

_DATA_PATH = Path(__file__).parent / "data" / "no_fly_zones.json"


@dataclass
class Incursion:
    zone_name: str
    entry_ts: str
    exit_ts: str
    point_count: int


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def _point_in_circle(lat: float, lon: float, zone: dict) -> bool:
    dist = _haversine_m(lat, lon, zone["center_lat"], zone["center_lon"])
    # Small epsilon so a point placed mathematically exactly on the
    # boundary (e.g. via the inverse of this same haversine formula) isn't
    # excluded by float round-trip error through degrees/radians/asin.
    return dist <= zone["radius_m"] + 1e-6


def _point_in_polygon(lat: float, lon: float, zone: dict) -> bool:
    """Standard ray-casting point-in-polygon test.

    Treats lat/lon as a flat 2D plane (x=lon, y=lat) — an approximation
    that's fine for the small, local zone footprints this toolkit deals
    with, not a geodesically exact test for large/global polygons.
    """
    points = zone["points"]
    n = len(points)
    inside = False
    x, y = lon, lat
    for i in range(n):
        y1, x1 = points[i][0], points[i][1]
        y2, x2 = points[(i + 1) % n][0], points[(i + 1) % n][1]
        if (y1 > y) != (y2 > y):
            x_intersect = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if x < x_intersect:
                inside = not inside
    return inside


def point_in_zone(lat: float, lon: float, zone: dict) -> bool:
    """True if (lat, lon) falls within the given zone's geometry."""
    zone_type = zone["type"]
    if zone_type == "circle":
        return _point_in_circle(lat, lon, zone)
    if zone_type == "polygon":
        return _point_in_polygon(lat, lon, zone)
    raise ValueError(f"Unknown zone type: {zone_type!r}")


def load_zones() -> list[dict]:
    """Load the bundled no-fly-zone dataset (toolkit/data/no_fly_zones.json)."""
    with open(_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def check_incursions(flight_path: list[dict], zones: list[dict]) -> list[Incursion]:
    """Detect intervals where the flight path is inside a restricted zone.

    Consecutive flight-path points inside the same zone are coalesced into
    a single Incursion (entry_ts = first inside timestamp, exit_ts = last
    inside timestamp before exiting, point_count = number of points in that
    run). If the path exits a zone and later re-enters it, that is a
    separate Incursion — non-contiguous crossings of the same zone are
    never merged.
    """
    incursions: list[Incursion] = []
    open_intervals: dict[str, dict] = {}

    for point in flight_path:
        lat = point["latitude"]
        lon = point["longitude"]
        ts = point["timestamp_utc"]

        zones_here = set()
        for zone in zones:
            if point_in_zone(lat, lon, zone):
                name = zone["name"]
                zones_here.add(name)
                if name in open_intervals:
                    interval = open_intervals[name]
                    interval["exit_ts"] = ts
                    interval["point_count"] += 1
                else:
                    open_intervals[name] = {
                        "entry_ts": ts,
                        "exit_ts": ts,
                        "point_count": 1,
                    }

        for name in list(open_intervals.keys()):
            if name not in zones_here:
                interval = open_intervals.pop(name)
                incursions.append(Incursion(
                    zone_name=name,
                    entry_ts=interval["entry_ts"],
                    exit_ts=interval["exit_ts"],
                    point_count=interval["point_count"],
                ))

    for name, interval in open_intervals.items():
        incursions.append(Incursion(
            zone_name=name,
            entry_ts=interval["entry_ts"],
            exit_ts=interval["exit_ts"],
            point_count=interval["point_count"],
        ))

    return incursions
