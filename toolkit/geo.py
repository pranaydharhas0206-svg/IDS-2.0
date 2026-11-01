"""Flight-path export to formats viewable in standard GIS tools
(Google Earth, QGIS) for forensic flight-path analysis."""

from __future__ import annotations

import json
from pathlib import Path

import simplekml


def export_kml(flight_path: list[dict], path: Path, name: str = "Flight Path") -> None:
    kml = simplekml.Kml()
    coords = [
        (p["longitude"], p["latitude"], p.get("altitude_m") or 0)
        for p in flight_path
    ]
    if coords:
        line = kml.newlinestring(name=name, coords=coords)
        line.altitudemode = simplekml.AltitudeMode.absolute
        line.extrude = 1
        kml.newpoint(name="Start", coords=[coords[0]])
        kml.newpoint(name="End", coords=[coords[-1]])
    kml.save(str(path))


def export_geojson(flight_path: list[dict], path: Path) -> None:
    coords = [
        [p["longitude"], p["latitude"], p.get("altitude_m") or 0]
        for p in flight_path
    ]
    feature = {
        "type": "Feature",
        "properties": {"point_count": len(coords)},
        "geometry": {"type": "LineString", "coordinates": coords},
    }
    geojson = {"type": "FeatureCollection", "features": [feature]}
    path.write_text(json.dumps(geojson, indent=2), encoding="utf-8")
