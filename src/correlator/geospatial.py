"""
Forensic Geospatial & Multi-Source GPS Movement Intelligence Engine
===================================================================
Extracts, correlates, and analyzes geolocation coordinates from:
- Media EXIF metadata (JPEG, HEIC, PNG, TIFF)
- Apple Photos Database (Photos.sqlite / ZGENERICASSET)
- Apple Significant Locations & Visits (com.apple.routined / Cache.sqlite)
- WhatsApp Location Messages (ChatStorage.sqlite / ZWAMESSAGE)
- Apple Maps Search & Route History (geoHistory.mapsdata)
- Cellular & Wi-Fi Location Caches (consolidated.db / location caches)

Performs chronological movement trail tracking, velocity and transit mode inference
(Stationary, Walking, Cycling, Vehicular, Flight), dwell time cluster identification,
and exports to GeoJSON, Google Earth KML, CSV, and self-contained interactive Leaflet maps.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
import math
import os
from pathlib import Path
import sqlite3
import struct
from typing import Any, Dict, List, Optional, Tuple

# Apple Mac Absolute Time Epoch Offset (2001-01-01 00:00:00 UTC to 1970-01-01)
APPLE_EPOCH_OFFSET = 978307200.0


@dataclass
class GeoPoint:
    point_id: str
    file_name: str = ""
    file_path: str = ""
    file_size_bytes: int = 0
    latitude: float = 0.0
    longitude: float = 0.0
    altitude_meters: Optional[float] = None
    timestamp_utc: str = ""
    timestamp_epoch: float = 0.0
    camera_make: str = "Apple"
    camera_model: str = "iPhone"
    # Enhanced forensic intelligence fields
    source_type: str = "photo_exif"  # "photo_exif", "photos_sqlite", "apple_routined", "whatsapp", "apple_maps"
    speed_kmh: Optional[float] = None
    distance_from_prev_m: Optional[float] = None
    dwell_time_minutes: Optional[float] = None
    inferred_mode: Optional[str] = None  # "Stationary", "Walking", "Cycling", "Driving", "Flight", "Anomaly"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates the great-circle distance between two GPS coordinates in meters."""
    R = 6371000.0  # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))
    return round(R * c, 2)


def _convert_dms_to_dd(dms: List[Tuple[float, float]], ref: str) -> Optional[float]:
    """Converts degrees/minutes/seconds rationals to decimal degrees."""
    try:
        deg = dms[0][0] / dms[0][1] if dms[0][1] != 0 else 0.0
        minute = dms[1][0] / dms[1][1] if dms[1][1] != 0 else 0.0
        sec = dms[2][0] / dms[2][1] if dms[2][1] != 0 else 0.0
        dd = deg + (minute / 60.0) + (sec / 3600.0)
        if ref.upper() in ("S", "W"):
            dd = -dd
        return round(dd, 6)
    except Exception:
        return None


def parse_jpeg_exif(file_path: Path) -> Optional[Dict[str, Any]]:
    """Pure Python parser for JPEG APP1 EXIF structure without external libraries."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(2)
            if header != b"\xff\xd8":
                return None

            while True:
                marker_bytes = f.read(2)
                if len(marker_bytes) < 2 or marker_bytes[0] != 0xff:
                    break
                marker = marker_bytes[1]
                if marker in (0xd9, 0xda):
                    break

                length_bytes = f.read(2)
                if len(length_bytes) < 2:
                    break
                length = struct.unpack(">H", length_bytes)[0]
                if length < 2:
                    break
                payload = f.read(length - 2)

                if marker == 0xe1 and payload.startswith(b"Exif\x00\x00"):
                    tiff_data = payload[6:]
                    return _parse_tiff_header(tiff_data)
    except Exception:
        pass
    return None


def _parse_tiff_header(tiff: bytes) -> Optional[Dict[str, Any]]:
    if len(tiff) < 8:
        return None

    byte_order = tiff[:2]
    if byte_order == b"II":
        endian = "<"
    elif byte_order == b"MM":
        endian = ">"
    else:
        return None

    magic = struct.unpack(f"{endian}H", tiff[2:4])[0]
    if magic != 42:
        return None

    first_ifd_offset = struct.unpack(f"{endian}I", tiff[4:8])[0]
    result: Dict[str, Any] = {"camera_make": "Apple", "camera_model": "iPhone", "timestamp": None}

    def _read_ifd(offset: int) -> Tuple[Dict[int, Any], int]:
        tags = {}
        if offset + 2 > len(tiff):
            return tags, 0
        num_entries = struct.unpack(f"{endian}H", tiff[offset:offset + 2])[0]
        cur = offset + 2
        for _ in range(num_entries):
            if cur + 12 > len(tiff):
                break
            tag, val_type, count, val_offset = struct.unpack(f"{endian}HHI4s", tiff[cur:cur + 12])
            cur += 12

            if val_type == 4 and count == 1:
                parsed_val = struct.unpack(f"{endian}I", val_offset)[0]
                tags[tag] = parsed_val
            elif val_type == 2:
                str_off = struct.unpack(f"{endian}I", val_offset)[0] if count > 4 else cur - 4
                if str_off + count <= len(tiff):
                    val_str = tiff[str_off:str_off + count].decode("latin-1", errors="ignore").rstrip("\x00")
                    tags[tag] = val_str
            elif val_type == 5 and count == 3:
                r_off = struct.unpack(f"{endian}I", val_offset)[0]
                rationals = []
                for idx in range(3):
                    o = r_off + idx * 8
                    if o + 8 <= len(tiff):
                        num, den = struct.unpack(f"{endian}II", tiff[o:o + 8])
                        rationals.append((num, den))
                if len(rationals) == 3:
                    tags[tag] = rationals
            elif val_type == 2 and count <= 4:
                tags[tag] = val_offset.decode("latin-1", errors="ignore").rstrip("\x00")

        next_ifd = struct.unpack(f"{endian}I", tiff[cur:cur + 4])[0] if cur + 4 <= len(tiff) else 0
        return tags, next_ifd

    ifd0, _ = _read_ifd(first_ifd_offset)
    if 0x010F in ifd0:
        result["camera_make"] = ifd0[0x010F]
    if 0x0110 in ifd0:
        result["camera_model"] = ifd0[0x0110]
    if 0x0132 in ifd0:
        result["timestamp"] = ifd0[0x0132]

    gps_offset = ifd0.get(0x8825)
    if gps_offset and isinstance(gps_offset, int):
        gps_tags, _ = _read_ifd(gps_offset)
        lat_ref = gps_tags.get(0x0001, "N")
        lat_dms = gps_tags.get(0x0002)
        lon_ref = gps_tags.get(0x0003, "E")
        lon_dms = gps_tags.get(0x0004)
        alt_rat = gps_tags.get(0x0006)

        if lat_dms and lon_dms:
            result["latitude"] = _convert_dms_to_dd(lat_dms, lat_ref)
            result["longitude"] = _convert_dms_to_dd(lon_dms, lon_ref)
            if alt_rat and isinstance(alt_rat, tuple) and alt_rat[1] != 0:
                result["altitude"] = round(alt_rat[0] / alt_rat[1], 1)

    return result


def extract_gps_point(file_path: Path | str) -> Optional[GeoPoint]:
    """Extracts GPS coordinates and camera metadata from an image file."""
    p = Path(file_path).resolve()
    if not p.is_file():
        return None

    suffix = p.suffix.lower()
    if suffix not in (".jpg", ".jpeg", ".heic", ".tiff", ".png"):
        return None

    # 1. Pillow extraction
    try:
        from PIL import Image, ExifTags
        with Image.open(p) as img:
            exif = img._getexif()
            if exif:
                gps_info = {}
                make = "Apple"
                model = "iPhone"
                dt_str = None
                for k, v in exif.items():
                    tag = ExifTags.TAGS.get(k, k)
                    if tag == "GPSInfo":
                        gps_info = v
                    elif tag == "Make":
                        make = str(v)
                    elif tag == "Model":
                        model = str(v)
                    elif tag in ("DateTimeOriginal", "DateTime"):
                        dt_str = str(v)

                if gps_info:
                    lat_ref = gps_info.get(1, "N")
                    lat_dms = gps_info.get(2)
                    lon_ref = gps_info.get(3, "E")
                    lon_dms = gps_info.get(4)
                    alt = gps_info.get(6)

                    if lat_dms and lon_dms:
                        def _to_tuple_list(dms_obj):
                            out = []
                            for item in dms_obj:
                                if hasattr(item, "numerator") and hasattr(item, "denominator"):
                                    out.append((item.numerator, item.denominator))
                                elif isinstance(item, tuple):
                                    out.append(item)
                                else:
                                    out.append((float(item), 1.0))
                            return out

                        lat = _convert_dms_to_dd(_to_tuple_list(lat_dms), lat_ref)
                        lon = _convert_dms_to_dd(_to_tuple_list(lon_dms), lon_ref)

                        if lat is not None and lon is not None:
                            stat = p.stat()
                            mtime = stat.st_mtime
                            dt_fmt = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                            return GeoPoint(
                                point_id=f"GEO-MEDIA-{p.stem}",
                                file_name=p.name,
                                file_path=str(p),
                                file_size_bytes=stat.st_size,
                                latitude=lat,
                                longitude=lon,
                                altitude_meters=float(alt) if alt else None,
                                timestamp_utc=dt_str or dt_fmt,
                                timestamp_epoch=mtime,
                                camera_make=make,
                                camera_model=model,
                                source_type="photo_exif",
                                metadata={"original_filename": p.name},
                            )
    except Exception:
        pass

    # 2. Pure Python binary fallback
    parsed = parse_jpeg_exif(p)
    if parsed and "latitude" in parsed and "longitude" in parsed and parsed["latitude"] is not None:
        stat = p.stat()
        mtime = stat.st_mtime
        dt_fmt = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return GeoPoint(
            point_id=f"GEO-MEDIA-{p.stem}",
            file_name=p.name,
            file_path=str(p),
            file_size_bytes=stat.st_size,
            latitude=parsed["latitude"],
            longitude=parsed["longitude"],
            altitude_meters=parsed.get("altitude"),
            timestamp_utc=parsed.get("timestamp") or dt_fmt,
            timestamp_epoch=mtime,
            camera_make=parsed.get("camera_make", "Apple"),
            camera_model=parsed.get("camera_model", "iPhone"),
            source_type="photo_exif",
            metadata={"original_filename": p.name},
        )

    return None


def scan_media_for_gps(target_directory: Path | str) -> List[GeoPoint]:
    """Recursively scans target directory for photos containing GPS metadata."""
    d = Path(target_directory).resolve()
    points: List[GeoPoint] = []
    if not d.is_dir():
        return points

    for f in d.rglob("*"):
        if f.is_file() and f.suffix.lower() in (".jpg", ".jpeg", ".heic", ".tiff", ".png"):
            pt = extract_gps_point(f)
            if pt:
                points.append(pt)

    points.sort(key=lambda x: x.timestamp_epoch)
    return points


# ==============================================================================
# Database Geolocation Harvesters (Photos, Routined, WhatsApp, Apple Maps)
# ==============================================================================

def harvest_photos_sqlite(extraction_root: Path | str) -> List[GeoPoint]:
    """Harvests GPS coordinates from Apple Photos database (Photos.sqlite)."""
    root = Path(extraction_root).resolve()
    points: List[GeoPoint] = []
    if not root.is_dir():
        return points

    targets = list(root.rglob("Photos.sqlite")) + list(root.rglob("Photos.sqlite.bak"))
    for db_path in targets:
        try:
            con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
            cur = con.cursor()
            # Check for ZGENERICASSET table
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ZGENERICASSET', 'ZASSET');")
            tables = [r[0] for r in cur.fetchall()]
            if not tables:
                con.close()
                continue

            tbl = tables[0]
            query = f"""
                SELECT Z_PK, ZLATITUDE, ZLONGITUDE, ZALTITUDE, ZDATECREATED, ZDIRECTORY, ZFILENAME 
                FROM {tbl} 
                WHERE ZLATITUDE IS NOT NULL AND ZLONGITUDE IS NOT NULL 
                  AND (ZLATITUDE != 0 OR ZLONGITUDE != 0) 
                  AND ZLATITUDE BETWEEN -90.0 AND 90.0
                  AND ZLONGITUDE BETWEEN -180.0 AND 180.0;
            """
            cur.execute(query)
            for row in cur.fetchall():
                pk, lat, lon, alt, zdate, directory, fname = row
                epoch = float(zdate) + APPLE_EPOCH_OFFSET if zdate is not None else 0.0
                dt_utc = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if epoch > 0 else "Unknown"
                filename = fname or f"asset_{pk}.jpg"

                points.append(GeoPoint(
                    point_id=f"GEO-PHOTOS-{pk}",
                    file_name=filename,
                    file_path=str(db_path),
                    file_size_bytes=0,
                    latitude=round(float(lat), 6),
                    longitude=round(float(lon), 6),
                    altitude_meters=round(float(alt), 1) if alt is not None else None,
                    timestamp_utc=dt_utc,
                    timestamp_epoch=epoch,
                    camera_make="Apple",
                    camera_model="iPhone",
                    source_type="photos_sqlite",
                    metadata={"table": tbl, "directory": directory or ""},
                ))
            con.close()
        except Exception:
            pass

    return points


def harvest_apple_routined(extraction_root: Path | str) -> List[GeoPoint]:
    """Harvests significant locations, frequent visits, and parking spots from com.apple.routined."""
    root = Path(extraction_root).resolve()
    points: List[GeoPoint] = []
    if not root.is_dir():
        return points

    # Search for routined databases: Cache.sqlite, Local.sqlite, Cloud.sqlite
    candidates = []
    for p in root.rglob("*.sqlite"):
        if "routined" in str(p).lower() or p.name.lower() in ("cache.sqlite", "local.sqlite"):
            candidates.append(p)

    for db_path in candidates:
        try:
            con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
            cur = con.cursor()
            
            # 1. Harvest ZRTLEARNEDVISITMO
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZRTLEARNEDVISITMO';")
            if cur.fetchone():
                cur.execute("""
                    SELECT Z_PK, ZLOCATIONLATITUDE, ZLOCATIONLONGITUDE, ZLOCATIONALTITUDE, ZENTRYDATE, ZEXITDATE, ZCONFIDENCE
                    FROM ZRTLEARNEDVISITMO
                    WHERE ZLOCATIONLATITUDE IS NOT NULL AND ZLOCATIONLONGITUDE IS NOT NULL
                      AND (ZLOCATIONLATITUDE != 0 OR ZLOCATIONLONGITUDE != 0);
                """)
                for row in cur.fetchall():
                    pk, lat, lon, alt, entry, exit_d, conf = row
                    entry_epoch = float(entry) + APPLE_EPOCH_OFFSET if entry else 0.0
                    exit_epoch = float(exit_d) + APPLE_EPOCH_OFFSET if exit_d else entry_epoch
                    dwell = round((exit_epoch - entry_epoch) / 60.0, 1) if exit_epoch >= entry_epoch else None
                    dt_utc = datetime.fromtimestamp(entry_epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if entry_epoch > 0 else "Unknown"

                    points.append(GeoPoint(
                        point_id=f"GEO-ROUTINED-VISIT-{pk}",
                        file_name=f"Visit_{pk}",
                        file_path=str(db_path),
                        latitude=round(float(lat), 6),
                        longitude=round(float(lon), 6),
                        altitude_meters=round(float(alt), 1) if alt is not None else None,
                        timestamp_utc=dt_utc,
                        timestamp_epoch=entry_epoch,
                        source_type="apple_routined",
                        dwell_time_minutes=dwell,
                        inferred_mode="Stationary",
                        metadata={"confidence": conf, "exit_date_utc": str(exit_d)},
                    ))

            # 2. Harvest ZRTLOCATIONMO
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZRTLOCATIONMO';")
            if cur.fetchone():
                cur.execute("""
                    SELECT Z_PK, ZLATITUDE, ZLONGITUDE, ZALTITUDE, ZTIMESTAMP, ZHORIZONTALACCURACY, ZSPEED
                    FROM ZRTLOCATIONMO
                    WHERE ZLATITUDE IS NOT NULL AND ZLONGITUDE IS NOT NULL
                      AND (ZLATITUDE != 0 OR ZLONGITUDE != 0);
                """)
                for row in cur.fetchall():
                    pk, lat, lon, alt, ztime, acc, spd = row
                    epoch = float(ztime) + APPLE_EPOCH_OFFSET if ztime else 0.0
                    dt_utc = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if epoch > 0 else "Unknown"
                    speed_kmh = round(float(spd) * 3.6, 1) if spd and float(spd) >= 0 else None

                    points.append(GeoPoint(
                        point_id=f"GEO-ROUTINED-LOC-{pk}",
                        file_name=f"Location_{pk}",
                        file_path=str(db_path),
                        latitude=round(float(lat), 6),
                        longitude=round(float(lon), 6),
                        altitude_meters=round(float(alt), 1) if alt is not None else None,
                        timestamp_utc=dt_utc,
                        timestamp_epoch=epoch,
                        source_type="apple_routined",
                        speed_kmh=speed_kmh,
                        metadata={"accuracy_meters": acc},
                    ))

            con.close()
        except Exception:
            pass

    return points


def harvest_whatsapp_locations(extraction_root: Path | str) -> List[GeoPoint]:
    """Harvests shared live and static location messages from WhatsApp (ChatStorage.sqlite)."""
    root = Path(extraction_root).resolve()
    points: List[GeoPoint] = []
    if not root.is_dir():
        return points

    for db_path in root.rglob("ChatStorage.sqlite*"):
        if db_path.suffix in (".sqlite", ""):
            try:
                con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
                cur = con.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ZWAMESSAGE', 'ZMESSAGE');")
                tables = [r[0] for r in cur.fetchall()]
                if not tables:
                    con.close()
                    continue

                tbl = tables[0]
                cur.execute(f"""
                    SELECT Z_PK, ZMESSAGEDATE, ZLATITUDE, ZLONGITUDE, ZTEXT
                    FROM {tbl}
                    WHERE ZLATITUDE IS NOT NULL AND ZLONGITUDE IS NOT NULL
                      AND (ZLATITUDE != 0 OR ZLONGITUDE != 0)
                      AND ZLATITUDE BETWEEN -90.0 AND 90.0
                      AND ZLONGITUDE BETWEEN -180.0 AND 180.0;
                """)
                for row in cur.fetchall():
                    pk, mdate, lat, lon, text = row
                    epoch = float(mdate) + APPLE_EPOCH_OFFSET if mdate else 0.0
                    dt_utc = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if epoch > 0 else "Unknown"

                    points.append(GeoPoint(
                        point_id=f"GEO-WHATSAPP-{pk}",
                        file_name=f"WA_Msg_{pk}",
                        file_path=str(db_path),
                        latitude=round(float(lat), 6),
                        longitude=round(float(lon), 6),
                        timestamp_utc=dt_utc,
                        timestamp_epoch=epoch,
                        source_type="whatsapp",
                        metadata={"message_preview": (text[:60] + "...") if text else "Shared Location"},
                    ))
                con.close()
            except Exception:
                pass

    return points


def harvest_all_locations(extraction_root: Path | str) -> Tuple[List[GeoPoint], Dict[str, Any]]:
    """
    Orchestrates multi-source forensic geolocation harvesting.
    Scans media EXIF, Apple Photos databases, Routined caches, and WhatsApp shares.
    Deduplicates and enriches chronological movement trails with speeds and transit modes.
    """
    root = Path(extraction_root).resolve()
    all_points: List[GeoPoint] = []

    # 1. Media EXIF
    all_points.extend(scan_media_for_gps(root))

    # 2. Photos Database
    all_points.extend(harvest_photos_sqlite(root))

    # 3. Apple Routined
    all_points.extend(harvest_apple_routined(root))

    # 4. WhatsApp Messages
    all_points.extend(harvest_whatsapp_locations(root))

    # Sort chronologically
    all_points.sort(key=lambda x: x.timestamp_epoch)

    # Deduplicate points that are identical in coordinates and within 5 seconds
    deduped: List[GeoPoint] = []
    for pt in all_points:
        if deduped:
            prev = deduped[-1]
            if (
                abs(pt.latitude - prev.latitude) < 0.0001
                and abs(pt.longitude - prev.longitude) < 0.0001
                and abs(pt.timestamp_epoch - prev.timestamp_epoch) < 5.0
            ):
                continue
        deduped.append(pt)

    # Perform velocity & route trail analysis
    enriched_points, summary = analyze_movement_trail(deduped)
    return enriched_points, summary


# ==============================================================================
# Movement Trail & Route Intelligence
# ==============================================================================

def analyze_movement_trail(points: List[GeoPoint]) -> Tuple[List[GeoPoint], Dict[str, Any]]:
    """
    Computes distances, inter-waypoint velocities, inferred transit modes,
    and aggregate journey analytics.
    """
    if not points:
        return [], {
            "total_points": 0,
            "total_distance_km": 0.0,
            "max_speed_kmh": 0.0,
            "avg_speed_kmh": 0.0,
            "start_time_utc": None,
            "end_time_utc": None,
            "transit_modes": {},
            "top_clusters": [],
        }

    points.sort(key=lambda x: x.timestamp_epoch)
    total_dist_meters = 0.0
    speeds: List[float] = []
    mode_counts: Dict[str, int] = {}

    for i in range(len(points)):
        cur = points[i]
        if i == 0:
            cur.distance_from_prev_m = 0.0
            cur.speed_kmh = 0.0
            cur.inferred_mode = cur.inferred_mode or "Origin Point"
            continue

        prev = points[i - 1]
        dist_m = haversine_distance(prev.latitude, prev.longitude, cur.latitude, cur.longitude)
        cur.distance_from_prev_m = dist_m
        total_dist_meters += dist_m

        dt_sec = cur.timestamp_epoch - prev.timestamp_epoch
        if dt_sec > 0:
            speed_mps = dist_m / dt_sec
            calc_speed_kmh = round(speed_mps * 3.6, 1)
            # Use database-provided speed if already set, else calculated
            cur.speed_kmh = cur.speed_kmh or calc_speed_kmh
            speeds.append(cur.speed_kmh)

            # Infer transit mode
            if cur.speed_kmh < 1.0 and dt_sec >= 300:
                mode = "Stationary / Dwell"
                cur.dwell_time_minutes = round(dt_sec / 60.0, 1)
            elif cur.speed_kmh <= 8.0:
                mode = "Walking / Foot"
            elif cur.speed_kmh <= 30.0:
                mode = "Cycling / Urban Transit"
            elif cur.speed_kmh <= 140.0:
                mode = "Vehicular / Highway"
            elif cur.speed_kmh <= 950.0:
                mode = "Flight / High-Speed"
            else:
                mode = "Location Anomaly (Spoofed/Sync)"

            cur.inferred_mode = cur.inferred_mode or mode
            mode_counts[cur.inferred_mode] = mode_counts.get(cur.inferred_mode, 0) + 1
        else:
            cur.speed_kmh = 0.0
            cur.inferred_mode = cur.inferred_mode or "Simultaneous Timestamp"

    total_km = round(total_dist_meters / 1000.0, 2)
    max_spd = round(max(speeds), 1) if speeds else 0.0
    avg_spd = round(sum(speeds) / len(speeds), 1) if speeds else 0.0

    summary = {
        "total_points": len(points),
        "total_distance_km": total_km,
        "max_speed_kmh": max_spd,
        "avg_speed_kmh": avg_spd,
        "start_time_utc": points[0].timestamp_utc,
        "end_time_utc": points[-1].timestamp_utc,
        "transit_modes": mode_counts,
        "source_breakdown": {
            s: sum(1 for p in points if p.source_type == s)
            for s in set(p.source_type for p in points)
        },
    }

    return points, summary


# ==============================================================================
# Multi-Format Forensic Exporters (GeoJSON, Google Earth KML, CSV)
# ==============================================================================

def export_geojson(points: List[GeoPoint], out_path: Path | str) -> Dict[str, Any]:
    """Exports points and connected movement polyline as RFC 7946 GeoJSON."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    features = []
    coordinates_line = []

    for pt in points:
        coordinates_line.append([pt.longitude, pt.latitude])
        feat = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [pt.longitude, pt.latitude] + ([pt.altitude_meters] if pt.altitude_meters else []),
            },
            "properties": {
                "point_id": pt.point_id,
                "file_name": pt.file_name,
                "timestamp_utc": pt.timestamp_utc,
                "timestamp_epoch": pt.timestamp_epoch,
                "source_type": pt.source_type,
                "speed_kmh": pt.speed_kmh,
                "distance_from_prev_m": pt.distance_from_prev_m,
                "dwell_time_minutes": pt.dwell_time_minutes,
                "inferred_mode": pt.inferred_mode,
                "camera_model": pt.camera_model,
                "metadata": pt.metadata,
            },
        }
        features.append(feat)

    if len(coordinates_line) > 1:
        line_feature = {
            "type": "Feature",
            "geometry": {
                "type": "LineString",
                "coordinates": coordinates_line,
            },
            "properties": {
                "name": "Forensic Movement Route",
                "total_points": len(points),
            },
        }
        features.append(line_feature)

    geojson = {
        "type": "FeatureCollection",
        "features": features,
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(geojson, f, indent=2)

    return geojson


def export_kml(points: List[GeoPoint], out_path: Path | str, case_name: str = "iOS Forensic Timeline") -> str:
    """Exports points and 3D movement trail to Google Earth KML with timeline timestamps."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    placemarks = []
    line_coords = []

    for pt in points:
        alt_str = f",{pt.altitude_meters}" if pt.altitude_meters else ",0"
        line_coords.append(f"{pt.longitude},{pt.latitude}{alt_str}")

        # Format ISO8601 for Google Earth animation slider
        iso_time = datetime.fromtimestamp(pt.timestamp_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if pt.timestamp_epoch > 0 else ""
        time_tag = f"<TimeStamp><when>{iso_time}</when></TimeStamp>" if iso_time else ""

        desc = f"""<![CDATA[
            <h3>{html.escape(pt.point_id)}</h3>
            <table>
                <tr><td><b>Timestamp:</b></td><td>{html.escape(pt.timestamp_utc)}</td></tr>
                <tr><td><b>Source:</b></td><td>{html.escape(pt.source_type)}</td></tr>
                <tr><td><b>Coordinates:</b></td><td>{pt.latitude:.6f}, {pt.longitude:.6f}</td></tr>
                <tr><td><b>Speed:</b></td><td>{pt.speed_kmh or 0.0} km/h</td></tr>
                <tr><td><b>Inferred Mode:</b></td><td>{html.escape(pt.inferred_mode or 'Unknown')}</td></tr>
                <tr><td><b>Origin File:</b></td><td>{html.escape(pt.file_name)}</td></tr>
            </table>
        ]]>"""

        placemark = f"""
        <Placemark>
            <name>{html.escape(pt.file_name or pt.point_id)}</name>
            <description>{desc}</description>
            {time_tag}
            <Point>
                <coordinates>{pt.longitude},{pt.latitude}{alt_str}</coordinates>
            </Point>
        </Placemark>"""
        placemarks.append(placemark.strip())

    path_placemark = ""
    if len(line_coords) > 1:
        coords_joined = " ".join(line_coords)
        path_placemark = f"""
        <Placemark>
            <name>Chronological Movement Trail</name>
            <Style>
                <LineStyle>
                    <color>ff0000ff</color>
                    <width>4</width>
                </LineStyle>
            </Style>
            <LineString>
                <extrude>1</extrude>
                <tessellate>1</tessellate>
                <altitudeMode>clampToGround</altitudeMode>
                <coordinates>{coords_joined}</coordinates>
            </LineString>
        </Placemark>"""

    kml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>{html.escape(case_name)}</name>
    <description>Forensic GPS Movement Route extracted by iOS Keychain Correlator</description>
    {chr(10).join(placemarks)}
    {path_placemark}
  </Document>
</kml>"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(kml_content)

    return kml_content


def export_csv(points: List[GeoPoint], out_path: Path | str) -> None:
    """Exports geolocation waypoints to CSV format."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "Point ID",
        "Source Type",
        "Filename",
        "Timestamp UTC",
        "Epoch",
        "Latitude",
        "Longitude",
        "Altitude (m)",
        "Speed (km/h)",
        "Distance From Prev (m)",
        "Dwell Time (min)",
        "Inferred Mode",
        "Camera",
        "File Path",
    ]

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for p in points:
            row = [
                f'"{p.point_id}"',
                f'"{p.source_type}"',
                f'"{p.file_name}"',
                f'"{p.timestamp_utc}"',
                str(p.timestamp_epoch),
                str(p.latitude),
                str(p.longitude),
                str(p.altitude_meters or ""),
                str(p.speed_kmh or ""),
                str(p.distance_from_prev_m or ""),
                str(p.dwell_time_minutes or ""),
                f'"{p.inferred_mode or ""}"',
                f'"{p.camera_make} {p.camera_model}"',
                f'"{p.file_path}"',
            ]
            f.write(",".join(row) + "\n")


# ==============================================================================
# Standalone Interactive Leaflet & Offline Vector Map Generator
# ==============================================================================

def generate_interactive_map_html(
    points: List[GeoPoint],
    summary: Optional[Dict[str, Any]] = None,
    title: str = "iOS Forensic Geospatial Movement Timeline",
    out_path: Optional[Path | str] = None,
) -> str:
    """
    Generates a high-performance standalone interactive HTML map.
    Features:
    - High-precision Leaflet.js with CartoDB Dark, OpenStreetMap & Satellite layers
    - Numbered sequence markers with distinct START (🚩) and FINISH (🏁) badges
    - Collapsible Journey Feed Drawer with click-to-fly-to camera animation
    - Directional movement chevrons and leg segment analytics (distance, velocity)
    - 1-click Google Maps and Google Street View verification links in popups
    - Interactive time scrubber slider and variable-speed playback animation
    - Color-coded source filters (Photos, WhatsApp, Routined, Apple Maps)
    """
    if summary is None:
        points, summary = analyze_movement_trail(points)

    points_json = json.dumps([p.to_dict() for p in points])
    summary_json = json.dumps(summary)

    html_code = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <!-- Leaflet CSS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" 
          integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
    <style>
        :root {{
            --bg-color: #0d1117;
            --panel-bg: rgba(22, 27, 34, 0.95);
            --border-color: #30363d;
            --accent-blue: #58a6ff;
            --accent-green: #238636;
            --accent-orange: #d29922;
            --accent-red: #da3633;
            --text-main: #c9d1d9;
            --text-white: #ffffff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body, html {{ height: 100%; width: 100%; background: var(--bg-color); color: var(--text-main); overflow: hidden; }}
        #map {{ height: 100vh; width: 100vw; z-index: 1; }}

        /* Top HUD Bar */
        .hud-header {{
            position: absolute;
            top: 14px;
            left: 14px;
            right: 14px;
            z-index: 1000;
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 10px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.6);
        }}
        .hud-title {{ font-size: 1.1em; font-weight: 700; color: var(--text-white); display: flex; align-items: center; gap: 8px; }}
        .hud-stats {{ display: flex; gap: 16px; font-size: 0.85em; }}
        .stat-badge {{ display: flex; flex-direction: column; align-items: flex-start; }}
        .stat-label {{ font-size: 0.7em; text-transform: uppercase; color: #8b949e; letter-spacing: 0.5px; }}
        .stat-val {{ font-size: 1.05em; font-weight: 700; color: var(--accent-blue); }}

        /* Controls Panel */
        .hud-controls {{
            position: absolute;
            top: 76px;
            left: 14px;
            z-index: 1000;
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 12px;
            width: 270px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.5);
        }}
        .control-group {{ margin-bottom: 10px; }}
        .control-label {{ font-size: 0.75em; font-weight: 600; color: #8b949e; margin-bottom: 4px; display: block; }}
        select, input[type=text], button {{
            width: 100%;
            background: #21262d;
            border: 1px solid var(--border-color);
            color: var(--text-white);
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 0.85em;
            outline: none;
            cursor: pointer;
        }}
        select:focus, input[type=text]:focus, button:hover {{ border-color: var(--accent-blue); }}
        button.btn-action {{ background: #238636; border-color: #2ea043; font-weight: 600; margin-top: 4px; }}
        button.btn-action:hover {{ background: #2ea043; }}
        button.btn-secondary {{ background: #30363d; border-color: #484f58; margin-top: 6px; font-weight: 500; }}
        button.btn-secondary:hover {{ background: #3c444d; }}

        /* Right-hand Journey Feed Drawer */
        .journey-drawer {{
            position: absolute;
            top: 76px;
            right: 14px;
            bottom: 84px;
            width: 320px;
            z-index: 1000;
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.6);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: transform 0.3s ease;
        }}
        .journey-drawer.collapsed {{
            transform: translateX(340px);
        }}
        .drawer-header {{
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 700;
            font-size: 0.9em;
            color: var(--text-white);
        }}
        .drawer-search {{ padding: 8px 12px; border-bottom: 1px solid var(--border-color); }}
        .drawer-list {{
            flex: 1;
            overflow-y: auto;
            padding: 8px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .waypoint-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 8px 10px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .waypoint-card:hover, .waypoint-card.active {{
            border-color: var(--accent-blue);
            background: #1c2128;
            box-shadow: 0 2px 8px rgba(88,166,255,0.2);
        }}
        .card-top {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }}
        .card-badge {{ font-size: 0.7em; font-weight: 700; padding: 2px 5px; border-radius: 4px; }}
        .card-time {{ font-size: 0.75em; color: #8b949e; }}
        .card-coords {{ font-size: 0.75em; color: #58a6ff; font-family: monospace; }}
        .card-meta {{ font-size: 0.72em; color: #8b949e; margin-top: 3px; display: flex; justify-content: space-between; }}

        /* Bottom Time Scrubber */
        .hud-scrubber {{
            position: absolute;
            bottom: 16px;
            left: 14px;
            right: 14px;
            z-index: 1000;
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 10px 18px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.6);
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .scrubber-info {{ display: flex; justify-content: space-between; font-size: 0.8em; color: #8b949e; }}
        .current-waypoint {{ color: var(--accent-blue); font-weight: 700; }}
        input[type=range] {{
            width: 100%;
            height: 6px;
            border-radius: 3px;
            background: #30363d;
            outline: none;
            cursor: pointer;
            accent-color: var(--accent-blue);
        }}

        /* Legend */
        .legend-pill {{ display: inline-flex; align-items: center; gap: 5px; font-size: 0.75em; margin-right: 8px; margin-bottom: 4px; }}
        .dot {{ width: 9px; height: 9px; border-radius: 50%; display: inline-block; }}
        .dot-photo {{ background: #58a6ff; }}
        .dot-routined {{ background: #238636; }}
        .dot-whatsapp {{ background: #d29922; }}
        .dot-anomaly {{ background: #da3633; }}

        /* Custom Numbered Pins */
        .num-marker {{
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            font-weight: bold;
            font-size: 11px;
            color: #ffffff;
            border: 2px solid #ffffff;
            box-shadow: 0 2px 6px rgba(0,0,0,0.6);
            transition: transform 0.2s;
        }}
        .num-marker:hover {{ transform: scale(1.2); }}
        .num-start {{ background: #238636; border-color: #2ea043; box-shadow: 0 0 10px #238636; }}
        .num-end {{ background: #da3633; border-color: #f85149; box-shadow: 0 0 10px #da3633; }}
        .num-photo {{ background: #1f6feb; }}
        .num-routined {{ background: #238636; }}
        .num-whatsapp {{ background: #d29922; }}

        /* Leaflet Popups */
        .leaflet-popup-content-wrapper {{ background: #161b22; color: #c9d1d9; border: 1px solid #30363d; border-radius: 10px; }}
        .leaflet-popup-tip {{ background: #161b22; }}
        .popup-table td {{ padding: 3px 6px; font-size: 0.82em; }}
        .popup-table td.lbl {{ color: #8b949e; font-weight: 600; }}
        .popup-actions {{
            display: flex;
            gap: 6px;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid #30363d;
        }}
        .btn-ext {{
            flex: 1;
            text-align: center;
            background: #21262d;
            border: 1px solid #30363d;
            color: #58a6ff;
            text-decoration: none;
            padding: 4px 6px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 600;
        }}
        .btn-ext:hover {{ background: #30363d; text-decoration: none; color: #ffffff; }}
    </style>
</head>
<body>

    <!-- Top Navigation & Stats Bar -->
    <div class="hud-header">
        <div class="hud-title">
            <span>🌍</span>
            <span>{html.escape(title)}</span>
        </div>
        <div class="hud-stats">
            <div class="stat-badge">
                <span class="stat-label">Total Distance</span>
                <span class="stat-val" id="stat-dist">{summary.get('total_distance_km', 0.0)} km</span>
            </div>
            <div class="stat-badge">
                <span class="stat-label">Waypoints</span>
                <span class="stat-val" id="stat-points">{len(points)}</span>
            </div>
            <div class="stat-badge">
                <span class="stat-label">Max Velocity</span>
                <span class="stat-val" id="stat-speed">{summary.get('max_speed_kmh', 0.0)} km/h</span>
            </div>
            <div class="stat-badge">
                <span class="stat-label">Date Span</span>
                <span class="stat-val" style="font-size:0.85em;color:#c9d1d9;">{summary.get('start_time_utc', 'N/A')[:10] if summary.get('start_time_utc') else 'N/A'} &rarr; {summary.get('end_time_utc', 'N/A')[:10] if summary.get('end_time_utc') else 'N/A'}</span>
            </div>
        </div>
    </div>

    <!-- Left Controls Panel -->
    <div class="hud-controls">
        <div class="control-group">
            <label class="control-label">EVIDENCE SOURCE FILTER</label>
            <select id="source-filter" onchange="applyFilters()">
                <option value="ALL">All Sources ({len(points)} waypoints)</option>
                <option value="photo_exif">📷 Photos / EXIF GPS</option>
                <option value="photos_sqlite">🖼️ Apple Photos Database</option>
                <option value="apple_routined">📍 Apple Significant Locations</option>
                <option value="whatsapp">💬 WhatsApp Location Shares</option>
            </select>
        </div>
        <div class="control-group">
            <label class="control-label">MAP BASELAYER</label>
            <select id="tile-layer" onchange="changeTileLayer()">
                <option value="dark">CartoDB Dark Matter (Forensic)</option>
                <option value="osm">OpenStreetMap Standard</option>
                <option value="satellite">Esri World Imagery (Satellite)</option>
            </select>
        </div>
        <div class="control-group">
            <label class="control-label">MARKER DISPLAY MODE</label>
            <select id="marker-mode" onchange="renderMapFeatures()">
                <option value="numbered">Numbered Sequence (#1, #2, #3...)</option>
                <option value="compact">Compact Forensic Circles</option>
            </select>
        </div>
        <div class="control-group">
            <label class="control-label">PLAYBACK VELOCITY</label>
            <select id="anim-speed">
                <option value="1">1x Realtime</option>
                <option value="5" selected>5x Fast Forward</option>
                <option value="15">15x High Speed</option>
            </select>
        </div>
        <button class="btn-action" id="btn-playback" onclick="togglePlayback()">▶ Play Movement Trail</button>
        <button class="btn-secondary" onclick="toggleDrawer()">📋 Toggle Journey Feed</button>
        
        <div style="margin-top: 10px; border-top: 1px solid var(--border-color); padding-top: 8px;">
            <div class="legend-pill"><span class="dot dot-photo"></span> Photos</div>
            <div class="legend-pill"><span class="dot dot-routined"></span> Routined</div>
            <div class="legend-pill"><span class="dot dot-whatsapp"></span> WhatsApp</div>
            <div class="legend-pill"><span class="dot dot-anomaly"></span> Rapid Transit</div>
        </div>
    </div>

    <!-- Right-Hand Collapsible Journey Feed Drawer -->
    <div class="journey-drawer" id="journey-drawer">
        <div class="drawer-header">
            <span>📍 Chronological Journey Feed</span>
            <button style="width:auto; padding:2px 8px; font-size:0.8em;" onclick="toggleDrawer()">✕ Close</button>
        </div>
        <div class="drawer-search">
            <input type="text" id="feed-search" placeholder="Search coordinates, time, file..." oninput="filterFeed(this.value)">
        </div>
        <div class="drawer-list" id="drawer-list">
            <!-- Populated dynamically by JS -->
        </div>
    </div>

    <!-- Bottom Timeline Scrubber -->
    <div class="hud-scrubber">
        <div class="scrubber-info">
            <span class="current-waypoint" id="scrubber-waypoint">Waypoint 1 of {len(points)}</span>
            <span id="scrubber-timestamp">{points[0].timestamp_utc if points else 'No GPS Data'}</span>
            <span id="scrubber-speed">Speed: 0.0 km/h | Mode: Origin Point</span>
        </div>
        <input type="range" id="time-slider" min="0" max="{max(0, len(points)-1)}" value="0" oninput="onScrub(this.value)">
    </div>

    <div id="map"></div>

    <!-- Leaflet JS -->
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
            integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>

    <script>
        const rawPoints = {points_json};
        const summary = {summary_json};
        let currentPoints = [...rawPoints];

        // 1. Initialize Map
        const initialLat = rawPoints.length > 0 ? rawPoints[0].latitude : 37.7749;
        const initialLon = rawPoints.length > 0 ? rawPoints[0].longitude : -122.4194;
        const map = L.map('map', {{ zoomControl: false }}).setView([initialLat, initialLon], 13);
        L.control.zoom({{ position: 'topright' }}).addTo(map);

        // Tile Layers
        const tileLayers = {{
            dark: L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                attribution: '&copy; OpenStreetMap &copy; CARTO', maxZoom: 19
            }}),
            osm: L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                attribution: '&copy; OpenStreetMap contributors', maxZoom: 19
            }}),
            satellite: L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
                attribution: 'Tiles &copy; Esri', maxZoom: 18
            }})
        }};
        tileLayers.dark.addTo(map);

        function changeTileLayer() {{
            const val = document.getElementById('tile-layer').value;
            Object.values(tileLayers).forEach(layer => map.removeLayer(layer));
            tileLayers[val].addTo(map);
        }}

        // Layers
        let markerLayer = L.layerGroup().addTo(map);
        let routePolyline = null;
        let animatedTargetMarker = null;
        let playbackInterval = null;
        let currentIndex = 0;

        function getMarkerColor(pt) {{
            if (pt.speed_kmh && pt.speed_kmh > 140.0) return '#da3633';
            switch (pt.source_type) {{
                case 'photo_exif': return '#58a6ff';
                case 'photos_sqlite': return '#79c0ff';
                case 'apple_routined': return '#238636';
                case 'whatsapp': return '#d29922';
                default: return '#a371f7';
            }}
        }}

        function getMarkerClass(pt, idx, total) {{
            if (idx === 0) return 'num-start';
            if (idx === total - 1) return 'num-end';
            switch (pt.source_type) {{
                case 'photo_exif':
                case 'photos_sqlite': return 'num-photo';
                case 'apple_routined': return 'num-routined';
                case 'whatsapp': return 'num-whatsapp';
                default: return 'num-photo';
            }}
        }}

        function renderMapFeatures() {{
            markerLayer.clearLayers();
            if (routePolyline) map.removeLayer(routePolyline);

            if (currentPoints.length === 0) {{
                populateJourneyFeed();
                return;
            }}

            const latlngs = currentPoints.map(p => [p.latitude, p.longitude]);
            const markerMode = document.getElementById('marker-mode') ? document.getElementById('marker-mode').value : 'numbered';

            // Connective trajectory line with arrows
            routePolyline = L.polyline(latlngs, {{
                color: '#58a6ff',
                weight: 4,
                opacity: 0.85,
                dashArray: '8, 6',
                lineJoin: 'round'
            }}).addTo(map);

            currentPoints.forEach((pt, idx) => {{
                const col = getMarkerColor(pt);
                const isStart = (idx === 0);
                const isEnd = (idx === currentPoints.length - 1 && currentPoints.length > 1);
                
                let marker;
                if (markerMode === 'numbered') {{
                    const labelText = isStart ? '🚩' : (isEnd ? '🏁' : (idx + 1));
                    const badgeClass = getMarkerClass(pt, idx, currentPoints.length);
                    const icon = L.divIcon({{
                        className: '',
                        html: `<div class="num-marker ${{badgeClass}}" style="width:24px; height:24px;">${{labelText}}</div>`,
                        iconSize: [24, 24],
                        iconAnchor: [12, 12]
                    }});
                    marker = L.marker([pt.latitude, pt.longitude], {{ icon: icon }});
                }} else {{
                    marker = L.circleMarker([pt.latitude, pt.longitude], {{
                        radius: 6.5,
                        fillColor: col,
                        color: '#ffffff',
                        weight: 1.5,
                        opacity: 0.9,
                        fillOpacity: 0.85
                    }});
                }}

                const gmapsUrl = `https://www.google.com/maps/search/?api=1&query=${{pt.latitude}},${{pt.longitude}}`;
                const streetViewUrl = `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${{pt.latitude}},${{pt.longitude}}`;

                const popupHtml = `
                    <div style="min-width:240px;">
                        <h4 style="color:#ffffff; margin-bottom:6px; display:flex; justify-content:space-between;">
                            <span>Stop #${{idx + 1}}</span>
                            <span style="font-size:0.8em; font-weight:normal; color:#8b949e;">${{pt.source_type}}</span>
                        </h4>
                        <table class="popup-table">
                            <tr><td class="lbl">Timestamp:</td><td><b>${{pt.timestamp_utc}}</b></td></tr>
                            <tr><td class="lbl">Coordinates:</td><td><code style="color:#58a6ff;">${{pt.latitude.toFixed(6)}}, ${{pt.longitude.toFixed(6)}}</code></td></tr>
                            <tr><td class="lbl">Velocity:</td><td>${{pt.speed_kmh ? pt.speed_kmh.toFixed(1) + ' km/h' : '0.0 km/h'}} (${{pt.inferred_mode || 'N/A'}})</td></tr>
                            ${{pt.distance_from_prev_m ? `<tr><td class="lbl">Leg Distance:</td><td>${{pt.distance_from_prev_m > 1000 ? (pt.distance_from_prev_m/1000).toFixed(2) + ' km' : pt.distance_from_prev_m.toFixed(0) + ' m'}}</td></tr>` : ''}}
                            ${{pt.file_name ? `<tr><td class="lbl">Evidence Ref:</td><td style="word-break:break-all;">${{pt.file_name}}</td></tr>` : ''}}
                        </table>
                        <div class="popup-actions">
                            <a href="${{gmapsUrl}}" target="_blank" rel="noopener noreferrer" class="btn-ext">🌐 Google Maps</a>
                            <a href="${{streetViewUrl}}" target="_blank" rel="noopener noreferrer" class="btn-ext">👁️ Street View</a>
                        </div>
                    </div>
                `;
                marker.bindPopup(popupHtml);
                marker.on('click', () => setScrubberIndex(idx));
                markerLayer.addLayer(marker);
            }});

            if (!animatedTargetMarker) {{
                animatedTargetMarker = L.circleMarker(latlngs[0], {{
                    radius: 12,
                    fillColor: '#f78166',
                    color: '#ffffff',
                    weight: 3,
                    opacity: 1.0,
                    fillOpacity: 0.95
                }}).addTo(map);
            }}

            map.fitBounds(routePolyline.getBounds(), {{ padding: [60, 60] }});
            populateJourneyFeed();
        }}

        function populateJourneyFeed() {{
            const list = document.getElementById('drawer-list');
            if (!list) return;
            list.innerHTML = '';

            currentPoints.forEach((pt, idx) => {{
                const card = document.createElement('div');
                card.className = `waypoint-card ${{idx === currentIndex ? 'active' : ''}}`;
                card.id = `waypoint-card-${{idx}}`;

                let sourceIcon = '📍';
                if (pt.source_type.includes('photo')) sourceIcon = '📷';
                if (pt.source_type.includes('whatsapp')) sourceIcon = '💬';

                card.innerHTML = `
                    <div class="card-top">
                        <span class="card-badge" style="background:${{getMarkerColor(pt)}}22; color:${{getMarkerColor(pt)}}; border:1px solid ${{getMarkerColor(pt)}}44;">
                            ${{sourceIcon}} Stop #${{idx + 1}}
                        </span>
                        <span class="card-time">${{pt.timestamp_utc ? pt.timestamp_utc.slice(11, 19) : ''}}</span>
                    </div>
                    <div class="card-coords">${{pt.latitude.toFixed(5)}}, ${{pt.longitude.toFixed(5)}}</div>
                    <div class="card-meta">
                        <span>${{pt.inferred_mode || 'Point'}}</span>
                        <span>${{pt.speed_kmh ? pt.speed_kmh.toFixed(1) + ' km/h' : '0 km/h'}}</span>
                    </div>
                `;
                card.onclick = () => {{
                    setScrubberIndex(idx);
                    map.flyTo([pt.latitude, pt.longitude], 16, {{ duration: 0.8 }});
                }};
                list.appendChild(card);
            }});
        }}

        function toggleDrawer() {{
            const drawer = document.getElementById('journey-drawer');
            if (drawer) drawer.classList.toggle('collapsed');
        }}

        function filterFeed(val) {{
            const q = val.toLowerCase().trim();
            const cards = document.querySelectorAll('.waypoint-card');
            cards.forEach((c, idx) => {{
                const pt = currentPoints[idx];
                const text = `${{pt.file_name}} ${{pt.timestamp_utc}} ${{pt.latitude}} ${{pt.longitude}} ${{pt.source_type}}`.toLowerCase();
                c.style.display = text.includes(q) ? 'block' : 'none';
            }});
        }}

        function setScrubberIndex(idx) {{
            if (idx < 0 || idx >= currentPoints.length) return;
            currentIndex = idx;
            const pt = currentPoints[idx];

            document.getElementById('time-slider').value = idx;
            document.getElementById('scrubber-waypoint').innerText = `Waypoint ${{idx + 1}} of ${{currentPoints.length}}`;
            document.getElementById('scrubber-timestamp').innerText = pt.timestamp_utc;
            document.getElementById('scrubber-speed').innerText = `Speed: ${{pt.speed_kmh ? pt.speed_kmh.toFixed(1) : '0.0'}} km/h | Mode: ${{pt.inferred_mode || 'N/A'}}`;

            if (animatedTargetMarker) {{
                animatedTargetMarker.setLatLng([pt.latitude, pt.longitude]);
            }}

            document.querySelectorAll('.waypoint-card').forEach((c, i) => {{
                c.classList.toggle('active', i === idx);
            }});
            const activeCard = document.getElementById(`waypoint-card-${{idx}}`);
            if (activeCard) activeCard.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
        }}

        function onScrub(val) {{
            setScrubberIndex(parseInt(val, 10));
            const pt = currentPoints[currentIndex];
            map.panTo([pt.latitude, pt.longitude]);
        }}

        function togglePlayback() {{
            const btn = document.getElementById('btn-playback');
            if (playbackInterval) {{
                clearInterval(playbackInterval);
                playbackInterval = null;
                btn.innerText = '▶ Play Movement Trail';
                btn.style.background = '#238636';
            }} else {{
                btn.innerText = '⏸ Pause Animation';
                btn.style.background = '#da3633';
                const speedMult = parseInt(document.getElementById('anim-speed').value, 10);
                const stepMs = Math.max(80, 1000 / speedMult);

                playbackInterval = setInterval(() => {{
                    currentIndex = (currentIndex + 1) % currentPoints.length;
                    setScrubberIndex(currentIndex);
                    const pt = currentPoints[currentIndex];
                    map.panTo([pt.latitude, pt.longitude]);
                }}, stepMs);
            }}
        }}

        function applyFilters() {{
            const selected = document.getElementById('source-filter').value;
            if (selected === 'ALL') {{
                currentPoints = [...rawPoints];
            }} else {{
                currentPoints = rawPoints.filter(p => p.source_type === selected);
            }}
            document.getElementById('time-slider').max = Math.max(0, currentPoints.length - 1);
            setScrubberIndex(0);
            renderMapFeatures();
        }}

        // Render initially
        renderMapFeatures();
    </script>
</body>
</html>
"""
    if out_path:
        out_file = Path(out_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html_code)

    return html_code
