"""Signature-based file carving over a raw disk/SD-card image.

Scans a raw removable-media image (SD/microSD dump, or any other raw byte
stream) for known file-type magic bytes and extracts matching byte ranges
as recovered files — independent of any filesystem metadata. This is what
makes it "carving" rather than ordinary file copying: it recovers files
even from unallocated space or a corrupted filesystem.

Supported types: JPEG (SOI/EOI), PNG (signature/IEND chunk), MP4/MOV/3GP
(`ftyp` box, size-prefixed atom walk). Scope explicitly excludes full
filesystem parsing (FAT/exFAT directory recovery) and fragmented-file
reconstruction — a file split across non-contiguous regions of the image
will carve as a truncated/corrupt file, flagged as such, never silently
"fixed".

The image is read in fixed-size buffered chunks with enough overlap
between chunks that a signature spanning a chunk boundary is never
missed — the whole image is never read into memory at once, since SD
images can be multi-gigabyte.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

# Buffered read chunk size for the single-pass signature scan and for
# streaming a carved file's bytes out to disk.
READ_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB

# Bytes carried over from the end of one chunk into the next so that a
# signature straddling a chunk boundary is still found intact. Larger than
# the longest signature/marker we search for (PNG's 8-byte signature and
# 12-byte IEND marker are the longest).
OVERLAP = 16

DEFAULT_MAX_FILE_SIZE = 200_000_000

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# The IEND chunk carries no data, so its on-disk bytes are always the same
# fixed 12 bytes: length(0) + "IEND" + crc32("IEND").
PNG_IEND = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)

MP4_FTYP_TAG = b"ftyp"

# Box types recognized during the atom walk that determines an MP4/MOV/3GP
# carve's extent. Deliberately a closed set rather than "any 4 printable
# ASCII bytes" - trailing garbage/unrelated data on the image can easily
# look like a plausible 4-character tag, and accepting it would carve
# unrelated bytes as part of the video. Covers the boxes commonly produced
# by companion-app photo/video captures; an unrecognized box type simply
# ends the walk there, which is the normal (not an error) way a carve ends.
MP4_KNOWN_BOX_TYPES = {
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot",
    b"mdia", b"minf", b"stbl", b"trak", b"edts", b"mvhd", b"tkhd",
    b"mdhd", b"hdlr", b"stsd", b"stts", b"stsc", b"stsz", b"stco",
    b"co64", b"ctts", b"elst", b"udta", b"meta", b"ilst", b"iods",
    b"vmhd", b"smhd", b"dinf", b"dref", b"gmhd", b"uuid", b"styp",
}

EXTENSIONS = {"jpeg": "jpg", "png": "png", "mp4": "mp4"}

# --- EXIF (JPEG only) -------------------------------------------------
#
# Best-effort extraction of the two forensically-relevant EXIF fields:
# capture timestamp and GPS position. Carved files have no filesystem
# timestamp of their own, so embedded EXIF is the only source of timing/
# location metadata for them, when present. Implemented as a small
# hand-rolled TIFF/IFD reader (rather than pulling in a dependency) since
# only a handful of well-known tags are needed.

JPEG_APP1_MARKER = 0xE1
JPEG_SOS_MARKER = 0xDA
JPEG_EOI_MARKER = 0xD9
EXIF_APP1_SIGNATURE = b"Exif\x00\x00"

TAG_DATETIME_ORIGINAL = 0x9003
TAG_EXIF_IFD_POINTER = 0x8769
TAG_GPS_IFD_POINTER = 0x8825
TAG_GPS_LATITUDE_REF = 0x0001
TAG_GPS_LATITUDE = 0x0002
TAG_GPS_LONGITUDE_REF = 0x0003
TAG_GPS_LONGITUDE = 0x0004

# TIFF field type -> byte size of one value.
_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
_TIFF_TYPE_ASCII = 2
_TIFF_TYPE_RATIONAL = 5


def _extract_jpeg_exif(path: Path) -> Optional[dict]:
    """Best-effort EXIF extraction from a carved JPEG file.

    Returns a dict with whichever of `DateTimeOriginal`, `GPSLatitude`,
    `GPSLongitude` are present, or `None` if the file has no EXIF segment,
    none of those tags, or the EXIF block is malformed/unparseable. Never
    raises - any parse failure degrades to `None` rather than aborting the
    whole carve operation.
    """
    try:
        tiff_data = _find_jpeg_exif_segment(path)
        if tiff_data is None:
            return None
        result = _parse_exif_tiff(tiff_data)
        return result or None
    except Exception:
        return None


def _find_jpeg_exif_segment(path: Path) -> Optional[bytes]:
    """Scan a JPEG's markers for the APP1/EXIF segment, return its TIFF payload.

    Stops at the first APP1/Exif segment found, or at SOS/EOI (start of
    image data / end of image), whichever comes first - EXIF always lives
    in the header region before compressed image data.
    """
    with open(path, "rb") as f:
        if f.read(2) != JPEG_SOI:
            return None

        while True:
            marker = f.read(2)
            if len(marker) < 2 or marker[0] != 0xFF:
                return None
            marker_id = marker[1]

            if marker_id == 0x00 or marker_id == 0xFF:
                # Padding / stuffing byte, not a real marker.
                f.seek(-1, 1)
                continue
            if 0xD0 <= marker_id <= 0xD7 or marker_id == 0x01:
                # Markers with no length/payload (RST0-7, TEM).
                continue
            if marker_id in (JPEG_SOS_MARKER, JPEG_EOI_MARKER):
                return None

            length_bytes = f.read(2)
            if len(length_bytes) < 2:
                return None
            (seg_len,) = struct.unpack(">H", length_bytes)
            if seg_len < 2:
                return None
            payload_len = seg_len - 2

            if marker_id == JPEG_APP1_MARKER:
                payload = f.read(payload_len)
                if len(payload) < payload_len:
                    return None
                if payload.startswith(EXIF_APP1_SIGNATURE):
                    return payload[len(EXIF_APP1_SIGNATURE):]
                continue

            f.seek(payload_len, 1)


def _parse_exif_tiff(tiff_data: bytes) -> dict:
    """Parse a TIFF/EXIF byte block and return the tags we care about."""
    if len(tiff_data) < 8:
        return {}

    byte_order_marker = tiff_data[0:2]
    if byte_order_marker == b"II":
        bo = "<"
    elif byte_order_marker == b"MM":
        bo = ">"
    else:
        return {}

    (magic,) = struct.unpack(bo + "H", tiff_data[2:4])
    if magic != 0x2A:
        return {}

    (ifd0_offset,) = struct.unpack(bo + "I", tiff_data[4:8])
    ifd0 = _read_ifd(tiff_data, ifd0_offset, bo)

    result: dict = {}

    if TAG_EXIF_IFD_POINTER in ifd0:
        exif_ifd_offset = ifd0[TAG_EXIF_IFD_POINTER][2]
        if isinstance(exif_ifd_offset, tuple):
            exif_ifd_offset = exif_ifd_offset[0]
        exif_ifd = _read_ifd(tiff_data, int(exif_ifd_offset), bo)
        if TAG_DATETIME_ORIGINAL in exif_ifd:
            value = exif_ifd[TAG_DATETIME_ORIGINAL][2]
            if isinstance(value, str):
                result["DateTimeOriginal"] = value.rstrip("\x00")

    if TAG_GPS_IFD_POINTER in ifd0:
        gps_ifd_offset = ifd0[TAG_GPS_IFD_POINTER][2]
        if isinstance(gps_ifd_offset, tuple):
            gps_ifd_offset = gps_ifd_offset[0]
        gps_ifd = _read_ifd(tiff_data, int(gps_ifd_offset), bo)
        lat = _gps_coordinate(gps_ifd, TAG_GPS_LATITUDE, TAG_GPS_LATITUDE_REF, ("S",))
        lon = _gps_coordinate(gps_ifd, TAG_GPS_LONGITUDE, TAG_GPS_LONGITUDE_REF, ("W",))
        if lat is not None:
            result["GPSLatitude"] = lat
        if lon is not None:
            result["GPSLongitude"] = lon

    return result


def _read_ifd(data: bytes, offset: int, bo: str) -> dict:
    """Read one IFD (Image File Directory) at `offset`, tag -> (type, count, value)."""
    if offset <= 0 or offset + 2 > len(data):
        return {}
    (entry_count,) = struct.unpack(bo + "H", data[offset:offset + 2])
    entries = {}
    pos = offset + 2
    for _ in range(entry_count):
        if pos + 12 > len(data):
            break
        tag, typ, count = struct.unpack(bo + "HHI", data[pos:pos + 8])
        value_field = data[pos + 8:pos + 12]
        entries[tag] = (typ, count, _resolve_value(data, typ, count, value_field, bo))
        pos += 12
    return entries


def _resolve_value(data: bytes, typ: int, count: int, value_field: bytes, bo: str):
    size = _TIFF_TYPE_SIZES.get(typ)
    if size is None or count < 0:
        return None
    total = size * count
    if total <= 4:
        raw = value_field[:total]
    else:
        (value_offset,) = struct.unpack(bo + "I", value_field)
        raw = data[value_offset:value_offset + total]
    if len(raw) < total:
        return None

    if typ == _TIFF_TYPE_ASCII:
        return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    if typ == _TIFF_TYPE_RATIONAL:
        values = []
        for i in range(count):
            num, den = struct.unpack(bo + "II", raw[i * 8:i * 8 + 8])
            values.append(num / den if den else 0.0)
        return tuple(values) if count != 1 else values[0]
    if typ in (3, 4, 9):  # SHORT, LONG, SLONG
        fmt = {3: "H", 4: "I", 9: "i"}[typ]
        values = struct.unpack(bo + fmt * count, raw[:size * count]) if count else ()
        return values if count != 1 else values[0]
    # Other types (BYTE, UNDEFINED, ...) - not needed for the tags we read.
    return raw


def _gps_coordinate(gps_ifd: dict, value_tag: int, ref_tag: int, negative_refs: tuple) -> Optional[float]:
    if value_tag not in gps_ifd or ref_tag not in gps_ifd:
        return None
    dms = gps_ifd[value_tag][2]
    ref = gps_ifd[ref_tag][2]
    if not isinstance(dms, tuple) or len(dms) != 3:
        return None
    if not isinstance(ref, str):
        return None
    degrees, minutes, seconds = dms
    decimal = float(degrees) + float(minutes) / 60.0 + float(seconds) / 3600.0
    if ref.strip().upper() in negative_refs:
        decimal = -decimal
    return decimal

# Signature name -> literal bytes to search for during the scan pass.
_START_SIGNATURES = (
    ("jpeg", JPEG_SOI),
    ("png", PNG_SIGNATURE),
    ("mp4", MP4_FTYP_TAG),
)


@dataclass
class CarvedFile:
    offset: int
    size: int
    file_type: str
    sha256: str
    output_path: Path
    exif: Optional[dict] = None


def carve_media(
    image_path: Path,
    out_dir: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> list["CarvedFile"]:
    """Scan `image_path` for known media signatures and carve matches into `out_dir`.

    Each carved file is written as `carved_<offset>_<sha256[:8]>.<ext>`. A
    file whose end signature is not found before `max_file_size` bytes is
    truncated at that cap and its `file_type` is suffixed "_truncated"
    rather than being silently treated as complete.
    """
    image_path = Path(image_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    file_size = image_path.stat().st_size
    candidates = _find_start_signatures(image_path)

    carved: list[CarvedFile] = []
    next_allowed_offset = 0
    with open(image_path, "rb") as f:
        for offset, base_type in candidates:
            if offset < next_allowed_offset:
                # Falls inside a file already carved from this pass.
                continue

            cap_end = min(offset + max_file_size, file_size)
            if base_type == "jpeg":
                end_offset, truncated = _extent_by_marker(f, offset + len(JPEG_SOI), JPEG_EOI, cap_end)
            elif base_type == "png":
                end_offset, truncated = _extent_by_marker(f, offset + len(PNG_SIGNATURE), PNG_IEND, cap_end)
            elif base_type == "mp4":
                end_offset, truncated = _extent_mp4(f, offset, cap_end, max_file_size)
            else:  # pragma: no cover - defensive, _START_SIGNATURES is closed
                continue

            size = end_offset - offset
            if size <= 0:
                continue

            carved.append(_carve_range(f, offset, size, out_dir, base_type, truncated))
            next_allowed_offset = end_offset

    return carved


def _find_start_signatures(image_path: Path) -> list[tuple[int, str]]:
    """Single buffered pass over the image locating every start signature.

    Reads in `READ_CHUNK_SIZE` chunks, carrying the last `OVERLAP` bytes of
    each chunk into the next so a signature that straddles a chunk
    boundary is still matched. Returns (offset, file_type) pairs sorted by
    offset; for MP4 the offset points at the start of the size-prefixed
    box (4 bytes before the `ftyp` tag itself), not at the tag.
    """
    matches: list[tuple[int, str]] = []
    with open(image_path, "rb") as f:
        carry = b""
        pos = 0
        while True:
            chunk = f.read(READ_CHUNK_SIZE)
            if not chunk:
                break

            window = carry + chunk
            window_offset = pos - len(carry)
            # Bytes before this absolute offset were already fully present
            # (and thus already searched) in the previous window.
            boundary = pos

            for file_type, sig in _START_SIGNATURES:
                search_from = 0
                while True:
                    idx = window.find(sig, search_from)
                    if idx == -1:
                        break
                    match_offset = window_offset + idx
                    match_end = match_offset + len(sig)
                    search_from = idx + 1
                    if match_end <= boundary:
                        # Fully contained in the carried-over tail -
                        # already reported on the previous iteration.
                        continue
                    if file_type == "mp4":
                        box_start = match_offset - 4
                        if box_start < 0:
                            continue
                        matches.append((box_start, "mp4"))
                    else:
                        matches.append((match_offset, file_type))

            pos += len(chunk)
            carry = window[-OVERLAP:] if len(window) > OVERLAP else window

    matches.sort(key=lambda m: m[0])
    return matches


def _find_marker(f: BinaryIO, start: int, end_limit: int, marker: bytes) -> Optional[int]:
    """Buffered forward search for `marker` in [start, end_limit) of `f`.

    Returns the absolute offset of the marker's first byte, or None if not
    found before `end_limit`. Reads in overlapping chunks so a marker
    spanning a chunk boundary is not missed.
    """
    if start >= end_limit:
        return None

    overlap = len(marker) - 1
    pos = start
    carry = b""
    while pos < end_limit:
        f.seek(pos)
        to_read = min(READ_CHUNK_SIZE, end_limit - pos)
        chunk = f.read(to_read)
        if not chunk:
            break

        window = carry + chunk
        window_offset = pos - len(carry)
        idx = window.find(marker)
        if idx != -1:
            return window_offset + idx

        pos += len(chunk)
        carry = window[-overlap:] if overlap and len(window) > overlap else (window if overlap else b"")

    return None


def _extent_by_marker(f: BinaryIO, search_start: int, marker: bytes, cap_end: int) -> tuple[int, bool]:
    """Return (end_offset, truncated) for a file whose end is `marker`."""
    found = _find_marker(f, search_start, cap_end, marker)
    if found is None:
        return cap_end, True
    return found + len(marker), False


def _extent_mp4(f: BinaryIO, offset: int, cap_end: int, max_file_size: int) -> tuple[int, bool]:
    """Walk size-prefixed MP4/MOV/3GP boxes from `offset` to find the file's extent.

    There is no fixed MP4 "end signature" - the file's extent is the sum
    of its consecutive, well-formed boxes (ftyp, moov, mdat, ...). The walk
    stops at the first box that doesn't parse as a plausible box (which is
    the normal, expected way an MP4 carve ends) or at the hard size cap
    (which is flagged as truncated).
    """
    hard_cap = offset + max_file_size
    pos = offset
    while pos + 8 <= cap_end:
        f.seek(pos)
        header = f.read(8)
        if len(header) < 8:
            break
        box_size, box_type = struct.unpack(">I4s", header)
        if box_size < 8 or box_type not in MP4_KNOWN_BOX_TYPES:
            break
        if pos + box_size > cap_end:
            pos = cap_end
            break
        pos += box_size

    if pos == offset:
        # Not even the leading ftyp box validated - nothing usable to carve.
        # Leave pos at offset (zero extent) so the caller's `size <= 0`
        # check rejects this candidate, rather than carving the whole
        # size-cap window as a bogus "file".
        return pos, False

    truncated = pos >= hard_cap
    return pos, truncated


def _carve_range(
    src: BinaryIO,
    offset: int,
    size: int,
    out_dir: Path,
    base_type: str,
    truncated: bool,
) -> CarvedFile:
    """Stream `size` bytes from `src` starting at `offset` out to a carved file."""
    digest = hashlib.sha256()
    tmp_path = out_dir / f".carving_tmp_{offset}"
    src.seek(offset)
    remaining = size
    with open(tmp_path, "wb") as out:
        while remaining > 0:
            data = src.read(min(READ_CHUNK_SIZE, remaining))
            if not data:
                break
            digest.update(data)
            out.write(data)
            remaining -= len(data)

    sha256 = digest.hexdigest()
    file_type = f"{base_type}_truncated" if truncated else base_type
    final_path = out_dir / f"carved_{offset}_{sha256[:8]}.{EXTENSIONS[base_type]}"
    tmp_path.replace(final_path)

    exif = _extract_jpeg_exif(final_path) if base_type == "jpeg" else None

    return CarvedFile(
        offset=offset,
        size=size,
        file_type=file_type,
        sha256=sha256,
        output_path=final_path,
        exif=exif,
    )
