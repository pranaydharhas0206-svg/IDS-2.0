import hashlib
import struct
import zlib

import pytest

from toolkit.carving import carve_media


def _minimal_jpeg() -> bytes:
    """A tiny but well-formed JPEG: SOI + APP0/JFIF segment + EOI."""
    app0 = (
        b"\xff\xe0"          # APP0 marker
        b"\x00\x10"          # segment length (16, includes these 2 bytes)
        b"JFIF\x00"          # identifier
        b"\x01\x01"          # version
        b"\x00"              # units
        b"\x00\x01\x00\x01"  # density x/y
        b"\x00\x00"          # thumbnail w/h
    )
    return b"\xff\xd8" + app0 + b"\xff\xd9"


def _jpeg_with_exif(date_time_original=None, gps=None) -> bytes:
    """A minimal JPEG with an APP1/EXIF segment carrying a hand-built TIFF.

    `date_time_original`, if given, is written as EXIF tag 0x9003
    (DateTimeOriginal, ASCII). `gps`, if given, is (lat_deg, lat_ref,
    lon_deg, lon_ref) written as GPSLatitude/GPSLatitudeRef/GPSLongitude/
    GPSLongitudeRef (each latitude/longitude as (deg, min, sec) rationals).
    Little-endian ("II") TIFF byte order.
    """

    def rational(num, den=1):
        return struct.pack("<II", num, den)

    def decimal_to_dms_rationals(value: float) -> bytes:
        deg = int(value)
        rem = (value - deg) * 60
        minutes = int(rem)
        seconds = (rem - minutes) * 60
        return (
            rational(deg, 1)
            + rational(minutes, 1)
            + rational(int(round(seconds * 100)), 100)
        )

    # --- Build IFD entries and their external ("overflow") data blocks. ---
    # TIFF header is 8 bytes ("II", 0x002A, IFD0 offset=8); all offsets in
    # entries are relative to the start of the TIFF data (this header).
    tiff_header = b"II" + struct.pack("<H", 0x002A) + struct.pack("<I", 8)

    ifd0_entries = []
    extra_blocks = []  # list of bytes, appended after all IFDs, in order

    exif_ifd_entries = []
    exif_extra_blocks = []
    if date_time_original is not None:
        value = date_time_original.encode("ascii") + b"\x00"
        exif_extra_blocks.append(("datetime", value))
        exif_ifd_entries.append((0x9003, 2, len(value), "datetime"))

    gps_ifd_entries = []
    gps_extra_blocks = []
    if gps is not None:
        lat_deg, lat_ref, lon_deg, lon_ref = gps
        lat_ref_bytes = (lat_ref.encode("ascii") + b"\x00\x00\x00")[:4]  # pad to 4
        lon_ref_bytes = (lon_ref.encode("ascii") + b"\x00\x00\x00")[:4]
        lat_rationals = decimal_to_dms_rationals(lat_deg)
        lon_rationals = decimal_to_dms_rationals(lon_deg)
        gps_extra_blocks.append(("lat", lat_rationals))
        gps_extra_blocks.append(("lon", lon_rationals))
        gps_ifd_entries.append((0x0001, 2, 2, None, lat_ref_bytes[:4]))
        gps_ifd_entries.append((0x0002, 5, 3, "lat", None))
        gps_ifd_entries.append((0x0003, 2, 2, None, lon_ref_bytes[:4]))
        gps_ifd_entries.append((0x0004, 5, 3, "lon", None))

    # Layout, in this order, right after the TIFF header:
    #   IFD0, [ExifIFD], [GPSIFD], datetime bytes, lat rationals, lon rationals
    pos = len(tiff_header)

    ifd0_count = len(ifd0_entries) + (1 if exif_ifd_entries else 0) + (1 if gps_ifd_entries else 0)
    ifd0_size = 2 + ifd0_count * 12 + 4
    ifd0_offset = pos
    pos += ifd0_size

    exif_ifd_offset = None
    if exif_ifd_entries:
        exif_ifd_offset = pos
        pos += 2 + len(exif_ifd_entries) * 12 + 4

    gps_ifd_offset = None
    if gps_ifd_entries:
        gps_ifd_offset = pos
        pos += 2 + len(gps_ifd_entries) * 12 + 4

    block_offsets = {}
    for name, data in exif_extra_blocks + gps_extra_blocks:
        block_offsets[name] = pos
        pos += len(data)

    def build_ifd(entries, block_offsets, next_ifd_offset=0):
        out = struct.pack("<H", len(entries))
        for entry in entries:
            if len(entry) == 5:
                tag, typ, count, block_name, inline_value = entry
            else:
                tag, typ, count, block_name = entry
                inline_value = None
            if inline_value is not None:
                value_field = inline_value
            else:
                value_field = struct.pack("<I", block_offsets[block_name])
            out += struct.pack("<HHI", tag, typ, count) + value_field
        out += struct.pack("<I", next_ifd_offset)
        return out

    full_ifd0_entries = list(ifd0_entries)
    if exif_ifd_entries:
        full_ifd0_entries.append((0x8769, 4, 1, None, struct.pack("<I", exif_ifd_offset)))
    if gps_ifd_entries:
        full_ifd0_entries.append((0x8825, 4, 1, None, struct.pack("<I", gps_ifd_offset)))

    tiff_bytes = tiff_header
    tiff_bytes += build_ifd(full_ifd0_entries, block_offsets)
    if exif_ifd_entries:
        tiff_bytes += build_ifd(exif_ifd_entries, block_offsets)
    if gps_ifd_entries:
        tiff_bytes += build_ifd(gps_ifd_entries, block_offsets)
    for _name, data in exif_extra_blocks + gps_extra_blocks:
        tiff_bytes += data

    app1_payload = b"Exif\x00\x00" + tiff_bytes
    app1 = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload

    return b"\xff\xd8" + app1 + b"\xff\xd9"


def _minimal_png() -> bytes:
    """A tiny but well-formed 1x1 PNG: signature + IHDR + IDAT + IEND."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _minimal_mp4() -> bytes:
    """A tiny but well-formed MP4: ftyp box + free box + mdat box."""

    def box(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", 8 + len(payload)) + tag + payload

    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isom")
    free = box(b"free", b"\x00" * 4)
    mdat = box(b"mdat", b"\x01\x02\x03\x04\x05\x06\x07\x08")
    return ftyp + free + mdat


# Filler bytes that deliberately avoid every signature/marker this module
# scans for (no 0xFF byte at all, so no accidental JPEG SOI/EOI; not the
# PNG signature; no "ftyp" substring).
PADDING = b"PADDING-BYTES-NOT-A-SIGNATURE-" * 20


def test_carve_media_finds_embedded_jpeg_png_and_mp4(tmp_path):
    jpeg_bytes = _minimal_jpeg()
    png_bytes = _minimal_png()
    mp4_bytes = _minimal_mp4()

    image = bytearray()
    image += PADDING
    jpeg_offset = len(image)
    image += jpeg_bytes
    image += PADDING
    png_offset = len(image)
    image += png_bytes
    image += PADDING
    mp4_offset = len(image)
    image += mp4_bytes
    image += PADDING

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir)

    assert len(results) == 3
    by_offset = {r.offset: r for r in results}

    jpeg_result = by_offset[jpeg_offset]
    assert jpeg_result.file_type == "jpeg"
    assert jpeg_result.size == len(jpeg_bytes)
    assert jpeg_result.sha256 == hashlib.sha256(jpeg_bytes).hexdigest()
    assert jpeg_result.output_path.exists()
    assert jpeg_result.output_path.read_bytes() == jpeg_bytes
    assert jpeg_result.exif is None

    png_result = by_offset[png_offset]
    assert png_result.file_type == "png"
    assert png_result.size == len(png_bytes)
    assert png_result.sha256 == hashlib.sha256(png_bytes).hexdigest()
    assert png_result.output_path.read_bytes() == png_bytes

    mp4_result = by_offset[mp4_offset]
    assert mp4_result.file_type == "mp4"
    assert mp4_result.size == len(mp4_bytes)
    assert mp4_result.sha256 == hashlib.sha256(mp4_bytes).hexdigest()
    assert mp4_result.output_path.read_bytes() == mp4_bytes

    for result in results:
        assert result.output_path.name == (
            f"carved_{result.offset}_{result.sha256[:8]}"
            f".{result.output_path.suffix.lstrip('.')}"
        )


def test_carve_media_truncates_at_size_cap_when_no_end_signature(tmp_path):
    max_file_size = 100

    image = bytearray()
    image += PADDING
    jpeg_offset = len(image)
    image += b"\xff\xd8"  # SOI with no matching EOI anywhere in the file
    # Filler that contains no 0xFF byte at all, so no accidental EOI, well
    # past the size cap.
    image += b"\x41" * (max_file_size * 3)

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir, max_file_size=max_file_size)

    assert len(results) == 1
    result = results[0]
    assert result.offset == jpeg_offset
    assert result.file_type == "jpeg_truncated"
    assert result.size == max_file_size
    assert result.output_path.stat().st_size == max_file_size


def test_carve_media_scan_survives_chunk_boundary_split_signature(tmp_path, monkeypatch):
    import toolkit.carving as carving_module

    # Force a tiny chunk size so the JPEG's start signature and the PNG's
    # 8-byte signature are each guaranteed to straddle a chunk boundary at
    # least once during the scan, exercising the overlap logic.
    monkeypatch.setattr(carving_module, "READ_CHUNK_SIZE", 5)

    jpeg_bytes = _minimal_jpeg()
    png_bytes = _minimal_png()

    image = bytearray()
    image += PADDING
    jpeg_offset = len(image)
    image += jpeg_bytes
    image += PADDING
    png_offset = len(image)
    image += png_bytes
    image += PADDING

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir)

    offsets = {r.offset: r.file_type for r in results}
    assert offsets.get(jpeg_offset) == "jpeg"
    assert offsets.get(png_offset) == "png"


def test_carve_media_extracts_exif_from_jpeg_with_datetime_and_gps(tmp_path):
    jpeg_bytes = _jpeg_with_exif(
        date_time_original="2024:03:15 10:30:00",
        gps=(12.345, "N", 98.765, "E"),
    )

    image = bytearray()
    image += PADDING
    jpeg_offset = len(image)
    image += jpeg_bytes
    image += PADDING

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir)

    by_offset = {r.offset: r for r in results}
    jpeg_result = by_offset[jpeg_offset]

    assert jpeg_result.exif is not None
    assert jpeg_result.exif["DateTimeOriginal"] == "2024:03:15 10:30:00"
    assert jpeg_result.exif["GPSLatitude"] == pytest.approx(12.345, abs=1e-3)
    assert jpeg_result.exif["GPSLongitude"] == pytest.approx(98.765, abs=1e-3)


def test_carve_media_rejects_coincidental_ftyp_match_with_invalid_leading_box(tmp_path):
    """A stray "ftyp" 4-byte substring not preceded by a valid box size must
    be rejected as a candidate, not carved as a giant garbage "file" up to
    the size cap (see final-review.md Important #1)."""
    max_file_size = 100

    image = bytearray()
    image += PADDING
    # A coincidental "ftyp" match: the 4 bytes immediately before it do not
    # form a valid box size (3 < 8, the minimum box header size), so the
    # leading box at this offset fails to validate.
    bogus_offset = len(image)
    image += struct.pack(">I", 3) + b"ftyp"
    # Filler well past the size cap, containing no other signatures, so if
    # the bug were present this candidate would be carved as a large
    # "file" spanning most of this filler.
    image += b"\x41" * (max_file_size * 3)

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir, max_file_size=max_file_size)

    mp4_results = [r for r in results if r.offset == bogus_offset]
    assert mp4_results == []
    assert results == []
    # No carved output file should have been written for the bogus candidate.
    assert list(out_dir.iterdir()) == []


def test_carve_media_jpeg_without_exif_has_none_exif(tmp_path):
    jpeg_bytes = _minimal_jpeg()

    image = bytearray()
    image += PADDING
    jpeg_offset = len(image)
    image += jpeg_bytes
    image += PADDING

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir)

    by_offset = {r.offset: r for r in results}
    jpeg_result = by_offset[jpeg_offset]

    assert jpeg_result.exif is None


def test_carve_media_jpeg_malformed_exif_degrades_to_none(tmp_path, monkeypatch):
    """A malformed/partial EXIF block must not crash the carve operation."""
    import toolkit.carving as carving_module

    jpeg_bytes = _jpeg_with_exif(date_time_original="2024:03:15 10:30:00")
    # Corrupt the TIFF header (right after "Exif\x00\x00") so byte-order and
    # IFD parsing hits garbage instead of a well-formed TIFF structure.
    marker = b"Exif\x00\x00"
    idx = jpeg_bytes.index(marker) + len(marker)
    corrupted = bytearray(jpeg_bytes)
    corrupted[idx:idx + 8] = b"\x00" * 8
    jpeg_bytes = bytes(corrupted)

    image = bytearray()
    image += PADDING
    jpeg_offset = len(image)
    image += jpeg_bytes
    image += PADDING

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(bytes(image))
    out_dir = tmp_path / "carved"

    results = carve_media(image_path, out_dir)  # must not raise

    by_offset = {r.offset: r for r in results}
    jpeg_result = by_offset[jpeg_offset]
    assert jpeg_result.exif is None
