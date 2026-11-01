from toolkit.core.hashing import sha256_file, verify_file


def test_sha256_file_matches_hashlib(tmp_path):
    import hashlib

    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello forensic world")
    expected = hashlib.sha256(b"hello forensic world").hexdigest()
    assert sha256_file(f) == expected


def test_sha256_file_is_deterministic(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"same bytes every time")
    assert sha256_file(f) == sha256_file(f)


def test_verify_file_detects_tamper(tmp_path):
    f = tmp_path / "evidence.bin"
    f.write_bytes(b"original evidence bytes")
    digest = sha256_file(f)
    assert verify_file(f, digest) is True

    f.write_bytes(b"tampered evidence bytes")
    assert verify_file(f, digest) is False
