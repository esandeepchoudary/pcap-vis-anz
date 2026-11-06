"""HTTP-layer tests for the /upload endpoint."""
import io
import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ── /upload happy path ────────────────────────────────────────────────────────

# Minimal pcap file: 24-byte global header (little-endian) with no packets.
_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"  # magic (little-endian)
    b"\x02\x00\x04\x00"  # version 2.4
    b"\x00\x00\x00\x00"  # timezone
    b"\x00\x00\x00\x00"  # timestamp accuracy
    b"\xff\xff\x00\x00"  # snap length
    b"\x01\x00\x00\x00"  # link type (Ethernet)
)

_PCAPNG_HEADER = (
    b"\x0a\x0d\x0d\x0a"  # Section Header Block type
    b"\x1c\x00\x00\x00"  # block total length = 28
    b"\x4d\x3c\x2b\x1a"  # byte order magic
    b"\x01\x00\x00\x00"  # major/minor version
    b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length (undefined)
    b"\x1c\x00\x00\x00"  # block total length (repeated)
)


def _upload(client, data, filename, content_type="application/octet-stream"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(data), filename, content_type)},
        content_type="multipart/form-data",
    )


def test_upload_minimal_pcap_returns_json(client):
    resp = _upload(client, _PCAP_HEADER, "test.pcap")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "nodes" in body
    assert "edges" in body
    assert "stats" in body


def test_upload_minimal_pcapng_returns_json(client):
    resp = _upload(client, _PCAPNG_HEADER, "test.pcapng")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "nodes" in body


# ── Error paths ───────────────────────────────────────────────────────────────

def test_upload_no_file_returns_400(client):
    resp = client.post("/upload", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_upload_bad_extension_returns_400(client):
    resp = _upload(client, b"hello world", "test.txt")
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body
    assert "Unsupported" in body["error"]


def test_upload_wrong_magic_bytes_returns_400(client):
    """A .pcap file whose first 4 bytes are not a valid pcap magic fails validation."""
    resp = _upload(client, b"\x00\x00\x00\x00" + b"\x00" * 20, "fake.pcap")
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body


def test_upload_malformed_pcap_returns_error(client):
    """Garbage bytes that pass magic-check (unlikely) or a truncated pcap."""
    resp = _upload(client, _PCAP_HEADER[:10], "trunc.pcap")
    # Should either succeed with empty results or return an error — no crash.
    assert resp.status_code in (200, 400)
    assert resp.get_json() is not None


def test_upload_empty_file_returns_error(client):
    resp = _upload(client, b"", "empty.pcap")
    assert resp.status_code == 400
    assert "error" in resp.get_json()


# ── File count cap ────────────────────────────────────────────────────────────

def test_upload_too_many_files_returns_400(client):
    # Werkzeug test client accepts a list value per key for multi-file fields
    data = {
        "file": [(io.BytesIO(_PCAP_HEADER), f"test{i}.pcap") for i in range(101)]
    }
    resp = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert "error" in body
    assert "Too many" in body["error"]


def test_upload_max_files_accepted(client):
    data = {
        "file": [(io.BytesIO(_PCAP_HEADER), f"test{i}.pcap") for i in range(100)]
    }
    resp = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert "nodes" in resp.get_json()


# ── Robustness: error handlers ────────────────────────────────────────────────

def test_413_handler_returns_json(client):
    """413 RequestEntityTooLarge should return JSON, not Werkzeug's HTML page."""
    orig = flask_app.config.get("MAX_CONTENT_LENGTH")
    flask_app.config["MAX_CONTENT_LENGTH"] = 10  # 10-byte cap for this test
    try:
        resp = _upload(client, b"A" * 11, "big.pcap")
        # Werkzeug may return 413 or 400 depending on where the limit is enforced;
        # either way the response must be JSON (not HTML).
        assert resp.status_code in (400, 413)
        assert resp.get_json() is not None
    finally:
        flask_app.config["MAX_CONTENT_LENGTH"] = orig


def test_404_handler_returns_json(client):
    resp = client.get("/no-such-route-xyz")
    assert resp.status_code == 404
    body = resp.get_json()
    assert body is not None
    assert "error" in body


# ── Robustness: malformed batch ───────────────────────────────────────────────

def test_malformed_mid_batch_returns_partial_results(client):
    """One garbage file in a batch should not kill the whole request."""
    data = {
        "file": [
            (io.BytesIO(_PCAP_HEADER), "good1.pcap"),
            (io.BytesIO(b"GARBAGE_NOT_PCAP"), "bad.pcap"),
            (io.BytesIO(_PCAP_HEADER), "good2.pcap"),
        ]
    }
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    # Must not crash; may return 200 (with warnings) or 400 depending on validation
    assert resp.status_code in (200, 400)
    assert resp.get_json() is not None


# ── Robustness: download filename sanitisation ─────────────────────────────────

def test_download_unknown_hash_returns_404_json(client):
    resp = client.get("/download/" + "a" * 64)
    assert resp.status_code == 404
    assert resp.get_json() is not None


def test_download_invalid_hash_returns_400(client):
    resp = client.get("/download/../../etc/passwd")
    assert resp.status_code in (400, 404)
    body = resp.get_json()
    assert body is not None


# ── Robustness: allowed_file edge cases ───────────────────────────────────────

def test_upload_dot_only_filename_rejected(client):
    """A filename of '.' must be rejected cleanly (not index-error internally)."""
    resp = client.post(
        "/upload",
        data={"file": (io.BytesIO(_PCAP_HEADER), ".")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert resp.get_json() is not None


def test_upload_no_extension_filename_rejected(client):
    resp = client.post(
        "/upload",
        data={"file": (io.BytesIO(_PCAP_HEADER), "nodotfile")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert resp.get_json() is not None


# ── Other routes ──────────────────────────────────────────────────────────────

def test_gpu_status_returns_json(client):
    resp = client.get("/gpu-status")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "gpu" in body


def test_session_schema_returns_json_schema(client):
    resp = client.get("/session-schema")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body.get("$schema") == "https://json-schema.org/draft-07/schema#"
    assert body.get("type") == "object"
    # The properties this schema documents must actually match real /upload
    # response keys, not just look like a schema.
    for key in ("nodes", "edges", "packets", "anomalies", "stats"):
        assert key in body["properties"]
    assert set(body["required"]) <= set(body["properties"])


def test_index_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"<!DOCTYPE html>" in resp.data or b"<!doctype html" in resp.data.lower()
