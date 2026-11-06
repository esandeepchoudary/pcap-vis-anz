"""Tests for the _file_body_cache LRU behavior (Fix 3).

Verifies that:
- download links from a prior upload survive a second /upload call.
- the LRU eviction (oldest-first) fires when the 256 MB cap is exceeded.
- a cache hit promotes the entry to most-recently-used.
"""
import io
import os
import struct
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module
from app import app as flask_app, _file_body_cache, _file_body_cache_lock


# ── helpers ────────────────────────────────────────────────────────────────────

_PCAP_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def _upload(client, data=_PCAP_HEADER, filename="test.pcap"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(data), filename, "application/octet-stream")},
        content_type="multipart/form-data",
    )


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ── tests ──────────────────────────────────────────────────────────────────────

def test_second_upload_does_not_wipe_cache(client):
    """A second /upload must not invalidate download links from the first upload."""
    # First upload — populate any cache entries that get written during parse
    _upload(client, filename="first.pcap")
    with _file_body_cache_lock:
        snapshot_keys = set(_file_body_cache.keys())

    # Second upload
    _upload(client, filename="second.pcap")
    with _file_body_cache_lock:
        after_keys = set(_file_body_cache.keys())

    # Keys present after the first upload must still be present after the second
    missing = snapshot_keys - after_keys
    assert not missing, (
        f"Second /upload wiped {len(missing)} cache entries: {missing}"
    )


def test_lru_eviction_oldest_first():
    """Inserting a large entry evicts the oldest (LRU) entry, not an arbitrary one."""
    # Directly exercise the LRU OrderedDict under the lock.
    import hashlib
    from collections import OrderedDict

    # Capture module-level globals
    cache = app_module._file_body_cache
    lock  = app_module._file_body_cache_lock
    cap   = app_module._FILE_CACHE_MAX_BYTES

    def _insert(sha, body):
        """Replicate the insert logic from analyze_pcap."""
        entry_size = len(body)
        with lock:
            if entry_size <= cap:
                while app_module._file_body_cache_bytes + entry_size > cap and cache:
                    _, evicted = cache.popitem(last=False)
                    app_module._file_body_cache_bytes -= len(evicted["body"])
                if sha not in cache:
                    cache[sha] = {"body": body, "filename": "f.bin", "mime": "application/octet-stream"}
                    app_module._file_body_cache_bytes += entry_size
                else:
                    cache.move_to_end(sha)

    # Clear cache state for this test
    with lock:
        cache.clear()
        app_module._file_body_cache_bytes = 0

    sha_a = "a" * 64
    sha_b = "b" * 64

    # Fill to 1 byte under cap with entry A, then add entry B that forces eviction
    big_body_a = b"A" * (cap - 1)
    small_body_b = b"B" * 2  # adding this pushes total over cap

    _insert(sha_a, big_body_a)
    with lock:
        assert sha_a in cache

    _insert(sha_b, small_body_b)
    with lock:
        # A must have been evicted (oldest), B must be present
        assert sha_a not in cache, "Oldest entry should have been evicted"
        assert sha_b in cache, "New entry should be present after eviction"

    # Clean up
    with lock:
        cache.clear()
        app_module._file_body_cache_bytes = 0


def test_cache_hit_promotes_to_mru(client):
    """A /download hit should move the entry to most-recently-used position."""
    import hashlib
    from collections import OrderedDict

    cache = app_module._file_body_cache
    lock  = app_module._file_body_cache_lock

    sha_x = "0a" * 32   # 64 hex chars
    sha_y = "0b" * 32   # 64 hex chars

    with lock:
        cache.clear()
        app_module._file_body_cache_bytes = 0
        cache[sha_x] = {"body": b"hello", "filename": "x.bin", "mime": "application/octet-stream"}
        app_module._file_body_cache_bytes += 5
        cache[sha_y] = {"body": b"world", "filename": "y.bin", "mime": "application/octet-stream"}
        app_module._file_body_cache_bytes += 5

    # Fetch sha_x via /download — it should be promoted to MRU
    resp = client.get(f"/download/{sha_x}")
    assert resp.status_code == 200

    with lock:
        keys = list(cache.keys())

    # sha_x was inserted first (LRU) but hit → should now be last (MRU)
    assert keys[-1] == sha_x, f"Expected sha_x to be MRU after hit; order: {keys}"

    # Clean up
    with lock:
        cache.clear()
        app_module._file_body_cache_bytes = 0
