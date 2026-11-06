"""Shared test configuration and fixtures.

This file is auto-loaded by pytest before any test module.  It:
  - Adds the project root to sys.path so tests can ``import app`` without
    each file repeating the same sys.path.insert boilerplate.
  - Exposes common pytest fixtures used across multiple test files.
"""
import os
import sys
import struct
import tempfile

import pytest

# ── Path setup ─────────────────────────────────────────────────────────────────
# Ensure the project root (one level above this file) is importable.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Shared packet-builder helpers ──────────────────────────────────────────────

def _pcap_header(snaplen=65535, network=1):
    """Return a libpcap global file header (little-endian, μs resolution)."""
    return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, snaplen, network)


def _pcap_record(payload, ts_sec=0, ts_usec=0):
    """Wrap *payload* bytes in a libpcap packet record."""
    return struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)) + payload


def _eth_ip_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=50000, dst_port=80,
                src_mac="aa:bb:cc:00:00:01", dst_mac="aa:bb:cc:00:00:02",
                payload=b""):
    """Build a raw Ethernet/IPv4/TCP frame as bytes."""
    def mac_bytes(m):
        return bytes(int(x, 16) for x in m.split(":"))

    def ip_bytes(a):
        return bytes(int(x) for x in a.split("."))

    tcp = struct.pack(">HHIIBBHHH",
                      src_port, dst_port,
                      0, 0,       # seq, ack
                      0x50, 0x02, # data offset=5, SYN flag
                      65535, 0, 0) + payload

    ip_hdr_no_chk = struct.pack(">BBHHHBBH4s4s",
                                0x45, 0, 20 + len(tcp),
                                0, 0, 64, 6, 0,
                                ip_bytes(src_ip), ip_bytes(dst_ip))
    # recompute checksum
    def checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF
    chk = checksum(ip_hdr_no_chk)
    ip_hdr = ip_hdr_no_chk[:10] + struct.pack(">H", chk) + ip_hdr_no_chk[12:]

    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00"
    return eth + ip_hdr + tcp


@pytest.fixture
def tmp_pcap(tmp_path):
    """Fixture: returns a helper that writes a list of raw frame bytes to a
    temporary .pcap file and returns the path string."""
    def _write(frames, ts_base=0):
        path = str(tmp_path / "test.pcap")
        with open(path, "wb") as f:
            f.write(_pcap_header())
            for i, frame in enumerate(frames):
                f.write(_pcap_record(frame, ts_sec=ts_base + i))
        return path
    return _write


@pytest.fixture
def simple_pcap(tmp_pcap):
    """Fixture: a minimal two-host TCP pcap (10.0.0.1:50000 → 10.0.0.2:80)."""
    frame = _eth_ip_tcp()
    return tmp_pcap([frame])
