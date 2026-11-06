"""Tests for IPv6 extension header traversal in analyze_pcap().

Verifies that the parser correctly walks hop-by-hop, routing, destination
options, and fragment extension headers to reach the transport layer, and
that transport-layer ports/protocols are reported correctly.
"""
import os
import socket
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import analyze_pcap

# ── raw frame helpers ──────────────────────────────────────────────────────────

def _pcap_file(frames):
    """Build an in-memory pcap (little-endian, µs) from a list of raw frame bytes."""
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    records = b"".join(
        struct.pack("<IIII", i, 0, len(f), len(f)) + f
        for i, f in enumerate(frames)
    )
    return hdr + records


def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def _ip6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def _eth_ipv6_frame(
    src_ip6="fd00::1",
    dst_ip6="fd00::2",
    next_hdr=6,          # TCP by default
    payload=b"",
    ext_headers=b"",     # raw extension header bytes (already chained)
):
    """Build Ethernet / IPv6 frame with optional pre-built extension header bytes.

    next_hdr is the value placed in the IPv6 base header's Next Header field;
    if ext_headers is non-empty it should chain into TCP/UDP itself.
    """
    src_mac = _mac("aa:bb:cc:00:00:01")
    dst_mac = _mac("aa:bb:cc:00:00:02")
    eth_type = b"\x86\xdd"

    ip6_payload = ext_headers + payload
    ipv6 = struct.pack(
        ">LHBB",
        0x60000000,           # version=6, TC=0, flow=0
        len(ip6_payload),     # payload length
        next_hdr,
        64,                   # hop limit
    ) + _ip6(src_ip6) + _ip6(dst_ip6)

    return dst_mac + src_mac + eth_type + ipv6 + ip6_payload


def _tcp_hdr(sport=50000, dport=80):
    """Minimal TCP SYN segment (no payload)."""
    return struct.pack(
        ">HHIIBBHHH",
        sport, dport,
        0, 0,        # seq, ack
        0x50, 0x02,  # data offset=5, SYN flag
        65535, 0, 0,
    )


def _udp_hdr(sport=50001, dport=53, payload=b""):
    """Minimal UDP segment."""
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def _hopbyhop_ext(next_hdr, body=b"\x01\x00"):
    """Build a Hop-by-Hop Options extension header (type 0).

    The header occupies (hdr_ext_len + 1) * 8 bytes total.
    body must pad out to a multiple of 8 minus 2 (for the NH + len fields).
    We always emit exactly one 8-byte unit: NH(1) + len=0(1) + 6 pad bytes.
    """
    pad = b"\x00" * 6   # PadN: enough to fill one 8-byte unit
    raw = bytes([next_hdr, 0]) + pad   # len=0 means 8 bytes total
    assert len(raw) == 8
    return raw


def _routing_ext(next_hdr, segments=b""):
    """Build a Routing extension header (type 43), length=0 (8 bytes total)."""
    raw = bytes([next_hdr, 0, 0, 0]) + b"\x00\x00\x00\x00"
    assert len(raw) == 8
    return raw


def _dest_options_ext(next_hdr):
    """Build a Destination Options extension header (type 60), length=0 (8 bytes)."""
    raw = bytes([next_hdr, 0]) + b"\x00" * 6
    assert len(raw) == 8
    return raw


def _fragment_ext(next_hdr, offset=0, more=0, identification=0):
    """Build a Fragment extension header (type 44), always 8 bytes.

    Layout: next_header(1) + reserved(1) + frag_offset+M flag(2) + identification(4)
    """
    frag_off_m = (offset & 0x1FFF) << 3 | (more & 1)
    raw = struct.pack(">BBHI", next_hdr, 0, frag_off_m, identification)
    assert len(raw) == 8
    return raw


def _analyze_frames(frames):
    """Write frames to a temp pcap and call analyze_pcap(); return the result."""
    data = _pcap_file(frames)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        return analyze_pcap(path)
    finally:
        os.unlink(path)


# ── tests ─────────────────────────────────────────────────────────────────────

def test_ipv6_no_extension_headers_tcp():
    """Baseline: plain IPv6 / TCP — transport is detected without ext headers."""
    tcp = _tcp_hdr(sport=50000, dport=80)
    frame = _eth_ipv6_frame(next_hdr=6, payload=tcp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    assert len(edges) >= 1, "Expected at least one edge for plain IPv6/TCP"
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 80 in ports_found, f"TCP port 80 not found in plain IPv6/TCP; ports: {ports_found}"


def test_ipv6_hop_by_hop_then_tcp():
    """IPv6 with a Hop-by-Hop extension header before TCP port 80."""
    # Chain: IPv6 base NH=0 (hop-by-hop) → hop-by-hop NH=6 (TCP) → TCP
    hbh = _hopbyhop_ext(next_hdr=6)   # hop-by-hop pointing to TCP
    tcp = _tcp_hdr(sport=50000, dport=80)
    frame = _eth_ipv6_frame(next_hdr=0, ext_headers=hbh, payload=tcp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    # Without ext-header parsing, no edge would appear (proto_num=0 → no dispatch)
    assert len(edges) >= 1, "Expected at least one edge after hop-by-hop traversal"
    # Confirm the edge involves port 80 (HTTP)
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 80 in ports_found, f"TCP port 80 not found; ports seen: {ports_found}"


def test_ipv6_routing_ext_then_tcp():
    """IPv6 with a Routing extension header before TCP port 502 (Modbus)."""
    rh = _routing_ext(next_hdr=6)     # routing → TCP
    tcp = _tcp_hdr(sport=50000, dport=502)
    frame = _eth_ipv6_frame(next_hdr=43, ext_headers=rh, payload=tcp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    assert len(edges) >= 1, "Expected edge after routing header traversal"
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 502 in ports_found, f"TCP port 502 not found; ports: {ports_found}"


def test_ipv6_dest_options_ext_then_udp():
    """IPv6 with a Destination Options extension header before UDP port 53 (DNS)."""
    do = _dest_options_ext(next_hdr=17)   # dest options → UDP
    udp = _udp_hdr(sport=50000, dport=53)
    frame = _eth_ipv6_frame(next_hdr=60, ext_headers=do, payload=udp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    assert len(edges) >= 1, "Expected edge after destination options traversal"
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 53 in ports_found, f"UDP port 53 not found; ports: {ports_found}"


def test_ipv6_fragment_ext_then_tcp():
    """IPv6 with a Fragment extension header before TCP."""
    frag = _fragment_ext(next_hdr=6, offset=0, more=0, identification=42)
    tcp = _tcp_hdr(sport=50000, dport=443)
    frame = _eth_ipv6_frame(next_hdr=44, ext_headers=frag, payload=tcp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    assert len(edges) >= 1, "Expected edge after fragment header traversal"
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 443 in ports_found, f"TCP port 443 not found; ports: {ports_found}"


def test_ipv6_chained_ext_headers_hop_then_routing_then_tcp():
    """IPv6 with two chained extension headers (hop-by-hop → routing → TCP)."""
    # Chain: base NH=0 → hop-by-hop[NH=43] → routing[NH=6] → TCP
    rh  = _routing_ext(next_hdr=6)
    hbh = _hopbyhop_ext(next_hdr=43)
    tcp = _tcp_hdr(sport=50000, dport=8080)
    ext = hbh + rh
    frame = _eth_ipv6_frame(next_hdr=0, ext_headers=ext, payload=tcp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    assert len(edges) >= 1, "Expected edge after chained ext header traversal"
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 8080 in ports_found, f"TCP port 8080 not found; ports: {ports_found}"


def test_ipv6_without_ext_headers_regression():
    """Regression: plain IPv6/UDP (no ext headers) still works after the change."""
    udp = _udp_hdr(sport=12345, dport=161)  # SNMP
    frame = _eth_ipv6_frame(next_hdr=17, payload=udp)
    result = _analyze_frames([frame])
    assert "error" not in result
    edges = result.get("edges", [])
    assert len(edges) >= 1, "Expected edge for plain IPv6/UDP"
    ports_found = set()
    for e in edges:
        ports_found.update(e.get("ports", []))
    assert 161 in ports_found, f"UDP port 161 not found; ports: {ports_found}"
