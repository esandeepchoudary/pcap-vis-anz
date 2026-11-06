"""Tests for full-fidelity serialization: no per-field truncation in output,
and honest backstop flags in stats."""
import os
import sys
import struct

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import analyze_pcap
from tests.conftest import _pcap_header, _pcap_record, _eth_ip_tcp


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_pcap(tmp_path, frames, ts_base=0):
    """Write frames to a temp pcap file and return the path."""
    path = str(tmp_path / "test.pcap")
    with open(path, "wb") as f:
        f.write(_pcap_header())
        for i, frame in enumerate(frames):
            f.write(_pcap_record(frame, ts_sec=ts_base + i))
    return path


def _make_frames_for_ports(src_ip, dst_ip, dst_ports):
    """Generate one TCP SYN frame per dst_port (same src/dst hosts, varied dst port)."""
    return [_eth_ip_tcp(src_ip=src_ip, dst_ip=dst_ip, src_port=50000, dst_port=p)
            for p in dst_ports]


# ── Tests: per-field un-truncation ────────────────────────────────────────────

def test_edge_ports_not_truncated(tmp_path):
    """A connection touching >20 distinct destination ports must appear fully in
    the serialized edge's 'ports' list — the old [:20] slice is removed."""
    dst_ports = list(range(80, 125))  # 45 distinct ports
    frames = _make_frames_for_ports("10.0.0.1", "10.0.0.2", dst_ports)
    pcap = _write_pcap(tmp_path, frames)

    result = analyze_pcap(pcap)
    edges = result["edges"]
    assert edges, "Expected at least one edge"

    # Find the edge for this pair (sorted key)
    target_edge = None
    for e in edges:
        src, dst = e["source"], e["target"]
        if set([src, dst]) == {"10.0.0.1", "10.0.0.2"}:
            target_edge = e
            break

    assert target_edge is not None, "Edge 10.0.0.1<->10.0.0.2 not found"
    edge_ports = target_edge["ports"]
    # All 45 ports must be present — not truncated to 20
    assert len(edge_ports) == len(dst_ports), (
        f"Expected {len(dst_ports)} ports, got {len(edge_ports)}: {edge_ports}"
    )
    for p in dst_ports:
        assert p in edge_ports, f"Port {p} missing from edge ports"


def test_node_open_ports_not_truncated(tmp_path):
    """A host seen on >30 distinct destination ports must have all ports in its
    serialized 'open_ports' list — the old [:30] slice is removed."""
    dst_ports = list(range(1024, 1065))  # 41 distinct ports
    frames = _make_frames_for_ports("10.1.0.1", "10.1.0.2", dst_ports)
    pcap = _write_pcap(tmp_path, frames)

    result = analyze_pcap(pcap)
    nodes = {n["ip"]: n for n in result["nodes"]}
    assert "10.1.0.2" in nodes, "Destination host not found in nodes"

    dst_node = nodes["10.1.0.2"]
    open_ports = dst_node["open_ports"]
    # All 41 ports must be present — not truncated to 30
    assert len(open_ports) == len(dst_ports), (
        f"Expected {len(dst_ports)} open ports on 10.1.0.2, got {len(open_ports)}"
    )
    for p in dst_ports:
        assert p in open_ports, f"Port {p} missing from open_ports"


# ── Tests: truncation-flag keys in stats ──────────────────────────────────────

def test_stats_has_truncation_flags(tmp_path):
    """Stats must always carry hosts_truncated and connections_truncated keys,
    both False for a small normal capture."""
    frames = [_eth_ip_tcp("10.0.0.1", "10.0.0.2")]
    pcap = _write_pcap(tmp_path, frames)

    result = analyze_pcap(pcap)
    stats = result["stats"]
    assert "hosts_truncated" in stats, "stats.hosts_truncated key missing"
    assert "connections_truncated" in stats, "stats.connections_truncated key missing"
    assert stats["hosts_truncated"] is False, "hosts_truncated should be False for small capture"
    assert stats["connections_truncated"] is False, "connections_truncated should be False for small capture"


# ── Tests: telnet cred-state cap does not drop packet counts (H3 regression) ──

def test_telnet_cred_cap_does_not_drop_packet_count(tmp_path, monkeypatch):
    """H3 fix: when the telnet cred-state table is full, subsequent telnet packets
    must still be counted toward hosts and edges — the old ``continue`` skipped the
    entire packet iteration including the counters.

    We monkeypatch MAX_CRED_STATE_ENTRIES to 0 so a single telnet packet triggers
    the cap guard, then assert the edge/host packet_count is non-zero.
    """
    import app as app_module

    # Lower the cap to 0 → every new telnet conn_key is "full", exercising the guard
    monkeypatch.setattr(app_module, "MAX_CRED_STATE_ENTRIES", 0)

    # Build a minimal Telnet TCP frame (port 23) with a tiny payload
    from tests.conftest import _pcap_header, _pcap_record, _eth_ip_tcp
    frame = _eth_ip_tcp(src_ip="10.5.0.1", dst_ip="10.5.0.2", src_port=54321, dst_port=23,
                        payload=b"login: ")
    path = str(tmp_path / "telnet_test.pcap")
    with open(path, "wb") as f:
        f.write(_pcap_header())
        f.write(_pcap_record(frame, ts_sec=0))

    result = app_module.analyze_pcap(path)

    # The packet must have been counted — edge and host should exist
    edges = {(e["source"], e["target"]): e for e in result.get("edges", [])}
    nodes = {n["ip"]: n for n in result.get("nodes", [])}

    assert "10.5.0.1" in nodes or "10.5.0.2" in nodes, (
        "Neither telnet host was recorded — packet counting appears broken"
    )
    # Find the edge (direction may be either way)
    pair = edges.get(("10.5.0.1", "10.5.0.2")) or edges.get(("10.5.0.2", "10.5.0.1"))
    assert pair is not None, "Telnet edge not recorded — packet was silently dropped"
    assert pair["packet_count"] >= 1, (
        f"Edge packet_count={pair['packet_count']} — telnet cap guard skipped packet counting"
    )
