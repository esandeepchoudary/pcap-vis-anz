"""Integration tests verifying pcapng upload/parse parity with pcap."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyze_pcap, merge_results

try:
    from scapy.utils import PcapNgWriter, wrpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")


# ── Helpers ────────────────────────────────────────────────────────────────────

MAC_A = "aa:bb:cc:11:00:01"
MAC_B = "aa:bb:cc:11:00:02"
MAC_C = "aa:bb:cc:11:00:03"
IP_A  = "10.1.0.1"
IP_B  = "10.1.0.2"
IP_C  = "10.1.0.3"


def _make_pkts():
    """Return a deterministic list of Ethernet/IP packets (TCP + DNS)."""
    return [
        # TCP SYN from A→B port 80
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        # TCP SYN-ACK from B→A
        Ether(src=MAC_B, dst=MAC_A) / IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=50001, flags="SA"),
        # TCP data A→B
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="A"),
        # DNS query from A→C (port 53)
        Ether(src=MAC_A, dst=MAC_C) / IP(src=IP_A, dst=IP_C) / UDP(sport=5300, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.com")),
    ]


def _write_pcapng(path, pkts):
    with PcapNgWriter(str(path)) as w:
        for p in pkts:
            w.write(p)


def _write_pcap(path, pkts):
    wrpcap(str(path), pkts)


def _file_is_pcapng(path):
    with open(str(path), "rb") as f:
        return f.read(4) == b"\x0a\x0d\x0d\x0a"


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_pcapng_file_is_actually_pcapng(tmp_path):
    """Sanity-check: PcapNgWriter really produces pcapng magic bytes."""
    p = tmp_path / "check.pcapng"
    _write_pcapng(p, _make_pkts())
    assert _file_is_pcapng(p), "PcapNgWriter did not produce pcapng magic 0x0a0d0d0a"


def test_analyze_pcapng_basic(tmp_path):
    """analyze_pcap() parses a pcapng file and produces the expected output."""
    pkts = _make_pkts()
    p = tmp_path / "test.pcapng"
    _write_pcapng(p, pkts)
    assert _file_is_pcapng(p)

    result = analyze_pcap(str(p))
    assert "error" not in result, f"analyze_pcap returned error: {result.get('error')}"

    node_ips = {n["ip"] for n in result["nodes"]}
    assert IP_A in node_ips, f"{IP_A} not found in nodes"
    assert IP_B in node_ips, f"{IP_B} not found in nodes"
    assert IP_C in node_ips, f"{IP_C} not found in nodes"
    assert len(node_ips) == 3

    # Expect 2 connections: A↔B (TCP) and A↔C (DNS/UDP)
    assert result["stats"]["total_connections"] == 2
    assert result["stats"]["total_packets"]     == len(pkts)

    # Each connection has at least one packet
    for edge in result["edges"]:
        assert edge["packet_count"] >= 1


def test_pcap_pcapng_parity(tmp_path):
    """analyze_pcap() produces the same structure for pcap and pcapng of identical packets."""
    pkts = _make_pkts()
    pcap_path   = tmp_path / "parity.pcap"
    pcapng_path = tmp_path / "parity.pcapng"
    _write_pcap(pcap_path, pkts)
    _write_pcapng(pcapng_path, pkts)

    r_pcap   = analyze_pcap(str(pcap_path))
    r_pcapng = analyze_pcap(str(pcapng_path))

    assert "error" not in r_pcap,   f"pcap error: {r_pcap.get('error')}"
    assert "error" not in r_pcapng, f"pcapng error: {r_pcapng.get('error')}"

    assert len(r_pcap["nodes"])   == len(r_pcapng["nodes"]),   "host count differs"
    assert len(r_pcap["edges"])   == len(r_pcapng["edges"]),   "edge count differs"
    assert r_pcap["stats"]["total_packets"] == r_pcapng["stats"]["total_packets"], \
        "packet count differs"

    pcap_ips   = {n["ip"] for n in r_pcap["nodes"]}
    pcapng_ips = {n["ip"] for n in r_pcapng["nodes"]}
    assert pcap_ips == pcapng_ips, f"node IPs differ: {pcap_ips} vs {pcapng_ips}"

    pcap_edges   = {(e["source"], e["target"]) for e in r_pcap["edges"]}
    pcapng_edges = {(e["source"], e["target"]) for e in r_pcapng["edges"]}
    assert pcap_edges == pcapng_edges, f"edge pairs differ"


def test_merge_mixed_formats(tmp_path):
    """merge_results() correctly merges a pcap result and a pcapng result."""
    pkts = _make_pkts()

    # Capture 1 (pcap): A↔B traffic only
    pcap_pkts = [p for p in pkts if IP_C not in (p[IP].src if p.haslayer(IP) else "", p[IP].dst if p.haslayer(IP) else "")]
    pcap_path = tmp_path / "cap1.pcap"
    _write_pcap(pcap_path, pcap_pkts)

    # Capture 2 (pcapng): A↔C traffic only
    pcapng_pkts = [p for p in pkts if p.haslayer(IP) and (p[IP].src == IP_C or p[IP].dst == IP_C)]
    pcapng_path = tmp_path / "cap2.pcapng"
    _write_pcapng(pcapng_path, pcapng_pkts)
    assert _file_is_pcapng(pcapng_path)

    r1 = analyze_pcap(str(pcap_path))
    r2 = analyze_pcap(str(pcapng_path))
    assert "error" not in r1 and "error" not in r2

    merged = merge_results([r1, r2])
    merged_ips = {n["ip"] for n in merged["nodes"]}

    # All three IPs should appear in the merged result
    assert IP_A in merged_ips
    assert IP_B in merged_ips
    assert IP_C in merged_ips

    # Total packets should equal the sum across both files
    total = r1["stats"]["total_packets"] + r2["stats"]["total_packets"]
    assert merged["stats"]["total_packets"] == total
