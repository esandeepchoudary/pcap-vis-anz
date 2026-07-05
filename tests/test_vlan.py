"""Tests for VLAN tag (802.1Q / QinQ) parsing and VLAN anomaly detection."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyze_pcap, merge_results, analyze_anomalies

try:
    from scapy.utils import wrpcap
    from scapy.layers.l2 import Ether, Dot1Q, Dot1AD, ARP
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")

MAC_A = "aa:bb:cc:11:00:01"
MAC_B = "aa:bb:cc:11:00:02"
MAC_C = "aa:bb:cc:11:00:03"
MAC_D = "aa:bb:cc:11:00:04"
IP_A  = "10.10.1.1"
IP_B  = "10.10.2.1"
IP_C  = "10.10.3.1"
IP_D  = "10.10.4.1"


def _write(path, pkts):
    wrpcap(str(path), pkts)


def _analyze(pkts):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        _write(f.name, pkts)
        result = analyze_pcap(f.name)
    os.unlink(f.name)
    return result


def _node(result, ip):
    return next((n for n in result["nodes"] if n["ip"] == ip), None)


# ── Single 802.1Q tag ─────────────────────────────────────────────────────────

def test_single_vlan_tag_extracted():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10, prio=2) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        Ether(src=MAC_B, dst=MAC_A) / Dot1Q(vlan=10, prio=2) /
        IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=50001, flags="SA"),
    ]
    r = _analyze(pkts)
    assert "error" not in r
    assert 10 in (r["stats"]["vlans"] or [])
    assert r["stats"]["vlans_detected"] >= 1

    na = _node(r, IP_A)
    nb = _node(r, IP_B)
    assert na is not None and nb is not None
    assert 10 in na["vlans"]
    assert 10 in nb["vlans"]
    assert 2 in na["vlan_pcps"]
    assert not na["vlan_untagged"]
    assert not na["vlan_qinq"]


def test_multiple_vlans_different_hosts():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        Ether(src=MAC_C, dst=MAC_D) / Dot1Q(vlan=20) /
        IP(src=IP_C, dst=IP_D) / TCP(sport=50002, dport=443, flags="S"),
    ]
    r = _analyze(pkts)
    vlans = r["stats"]["vlans"]
    assert 10 in vlans
    assert 20 in vlans
    assert r["stats"]["vlans_detected"] == 2


def test_untagged_frame_no_vlan_fields():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) /
        TCP(sport=50001, dport=80, flags="S"),
    ]
    r = _analyze(pkts)
    assert r["stats"]["vlans_detected"] == 0
    na = _node(r, IP_A)
    assert na is not None
    assert na["vlans"] == []
    assert na["vlan_untagged"] is True
    assert na["vlan_qinq"] is False


def test_vlan_id_in_edge():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=42) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        Ether(src=MAC_B, dst=MAC_A) / Dot1Q(vlan=42) /
        IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=50001, flags="SA"),
    ]
    r = _analyze(pkts)
    edges = r["edges"]
    assert len(edges) >= 1
    edge = next((e for e in edges if set([e["source"], e["target"]]) == {IP_A, IP_B}), None)
    assert edge is not None
    assert 42 in edge["vlans"]


# ── QinQ (802.1ad double-tagged) ──────────────────────────────────────────────

def test_qinq_outer_inner_vlan_extracted():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1AD(vlan=100) / Dot1Q(vlan=200, prio=4) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
    ]
    r = _analyze(pkts)
    na = _node(r, IP_A)
    assert na is not None
    assert na["vlan_qinq"] is True
    assert 200 in na["vlans"]
    assert 100 in na["vlan_outer"]
    assert 4 in na["vlan_pcps"]


def test_stacked_dot1q_qinq_extracted():
    """Regression: legacy tag-in-tag QinQ (0x8100 outer + 0x8100 inner, no 0x88A8)
    must not be silently dropped. Before the fix, this frame's second ethertype
    (0x8100) matched no known L3 type and the whole packet was discarded — no host,
    no VLAN, no flow recorded."""
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=100) / Dot1Q(vlan=200, prio=4) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
    ]
    r = _analyze(pkts)
    assert "error" not in r
    na = _node(r, IP_A)
    assert na is not None, "stacked 0x8100/0x8100 QinQ frame was dropped"
    assert na["vlan_qinq"] is True
    assert 200 in na["vlans"]
    assert 100 in na["vlan_outer"]
    assert 4 in na["vlan_pcps"]


# ── JSON round-trip: VLAN fields present on all nodes ─────────────────────────

def test_vlan_fields_present_on_all_nodes():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=15) /
        IP(src=IP_A, dst=IP_B) / UDP(sport=1000, dport=1001),
    ]
    r = _analyze(pkts)
    for node in r["nodes"]:
        assert "vlans" in node
        assert "vlan_outer" in node
        assert "vlan_pcps" in node
        assert "vlan_untagged" in node
        assert "vlan_qinq" in node
    assert "vlans" in r["stats"]
    assert "vlans_detected" in r["stats"]


# ── Merge: VLAN sets unioned across PCAPs ─────────────────────────────────────

def test_merge_vlan_sets_unioned():
    pkts1 = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
    ]
    pkts2 = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=20) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50002, dport=80, flags="S"),
    ]
    r1 = _analyze(pkts1)
    r2 = _analyze(pkts2)
    merged = merge_results([r1, r2])
    na = next((n for n in merged["nodes"] if n["ip"] == IP_A), None)
    assert na is not None
    assert 10 in na["vlans"]
    assert 20 in na["vlans"]
    assert merged["stats"]["vlans_detected"] == 2


def test_merge_vlan_untagged_ored():
    pkts1 = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) /
        TCP(sport=50001, dport=80, flags="S"),
    ]
    pkts2 = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50002, dport=80, flags="S"),
    ]
    r1 = _analyze(pkts1)
    r2 = _analyze(pkts2)
    merged = merge_results([r1, r2])
    na = next((n for n in merged["nodes"] if n["ip"] == IP_A), None)
    assert na["vlan_untagged"] is True
    assert 10 in na["vlans"]


# ── Anomaly detection ─────────────────────────────────────────────────────────

def _make_host(vlan_ids=None, vlan_untagged=False, vlan_qinq=False, vlan_outer_ids=None,
               host_type="Windows Host", ot_role="unknown", is_private=True, bytes_sent=0):
    return {
        "bytes_sent": bytes_sent,
        "bytes_recv": 0,
        "host_type": host_type,
        "packet_count": 1,
        "is_private": is_private,
        "vlan_ids": set(vlan_ids or []),
        "vlan_untagged": vlan_untagged,
        "vlan_qinq": vlan_qinq,
        "vlan_outer_ids": set(vlan_outer_ids or []),
        "vlan_pcps": set(),
        "ot_role": ot_role,
        "tls_ja3": set(),
        "dns_queries": set(),
        "modbus_unit_ids": set(),
    }


def _conn(dst_ports=None, packet_count=1, bytes_total=0, vlan_ids=None):
    return {
        "dst_ports": set(dst_ports or []),
        "packet_count": packet_count,
        "bytes": bytes_total,
        "vlan_ids": set(vlan_ids or []),
    }


def test_vlan_hopping_detected():
    hosts = {
        "10.0.0.1": _make_host(vlan_ids={10, 20}, host_type="Windows Host"),
        "10.0.0.2": _make_host(vlan_ids={10}),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(vlan_ids={10})}
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_hopping" in types
    a = next(x for x in anomalies if x["type"] == "vlan_hopping")
    assert a["src"] == "10.0.0.1"
    assert a["severity"] == "medium"


def test_vlan_native_leak_detected():
    hosts = {
        "10.0.0.1": _make_host(vlan_ids={10}, vlan_untagged=True),
        "10.0.0.2": _make_host(vlan_ids={10}),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(vlan_ids={10})}
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_native_leak" in types
    a = next(x for x in anomalies if x["type"] == "vlan_native_leak")
    assert a["severity"] == "low"


def test_vlan_qinq_anomaly_detected():
    hosts = {
        "10.0.0.1": _make_host(vlan_ids={200}, vlan_qinq=True, vlan_outer_ids={100}),
        "10.0.0.2": _make_host(vlan_ids={200}),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(vlan_ids={200})}
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_qinq" in types
    a = next(x for x in anomalies if x["type"] == "vlan_qinq")
    assert a["severity"] == "medium"


def test_vlan_cross_segment_ot_detected():
    hosts = {
        "10.0.0.10": _make_host(vlan_ids={10}, host_type="PLC", ot_role="outstation"),
        "10.0.0.20": _make_host(vlan_ids={20}, host_type="Windows Host"),
    }
    connections = {
        ("10.0.0.10", "10.0.0.20"): _conn(dst_ports={502}, vlan_ids={10}),
    }
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_cross_segment_ot" in types
    a = next(x for x in anomalies if x["type"] == "vlan_cross_segment_ot")
    assert a["severity"] == "high"


def test_no_vlan_cross_segment_same_vlan():
    hosts = {
        "10.0.0.10": _make_host(vlan_ids={10}, host_type="PLC", ot_role="outstation"),
        "10.0.0.20": _make_host(vlan_ids={10}, host_type="Windows Host"),
    }
    connections = {
        ("10.0.0.10", "10.0.0.20"): _conn(dst_ports={502}, vlan_ids={10}),
    }
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_cross_segment_ot" not in types


def test_broadcast_storm_carries_vlan_id():
    """Regression: broadcast_storm is emitted with src=dst=None (it's a VLAN-wide
    condition, not a host-to-host one), so consumers that key off src/dst (e.g. the
    VLAN flow matrix) need an explicit vlan_id to place it anywhere at all."""
    hosts = {"10.0.0.1": _make_host(vlan_ids={30})}
    vlan_pkt_total = {30: 100}
    vlan_pkt_bcast = {30: 40}   # 40% > 10% threshold, 100 >= BCAST_MIN_PKTS
    anomalies = analyze_anomalies(hosts, {}, {}, vlan_pkt_total=vlan_pkt_total,
                                  vlan_pkt_bcast=vlan_pkt_bcast)
    storms = [a for a in anomalies if a["type"] == "broadcast_storm"]
    assert len(storms) == 1
    assert storms[0]["vlan_id"] == 30
    assert storms[0]["src"] is None and storms[0]["dst"] is None


# ── ARP frames counted toward per-VLAN broadcast tally (integration) ──────────

def test_arp_broadcast_drives_broadcast_storm():
    """Regression: ARP frames (mostly L2-broadcast) previously `continue`d before
    ever reaching the IP-only vlan_pkt_total/vlan_pkt_bcast tally, so an ARP-storm
    VLAN — the most common real-world broadcast storm — could never trip the rule."""
    pkts = [
        Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=30) /
        ARP(psrc=f"10.30.0.{i % 250 + 1}", hwsrc=MAC_A, pdst="10.30.0.254")
        for i in range(60)
    ]
    r = _analyze(pkts)
    assert "error" not in r
    types = {a["type"] for a in r["anomalies"]}
    assert "broadcast_storm" in types
    storm = next(a for a in r["anomalies"] if a["type"] == "broadcast_storm")
    assert storm["vlan_id"] == 30


# ── ip_version field + stats (both serialization paths) ──────────────────────

def test_node_has_ip_version_v4():
    """IPv4 hosts are emitted with ip_version=4."""
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1234, dport=80),
    ]
    r = _analyze(pkts)
    node = _node(r, IP_A)
    assert node is not None
    assert node["ip_version"] == 4


def test_node_has_ip_version_v6():
    """IPv6 hosts are emitted with ip_version=6."""
    IPV6_SRC = "fe80::1"
    IPV6_DST = "fe80::2"
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IPv6(src=IPV6_SRC, dst=IPV6_DST) / TCP(sport=1234, dport=80),
    ]
    r = _analyze(pkts)
    node = _node(r, IPV6_SRC)
    assert node is not None
    assert node["ip_version"] == 6


def test_stats_ip_versions_and_counts():
    """stats carries ip_versions list and correct ipv4_count/ipv6_count."""
    IPV6_SRC = "2001:db8::1"
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1, dport=80),
        Ether(src=MAC_A, dst=MAC_B) / IPv6(src=IPV6_SRC, dst="2001:db8::2") / TCP(sport=2, dport=80),
    ]
    r = _analyze(pkts)
    s = r["stats"]
    assert sorted(s["ip_versions"]) == [4, 6]
    # Counts must be positive; exact values depend on how many IPs scapy assigns
    assert s["ipv4_count"] >= 1
    assert s["ipv6_count"] >= 1


def test_stats_has_untagged_true():
    """has_untagged is True when untagged frames are present."""
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1, dport=80),
    ]
    r = _analyze(pkts)
    assert r["stats"]["has_untagged"] is True


def test_stats_has_untagged_false():
    """has_untagged is False when all frames are VLAN-tagged."""
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) / IP(src=IP_A, dst=IP_B) / TCP(sport=1, dport=80),
    ]
    r = _analyze(pkts)
    assert r["stats"]["has_untagged"] is False


def test_merge_ip_version_preserved():
    """merge_results preserves ip_version on each node and unions ip_versions in stats."""
    IPV6_SRC = "fd00::1"
    pkts_v4 = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1, dport=80),
    ]
    pkts_v6 = [
        Ether(src=MAC_C, dst=MAC_D) / IPv6(src=IPV6_SRC, dst="fd00::2") / TCP(sport=2, dport=80),
    ]
    r4 = _analyze(pkts_v4)
    r6 = _analyze(pkts_v6)
    merged = merge_results([r4, r6])

    # Each node carries ip_version
    node_v4 = _node(merged, IP_A)
    node_v6 = _node(merged, IPV6_SRC)
    assert node_v4 is not None and node_v4["ip_version"] == 4
    assert node_v6 is not None and node_v6["ip_version"] == 6

    # Stats unions ip_versions
    assert sorted(merged["stats"]["ip_versions"]) == [4, 6]
    assert merged["stats"]["ipv4_count"] >= 1
    assert merged["stats"]["ipv6_count"] >= 1


# ── Regression tests for previously-fixed bugs ───────────────────────────────

def test_destination_host_packet_count_incremented():
    """Regression: dh['packet_count'] must be incremented (Bug 1 fix)."""
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1234, dport=80),
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1234, dport=80),
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1234, dport=80),
    ]
    r = _analyze(pkts)
    node_b = _node(r, IP_B)
    assert node_b is not None
    assert node_b["packet_count"] >= 1, (
        "Destination host must have packet_count > 0 (fix: dh['packet_count'] += 1)"
    )


def test_host_type_priority_over_frequency():
    """Regression: HOST_TYPE_PRIORITY first-observed wins over most-common (Bug 2 fix).

    10 HTTP packets → IP_B accumulates 10 'Web Server' hints.
    1 Modbus packet → IP_B accumulates 1 'PLC' hint.
    Expected: IP_B is classified as 'PLC' (higher priority) not 'Web Server'.
    """
    pkts = (
        # 10 HTTP connections → "Web Server" hint (dport 80)
        [Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1000 + i, dport=80)
         for i in range(10)]
        +
        # 1 Modbus connection → "PLC" hint (dport 502)
        [Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=2000, dport=502)]
    )
    r = _analyze(pkts)
    node_b = _node(r, IP_B)
    assert node_b is not None
    assert node_b["host_type"] == "PLC", (
        f"Got '{node_b['host_type']}' — HOST_TYPE_PRIORITY should pick 'PLC' over 'Web Server' "
        "regardless of frequency"
    )


def test_merge_reclassifies_host_type_by_priority():
    """Regression: merge_results must re-classify host_type using priority (Bug 6 fix).

    r1: IP_B has only HTTP traffic → classified as 'Web Server'.
    r2: IP_B has only Modbus traffic → classified as 'PLC'.
    Merged: host_type_hints = {'Web Server': N, 'PLC': M}.
    Expected: 'PLC' wins (higher priority) regardless of which PCAP was first.
    """
    pkts_http = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1000, dport=80),
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / TCP(sport=1001, dport=80),
    ]
    pkts_modbus = [
        Ether(src=MAC_C, dst=MAC_B) / IP(src=IP_C, dst=IP_B) / TCP(sport=2000, dport=502),
    ]
    r1 = _analyze(pkts_http)
    r2 = _analyze(pkts_modbus)
    merged = merge_results([r1, r2])
    node_b = _node(merged, IP_B)
    assert node_b is not None
    assert node_b["host_type"] == "PLC", (
        f"Got '{node_b['host_type']}' — merged host_type should be 'PLC' (higher priority)"
    )
