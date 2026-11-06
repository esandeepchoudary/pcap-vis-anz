"""Unit tests for merge_results."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import merge_results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _node(ip, host_type="Windows Host", packet_count=10, bytes_sent=100,
          bytes_recv=200, protocols=None, services=None, open_ports=None,
          hostname="", mac="aa:bb:cc:dd:ee:ff", mac_vendor=None,
          dns_names=None, dns_queries=None, os_hint="Windows",
          is_private=True, geo=None, ot_role="unknown",
          modbus_unit_ids=None, dnp3_addresses=None, flags=None,
          risk_score=0):
    return {
        "ip": ip,
        "id": ip,
        "mac": mac,
        "mac_vendor": mac_vendor,
        "hostname": hostname,
        "dns_names": dns_names or [],
        "dns_queries": dns_queries or [],
        "protocols": protocols or ["TCP"],
        "services": services or [],
        "open_ports": open_ports or [80],
        "os_hint": os_hint,
        "host_type": host_type,
        "packet_count": packet_count,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "is_private": is_private,
        "flags": flags or [],
        "geo": geo,
        "ot_role": ot_role,
        "modbus_unit_ids": modbus_unit_ids or [],
        "dnp3_addresses": dnp3_addresses or [],
        "risk_score": risk_score,
    }


def _edge(source, target, protocols=None, packet_count=5, bytes_total=500,
          ports=None, first_seen=None, last_seen=None,
          ot_reads=0, ot_writes=0, ot_errors=0):
    return {
        "source": source,
        "target": target,
        "protocols": protocols or ["TCP"],
        "packet_count": packet_count,
        "bytes": bytes_total,
        "ports": ports or [80],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "ot_reads": ot_reads,
        "ot_writes": ot_writes,
        "ot_errors": ot_errors,
    }


def _result(nodes, edges, packets=None, anomalies=None, total_packets=100, truncated=False):
    return {
        "nodes": nodes,
        "edges": edges,
        "packets": packets or {},
        "anomalies": anomalies or [],
        "stats": {"total_packets": total_packets, "truncated": truncated},
    }


def _error_result():
    return {"error": "parse failed"}


# ── Basic merging ─────────────────────────────────────────────────────────────

def test_merge_single_result():
    r = _result(
        nodes=[_node("10.0.0.1")],
        edges=[_edge("10.0.0.1", "10.0.0.2")],
        total_packets=50,
    )
    out = merge_results([r])
    assert len(out["nodes"]) == 1
    assert out["nodes"][0]["ip"] == "10.0.0.1"
    assert len(out["edges"]) == 1
    assert out["stats"]["total_packets"] == 50


def test_merge_empty_results():
    out = merge_results([])
    assert out["nodes"] == []
    assert out["edges"] == []
    assert out["anomalies"] == []
    assert out["stats"]["total_packets"] == 0


def test_merge_skips_error_results():
    good = _result(nodes=[_node("10.0.0.1")], edges=[], total_packets=20)
    out = merge_results([_error_result(), good, _error_result()])
    assert len(out["nodes"]) == 1
    assert out["stats"]["total_packets"] == 20


def test_merge_all_error_results():
    out = merge_results([_error_result(), _error_result()])
    assert out["nodes"] == []
    assert out["stats"]["total_packets"] == 0


# ── Node deduplication ────────────────────────────────────────────────────────

def test_merge_nodes_same_ip_accumulates():
    r1 = _result(nodes=[_node("10.0.0.1", packet_count=10, bytes_sent=100,
                               protocols=["TCP"])], edges=[], total_packets=10)
    r2 = _result(nodes=[_node("10.0.0.1", packet_count=20, bytes_sent=200,
                               protocols=["UDP"])], edges=[], total_packets=20)
    out = merge_results([r1, r2])
    assert len(out["nodes"]) == 1
    n = out["nodes"][0]
    assert n["packet_count"] == 30
    assert n["bytes_sent"] == 300
    assert "TCP" in n["protocols"]
    assert "UDP" in n["protocols"]


def test_merge_nodes_different_ips():
    r1 = _result(nodes=[_node("10.0.0.1")], edges=[], total_packets=10)
    r2 = _result(nodes=[_node("10.0.0.2")], edges=[], total_packets=10)
    out = merge_results([r1, r2])
    ips = {n["ip"] for n in out["nodes"]}
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips


def test_merge_node_hostname_filled_from_second():
    r1 = _result(nodes=[_node("10.0.0.1", hostname="")], edges=[], total_packets=5)
    r2 = _result(nodes=[_node("10.0.0.1", hostname="myhost.local")], edges=[], total_packets=5)
    out = merge_results([r1, r2])
    assert out["nodes"][0]["hostname"] == "myhost.local"


def test_merge_node_hostname_not_overwritten():
    r1 = _result(nodes=[_node("10.0.0.1", hostname="first.local")], edges=[], total_packets=5)
    r2 = _result(nodes=[_node("10.0.0.1", hostname="second.local")], edges=[], total_packets=5)
    out = merge_results([r1, r2])
    assert out["nodes"][0]["hostname"] == "first.local"


def test_merge_node_open_ports_all_preserved():
    """merge_results now preserves ALL ports (no [:30] cap) so exports are lossless."""
    ports_a = list(range(1, 26))   # 25 ports
    ports_b = list(range(26, 51))  # 25 more ports = 50 total
    r1 = _result(nodes=[_node("10.0.0.1", open_ports=ports_a)], edges=[], total_packets=5)
    r2 = _result(nodes=[_node("10.0.0.1", open_ports=ports_b)], edges=[], total_packets=5)
    out = merge_results([r1, r2])
    # All 50 ports must survive — render-side display slicing is handled in the frontend
    assert len(out["nodes"][0]["open_ports"]) == 50


def test_merge_node_dns_names_merged():
    r1 = _result(nodes=[_node("10.0.0.1", dns_names=["a.local"])], edges=[], total_packets=5)
    r2 = _result(nodes=[_node("10.0.0.1", dns_names=["b.local"])], edges=[], total_packets=5)
    out = merge_results([r1, r2])
    assert set(out["nodes"][0]["dns_names"]) >= {"a.local", "b.local"}


# ── Edge merging ──────────────────────────────────────────────────────────────

def test_merge_edges_same_pair_accumulates():
    r1 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2", packet_count=5,
                                        bytes_total=500, protocols=["TCP"])],
                 total_packets=5)
    r2 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2", packet_count=10,
                                        bytes_total=1000, protocols=["UDP"])],
                 total_packets=10)
    out = merge_results([r1, r2])
    assert len(out["edges"]) == 1
    e = out["edges"][0]
    assert e["packet_count"] == 15
    assert e["bytes"] == 1500
    assert "TCP" in e["protocols"]
    assert "UDP" in e["protocols"]


def test_merge_edges_reversed_pair_deduped():
    # (A, B) and (B, A) should merge into a single edge
    r1 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2", packet_count=3)],
                 total_packets=3)
    r2 = _result(nodes=[], edges=[_edge("10.0.0.2", "10.0.0.1", packet_count=7)],
                 total_packets=7)
    out = merge_results([r1, r2])
    assert len(out["edges"]) == 1
    assert out["edges"][0]["packet_count"] == 10


def test_merge_edges_ot_counters_accumulated():
    r1 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2",
                                        ot_reads=5, ot_writes=2, ot_errors=1)],
                 total_packets=5)
    r2 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2",
                                        ot_reads=3, ot_writes=4, ot_errors=0)],
                 total_packets=5)
    out = merge_results([r1, r2])
    e = out["edges"][0]
    assert e["ot_reads"] == 8
    assert e["ot_writes"] == 6
    assert e["ot_errors"] == 1


def test_merge_edges_last_seen_takes_max():
    r1 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2", last_seen=1000.0)],
                 total_packets=5)
    r2 = _result(nodes=[], edges=[_edge("10.0.0.1", "10.0.0.2", last_seen=2000.0)],
                 total_packets=5)
    out = merge_results([r1, r2])
    assert out["edges"][0]["last_seen"] == 2000.0


# ── Packet merging ────────────────────────────────────────────────────────────

def test_merge_packets_combined():
    pkts_a = [{"no": i, "time": i} for i in range(30)]
    pkts_b = [{"no": i + 30, "time": i + 30} for i in range(30)]
    r1 = _result(nodes=[], edges=[],
                 packets={"10.0.0.1|10.0.0.2": pkts_a}, total_packets=30)
    r2 = _result(nodes=[], edges=[],
                 packets={"10.0.0.1|10.0.0.2": pkts_b}, total_packets=30)
    out = merge_results([r1, r2])
    # capped at 50
    assert len(out["packets"]["10.0.0.1|10.0.0.2"]) == 50


def test_merge_packets_different_keys():
    pkts_a = [{"no": 1}]
    pkts_b = [{"no": 2}]
    r1 = _result(nodes=[], edges=[],
                 packets={"10.0.0.1|10.0.0.2": pkts_a}, total_packets=1)
    r2 = _result(nodes=[], edges=[],
                 packets={"10.0.0.3|10.0.0.4": pkts_b}, total_packets=1)
    out = merge_results([r1, r2])
    assert "10.0.0.1|10.0.0.2" in out["packets"]
    assert "10.0.0.3|10.0.0.4" in out["packets"]


# ── Anomaly deduplication ─────────────────────────────────────────────────────

def test_merge_anomalies_deduplicated():
    anomaly = {"type": "port_scan", "src": "10.0.0.1", "dst": None,
               "severity": "high", "description": "scan"}
    r1 = _result(nodes=[], edges=[], anomalies=[anomaly], total_packets=10)
    r2 = _result(nodes=[], edges=[], anomalies=[anomaly], total_packets=10)
    out = merge_results([r1, r2])
    assert len(out["anomalies"]) == 1


def test_merge_anomalies_different_kept():
    a1 = {"type": "port_scan", "src": "10.0.0.1", "dst": None,
          "severity": "high", "description": "scan from 1"}
    a2 = {"type": "port_scan", "src": "10.0.0.2", "dst": None,
          "severity": "high", "description": "scan from 2"}
    r1 = _result(nodes=[], edges=[], anomalies=[a1], total_packets=10)
    r2 = _result(nodes=[], edges=[], anomalies=[a2], total_packets=10)
    out = merge_results([r1, r2])
    assert len(out["anomalies"]) == 2


# ── Stats ─────────────────────────────────────────────────────────────────────

def test_merge_total_packets_summed():
    r1 = _result(nodes=[], edges=[], total_packets=100)
    r2 = _result(nodes=[], edges=[], total_packets=200)
    out = merge_results([r1, r2])
    assert out["stats"]["total_packets"] == 300


def test_merge_truncated_flag_propagates():
    r1 = _result(nodes=[], edges=[], total_packets=100, truncated=False)
    r2 = _result(nodes=[], edges=[], total_packets=200, truncated=True)
    out = merge_results([r1, r2])
    assert out["stats"]["truncated"] is True


def test_merge_truncated_false_when_none():
    r1 = _result(nodes=[], edges=[], total_packets=10, truncated=False)
    out = merge_results([r1])
    assert out["stats"]["truncated"] is False


def test_merge_output_has_required_keys():
    out = merge_results([_result(nodes=[], edges=[], total_packets=0)])
    for key in ("nodes", "edges", "packets", "anomalies", "stats"):
        assert key in out
    for key in ("total_packets", "truncated"):
        assert key in out["stats"]


# ── Risk score propagation ────────────────────────────────────────────────────

def test_merge_risk_score_preserved():
    r = _result(nodes=[_node("10.0.0.1", risk_score=75)], edges=[], total_packets=10)
    out = merge_results([r])
    assert out["nodes"][0]["risk_score"] == 75


def test_merge_risk_score_takes_max_on_duplicate():
    r1 = _result(nodes=[_node("10.0.0.1", risk_score=30)], edges=[], total_packets=5)
    r2 = _result(nodes=[_node("10.0.0.1", risk_score=80)], edges=[], total_packets=5)
    out = merge_results([r1, r2])
    assert out["nodes"][0]["risk_score"] == 80


def test_merge_risk_score_defaults_zero():
    r = _result(nodes=[_node("10.0.0.1")], edges=[], total_packets=5)
    out = merge_results([r])
    assert out["nodes"][0]["risk_score"] == 0


# ── Stats schema completeness (M1 regression) ─────────────────────────────────

def _result_with_stats(extra_stats, **kwargs):
    """Like _result() but merges extra_stats into the stats dict."""
    r = _result(**kwargs)
    r["stats"].update(extra_stats)
    return r


def test_merge_stats_has_parse_errors():
    """merge_results must propagate parse_errors so the frontend can show a toast."""
    r1 = _result_with_stats({"parse_errors": 3}, nodes=[], edges=[], total_packets=10)
    r2 = _result_with_stats({"parse_errors": 2}, nodes=[], edges=[], total_packets=10)
    out = merge_results([r1, r2])
    assert "parse_errors" in out["stats"], "parse_errors key missing from merged stats"
    assert out["stats"]["parse_errors"] == 5


def test_merge_stats_has_geoip_available():
    """merge_results must carry geoip_available so the frontend GeoIP toast fires."""
    r = _result(nodes=[], edges=[], total_packets=5)
    out = merge_results([r])
    assert "geoip_available" in out["stats"], "geoip_available key missing from merged stats"
    # Value is boolean (may be True or False depending on test environment)
    assert isinstance(out["stats"]["geoip_available"], bool)


def test_merge_stats_has_cdp_lldp_discovered():
    """merge_results must sum cdp_lldp_discovered across files."""
    r1 = _result_with_stats({"cdp_lldp_discovered": 2}, nodes=[], edges=[], total_packets=5)
    r2 = _result_with_stats({"cdp_lldp_discovered": 3}, nodes=[], edges=[], total_packets=5)
    out = merge_results([r1, r2])
    assert "cdp_lldp_discovered" in out["stats"], "cdp_lldp_discovered key missing from merged stats"
    assert out["stats"]["cdp_lldp_discovered"] == 5
