"""Unit tests for analyze_anomalies and BACnet parser."""
import struct
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyze_anomalies, parse_bacnet


# ── Helpers ───────────────────────────────────────────────────────────────────

def _host(bytes_sent=0, host_type="Windows Host", is_private=True):
    return {
        "bytes_sent": bytes_sent,
        "bytes_recv": 0,
        "host_type": host_type,
        "packet_count": 0,
        "is_private": is_private,
    }


def _conn(dst_ports=None, packet_count=1, bytes_total=0):
    return {
        "dst_ports": set(dst_ports or []),
        "packet_count": packet_count,
        "bytes": bytes_total,
    }


def _pkt(src, dst, dport=None, sport=None, t=None, hex_data=""):
    pkt = {
        "src": src,
        "dst": dst,
        "dport": dport,
        "sport": sport,
        "time": t if t is not None else time.time(),
        "hex": hex_data or "00",  # "hex" is always present in real stored packets
    }
    if hex_data:
        pkt["payload_hex"] = hex_data  # only present when transport payload exists
    return pkt


def _host_full(is_private=True, host_type="Windows Host", macs=None, vlan_ids=None, vlan_untagged=False, bytes_sent=0):
    """Return a host dict with all fields needed by analyze_anomalies."""
    return {
        "bytes_sent": bytes_sent,
        "bytes_recv": 0,
        "host_type": host_type,
        "packet_count": 0,
        "is_private": is_private,
        "macs": set(macs or []),
        "mac": (list(macs)[0] if macs else ""),
        "vlan_ids": set(vlan_ids or []),
        "vlan_untagged": vlan_untagged,
    }


def _anomaly_types(anomalies):
    return {a["type"] for a in anomalies}


# ── Port scan ─────────────────────────────────────────────────────────────────

def test_port_scan_detected():
    hosts = {f"192.168.1.{i}": _host() for i in range(2, 10)}
    hosts["10.0.0.1"] = _host()
    connections = {}
    for i in range(2, 10):
        ip = f"192.168.1.{i}"
        connections[("10.0.0.1", ip)] = _conn(dst_ports=list(range(i * 10, i * 10 + 3)))
    # scanner contacts 8 unique IPs with enough ports
    # need > 5 unique dst IPs and > 15 unique ports
    packet_store = {}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    types = _anomaly_types(anomalies)
    assert "port_scan" in types
    scan = next(a for a in anomalies if a["type"] == "port_scan")
    assert scan["src"] == "10.0.0.1"
    assert scan["severity"] == "high"


def test_port_scan_not_triggered_too_few_ips():
    # Only 3 unique dst IPs — below threshold of 5
    hosts = {"10.0.0.1": _host(), "192.168.1.1": _host(),
             "192.168.1.2": _host(), "192.168.1.3": _host()}
    connections = {
        ("10.0.0.1", "192.168.1.1"): _conn(dst_ports=list(range(20))),
        ("10.0.0.1", "192.168.1.2"): _conn(dst_ports=list(range(20))),
        ("10.0.0.1", "192.168.1.3"): _conn(dst_ports=list(range(20))),
    }
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "port_scan" not in _anomaly_types(anomalies)


# ── Cleartext credentials ─────────────────────────────────────────────────────

def test_cleartext_ftp_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[21])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=21, hex_data="deadbeef")
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    types = _anomaly_types(anomalies)
    assert "cleartext_credentials" in types
    a = next(x for x in anomalies if x["type"] == "cleartext_credentials")
    assert "FTP" in a["description"]


def test_cleartext_telnet_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[23])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=23, hex_data="aabbcc")
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    types = _anomaly_types(anomalies)
    assert "cleartext_credentials" in types
    a = next(x for x in anomalies if x["type"] == "cleartext_credentials")
    assert "Telnet" in a["description"]


def test_cleartext_not_detected_without_payload():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[21])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=21, hex_data="")  # no payload
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "cleartext_credentials" not in _anomaly_types(anomalies)


# ── Beaconing ─────────────────────────────────────────────────────────────────

def test_beaconing_detected_regular_intervals():
    base = 1000.0
    # 20 packets at exactly 10-second intervals → CV = 0 (minimum threshold is now 20)
    pkts = [_pkt("10.0.0.1", "10.0.0.2", t=base + i * 10.0) for i in range(20)]
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {("10.0.0.1", "10.0.0.2"): pkts}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "beaconing" in _anomaly_types(anomalies)
    a = next(x for x in anomalies if x["type"] == "beaconing")
    assert a["src"] == "10.0.0.1"
    assert "CV=" in a["description"]


def test_beaconing_not_detected_irregular():
    import random
    random.seed(42)
    base = 1000.0
    # 20 packets with highly variable timing
    times = sorted(base + random.uniform(0, 500) for _ in range(20))
    pkts = [_pkt("10.0.0.1", "10.0.0.2", t=t) for t in times]
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {("10.0.0.1", "10.0.0.2"): pkts}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "beaconing" not in _anomaly_types(anomalies)


def test_beaconing_requires_20_packets():
    base = 1000.0
    # 19 packets (one below the new minimum of 20) → should not fire
    pkts = [_pkt("10.0.0.1", "10.0.0.2", t=base + i * 10.0) for i in range(19)]
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {("10.0.0.1", "10.0.0.2"): pkts}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "beaconing" not in _anomaly_types(anomalies)


# ── Data exfiltration ─────────────────────────────────────────────────────────

def test_exfiltration_detected():
    # New logic: fires when conn["bytes"] > 10MB on a private↔public connection
    TEN_MB = 10 * 1024 * 1024 + 1
    hosts = {
        "10.0.0.1": _host(),
        "8.8.8.8": _host(is_private=False),
    }
    connections = {("10.0.0.1", "8.8.8.8"): _conn(bytes_total=TEN_MB)}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "exfiltration" in _anomaly_types(anomalies)
    a = next(x for x in anomalies if x["type"] == "exfiltration")
    assert a["src"] == "10.0.0.1"
    assert a["dst"] == "8.8.8.8"


def test_exfiltration_not_detected_internal():
    TEN_MB = 10 * 1024 * 1024 + 1
    hosts = {
        "10.0.0.1": _host(),
        "10.0.0.2": _host(),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(bytes_total=TEN_MB)}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "exfiltration" not in _anomaly_types(anomalies)


def test_exfiltration_not_detected_below_threshold():
    hosts = {
        "10.0.0.1": _host(),
        "8.8.8.8": _host(is_private=False),
    }
    connections = {("10.0.0.1", "8.8.8.8"): _conn(bytes_total=1024)}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "exfiltration" not in _anomaly_types(anomalies)


def test_exfiltration_not_false_positive_on_large_internal_traffic():
    """Regression: large internal traffic must not trigger exfiltration on a small external conn."""
    TEN_MB = 10 * 1024 * 1024 + 1
    hosts = {
        "10.0.0.1": _host(bytes_sent=TEN_MB),  # lots of internal traffic
        "10.0.0.2": _host(),
        "8.8.8.8": _host(is_private=False),
    }
    connections = {
        ("10.0.0.1", "10.0.0.2"): _conn(bytes_total=TEN_MB),  # large internal conn
        ("10.0.0.1", "8.8.8.8"):  _conn(bytes_total=100),      # tiny external conn
    }
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "exfiltration" not in _anomaly_types(anomalies), (
        "Large internal traffic + tiny external conn must not trigger exfiltration"
    )


# ── Suspicious ports ──────────────────────────────────────────────────────────

def test_suspicious_port_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[4444])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "suspicious_port" in _anomaly_types(anomalies)
    a = next(x for x in anomalies if x["type"] == "suspicious_port")
    assert "4444" in a["description"]
    assert a["severity"] == "high"


def test_suspicious_port_metasploit():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[1337])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "suspicious_port" in _anomaly_types(anomalies)


def test_suspicious_port_not_for_normal_port():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[80, 443])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "suspicious_port" not in _anomaly_types(anomalies)


# ── OT/IoT anomalies ──────────────────────────────────────────────────────────

def test_ot_internet_exposure():
    hosts = {
        "10.0.0.5": _host(host_type="PLC"),
        "8.8.8.8": _host(is_private=False),
    }
    connections = {("10.0.0.5", "8.8.8.8"): _conn()}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "ot_internet_exposure" in _anomaly_types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_internet_exposure")
    assert a["dst"] == "10.0.0.5"
    assert a["severity"] == "high"


def test_ot_cleartext_modbus():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host(host_type="PLC")}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[502])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [_pkt("10.0.0.1", "10.0.0.2", dport=502)]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_cleartext" in _anomaly_types(anomalies)


def test_mqtt_cleartext_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host(host_type="IoT Sensor")}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[1883])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [_pkt("10.0.0.1", "10.0.0.2", dport=1883)]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "iot_mqtt_cleartext" in _anomaly_types(anomalies)


def test_empty_inputs_no_crash():
    anomalies = analyze_anomalies({}, {}, {})
    assert isinstance(anomalies, list)
    assert len(anomalies) == 0


# ── parse_bacnet ──────────────────────────────────────────────────────────────

def _bacnet_pkt(bvlc_func=0x0A, npdu_version=0x01, npdu_ctrl=0x00, apdu=b""):
    """Build a minimal BACnet/IP packet."""
    body = bytes([0x81, bvlc_func]) + (6 + len(apdu)).to_bytes(2, "big") + \
           bytes([npdu_version, npdu_ctrl]) + apdu
    return body


def test_bacnet_unicast_who_is():
    # Unconfirmed-Request (pdu_type=0x1), who-Is (service=9)
    apdu = bytes([0x10, 0x09])  # (1 << 4) | 0, service 9
    pkt = _bacnet_pkt(bvlc_func=0x0A, apdu=apdu)
    r = parse_bacnet(pkt)
    assert r is not None
    assert r["bvlc_function_name"] == "Original-Unicast-NPDU"
    assert r["pdu_type_name"] == "Unconfirmed-Request"
    assert r["service_name"] == "who-Is"
    assert r["is_write"] is False


def test_bacnet_confirmed_read_property():
    # Confirmed-Request (pdu_type=0x0), invoke_id=1, service=14 (readProperty)
    apdu = bytes([0x00, 0x05, 0x01, 14])  # pdu_type=0, max_apdu_len, invoke_id, service
    pkt = _bacnet_pkt(bvlc_func=0x0A, apdu=apdu)
    r = parse_bacnet(pkt)
    assert r is not None
    assert r["pdu_type_name"] == "Confirmed-Request"
    assert r["service_name"] == "readProperty"
    assert r["invoke_id"] == 1
    assert r["is_write"] is False


def test_bacnet_confirmed_write_property():
    # Confirmed-Request, service=17 (writeProperty)
    apdu = bytes([0x00, 0x05, 0x02, 17])
    pkt = _bacnet_pkt(bvlc_func=0x0A, apdu=apdu)
    r = parse_bacnet(pkt)
    assert r["service_name"] == "writeProperty"
    assert r["is_write"] is True


def test_bacnet_i_am_broadcast():
    # Broadcast (0x0B), Unconfirmed i-Am (service=0)
    apdu = bytes([0x10, 0x00])
    pkt = _bacnet_pkt(bvlc_func=0x0B, apdu=apdu)
    r = parse_bacnet(pkt)
    assert r["bvlc_function_name"] == "Original-Broadcast-NPDU"
    assert r["service_name"] == "i-Am"


def test_bacnet_error_pdu():
    # Error pdu_type = 0x5
    apdu = bytes([0x50, 0x00, 0x01, 0x02])
    pkt = _bacnet_pkt(apdu=apdu)
    r = parse_bacnet(pkt)
    assert r["pdu_type_name"] == "Error"
    assert r["is_error"] is True


def test_bacnet_invalid_bvlc_type():
    # First byte must be 0x81
    pkt = bytes([0x82, 0x0A, 0x00, 0x08, 0x01, 0x00])
    assert parse_bacnet(pkt) is None


def test_bacnet_too_short():
    assert parse_bacnet(b"\x81\x0A\x00") is None
    assert parse_bacnet(None) is None
    assert parse_bacnet(b"") is None


def test_bacnet_write_file_is_write():
    # atomicWriteFile = service 9 → is_write
    apdu = bytes([0x00, 0x05, 0x03, 9])
    pkt = _bacnet_pkt(apdu=apdu)
    r = parse_bacnet(pkt)
    assert r["is_write"] is True
    assert r["service_name"] == "atomicWriteFile"


def test_bacnet_reinitialize_device_is_write():
    # reinitializeDevice = service 30 → is_write
    apdu = bytes([0x00, 0x05, 0x04, 30])
    pkt = _bacnet_pkt(apdu=apdu)
    r = parse_bacnet(pkt)
    assert r["is_write"] is True


# ── DNS tunneling detection ───────────────────────────────────────────────────

def _dns_host(queries):
    """Build a minimal host dict with a dns_queries set."""
    return {
        "bytes_sent": 0, "bytes_recv": 0,
        "host_type": "Windows Host", "packet_count": 0,
        "is_private": True, "dns_queries": set(queries),
    }


def test_dns_tunneling_high_entropy_label():
    # base64-looking subdomain with entropy > 4.5
    label = "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo"  # 33 chars, ~4.8 bits
    queries = [f"{label}.evil.com", f"{label}x.evil.com", f"{label}y.evil.com"]
    hosts = {"10.0.0.5": _dns_host(queries)}
    anomalies = analyze_anomalies(hosts, {}, {})
    types = {a["type"] for a in anomalies}
    assert "dns_tunneling" in types
    a = next(x for x in anomalies if x["type"] == "dns_tunneling")
    assert a["src"] == "10.0.0.5"
    assert a["severity"] == "high"


def test_dns_tunneling_long_average():
    # 5 distinct queries each ~72 chars (simulated DNS tunnel payloads)
    queries = [f"{'a' * 20}{i:010d}.{'b' * 20}.tunnel.example.net" for i in range(5)]
    hosts = {"10.0.0.6": _dns_host(queries)}
    anomalies = analyze_anomalies(hosts, {}, {})
    types = {a["type"] for a in anomalies}
    assert "dns_tunneling" in types


def test_dns_tunneling_unique_subdomain_flood():
    # 25 unique 3rd-level labels under same parent
    queries = [f"sub{i:04d}.c2.com" for i in range(25)]
    hosts = {"10.0.0.7": _dns_host(queries)}
    anomalies = analyze_anomalies(hosts, {}, {})
    types = {a["type"] for a in anomalies}
    assert "dns_tunneling" in types


def test_dns_tunneling_not_triggered_normal():
    # Normal short queries — should not fire
    queries = ["google.com", "api.github.com", "example.org"]
    hosts = {"10.0.0.8": _dns_host(queries)}
    anomalies = analyze_anomalies(hosts, {}, {})
    types = {a["type"] for a in anomalies}
    assert "dns_tunneling" not in types


def test_dns_tunneling_not_triggered_too_few_queries():
    # Only 2 queries — below minimum of 3
    label = "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRo"
    queries = [f"{label}.evil.com", f"{label}x.evil.com"]
    hosts = {"10.0.0.9": _dns_host(queries)}
    anomalies = analyze_anomalies(hosts, {}, {})
    types = {a["type"] for a in anomalies}
    assert "dns_tunneling" not in types


# ── Bug-sweep regression tests (B1, B2, B3, B10) ──────────────────────────────

def test_arp_spoofing_fires_for_multiple_macs():
    """B1: ARP-spoofing detector must fire when two MACs claim the same IP on a VLAN."""
    hosts = {
        "192.168.10.1": _host_full(
            macs={"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"},
            vlan_ids={10},
        ),
        "192.168.10.2": _host_full(macs={"aa:bb:cc:00:00:01"}, vlan_ids={10}),
    }
    anomalies = analyze_anomalies(hosts, {}, {})
    types = _anomaly_types(anomalies)
    assert "arp_spoofing" in types, "Expected arp_spoofing with two MACs on same VLAN"
    a = next(x for x in anomalies if x["type"] == "arp_spoofing")
    assert a["src"] == "192.168.10.1"


def test_arp_spoofing_does_not_fire_single_mac():
    """B1: ARP-spoofing must not fire when a host has only one MAC."""
    hosts = {
        "192.168.10.1": _host_full(macs={"aa:bb:cc:dd:ee:ff"}, vlan_ids={10}),
    }
    anomalies = analyze_anomalies(hosts, {}, {})
    assert "arp_spoofing" not in _anomaly_types(anomalies)


def test_cleartext_requires_payload_hex():
    """B2: cleartext_credentials must NOT fire when packet has no payload (no payload_hex)."""
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[21])}
    # Packet has "hex" (raw bytes always set) but no "payload_hex"
    no_payload_pkt = {
        "src": "10.0.0.1", "dst": "10.0.0.2",
        "dport": 21, "sport": 12345,
        "time": 1000.0,
        "hex": "deadbeef",  # raw bytes present but no transport payload
    }
    packet_store = {("10.0.0.1", "10.0.0.2"): [no_payload_pkt]}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "cleartext_credentials" not in _anomaly_types(anomalies), (
        "cleartext_credentials must not fire without payload_hex"
    )


def test_cleartext_fires_with_payload_hex():
    """B2: cleartext_credentials MUST fire when payload_hex is present."""
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[21])}
    with_payload_pkt = {
        "src": "10.0.0.1", "dst": "10.0.0.2",
        "dport": 21, "sport": 12345,
        "time": 1000.0,
        "hex": "deadbeef",
        "payload_hex": "deadbeef",  # payload present
    }
    packet_store = {("10.0.0.1", "10.0.0.2"): [with_payload_pkt]}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "cleartext_credentials" in _anomaly_types(anomalies)


def test_password_reuse_dedup_keeps_distinct():
    """B3: dedup must NOT collapse two distinct password_reuse anomalies into one."""
    # Two different passwords each reused across 2+ services → two distinct anomalies
    credentials = [
        {"password": "hunter2", "protocol": "FTP",   "dst": "10.0.0.2"},
        {"password": "hunter2", "protocol": "Telnet", "dst": "10.0.0.3"},
        {"password": "letmein", "protocol": "SSH",   "dst": "10.0.0.4"},
        {"password": "letmein", "protocol": "RDP",   "dst": "10.0.0.5"},
    ]
    anomalies = analyze_anomalies({}, {}, {}, credentials=credentials)
    reuse = [a for a in anomalies if a["type"] == "password_reuse"]
    assert len(reuse) == 2, f"Expected 2 distinct password_reuse anomalies, got {len(reuse)}"


def test_beaconing_ignores_subsecond_intervals():
    """B10: beaconing must NOT fire when mean interval < 1 second (bulk transfers/ACK storms)."""
    base = 1000.0
    # 20 packets at 0.1-second intervals — regular but sub-second (ACK storm pattern)
    pkts = [_pkt("10.0.0.1", "10.0.0.2", t=base + i * 0.1) for i in range(20)]
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {("10.0.0.1", "10.0.0.2"): pkts}
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "beaconing" not in _anomaly_types(anomalies), (
        "Sub-second regular intervals must not trigger beaconing"
    )
