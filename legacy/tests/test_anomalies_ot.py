"""Tests for OT/IoT anomaly detection rules missing from test_anomalies.py."""
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyze_anomalies


def _host(host_type="Windows Host", is_private=True, bytes_sent=0,
          modbus_unit_ids=None):
    h = {
        "bytes_sent": bytes_sent,
        "bytes_recv": 0,
        "host_type": host_type,
        "packet_count": 1,
        "is_private": is_private,
    }
    if modbus_unit_ids is not None:
        h["modbus_unit_ids"] = modbus_unit_ids
    return h


def _conn(dst_ports=None, packet_count=1, bytes_total=0):
    return {
        "dst_ports": set(dst_ports or []),
        "packet_count": packet_count,
        "bytes": bytes_total,
    }


def _pkt(src, dst, dport=None, sport=None, **protocol_fields):
    p = {"src": src, "dst": dst, "dport": dport, "sport": sport,
         "time": time.time(), "hex": ""}
    p.update(protocol_fields)
    return p


def _types(anomalies):
    return {a["type"] for a in anomalies}


# ── ot_modbus_write ───────────────────────────────────────────────────────────

def _modbus_write_hex():
    """Build a Modbus TCP Write Multiple Registers frame preceded by 40 null bytes
    so that the offset-scan in analyze_anomalies finds it."""
    # Modbus TCP: Txn=1, Proto=0, Len=7, UnitID=1, FC=16(write), Addr=0, Qty=1, ByteCnt=2, Val=0x0100
    modbus_frame = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01,
                          0x10, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00])
    raw = b"\x00" * 40 + modbus_frame
    return raw.hex()


def test_ot_modbus_write_detected():
    hosts = {"10.0.0.1": _host(), "192.168.1.100": _host()}
    connections = {("10.0.0.1", "192.168.1.100"): _conn(dst_ports=[502])}
    packet_store = {
        ("10.0.0.1", "192.168.1.100"): [
            _pkt("10.0.0.1", "192.168.1.100", dport=502, hex=_modbus_write_hex()),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_modbus_write" in _types(anomalies)


# ── ot_modbus_bulk_read ───────────────────────────────────────────────────────

def test_ot_modbus_bulk_read_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 modbus={"function_code": 3, "quantity": 125, "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_modbus_bulk_read" in _types(anomalies)


def test_ot_modbus_bulk_read_fc4():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 modbus={"function_code": 4, "quantity": 200, "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_modbus_bulk_read" in _types(anomalies)


def test_ot_modbus_bulk_read_not_triggered_small():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 modbus={"function_code": 3, "quantity": 10, "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_modbus_bulk_read" not in _types(anomalies)


# ── ot_modbus_broadcast ───────────────────────────────────────────────────────

def test_ot_modbus_broadcast_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 modbus={"function_code": 16, "unit_id_zero": True, "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_modbus_broadcast" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_modbus_broadcast")
    assert a["severity"] == "high"


# ── ot_modbus_exception ───────────────────────────────────────────────────────

def test_ot_modbus_exception_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 modbus={"function_code": 0x90, "exception_code": 2,
                         "exception_name": "Illegal Data Address"}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_modbus_exception" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_modbus_exception")
    assert a["severity"] == "medium"


# ── ot_multiunit_poll ─────────────────────────────────────────────────────────

def test_ot_multiunit_poll_detected():
    hosts = {
        "10.0.0.1": _host(modbus_unit_ids={1, 2, 3, 4, 5}),
        "10.0.0.2": _host(),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "ot_multiunit_poll" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_multiunit_poll")
    assert a["severity"] == "medium"
    assert a["src"] == "10.0.0.1"


def test_ot_multiunit_poll_not_triggered_few_ids():
    hosts = {
        "10.0.0.1": _host(modbus_unit_ids={1, 2, 3}),
        "10.0.0.2": _host(),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "ot_multiunit_poll" not in _types(anomalies)


def test_ot_multiunit_poll_ignores_unit_id_zero():
    # 4 real unit IDs + broadcast 0 → only 4 non-zero, below threshold
    hosts = {
        "10.0.0.1": _host(modbus_unit_ids={0, 1, 2, 3, 4}),
        "10.0.0.2": _host(),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "ot_multiunit_poll" not in _types(anomalies)


# ── ot_dnp3_control ──────────────────────────────────────────────────────────

def test_ot_dnp3_control_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[20000])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=20000,
                 dnp3={"function_code": 3, "function_name": "DIRECT_OPERATE",
                       "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_dnp3_control" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_dnp3_control")
    assert a["severity"] == "high"


def test_ot_dnp3_control_not_triggered_read():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[20000])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=20000,
                 dnp3={"function_code": 1, "function_name": "READ", "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_dnp3_control" not in _types(anomalies)


# ── ot_dnp3_unusual_fc ───────────────────────────────────────────────────────

def test_ot_dnp3_unusual_fc_freeze():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 dnp3={"function_code": 4, "function_name": "IMMED_FREEZE_NO_REPLY",
                       "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_dnp3_unusual_fc" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_dnp3_unusual_fc")
    assert a["severity"] == "medium"


def test_ot_dnp3_unusual_fc_warm_restart():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 dnp3={"function_code": 14, "function_name": "WARM_RESTART",
                       "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_dnp3_unusual_fc" in _types(anomalies)


# ── ot_s7_write ──────────────────────────────────────────────────────────────

def test_ot_s7_write_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[102])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=102,
                 s7comm={"function_code": 0x05, "function_name": "Write Variable",
                         "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_s7_write" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_s7_write")
    assert a["severity"] == "high"


# ── ot_s7_critical ───────────────────────────────────────────────────────────

def test_ot_s7_critical_plc_stop():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[102])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=102,
                 s7comm={"function_code": 0x29, "function_name": "PLC Stop",
                         "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_s7_critical" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_s7_critical")
    assert a["severity"] == "high"


def test_ot_s7_critical_plc_start():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[102])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=102,
                 s7comm={"function_code": 0x28, "function_name": "PLC Start",
                         "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_s7_critical" in _types(anomalies)


# ── ot_s7_code_download ──────────────────────────────────────────────────────

def test_ot_s7_code_download_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn()}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2",
                 s7comm={"function_code": 0x1A, "function_name": "Download Block",
                         "is_write": True, "block_type": "OB", "block_number": 1}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_s7_code_download" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_s7_code_download")
    assert a["severity"] == "high"
    assert "OB" in a["description"]


# ── ot_enip_write ─────────────────────────────────────────────────────────────

def test_ot_enip_write_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[44818])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=44818,
                 enip={"cip_service": 0x10, "cip_service_name": "Write Tag",
                       "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_enip_write" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_enip_write")
    assert a["severity"] == "high"


def test_ot_enip_write_port_2222():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[2222])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=2222,
                 enip={"cip_service": 0x4D, "cip_service_name": "Forward Open",
                       "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_enip_write" in _types(anomalies)


# ── ot_iec104_command ─────────────────────────────────────────────────────────

def test_ot_iec104_command_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[2404])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=2404,
                 iec104={"type_id": 45, "type_name": "C_SC_NA_1",
                         "cot_val": 6, "cot_name": "Activation", "is_write": True}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_iec104_command" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_iec104_command")
    assert a["severity"] == "high"


def test_ot_iec104_command_not_triggered_on_read():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[2404])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=2404,
                 iec104={"type_id": 1, "type_name": "M_SP_NA_1",
                         "cot_val": 3, "cot_name": "Spontaneous", "is_write": False}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_iec104_command" not in _types(anomalies)


# ── ot_bacnet_write ───────────────────────────────────────────────────────────

def test_ot_bacnet_write_detected():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[47808])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=47808,
                 bacnet={"service_choice": 17, "service_name": "writeProperty",
                         "is_write": True, "pdu_type": 0}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_bacnet_write" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "ot_bacnet_write")
    assert a["severity"] == "high"


def test_ot_bacnet_write_not_triggered_read():
    hosts = {"10.0.0.1": _host(), "10.0.0.2": _host()}
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[47808])}
    packet_store = {
        ("10.0.0.1", "10.0.0.2"): [
            _pkt("10.0.0.1", "10.0.0.2", dport=47808,
                 bacnet={"service_choice": 14, "service_name": "readProperty",
                         "is_write": False, "pdu_type": 0}),
        ]
    }
    anomalies = analyze_anomalies(hosts, connections, packet_store)
    assert "ot_bacnet_write" not in _types(anomalies)


# ── iot_telnet ────────────────────────────────────────────────────────────────

def test_iot_telnet_detected():
    hosts = {
        "10.0.0.1": _host(),
        "10.0.0.2": _host(host_type="IP Camera"),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[23])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_telnet" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "iot_telnet")
    assert a["severity"] == "high"
    assert a["dst"] == "10.0.0.2"


def test_iot_telnet_smart_meter():
    hosts = {
        "192.168.1.50": _host(host_type="Smart Meter"),
        "10.0.0.1": _host(),
    }
    connections = {("10.0.0.1", "192.168.1.50"): _conn(dst_ports=[23, 80])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_telnet" in _types(anomalies)


def test_iot_telnet_not_triggered_non_iot():
    hosts = {
        "10.0.0.1": _host(),
        "10.0.0.2": _host(host_type="Windows Host"),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(dst_ports=[23])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_telnet" not in _types(anomalies)


# ── iot_camera_exfil ─────────────────────────────────────────────────────────

def test_iot_camera_exfil_detected():
    hosts = {
        "192.168.1.20": _host(host_type="IP Camera"),
        "8.8.8.8": _host(is_private=False),
    }
    connections = {("192.168.1.20", "8.8.8.8"): _conn(bytes_total=5_000_000)}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_camera_exfil" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "iot_camera_exfil")
    assert a["severity"] == "high"
    assert a["src"] == "192.168.1.20"


def test_iot_camera_exfil_not_triggered_internal():
    hosts = {
        "192.168.1.20": _host(host_type="IP Camera"),
        "192.168.1.1": _host(),
    }
    connections = {("192.168.1.20", "192.168.1.1"): _conn(bytes_total=5_000_000)}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_camera_exfil" not in _types(anomalies)


def test_iot_camera_exfil_not_triggered_other_host_type():
    hosts = {
        "192.168.1.20": _host(host_type="Linux Host"),
        "8.8.8.8": _host(is_private=False),
    }
    connections = {("192.168.1.20", "8.8.8.8"): _conn(bytes_total=5_000_000)}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_camera_exfil" not in _types(anomalies)


# ── iot_tr069 ─────────────────────────────────────────────────────────────────

def test_iot_tr069_detected():
    hosts = {"10.0.0.1": _host(), "1.2.3.4": _host(is_private=False)}
    connections = {("10.0.0.1", "1.2.3.4"): _conn(dst_ports=[7547])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_tr069" in _types(anomalies)
    a = next(x for x in anomalies if x["type"] == "iot_tr069")
    assert a["severity"] == "medium"


def test_iot_tr069_not_triggered_other_port():
    hosts = {"10.0.0.1": _host(), "1.2.3.4": _host(is_private=False)}
    connections = {("10.0.0.1", "1.2.3.4"): _conn(dst_ports=[80])}
    anomalies = analyze_anomalies(hosts, connections, {})
    assert "iot_tr069" not in _types(anomalies)
