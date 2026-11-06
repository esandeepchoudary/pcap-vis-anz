"""Passive fingerprinting: identity devices reveal in their own responses (M5). Uses real tshark."""

import shutil

import pytest
from scapy.all import Ether, Raw
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING, ASN1_TIME_TICKS
from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind

from pcapvis.engine.analyze import analyze_capture
from pcapvis.engine.fingerprint import cip_type_hint, clean, os_from_dhcp, type_hints
from tests import pcapgen as g
from tests.pcapgen import Cap
from tests.test_parallel import _same

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")

HMI = ("00:0c:29:00:00:10", "10.0.2.10")
PLC = ("00:1b:1b:00:00:51", "10.0.2.51")


def run(cap: Cap, tmp_path, **kw):
    return analyze_capture(cap.write(tmp_path / "fp.pcap"), **kw)


def host(r, ip):
    return next(h for h in r.hosts if h.ip == ip)


def modbus_cap():
    c = Cap()
    c.tcp_session(
        HMI,
        PLC,
        50001,
        502,
        [
            ("c", g.modbus(1, 1, g.modbus_device_id_request())),
            (
                "s",
                g.modbus(
                    1,
                    1,
                    g.modbus_device_id_response(
                        {
                            0: "Schneider Electric",
                            1: "BMXP342020",
                            2: "v2.70",
                            4: "Modicon M340",
                            5: "BMX P34 2020",
                        }
                    ),
                ),
            ),
        ],
    )
    return c


def s7_cap():
    c = Cap()
    c.tcp_session(
        HMI,
        PLC,
        50002,
        102,
        [
            ("c", g.s7(1, g.S7_SETUP)),
            ("s", g.s7(3, g.S7_SETUP)),
            ("c", g.s7_szl_request(0x11)),
            (
                "s",
                g.s7_szl_response(
                    0x11,
                    [
                        g.szl_0011_record(1, "6ES7 516-3AN01-0AB0"),
                        g.szl_0011_record(7, "", 0, 0x5602, 0x0904),
                    ],
                    28,
                ),
            ),
            ("c", g.s7_szl_request(0x1C)),
            (
                "s",
                g.s7_szl_response(
                    0x1C,
                    [
                        g.szl_001c_record(1, "PLC_LINE2"),
                        g.szl_001c_record(5, "S C-X4U421302020"),
                        g.szl_001c_record(7, "CPU 1516-3 PN/DP"),
                    ],
                    34,
                ),
            ),
        ],
    )
    return c


def snmp_response(varbinds, sport=161):
    pdu = SNMP(
        community="public",
        PDU=SNMPresponse(id=1, varbindlist=[SNMPvarbind(oid=ASN1_OID(o), value=v) for o, v in varbinds]),
    )
    c = Cap()
    c.udp(
        ("00:0c:29:00:00:99", "10.0.0.99"),
        ("00:0c:29:00:00:02", "10.0.0.2"),
        sport,
        40000 if sport == 161 else 161,
        bytes(pdu),
    )
    return c


@needs_tshark
def test_modbus_device_identification(tmp_path):
    h = host(run(modbus_cap(), tmp_path), PLC[1])
    assert h.identity["modbus_vendor"] == "Schneider Electric"
    assert h.identity["modbus_model"] == "BMX P34 2020" and h.identity["modbus_revision"] == "v2.70"
    assert (
        "modbus_vendor" not in host(run(modbus_cap(), tmp_path), HMI[1]).identity
    )  # the requester isn't the device


@needs_tshark
def test_s7_szl_identifies_the_plc(tmp_path):
    h = host(run(s7_cap(), tmp_path), PLC[1])
    assert h.identity["s7_order_number"] == "6ES7 516-3AN01-0AB0"
    assert h.identity["s7_firmware"] == "V2.9.4"
    assert h.identity["s7_plc_name"] == "PLC_LINE2" and h.identity["s7_serial"] == "S C-X4U421302020"
    assert h.host_type == "PLC" and h.host_type_confidence == "high"
    assert any(e.kind == "fingerprint" and "CPU 1516-3 PN/DP" in e.detail for e in h.host_type_evidence)


@needs_tshark
def test_cip_identity_object(tmp_path):
    dev = ("00:00:bc:00:00:60", "10.0.2.60")
    c = Cap()
    c.tcp_session(
        HMI,
        dev,
        50003,
        44818,
        [
            ("c", g.enip_cip(0x01, b"\x20\x01\x24\x01")),
            ("s", g.enip_cip(0x01, b"", g.cip_identity_attributes(), response=True)),
        ],
    )
    h = host(run(c, tmp_path), dev[1])
    assert h.identity["enip_product_name"] == "1769-L33ER"
    assert h.identity["enip_vendor"] == "Rockwell Automation/Allen-Bradley"
    assert h.identity["enip_revision"] == "30.11"
    assert h.host_type == "PLC"
    assert any("EtherNet/IP identity" in e.detail for e in h.host_type_evidence)


@needs_tshark
def test_list_identity_device_type_now_classifies(tmp_path):
    dev = ("00:00:bc:00:00:61", "10.0.2.61")
    c = Cap()
    c.udp(HMI, dev, 50004, 44818, b"\x63\x00\x00\x00" + b"\x00" * 20)
    c.udp(dev, HMI, 44818, 50004, g.enip_list_identity_response())
    h = host(run(c, tmp_path), dev[1])
    assert h.host_type == "PLC" and h.host_type_confidence == "high"


@needs_tshark
@pytest.mark.parametrize(("role", "expected"), [(0x02, "PLC"), (0x01, "Field Device")])
def test_profinet_dcp_identifies_a_layer2_device(tmp_path, role, expected):
    c = Cap()
    c.add(
        Ether(src="00:1b:1b:00:00:52", dst=HMI[0], type=0x8892)
        / Raw(
            g.profinet_dcp_identify_response(
                "et200-line2", "ET 200SP", 0x002A, 0x0313, "10.0.2.52", role=role
            )
        )
    )
    h = host(run(c, tmp_path), "10.0.2.52")  # host created from the address the device announced
    assert h.mac == "00:1b:1b:00:00:52"
    assert (
        h.identity["pn_name_of_station"] == "et200-line2" and h.identity["pn_type_of_station"] == "ET 200SP"
    )
    assert h.host_type == expected


@needs_tshark
def test_snmp_system_group(tmp_path):
    cap = snmp_response(
        [
            ("1.3.6.1.2.1.1.1.0", ASN1_STRING(b"Cisco IOS Software, IE2000, Version 15.2(7)E8")),
            ("1.3.6.1.2.1.1.3.0", ASN1_TIME_TICKS(12345)),  # not a string: must not shift the pairing
            ("1.3.6.1.2.1.1.5.0", ASN1_STRING(b"ie2000-cell2")),
            ("1.3.6.1.2.1.1.6.0", ASN1_STRING(b"Building 4, cabinet 12")),
        ]
    )
    h = host(run(cap, tmp_path), "10.0.0.99")
    assert h.identity["snmp_sys_descr"].startswith("Cisco IOS Software")
    assert h.identity["snmp_sys_name"] == "ie2000-cell2"
    assert h.identity["snmp_sys_location"] == "Building 4, cabinet 12"


@needs_tshark
def test_snmp_ignores_requests_and_ambiguous_responses(tmp_path):
    request_side = snmp_response([("1.3.6.1.2.1.1.5.0", ASN1_STRING(b"spoofed"))], sport=40000)
    assert "snmp_sys_name" not in host(run(request_side, tmp_path), "10.0.0.99").identity
    ambiguous = snmp_response(
        [
            (
                "1.3.6.1.2.1.2.2.1.2.1",
                ASN1_STRING(b"GigabitEthernet1/1"),
            ),  # ifDescr: an unknown string varbind
            ("1.3.6.1.2.1.1.5.0", ASN1_STRING(b"ie2000-cell2")),
        ]
    )
    assert "snmp_sys_name" not in host(run(ambiguous, tmp_path), "10.0.0.99").identity


@needs_tshark
def test_bacnet_device_object_name(tmp_path):
    c = Cap()
    c.udp(
        ("00:0c:29:00:00:70", "10.0.3.70"),
        HMI,
        47808,
        47808,
        g.bacnet_read_property_ack_object_name(1234, "AHU-1 controller"),
    )
    assert host(run(c, tmp_path), "10.0.3.70").identity["bacnet_device_name"] == "AHU-1 controller"


@needs_tshark
def test_dhcp_vendor_class_names_the_os(tmp_path):
    c = Cap()
    c.dhcp_request("00:0c:29:00:00:33", "WS-033", vendor_class="MSFT 5.0")
    c.udp(("00:0c:29:00:00:33", "10.0.1.33"), ("00:0c:29:00:00:01", "10.0.1.1"), 50000, 9999, ttl=64)
    h = host(run(c, tmp_path), "10.0.1.33")
    assert h.os_hint == "Windows"  # DHCP beats the Linux-like TTL


@needs_tshark
@pytest.mark.parametrize("workers", [2, 3])
def test_parallel_equals_serial_with_fingerprints(tmp_path, workers):
    c = s7_cap()
    for f in modbus_cap().frames:
        c.add(f)
    c.add(
        Ether(src="00:1b:1b:00:00:52", dst=HMI[0], type=0x8892)
        / Raw(g.profinet_dcp_identify_response("et200", "ET 200SP", 0x2A, 0x313, "10.0.2.52", role=1))
    )
    path = c.write(tmp_path / "par.pcap")
    _same(analyze_capture(path, workers=1), analyze_capture(path, workers=workers))


def test_clean_strips_control_characters_and_caps_length():
    assert clean("A\x00B\r\nC") == "A B C"
    assert clean(" " * 5) is None
    assert len(clean("x" * 1000)) == 200


def test_type_hint_helpers():
    assert cip_type_hint("Programmable Logic Controller") == "PLC"
    assert cip_type_hint("AC Drive Device") == "Field Device"
    assert cip_type_hint("Generic Device (deprecated)") is None
    assert os_from_dhcp("MSFT 5.0") == "Windows" and os_from_dhcp("android-dhcp-13") == "Android"
    assert os_from_dhcp(None) is None
    assert [t for t, _e in type_hints({"pn_role": "IO controller"})] == ["PLC"]
    assert type_hints({"snmp_sys_name": "x"}) == []
