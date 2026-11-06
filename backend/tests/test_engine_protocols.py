"""Engine step B: OT commands, identity, IoT notes, credentials, files. Uses real tshark."""

import hashlib
import shutil

import pytest

from pcapvis.engine.analyze import analyze_capture
from pcapvis.engine.fields import ALL_FIELDS
from pcapvis.engine.tshark_env import load_env
from tests import pcapgen as g
from tests.pcapgen import Cap

pytestmark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")

C = ("00:0c:29:00:00:01", "10.0.0.5")  # engineering workstation / HMI
S = ("00:a0:87:00:00:02", "10.0.0.50")  # PLC / outstation


def run(cap: Cap, tmp_path, **kw):
    return analyze_capture(cap.write(tmp_path / "t.pcap"), **kw)


def host(r, ip):
    return next(h for h in r.hosts if h.ip == ip)


def cmds(r, protocol=None):
    return [c for c in r.ot_commands if protocol is None or c.protocol == protocol]


def test_every_requested_field_exists_in_installed_tshark():
    """Catches typos in fields.py (a wrong name silently yields no data)."""
    env = load_env()
    assert env.missing_fields == [], env.missing_fields
    assert set(env.fields) == set(ALL_FIELDS)


# ── Modbus ────────────────────────────────────────────────────────────────────


def modbus_session(cap, cport, exchanges):
    return cap.tcp_session(C, S, cport, 502, exchanges)


def test_modbus_read_write_exception_and_roles(tmp_path):
    cap = Cap()
    modbus_session(
        cap,
        50000,
        [
            ("c", g.modbus(1, 1, b"\x03\x00\x0a\x00\x02")),
            ("s", g.modbus(1, 1, b"\x03\x04\x00\x01\x00\x02")),
            ("c", g.modbus(2, 1, b"\x06\x00\x10\x00\xff")),
            ("s", g.modbus(2, 1, b"\x06\x00\x10\x00\xff")),
            ("c", g.modbus(3, 2, b"\x03\x01\x00\x00\x01")),
            ("s", g.modbus(3, 2, b"\x83\x02")),
        ],
    )
    r = run(cap, tmp_path)
    mb = cmds(r, "Modbus")
    assert [(c.function, c.kind, c.unit) for c in mb] == [
        ("Read Holding Registers", "read", 1),
        ("Write Single Register", "write", 1),
        ("Read Holding Registers", "read", 2),
        ("Read Holding Registers", "error", 2),
    ]
    assert mb[0].address == 10 and mb[0].quantity == 2
    assert mb[3].detail == "Exception: Illegal data address"
    assert all(c.src == "10.0.0.5" for c in mb if c.is_request)
    f = next(f for f in r.flows if f.server_port == 502)
    assert (f.ot_reads, f.ot_writes, f.ot_errors) == (2, 1, 1)
    assert f.function_counts["Modbus: Read Holding Registers"] == 2
    assert host(r, "10.0.0.5").ot_role == "master"
    plc = host(r, "10.0.0.50")
    assert plc.ot_role == "outstation" and plc.modbus_unit_ids == [1, 2]


def test_retransmitted_write_counted_once(tmp_path):
    """A real retransmission (same non-zero seq, same bytes) must not double-count a PLC write."""
    from scapy.all import IP, TCP, Ether, Raw

    cap = Cap()
    write = g.modbus(9, 1, b"\x06\x00\x01\x00\x01")
    other = g.modbus(10, 1, b"\x06\x00\x02\x00\x02")
    for payload, seq in ((write, 123456), (write, 123456), (other, 123456 + len(write))):
        cap.add(
            Ether(src=C[0], dst=S[0])
            / IP(src=C[1], dst=S[1])
            / TCP(sport=50010, dport=502, flags="PA", seq=seq, ack=1)
            / Raw(payload)
        )
    r = run(cap, tmp_path)
    assert [(c.function, c.address) for c in cmds(r, "Modbus")] == [
        ("Write Single Register", 1),
        ("Write Single Register", 2),
    ]
    f = r.flows[0]
    assert f.ot_writes == 2 and f.packets_c2s == 3  # traffic still counted


# ── DNP3 ──────────────────────────────────────────────────────────────────────


def test_dnp3_master_outstation_addresses_and_restart_is_write(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        20000,
        [
            ("c", g.dnp3(1, 10, b"\xc0\x0d")),  # cold restart from master 1 to outstation 10
            ("s", g.dnp3(10, 1, b"\xc0\x81\x00\x00", from_master=False)),  # response
            ("c", g.dnp3(1, 10, b"\xc1\x01\x3c\x01\x06")),  # read class 0
        ],
    )
    r = run(cap, tmp_path)
    d = cmds(r, "DNP3")
    assert [(c.function, c.kind) for c in d if c.is_request] == [("Cold Restart", "write"), ("Read", "read")]
    assert host(r, "10.0.0.5").ot_role == "master" and host(r, "10.0.0.5").dnp3_addresses == [1]
    assert host(r, "10.0.0.50").ot_role == "outstation" and host(r, "10.0.0.50").dnp3_addresses == [10]
    assert host(r, "10.0.0.50").host_type == "RTU"


# ── S7comm ────────────────────────────────────────────────────────────────────


def test_s7_functions_download_marks_engineering_workstation(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        102,
        [
            ("c", g.s7(1, g.S7_SETUP)),
            ("c", g.s7(1, g.S7_READ_VAR)),
            ("c", g.s7(1, g.S7_WRITE_VAR)),
            ("c", g.s7(1, g.S7_REQUEST_DOWNLOAD)),
            ("c", g.s7(1, g.S7_PLC_STOP)),
            ("s", g.s7(3, b"\x29", err=(0x85, 0x00))),
        ],
    )
    r = run(cap, tmp_path)
    s7 = cmds(r, "S7comm")
    assert [(c.function, c.kind) for c in s7] == [
        ("Setup communication", "other"),
        ("Read Var", "read"),
        ("Write Var", "write"),
        ("Request download", "write"),
        ("PLC Stop", "write"),
        ("PLC Stop", "error"),
    ]
    ws = host(r, "10.0.0.5")
    assert ws.host_type == "Engineering Workstation" and ws.host_type_confidence == "high"
    assert any(e.kind == "s7_download" for e in ws.host_type_evidence)
    assert ws.purdue_level == 3
    assert host(r, "10.0.0.50").host_type == "PLC"


# ── EtherNet/IP / CIP ─────────────────────────────────────────────────────────


def test_enip_list_identity_fingerprints_device(tmp_path):
    cap = Cap().udp(S, C, 44818, 50002, g.enip_list_identity_response(name="1756-L83E/B", serial=0x60C0FFEE))
    plc = host(run(cap, tmp_path), "10.0.0.50")
    assert plc.identity["enip_product_name"] == "1756-L83E/B"
    assert "Rockwell" in plc.identity["enip_vendor"]
    assert plc.identity["enip_serial"].lower().endswith("60c0ffee")
    assert plc.identity["enip_revision"]


def test_cip_write_tag_and_error_status(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50003,
        44818,
        [
            ("c", g.enip_cip(0x4D, g.cip_symbol_path("Pump1_Speed"), b"\xc4\x00\x01\x00\x0a\x00\x00\x00")),
            ("s", g.enip_cip(0x4D, b"", response=True, status=5)),
            ("c", g.enip_cip(0x4C, g.cip_symbol_path("Tank_Level"), b"\x01\x00")),
        ],
    )
    c = cmds(run(cap, tmp_path), "EtherNet/IP")
    assert [(x.function, x.kind, x.detail) for x in c] == [
        ("Write Tag", "write", "Pump1_Speed"),
        ("Write Tag", "error", c[1].detail),
        ("Read Tag", "read", "Tank_Level"),
    ]
    assert c[1].detail  # status name from Wireshark, e.g. "Path destination unknown"


def test_cip_connection_manager_services_are_not_writes(tmp_path):
    """0x4E/0x52 are Forward Close / Unconnected Send on the Connection Manager (class 6), not tag writes."""
    cm_path = b"\x20\x06\x24\x01"  # class 0x06, instance 1
    cap = Cap().tcp_session(
        C,
        S,
        50003,
        44818,
        [
            ("c", g.enip_cip(0x4E, cm_path, b"\x0a\x0e" + b"\x00" * 10)),
            ("c", g.enip_cip(0x52, cm_path, b"\x0a\x0e\x02\x00\x01\x00")),
        ],
    )
    r = run(cap, tmp_path)
    c = cmds(r, "EtherNet/IP")
    assert [(x.function, x.kind) for x in c] == [("Forward Close", "other"), ("Unconnected Send", "other")]
    assert next(f for f in r.flows if f.server_port == 44818).ot_writes == 0


def test_cip_common_set_attribute_is_write(tmp_path):
    path = b"\x20\x01\x24\x01\x30\x07"  # identity object, instance 1, attribute 7
    cap = Cap().tcp_session(C, S, 50003, 44818, [("c", g.enip_cip(0x10, path, b"\x01"))])
    c = cmds(run(cap, tmp_path), "EtherNet/IP")
    assert [(x.function, x.kind) for x in c] == [("Set Attribute Single", "write")]


# ── IEC 60870-5-104 ───────────────────────────────────────────────────────────


def test_iec104_command_interrogation_and_error(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50004,
        2404,
        [
            ("c", g.iec104_i(45, 6)),  # single command, activation → write
            ("c", g.iec104_i(100, 6, element=b"\x14")),  # general interrogation → read
            ("s", g.iec104_i(45, 44)),  # unknown type id → error
            ("s", g.iec104_i(1, 3, element=b"\x01")),  # spontaneous monitoring data → not a request
        ],
    )
    c = cmds(run(cap, tmp_path), "IEC-104")
    assert [(x.function, x.kind) for x in c] == [
        ("C_SC_NA_1", "write"),
        ("C_IC_NA_1", "read"),
        ("C_SC_NA_1", "error"),
    ]


# ── BACnet ────────────────────────────────────────────────────────────────────


def test_bacnet_write_vs_read_property(tmp_path):
    """Regression for a legacy bug: its table called readProperty (12) a write ('createObject')."""
    cap = (
        Cap().udp(C, S, 47808, 47808, g.bacnet_confirmed(15)).udp(C, S, 47808, 47808, g.bacnet_confirmed(12))
    )
    c = cmds(run(cap, tmp_path), "BACnet")
    assert [(x.function, x.kind) for x in c] == [("writeProperty", "write"), ("readProperty", "read")]


def test_bacnet_iam_identity_and_error(tmp_path):
    cap = (
        Cap()
        .udp(S, ("ff:ff:ff:ff:ff:ff", "10.0.0.255"), 47808, 47808, g.bacnet_iam(instance=4321, vendor=5))
        .udp(S, C, 47808, 47808, g.bacnet_error())
    )
    r = run(cap, tmp_path)
    dev = host(r, "10.0.0.50")
    assert dev.identity["bacnet_device_instance"] == "4321"
    assert "Johnson" in dev.identity["bacnet_vendor"]  # vendor 5 per ASHRAE registry
    assert [x.kind for x in cmds(r, "BACnet")] == ["other", "error"]


# ── IoT ───────────────────────────────────────────────────────────────────────


def test_mqtt_credentials_topics_client_id(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50005,
        1883,
        [
            ("c", g.mqtt_connect("plc-gw", "operator", "s3cret!")),
            ("c", g.mqtt_publish("plant/line1/temp", b"21.5")),
        ],
    )
    r = run(cap, tmp_path)
    cred = r.credentials[0]
    assert (cred.protocol, cred.username, cred.secret, cred.client, cred.server) == (
        "MQTT",
        "operator",
        "s3cret!",
        "10.0.0.5",
        "10.0.0.50",
    )
    f = next(f for f in r.flows if f.server_port == 1883)
    assert f.notes["mqtt_topics"] == ["plant/line1/temp"] and f.notes["mqtt_client_ids"] == ["plc-gw"]


def test_coap_path_note(tmp_path):
    r = run(Cap().udp(C, S, 50006, 5683, g.coap_get(["sensors", "temp"])), tmp_path)
    assert r.flows[0].notes["coap_paths"] == ["/sensors/temp"] and r.flows[0].protocol == "CoAP"


# ── Credentials ───────────────────────────────────────────────────────────────


def test_ftp_user_pass_pairing(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        21,
        [
            ("s", b"220 ready\r\n"),
            ("c", b"USER plcadmin\r\n"),
            ("s", b"331 pw\r\n"),
            ("c", b"PASS Winter2024!\r\n"),
            ("s", b"230 ok\r\n"),
        ],
    )
    c = run(cap, tmp_path).credentials
    assert [(x.protocol, x.username, x.secret, x.kind) for x in c] == [
        ("FTP", "plcadmin", "Winter2024!", "password")
    ]


def test_pop3_credentials(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        110,
        [("s", b"+OK ready\r\n"), ("c", b"USER mail\r\n"), ("s", b"+OK\r\n"), ("c", b"PASS mailpw\r\n")],
    )
    assert [(x.protocol, x.username, x.secret) for x in run(cap, tmp_path).credentials] == [
        ("POP3", "mail", "mailpw")
    ]


def test_http_basic_form_and_bearer(tmp_path):
    form = b"username=jdoe&password=Summer2024%21&remember=1"
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        80,
        [
            ("c", b"GET /admin HTTP/1.1\r\nHost: hmi\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n"),
            ("s", g.http_ok()),
            (
                "c",
                b"POST /login HTTP/1.1\r\nHost: hmi\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form,
            ),
            ("s", g.http_ok()),
            ("c", b"GET /api HTTP/1.1\r\nHost: hmi\r\nAuthorization: Bearer eyJhbGciOi.abc.def\r\n\r\n"),
        ],
    )
    c = {x.kind: x for x in run(cap, tmp_path).credentials}
    assert (c["basic_auth"].username, c["basic_auth"].secret) == ("admin", "admin")
    assert (c["form"].username, c["form"].secret) == ("jdoe", "Summer2024!")
    assert c["token"].secret == "eyJhbGciOi.abc.def"


def test_form_without_password_field_is_not_a_credential(tmp_path):
    form = b"q=pump&page=2"
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        80,
        [
            (
                "c",
                b"POST /search HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form,
            )
        ],
    )
    assert run(cap, tmp_path).credentials == []


def test_snmp_community(tmp_path):
    r = run(Cap().udp(C, S, 50007, 161, g.snmp_get("private")), tmp_path)
    assert [(x.protocol, x.kind, x.secret) for x in r.credentials] == [("SNMP", "community", "private")]


def test_telnet_login_with_backspace(tmp_path):
    cap = Cap().tcp_session(
        C,
        S,
        50000,
        23,
        [
            ("s", b"\r\nPLC-GW login: "),
            ("c", b"r"),
            ("c", b"o"),
            ("c", b"x\x7f"),
            ("c", b"ot\r\n"),
            ("s", b"Password: "),
            ("c", b"hunter2\r\n"),
            ("s", b"\r\n$ "),
        ],
    )
    c = run(cap, tmp_path).credentials
    assert [(x.protocol, x.username, x.secret) for x in c] == [("Telnet", "root", "hunter2")]


def test_telnet_without_prompt_yields_nothing(tmp_path):
    cap = Cap().tcp_session(C, S, 50000, 23, [("c", b"ls -la\r\n"), ("s", b"total 0\r\n")])
    assert run(cap, tmp_path).credentials == []


def test_repeated_credential_is_counted_not_duplicated(tmp_path):
    cap = Cap()
    for port in (50000, 50001):
        cap.tcp_session(C, S, port, 1883, [("c", g.mqtt_connect("x", "u", "p"))])
    c = run(cap, tmp_path).credentials
    assert len(c) == 1 and c[0].count == 2


# ── HTTP notes, identity and file extraction ──────────────────────────────────

EXE = b"MZ\x90\x00" + b"\x00" * 200


def test_http_notes_server_identity_and_file_extraction(tmp_path):
    cap = (
        Cap()
        .tcp_session(
            C,
            S,
            50000,
            80,
            [
                ("c", g.http_get("hmi.plant", "/downloads/update.exe", ua="Mozilla/5.0 test")),
                ("s", g.http_ok(EXE, server="Siemens-HMI/1.0", ctype="application/octet-stream")),
            ],
        )
        .tcp_session(
            C,
            S,
            50001,
            80,
            [
                ("c", g.http_get("hmi.plant", "/index.html")),
                ("s", g.http_ok(b"<html>hi</html>", ctype="text/html")),
            ],
        )
    )
    store = tmp_path / "files"
    r = run(cap, tmp_path, files_dir=store)
    f = next(f for f in r.flows if f.client_port == 50000)
    assert f.notes["http_requests"] == ["GET hmi.plant/downloads/update.exe"]
    assert f.notes["user_agents"] == ["Mozilla/5.0 test"]
    assert host(r, "10.0.0.50").identity["http_server"] == "Siemens-HMI/1.0"
    exe = next(x for x in r.files if x.filename == "update.exe")
    assert exe.size == len(EXE) and exe.sha256 == hashlib.sha256(EXE).hexdigest()
    assert exe.mime == "application/x-msdownload" and exe.interesting
    assert exe.source_url == "hmi.plant/downloads/update.exe"
    assert (store / exe.sha256).read_bytes() == EXE
    html = next(x for x in r.files if x.filename == "index.html")
    assert not html.interesting


def test_no_export_pass_without_file_protocols(tmp_path, monkeypatch):
    import pcapvis.engine.analyze as A

    called = []
    monkeypatch.setattr(A, "extract_files", lambda *a, **k: called.append(1) or [])
    run(Cap().udp(C, S, 50000, 161, g.snmp_get("public")), tmp_path)
    assert called == []


def test_extract_objects_can_be_disabled(tmp_path):
    cap = Cap().tcp_session(C, S, 50000, 80, [("c", g.http_get("h", "/a.exe")), ("s", g.http_ok(EXE))])
    assert run(cap, tmp_path, extract_objects=False).files == []


def test_ot_command_cap(tmp_path, monkeypatch):
    import pcapvis.engine.aggregate as agg

    monkeypatch.setattr(agg, "MAX_OT_COMMANDS", 2)
    ex = [("c", g.modbus(i, 1, b"\x03\x00\x00\x00\x01")) for i in range(1, 5)]
    r = run(Cap().tcp_session(C, S, 50000, 502, ex), tmp_path)
    assert len(r.ot_commands) == 2 and r.ot_commands_truncated
    assert next(f for f in r.flows if f.server_port == 502).ot_reads == 4  # counters stay exact


def test_demo_capture_end_to_end():
    """The shared demo capture: credentials, OT writes, engineering workstation."""
    from pathlib import Path

    r = analyze_capture(Path(__file__).resolve().parents[2] / "fixtures" / "network-capture-demo.pcap")
    kinds = {(c.protocol, c.kind) for c in r.credentials}
    assert {
        ("HTTP", "basic_auth"),
        ("HTTP", "form"),
        ("FTP", "password"),
        ("MQTT", "password"),
        ("Telnet", "password"),
    } <= kinds
    writes = {c.function for c in r.ot_commands if c.kind == "write"}
    assert {
        "Write Single Register",
        "Write Multiple Registers",
        "Write Var",
        "Request download",
        "PLC Stop",
    } <= writes
    assert host(r, "10.0.2.10").host_type == "Engineering Workstation"
    assert any(f.filename.endswith(".pdf") and f.interesting for f in r.files)
