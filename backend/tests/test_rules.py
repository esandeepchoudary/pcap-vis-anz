"""Anomaly rules: each rule on hand-built results (both sides of every threshold), plus L2 rules end to end."""

import shutil

import pytest

from pcapvis.engine import rules as R
from pcapvis.engine.model import (
    AnalysisResult,
    ArpClaim,
    CaptureSummary,
    Credential,
    Flow,
    Host,
    OtCommand,
    VlanStat,
)

T0 = 1_700_000_000.0


def host(ip, **kw):
    from pcapvis.engine.knowledge import ip_info

    v, private, mc = ip_info(ip)
    kw.setdefault("host_type", "Linux Host")
    return Host(ip=ip, ip_version=v, is_private=kw.pop("is_private", private), is_multicast=mc, **kw)


_fid = iter(range(1, 10_000_000))


def flow(client, server, port, transport="tcp", protocol="TCP", **kw):
    kw.setdefault("first_seen", T0)
    kw.setdefault("last_seen", T0 + 1)
    kw.setdefault("direction_basis", "handshake")
    return Flow(
        id=kw.pop("id", next(_fid)),
        transport=transport,
        client=client,
        client_port=kw.pop("cport", 50000),
        server=server,
        server_port=port,
        protocol=protocol,
        **kw,
    )


def cmd(src, dst, protocol, fc, function, kind, is_request=True, t=T0, **kw):
    return OtCommand(
        time=t,
        flow_id=kw.pop("flow_id", 1),
        src=src,
        dst=dst,
        protocol=protocol,
        function_code=fc,
        function=function,
        kind=kind,
        is_request=is_request,
        **kw,
    )


def cred(protocol, client, server, username, secret, kind="password", port=21, count=1):
    return Credential(
        protocol=protocol,
        kind=kind,
        client=client,
        server=server,
        server_port=port,
        username=username,
        secret=secret,
        flow_id=1,
        first_seen=T0,
        count=count,
    )


def result(hosts=(), flows=(), cmds=(), creds=(), vlan_stats=(), arp=()):
    ips = {h.ip for h in hosts}
    extra = [host(ip) for f in flows for ip in (f.client, f.server) if ip not in ips]
    seen, all_hosts = set(), []
    for h in [*hosts, *extra]:
        if h.ip not in seen:
            seen.add(h.ip)
            all_hosts.append(h)
    return AnalysisResult(
        capture=CaptureSummary(file_name="x", file_size=0, packets=0, bytes=0, first_seen=T0, last_seen=T0),
        hosts=all_hosts,
        flows=list(flows),
        ot_commands=list(cmds),
        credentials=list(creds),
        vlan_stats=list(vlan_stats),
        arp_claims=list(arp),
    )


def hits(res, rule_id):
    return [a for a in R.run_rules(res) if a.rule == rule_id]


# ── registry ──────────────────────────────────────────────────────────────────


def test_every_rule_has_metadata_and_unique_id():
    assert len(R.RULES) >= 30
    for rid, info in R.RULES.items():
        assert info.id == rid and info.category in {"network", "credentials", "ot", "iot", "vlan"}
        assert info.severity in R.SEVERITY_ORDER and info.title


def test_results_sorted_by_severity_and_ids_stable():
    res = result(
        flows=[flow("10.0.0.5", "8.8.8.8", 4444)],
        cmds=[cmd("10.0.0.5", "10.0.0.50", "S7comm", 0x29, "PLC Stop", "write")],
    )
    a1, a2 = R.run_rules(res), R.run_rules(res)
    assert [x.severity for x in a1] == sorted((x.severity for x in a1), key=R.SEVERITY_ORDER.get)
    assert [x.id for x in a1] == [x.id for x in a2]


# ── network ───────────────────────────────────────────────────────────────────


def _scan(n_hosts, n_ports, basis="handshake"):
    fl = []
    for i in range(n_ports):
        fl.append(flow("10.0.0.66", f"10.0.1.{i % n_hosts + 1}", 1000 + i, direction_basis=basis))
    return result(flows=fl)


def test_port_scan_thresholds():
    assert len(hits(_scan(6, 16), "port_scan")) == 1
    assert hits(_scan(5, 16), "port_scan") == []  # too few hosts
    assert hits(_scan(6, 15), "port_scan") == []  # too few ports


def test_port_scan_attributed_to_initiator_only():
    """Legacy bug: undirected keys blamed the *targets* too. Servers answering a scan aren't scanners."""
    a = hits(_scan(8, 20), "port_scan")
    assert [x.src for x in a] == ["10.0.0.66"]


def test_port_scan_ignores_unoriented_flows():
    assert hits(_scan(8, 20, basis="first_packet"), "port_scan") == []


def test_exfiltration_counts_only_bytes_sent_out():
    big = 11 * 1024 * 1024
    upload = flow("10.0.0.5", "93.184.216.34", 443, bytes_c2s=big, bytes_s2c=1000)
    download = flow("10.0.0.6", "93.184.216.34", 443, bytes_c2s=1000, bytes_s2c=big)  # legacy false positive
    a = hits(result(flows=[upload, download]), "exfiltration")
    assert [(x.src, x.dst) for x in a] == [("10.0.0.5", "93.184.216.34")]


def test_exfiltration_from_internal_server_to_external_client():
    f = flow("93.184.216.34", "10.0.0.80", 443, bytes_c2s=100, bytes_s2c=11 * 1024 * 1024)
    assert [(x.src, x.dst) for x in hits(result(flows=[f]), "exfiltration")] == [
        ("10.0.0.80", "93.184.216.34")
    ]


def test_exfiltration_needs_internal_external_pair_and_threshold():
    internal = flow("10.0.0.5", "10.0.0.6", 445, bytes_c2s=50 * 1024 * 1024)
    small = flow("10.0.0.5", "93.184.216.34", 443, bytes_c2s=9 * 1024 * 1024)
    assert hits(result(flows=[internal, small]), "exfiltration") == []


def test_exfiltration_sums_multiple_flows():
    fl = [flow("10.0.0.5", "93.184.216.34", 443, bytes_c2s=4 * 1024 * 1024) for _ in range(3)]
    assert len(hits(result(flows=fl), "exfiltration")) == 1


@pytest.mark.parametrize(
    "gap,jitter,n,expect",
    [
        (30.0, 0.1, 25, 1),  # regular, every 30s
        (30.0, 15.0, 25, 0),  # irregular
        (0.5, 0.0, 25, 0),  # sub-second bursts ignored
        (30.0, 0.1, 15, 0),  # too few events
    ],
)
def test_beaconing_within_a_flow(gap, jitter, n, expect):
    times = [T0 + i * gap + (jitter if i % 2 else -jitter) for i in range(n)]
    f = flow("10.0.0.5", "203.0.113.66", 8443, c2s_times=times)
    assert len(hits(result(flows=[f]), "beaconing")) == expect


def test_beaconing_across_repeated_connections():
    fl = [
        flow("10.0.0.5", "203.0.113.66", 443, first_seen=T0 + i * 60, last_seen=T0 + i * 60 + 1)
        for i in range(22)
    ]
    a = hits(result(flows=fl), "beaconing")
    assert len(a) == 1 and a[0].count == 22 and len(a[0].flow_ids) == 22


def test_suspicious_port_uses_server_port_only():
    ok = flow("10.0.0.5", "203.0.113.66", 4444)
    client_side = flow("10.0.0.5", "203.0.113.66", 443, cport=4444)  # ephemeral client port, not suspicious
    a = hits(result(flows=[ok, client_side]), "suspicious_port")
    assert len(a) == 1 and a[0].dst == "203.0.113.66"


def test_known_bad_ja3():
    bad = next(iter(R.KNOWN_BAD_JA3))
    a = hits(result(hosts=[host("10.0.0.5", tls_ja3=[bad, "0" * 32])]), "unusual_ja3")
    assert len(a) == 1 and R.KNOWN_BAD_JA3[bad] in a[0].description


@pytest.mark.parametrize(
    "queries,expect",
    [
        ([f"{'aZ9xQ2mK7pL4vB8nR3tY6wE1cU5'}{i}.evil.com" for i in range(3)], 1),  # high-entropy label
        ([f"{'a' * 70}{i}.example.com" for i in range(5)], 1),  # long names
        ([f"s{i}.tunnel.example.org" for i in range(25)], 1),  # many unique subdomains
        (["www.google.com", "mail.google.com", "docs.google.com"], 0),
        (["only.two.com"], 0),
    ],
)
def test_dns_tunneling(queries, expect):
    assert len(hits(result(hosts=[host("10.0.0.5", dns_queries=queries)]), "dns_tunneling")) == expect


# ── credentials ───────────────────────────────────────────────────────────────


def test_cleartext_credentials_grouped_and_snmp_is_medium():
    res = result(
        creds=[
            cred("FTP", "10.0.0.5", "10.0.0.80", "bob", "x1", count=3),
            cred("SNMP", "10.0.0.5", "10.0.0.1", None, "corpcomm", kind="community", port=161),
        ]
    )
    a = {x.description.split(" ")[0]: x for x in hits(res, "cleartext_credentials")}
    assert a["FTP"].severity == "high" and a["FTP"].count == 3
    assert a["SNMP"].severity == "medium"


@pytest.mark.parametrize(
    "user,secret,expect",
    [
        ("admin", "admin", 1),
        ("operator", "password", 1),
        (None, "public", 1),
        ("bob", "Tr0ub4dor&3", 0),
        ("bob", "", 0),
    ],
)
def test_default_credentials(user, secret, expect):
    res = result(creds=[cred("Telnet", "10.0.0.5", "10.0.0.30", user, secret, port=23)])
    assert len(hits(res, "default_credentials")) == expect


def test_password_reuse_needs_two_services_and_min_length():
    reuse = [
        cred("FTP", "10.0.0.5", "10.0.0.80", "a", "Summer2024!"),
        cred("HTTP", "10.0.0.5", "10.0.0.81", "a", "Summer2024!", kind="form", port=80),
    ]
    same_service = [
        cred("FTP", "10.0.0.5", "10.0.0.80", "a", "Summer2024!"),
        cred("FTP", "10.0.0.6", "10.0.0.80", "b", "Summer2024!"),
    ]
    short = [
        cred("FTP", "10.0.0.5", "10.0.0.80", "a", "abc"),
        cred("HTTP", "10.0.0.5", "10.0.0.81", "a", "abc"),
    ]
    assert len(hits(result(creds=reuse), "password_reuse")) == 1
    assert hits(result(creds=same_service), "password_reuse") == []
    assert hits(result(creds=short), "password_reuse") == []
    assert "Summer2024!" not in hits(result(creds=reuse), "password_reuse")[0].id  # secret never in the id


# ── OT ────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("protocol,rule_id", [(p, r[0]) for p, r in R.OT_WRITE_RULES.items()])
def test_ot_write_rules_per_protocol(protocol, rule_id):
    cmds = [
        cmd("10.0.0.5", "10.0.0.50", protocol, 6, "Write X", "write", t=T0 + i, address=i) for i in range(3)
    ]
    a = hits(result(cmds=cmds), rule_id)
    assert len(a) == 1 and a[0].count == 3 and a[0].first_seen == T0 and a[0].last_seen == T0 + 2
    assert "T0855" in a[0].attack and len(a[0].evidence) == 3


def test_ot_reads_and_responses_are_not_writes():
    cmds = [
        cmd("10.0.0.5", "10.0.0.50", "Modbus", 3, "Read Holding Registers", "read"),
        cmd("10.0.0.50", "10.0.0.5", "Modbus", 6, "Write Single Register", "write", is_request=False),
    ]
    assert hits(result(cmds=cmds), "ot_modbus_write") == []


def test_s7_download_and_stop_are_critical_and_separate():
    cmds = [
        cmd("10.0.0.5", "10.0.0.51", "S7comm", 0x1A, "Request download", "write", detail="Block OB1"),
        cmd("10.0.0.5", "10.0.0.51", "S7comm", 0x29, "PLC Stop", "write"),
        cmd("10.0.0.5", "10.0.0.51", "S7comm", 0x05, "Write Var", "write"),
    ]
    res = result(cmds=cmds)
    assert [(a.severity, a.evidence) for a in hits(res, "ot_s7_code_download")] == [
        ("critical", ["Block OB1"])
    ]
    assert hits(res, "ot_s7_critical")[0].severity == "critical"
    assert hits(res, "ot_s7_write")[0].count == 1  # download and stop aren't double-reported as writes


def test_modbus_bulk_read_threshold():
    big = cmd("10.0.0.5", "10.0.0.50", "Modbus", 3, "Read Holding Registers", "read", quantity=125, address=0)
    edge = cmd("10.0.0.5", "10.0.0.50", "Modbus", 3, "Read Holding Registers", "read", quantity=100)
    assert len(hits(result(cmds=[big]), "ot_modbus_bulk_read")) == 1
    assert hits(result(cmds=[edge]), "ot_modbus_bulk_read") == []


def test_modbus_broadcast_unit_zero():
    c0 = cmd("10.0.0.5", "10.0.0.50", "Modbus", 6, "Write Single Register", "write", unit=0)
    c1 = cmd("10.0.0.5", "10.0.0.50", "Modbus", 6, "Write Single Register", "write", unit=1)
    assert len(hits(result(cmds=[c0, c1]), "ot_modbus_broadcast")) == 1


def test_modbus_exception_reported_from_client_view():
    e = cmd(
        "10.0.0.50",
        "10.0.0.5",
        "Modbus",
        3,
        "Read Holding Registers",
        "error",
        is_request=False,
        detail="Exception: Illegal data address",
    )
    a = hits(result(cmds=[e]), "ot_modbus_exception")
    assert (a[0].src, a[0].dst) == ("10.0.0.5", "10.0.0.50")


def test_dnp3_disruptive_functions():
    """Legacy bug: called FC 4 (Operate) 'Immediate Freeze'. Restarts/stop/disable-unsolicited are the risky ones."""
    restart = cmd("10.0.0.5", "10.0.0.60", "DNP3", 13, "Cold Restart", "write")
    operate = cmd("10.0.0.5", "10.0.0.60", "DNP3", 4, "Operate", "write")
    a = hits(result(cmds=[restart, operate]), "ot_dnp3_unusual_fc")
    assert [x.description for x in a] == ["10.0.0.5 sent DNP3 'Cold Restart' to 10.0.0.60"]


def test_multiunit_poll_ignores_unit_zero():
    five = [cmd("10.0.0.5", "10.0.0.50", "Modbus", 3, "Read", "read", unit=u) for u in range(1, 6)]
    four_plus_zero = [cmd("10.0.0.5", "10.0.0.50", "Modbus", 3, "Read", "read", unit=u) for u in range(0, 5)]
    assert len(hits(result(cmds=five), "ot_multiunit_poll")) == 1
    assert hits(result(cmds=four_plus_zero), "ot_multiunit_poll") == []


def test_ot_internet_exposure():
    plc = host("10.0.0.50", host_type="PLC")
    a = hits(
        result(hosts=[plc], flows=[flow("93.184.216.34", "10.0.0.50", 502, protocol="Modbus")]),
        "ot_internet_exposure",
    )
    assert (a[0].src, a[0].dst, a[0].severity) == ("10.0.0.50", "93.184.216.34", "critical")
    office = host("10.0.0.7", host_type="Windows Host")
    assert (
        hits(result(hosts=[office], flows=[flow("10.0.0.7", "93.184.216.34", 443)]), "ot_internet_exposure")
        == []
    )


def test_ot_cleartext_grouped_per_server_protocol():
    fl = [flow(f"10.0.0.{i}", "10.0.0.50", 502, protocol="Modbus") for i in range(5, 9)]
    a = hits(result(flows=fl), "ot_cleartext")
    assert len(a) == 1 and a[0].count == 4 and len(a[0].evidence) == 4


# ── IoT ───────────────────────────────────────────────────────────────────────


def test_camera_exfil_only_outbound_or_large():
    cam = host("10.0.0.30", host_type="IP Camera")
    outbound = flow("10.0.0.30", "93.184.216.34", 443, bytes_c2s=5000)
    inbound_small = flow("198.51.100.9", "10.0.0.30", 23, bytes_s2c=300)
    inbound_large = flow("198.51.100.10", "10.0.0.30", 554, bytes_s2c=5 * 1024 * 1024)
    a = hits(result(hosts=[cam], flows=[outbound, inbound_small, inbound_large]), "iot_camera_exfil")
    assert sorted(x.dst for x in a) == ["198.51.100.10", "93.184.216.34"]


def test_iot_telnet_and_mqtt_and_tr069():
    cam = host("10.0.0.30", host_type="IP Camera")
    res = result(
        hosts=[cam],
        flows=[
            flow("10.0.0.5", "10.0.0.30", 23, protocol="Telnet"),
            flow("10.0.0.5", "10.0.0.31", 23, protocol="Telnet"),
            flow("10.0.0.40", "10.0.0.60", 1883, protocol="MQTT"),
            flow("10.0.0.1", "93.184.216.34", 7547),
        ],
    )
    assert [a.dst for a in hits(res, "iot_telnet")] == ["10.0.0.30"]  # only the IoT target
    assert len(hits(res, "iot_mqtt_cleartext")) == 1
    assert len(hits(res, "iot_tr069")) == 1


# ── VLAN (model level) ────────────────────────────────────────────────────────


def test_vlan_hopping_excludes_routers_qinq_and_gateway_seen_hosts():
    res = result(
        hosts=[
            host("10.0.0.5", vlans=[10, 20], host_type="Windows Host"),
            host("10.0.0.1", vlans=[10, 20], host_type="Router"),
            host("10.0.0.6", vlans=[10, 20], vlan_qinq=True),
            host("10.0.0.7", vlans=[10, 20], mac_is_gateway=True),
            host("93.184.216.34", vlans=[10, 20]),
        ]
    )
    assert [a.src for a in hits(res, "vlan_hopping")] == ["10.0.0.5"]


def test_native_leak_requires_sent_frames():
    res = result(
        hosts=[
            host("10.0.0.5", vlans=[10], vlan_untagged=True, packets_sent=3),
            host("10.0.0.6", vlans=[10], vlan_untagged=True, packets_sent=0),
        ]
    )
    assert [a.src for a in hits(res, "vlan_native_leak")] == ["10.0.0.5"]


def test_cross_segment_ot():
    plc = host("10.0.0.50", host_type="PLC", vlans=[30])
    hmi = host("10.0.0.5", vlans=[10])
    same = host("10.0.0.6", vlans=[30])
    res = result(
        hosts=[plc, hmi, same],
        flows=[
            flow("10.0.0.5", "10.0.0.50", 502, protocol="Modbus"),
            flow("10.0.0.6", "10.0.0.50", 502, protocol="Modbus"),
        ],
    )
    assert [a.src for a in hits(res, "vlan_cross_segment_ot")] == ["10.0.0.5"]


@pytest.mark.parametrize(
    "pcps,htype,expect",
    [([7], "Windows Host", 1), ([6], "IP Camera", 1), ([5], "Windows Host", 0), ([7], "Router", 0)],
)
def test_pcp_abuse(pcps, htype, expect):
    assert len(hits(result(hosts=[host("10.0.0.5", vlan_pcps=pcps, host_type=htype)]), "pcp_abuse")) == expect


def test_arp_spoofing_and_broadcast_storm_from_stats():
    res = result(
        arp=[
            ArpClaim(vlan=10, ip="10.0.0.1", macs=["aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02"]),
            ArpClaim(vlan=10, ip="10.0.0.2", macs=["aa:aa:aa:aa:aa:03"]),
        ],
        vlan_stats=[
            VlanStat(vlan=10, packets=400, broadcast=60),
            VlanStat(vlan=20, packets=100, broadcast=40),
            VlanStat(vlan=None, packets=1000, broadcast=50),
        ],
    )
    assert [a.src for a in hits(res, "arp_spoofing")] == ["10.0.0.1"]
    storms = hits(res, "broadcast_storm")
    # VLAN 10: 15% of 400 with 60 broadcasts. VLAN 20: only 40 broadcasts. Untagged: just 5%.
    assert len(storms) == 1 and "VLAN 10" in storms[0].description and "15%" in storms[0].description


# ── L2 rules end to end (real tshark) ─────────────────────────────────────────

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")


@needs_tshark
def test_l2_rules_from_capture(tmp_path):
    from pcapvis.engine.analyze import analyze_capture
    from tests.pcapgen import Cap

    cap = Cap()
    cap.arp_reply("00:0c:29:00:00:01", "10.0.0.1", vlan=10)
    cap.arp_reply("00:0c:29:66:66:66", "10.0.0.1", vlan=10)  # second MAC claims the gateway IP
    for i in range(60):
        cap.arp_request("00:0c:29:00:00:09", "10.0.0.9", f"10.0.0.{100 + i % 50}", vlan=10)
    cap.udp(("00:0c:29:00:00:05", "10.0.0.5"), ("00:0c:29:00:00:50", "10.0.0.50"), 50000, 161, vlan=10, pcp=7)
    cap.udp(("00:0c:29:00:00:07", "10.0.0.7"), ("00:0c:29:00:00:50", "10.0.0.50"), 50000, 161, qinq=(100, 10))
    r = analyze_capture(cap.write(tmp_path / "l2.pcap"))
    rules_hit = {a.rule for a in r.anomalies}
    assert {"arp_spoofing", "broadcast_storm", "pcp_abuse", "vlan_qinq"} <= rules_hit
    assert next(a for a in r.anomalies if a.rule == "arp_spoofing").src == "10.0.0.1"
