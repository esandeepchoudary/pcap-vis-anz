"""Engine step A: decoding, directional flows, hosts, classification, evidence. Uses real tshark."""

import shutil
from pathlib import Path

import pytest

from pcapvis.engine.analyze import analyze_capture
from pcapvis.engine.runner import CaptureError
from tests.pcapgen import Cap, http_get, http_ok, modbus, tls_client_hello

pytestmark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")

C = ("00:0c:29:00:00:01", "10.0.0.5")  # client workstation
S = ("00:a0:87:00:00:02", "10.0.0.50")  # server / PLC
R = ("00:00:5e:00:01:01", "10.0.0.1")  # router
REPO = Path(__file__).resolve().parents[2]


def run(cap: Cap, tmp_path, **kw):
    return analyze_capture(cap.write(tmp_path / "t.pcap"), **kw)


def host(r, ip):
    return next(h for h in r.hosts if h.ip == ip)


def flow(r, server_port):
    return next(f for f in r.flows if f.server_port == server_port)


# ── Directional flows ─────────────────────────────────────────────────────────


def test_tcp_handshake_orients_flow_and_counts_each_direction(tmp_path):
    cap = Cap().tcp_session(C, S, 50000, 80, [("c", http_get("plc")), ("s", http_ok(b"hello"))])
    r = run(cap, tmp_path)
    f = flow(r, 80)
    assert (f.client, f.client_port, f.server, f.server_port) == ("10.0.0.5", 50000, "10.0.0.50", 80)
    assert f.direction_basis == "handshake" and f.syn_seen
    assert f.packets_c2s == 4 and f.packets_s2c == 3  # SYN, ACK, GET, FIN | SYN-ACK, 200, FIN
    assert f.bytes_c2s > 0 and f.bytes_s2c > 0
    assert f.protocol == "HTTP" and "HTTP" in f.detected_protocols


def test_midstream_tcp_uses_server_port(tmp_path):
    # Capture starts mid-conversation: first packet is the server's reply.
    cap = Cap().tcp_session(
        C,
        S,
        50001,
        502,
        [("s", modbus(1, 1, b"\x03\x02\x00\x01")), ("c", modbus(2, 1, b"\x03\x00\x00\x00\x01"))],
        handshake=False,
    )
    f = flow(run(cap, tmp_path), 502)
    assert (f.client, f.server) == ("10.0.0.5", "10.0.0.50")
    assert f.direction_basis == "port"
    assert f.packets_c2s == 1 and f.packets_s2c == 1


def test_late_syn_flips_a_wrong_first_guess(tmp_path):
    # Both ports ephemeral, server speaks first (wrong guess), then a SYN reveals the real client.
    cap = Cap()
    cap.tcp_session(C, S, 50002, 50003, [("s", b"banner")], handshake=False)
    cap.tcp_session(C, S, 50002, 50003, [("c", b"hi")], handshake=True, close=False)
    f = next(f for f in run(cap, tmp_path).flows if f.transport == "tcp")
    assert (f.client, f.client_port, f.server_port) == ("10.0.0.5", 50002, 50003)
    assert f.direction_basis == "handshake"
    # banner + SYN-ACK from the server; SYN + ACK + "hi" from the client
    assert f.packets_s2c == 2 and f.packets_c2s == 3


def test_udp_dns_direction(tmp_path):
    cap = Cap().dns(C, S, "historian.plant.local", answers=["10.0.0.60"])
    f = flow(run(cap, tmp_path), 53)
    assert f.client == "10.0.0.5" and f.transport == "udp" and f.protocol == "DNS"


@pytest.mark.parametrize("ipv6", [False, True])
def test_icmp_echo_direction_even_when_reply_comes_first(tmp_path, ipv6):
    c = (C[0], "fd00::5") if ipv6 else C
    s = (S[0], "fd00::50") if ipv6 else S
    r = run(Cap().ping(c, s, reply_first=True, ipv6=ipv6), tmp_path)
    f = r.flows[0]
    assert f.client == c[1] and f.server == s[1]
    assert f.direction_basis == "request"
    assert f.protocol == ("ICMPv6" if ipv6 else "ICMP")


def test_separate_connections_are_separate_flows(tmp_path):
    cap = Cap().tcp_session(C, S, 50010, 80).tcp_session(C, S, 50011, 80)
    r = run(cap, tmp_path)
    assert len([f for f in r.flows if f.server_port == 80]) == 2


# ── Hosts: MACs, vendors, gateways ────────────────────────────────────────────


def test_mac_and_wireshark_vendor(tmp_path):
    r = run(Cap().tcp_session(C, S, 50000, 502), tmp_path)
    plc = host(r, "10.0.0.50")
    assert plc.mac == "00:a0:87:00:00:02"
    assert plc.mac_vendor  # resolved from Wireshark's OUI database, not a hand-made table


def test_router_mac_not_attributed_to_internet_hosts(tmp_path):
    cap = Cap()
    cap.arp_reply(R[0], R[1])
    for i in range(4):  # internet servers all arrive with the router's MAC
        cap.tcp_session(C, (R[0], f"93.184.216.{i + 1}"), 50100 + i, 443)
    r = run(cap, tmp_path)
    ext = host(r, "93.184.216.1")
    assert ext.mac is None and ext.mac_is_gateway
    assert ext.is_private is False and ext.purdue_level == 6
    router = host(r, "10.0.0.1")
    assert router.mac == R[0] and router.host_type == "Router"
    assert any(e.kind == "gateway_mac" for e in router.host_type_evidence)


def test_arp_only_host_is_discovered(tmp_path):
    r = run(Cap().arp_reply("00:1d:9c:00:00:09", "10.0.0.9"), tmp_path)
    h = host(r, "10.0.0.9")
    assert h.mac == "00:1d:9c:00:00:09" and h.packets_sent == 0


# ── VLANs ─────────────────────────────────────────────────────────────────────


def test_single_vlan_and_untagged(tmp_path):
    cap = (
        Cap()
        .tcp_session(C, S, 50000, 502, vlan=20)
        .tcp_session(("00:0c:29:00:00:07", "10.0.0.7"), S, 50001, 80)
    )
    r = run(cap, tmp_path)
    assert host(r, "10.0.0.5").vlans == [20]
    assert host(r, "10.0.0.50").vlans == [20]
    assert host(r, "10.0.0.7").vlan_untagged and host(r, "10.0.0.7").vlans == []
    assert flow(r, 502).vlans == [20]


def test_routed_traffic_doesnt_put_hosts_on_the_senders_vlan(tmp_path):
    """Between VLANs, frames reach the router tagged with the sender's VLAN: the receiver isn't on it."""
    from scapy.all import IP, TCP, Dot1Q, Ether

    router = "00:1b:54:00:00:01"
    hmi, plc = ("00:0e:8c:00:00:01", "10.40.0.11"), ("00:1b:1b:00:00:10", "10.50.0.10")
    cap = Cap()
    for i in range(3):  # HMI on VLAN 400 → router; reply from the PLC on VLAN 500 → router
        cap.add(
            Ether(src=hmi[0], dst=router)
            / Dot1Q(vlan=400)
            / IP(src=hmi[1], dst=plc[1])
            / TCP(sport=50000, dport=102, flags="S" if i == 0 else "A")
        )
        cap.add(
            Ether(src=plc[0], dst=router)
            / Dot1Q(vlan=500)
            / IP(src=plc[1], dst=hmi[1])
            / TCP(sport=102, dport=50000, flags="SA" if i == 0 else "A")
        )
    # A silent host (never answers) on VLAN 500, reached at its own MAC: it is on VLAN 500.
    cap.add(
        Ether(src=plc[0], dst="00:1b:1b:00:00:11")
        / Dot1Q(vlan=500)
        / IP(src=plc[1], dst="10.50.0.11")
        / TCP(sport=40000, dport=102, flags="S")
    )
    r = run(cap, tmp_path)
    assert host(r, "10.40.0.11").vlans == [400]
    assert host(r, "10.50.0.10").vlans == [500]
    assert host(r, "10.50.0.11").vlans == [500]


@pytest.mark.parametrize("kw", [{"qinq": (100, 20)}, {"stacked": (100, 20)}])
def test_qinq_inner_and_outer(tmp_path, kw):
    r = run(Cap().udp(C, S, 50000, 161, **kw), tmp_path)
    h = host(r, "10.0.0.5")
    assert h.vlans == [20] and h.vlan_outer == [100] and h.vlan_qinq


def test_pcp_recorded(tmp_path):
    r = run(Cap().udp(C, S, 50000, 161, vlan=10, pcp=6), tmp_path)
    assert host(r, "10.0.0.5").vlan_pcps == [6]


# ── Names, TLS ────────────────────────────────────────────────────────────────


def test_dns_answers_name_hosts_and_queries_are_recorded(tmp_path):
    hist = ("00:0c:29:00:00:60", "10.0.0.60")
    cap = Cap().dns(C, S, "historian.plant.local", answers=["10.0.0.60", "10.0.0.61"])
    cap.tcp_session(C, hist, 50000, 443)  # the client then talks to the historian
    r = run(cap, tmp_path)
    assert host(r, "10.0.0.60").hostname == "historian.plant.local"
    assert host(r, "10.0.0.60").hostnames[0].source == "dns"
    assert host(r, "10.0.0.5").dns_queries == ["historian.plant.local"]
    # 10.0.0.61 was only named in the answer, never seen on the wire: not a device in the inventory.
    assert "10.0.0.61" not in {h.ip for h in r.hosts}


def test_lldp_names_switch_and_classifies_network_device(tmp_path):
    sw = ("00:01:2f:00:00:aa", "10.0.0.2")
    cap = Cap().lldp(sw[0], "core-sw-01").arp_reply(*sw)
    h = host(run(cap, tmp_path), "10.0.0.2")
    assert h.hostname == "core-sw-01"
    assert h.host_type == "Network Device" and h.host_type_confidence == "high"
    assert h.identity.get("lldp_system_description") == "Test switch OS 1.0"


def test_cdp_names_switch(tmp_path):
    sw = ("00:01:2f:00:00:bb", "10.0.0.3")
    cap = Cap().cdp(sw[0], "dist-sw-02", native_vlan=99).arp_reply(*sw)
    h = host(run(cap, tmp_path), "10.0.0.3")
    assert h.hostname == "dist-sw-02" and h.host_type == "Network Device"
    assert h.identity.get("cdp_platform") == "cisco WS-C2960"


def test_dhcp_hostname_links_via_mac(tmp_path):
    cap = Cap().dhcp_request(C[0], "ENG-WS-01").tcp_session(C, S, 50000, 80)
    h = host(run(cap, tmp_path), "10.0.0.5")
    assert any(n.name == "ENG-WS-01" and n.source == "dhcp" for n in h.hostnames)
    assert h.identity.get("dhcp_vendor_class") == "MSFT 5.0"


def test_tls_sni_ja3_ja4(tmp_path):
    cap = Cap().tcp_session(
        C, ("00:00:5e:00:01:01", "93.184.216.34"), 50000, 443, [("c", tls_client_hello("shop.example.com"))]
    )
    r = run(cap, tmp_path)
    c = host(r, "10.0.0.5")
    assert c.tls_sni == ["shop.example.com"]
    assert len(c.tls_ja3) == 1 and len(c.tls_ja3[0]) == 32
    assert len(c.tls_ja4) == 1
    assert flow(r, 443).protocol == "HTTPS"


# ── Classification & Purdue ───────────────────────────────────────────────────


def test_priority_picks_plc_over_web_and_lists_alternatives(tmp_path):
    cap = (
        Cap()
        .tcp_session(C, S, 50000, 80, [("c", http_get("plc")), ("s", http_ok())])
        .tcp_session(
            C,
            S,
            50001,
            502,
            [("c", modbus(1, 1, b"\x03\x00\x00\x00\x01")), ("s", modbus(1, 1, b"\x03\x02\x00\x07"))],
        )
    )
    plc = host(run(cap, tmp_path), "10.0.0.50")
    assert plc.host_type == "PLC" and plc.host_type_confidence == "high"
    assert "tshark" in plc.host_type_evidence[0].detail and "502" in plc.host_type_evidence[0].detail
    assert any("Web Server" in e.detail for e in plc.host_type_evidence if e.kind == "also_suggested")
    assert plc.purdue_level == 1


def test_port_only_hint_is_medium_confidence(tmp_path):
    # Bare SYN/SYN-ACK on 3306 without payload: tshark can't identify MySQL, the port table can.
    h = host(run(Cap().tcp_session(C, S, 50000, 3306), tmp_path), "10.0.0.50")
    assert h.host_type == "Database Server" and h.host_type_confidence == "medium"
    assert "by port number" in h.host_type_evidence[0].detail


def test_os_fallback_is_low_confidence(tmp_path):
    r = run(Cap().tcp_session(C, S, 50000, 50001, ttl_c=128, handshake=True), tmp_path)
    c = host(r, "10.0.0.5")
    assert c.os_hint == "Windows" and c.host_type == "Windows Host" and c.host_type_confidence == "low"


def test_it_host_talking_ot_is_level_3(tmp_path):
    # A Windows file server (SMB) that also polls a PLC over Modbus → supervisory (L3), not business (L4).
    ws = ("00:15:5d:00:00:05", "10.0.0.6")
    cap = (
        Cap()
        .tcp_session(C, ws, 50000, 445)
        .tcp_session(ws, S, 50001, 502, [("c", modbus(1, 1, b"\x03\x00\x00\x00\x01"))])
    )
    h = host(run(cap, tmp_path), "10.0.0.6")
    assert h.host_type == "Windows Host" and h.purdue_level == 3
    assert any(e.kind == "ot_protocols" for e in h.purdue_evidence)


@pytest.mark.parametrize(
    "ip,private",
    [
        ("10.1.2.3", True),
        ("172.16.0.1", True),
        ("192.168.1.1", True),
        ("100.64.0.1", True),
        ("169.254.1.1", True),
        ("8.8.8.8", False),
        ("198.51.100.7", False),
        ("172.32.0.1", False),
    ],
)
def test_private_ranges(ip, private):
    from pcapvis.engine.knowledge import ip_info

    assert ip_info(ip)[1] is private


def test_broadcast_and_multicast(tmp_path):
    cap = (
        Cap()
        .udp(C, ("ff:ff:ff:ff:ff:ff", "255.255.255.255"), 68, 67)
        .udp(C, ("01:00:5e:00:00:fb", "224.0.0.251"), 5353, 5353)
    )
    r = run(cap, tmp_path)
    assert host(r, "255.255.255.255").host_type == "Broadcast"
    assert host(r, "224.0.0.251").host_type == "Multicast"
    assert host(r, "224.0.0.251").purdue_level == -1


# ── Capture handling ──────────────────────────────────────────────────────────


def test_summary_counts_and_times(tmp_path):
    cap = Cap(start=1_700_000_000.0, step=0.5).tcp_session(C, S, 50000, 80)
    r = run(cap, tmp_path)
    assert r.capture.packets == 5 and r.capture.bytes > 0
    assert r.capture.first_seen == pytest.approx(1_700_000_000.5)
    assert r.capture.last_seen == pytest.approx(1_700_000_002.5)
    assert r.capture.link_types == ["eth"] and r.capture.truncated is False
    assert r.capture.tshark_version


def test_max_packets_truncates(tmp_path):
    cap = Cap()
    for i in range(10):
        cap.tcp_session(C, S, 50000 + i, 80)
    r = run(cap, tmp_path, max_packets=7)
    assert r.capture.packets == 7 and r.capture.truncated


def test_progress_and_cancel(tmp_path):
    cap = Cap()
    for _ in range(1200):
        cap.udp(C, S, 50000, 161)
    calls = []
    r = run(cap, tmp_path, progress=lambda fed, total, n: calls.append((fed, total, n)))
    assert calls and calls[-1][0] == calls[-1][1] and calls[-1][2] == 1200
    r = run(cap, tmp_path, should_cancel=lambda: True)
    assert r.capture.truncated and r.capture.packets == 1000


def test_not_a_capture_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture file")
    with pytest.raises(CaptureError, match="capture"):
        analyze_capture(bad)


def test_empty_capture_is_ok(tmp_path):
    empty = tmp_path / "empty.pcap"
    Cap().write(empty)  # header only, no packets
    r = analyze_capture(empty)
    assert r.capture.packets == 0 and r.hosts == [] and r.flows == []


def test_pcapng_supported(tmp_path):
    from scapy.utils import PcapNgWriter

    path = tmp_path / "t.pcapng"
    cap = Cap().tcp_session(C, S, 50000, 80)
    with PcapNgWriter(str(path)) as w:
        for f in cap.frames:
            w.write(f)
    assert analyze_capture(path).capture.packets == 5


def test_reads_files_outside_tmp(tmp_path):
    """Feeding via stdin sidesteps tshark's AppArmor profile, which only allows /tmp paths."""
    r = analyze_capture(REPO / "fixtures" / "network-capture-demo.pcap")
    assert r.capture.packets == 401 and len(r.hosts) > 20


def test_result_is_json_serialisable(tmp_path):
    r = run(Cap().tcp_session(C, S, 50000, 80), tmp_path)
    data = r.model_dump_json()
    assert '"hosts"' in data and '"flows"' in data


# ── Behaviours found by the legacy parity harness ─────────────────────────────


def test_silent_host_gets_mac_from_frames_sent_to_it(tmp_path):
    # A scan target that never answers: its MAC is still the destination MAC of frames sent to it.
    r = run(Cap().udp(C, ("00:0c:29:00:00:99", "10.0.0.99"), 50000, 161), tmp_path)
    h = host(r, "10.0.0.99")
    assert h.packets_sent == 0 and h.mac == "00:0c:29:00:00:99" and not h.mac_is_gateway


def test_router_mac_as_destination_is_not_given_to_remote_hosts(tmp_path):
    cap = Cap()
    for i in range(4):  # the router's MAC is the destination for several remote IPs
        cap.udp(C, (R[0], f"10.9.{i}.1"), 50000, 161)
    r = run(cap, tmp_path)
    assert host(r, "10.9.0.1").mac is None and host(r, "10.9.0.1").mac_is_gateway


def test_symmetric_port_peer_is_a_device_too(tmp_path):
    # CoAP sensor posting to a gateway, both on udp/5683: the sensor is an IoT device, not "Linux Host".
    from tests.pcapgen import coap_get

    sensor = ("d8:eb:d3:00:00:40", "10.0.0.40")
    gw = ("f4:f2:6d:00:00:60", "10.0.0.60")
    r = run(Cap().udp(sensor, gw, 5683, 5683, coap_get(["temp"])), tmp_path)
    assert host(r, "10.0.0.40").host_type == "IoT Sensor"
    assert host(r, "10.0.0.60").host_type == "IoT Sensor"


def test_symmetric_port_master_is_not_called_a_device(tmp_path):
    # A BMS workstation *sending* BACnet writes from 47808 is the master, not a building controller.
    from tests.pcapgen import bacnet_confirmed

    bms = ("00:0c:29:00:00:05", "10.0.0.5")
    ctrl = ("00:0c:29:00:00:80", "10.0.0.80")
    r = run(Cap().udp(bms, ctrl, 47808, 47808, bacnet_confirmed(15)), tmp_path)
    assert host(r, "10.0.0.80").host_type == "Building Controller"
    assert host(r, "10.0.0.5").host_type != "Building Controller"
    assert host(r, "10.0.0.5").purdue_level == 3  # it commands OT devices


def test_netbios_from_port_137_does_not_make_a_windows_host(tmp_path):
    lin = ("08:00:27:00:00:10", "10.0.0.10")
    r = run(Cap().udp(lin, ("ff:ff:ff:ff:ff:ff", "10.0.0.255"), 137, 137, b"\x00" * 50, ttl=64), tmp_path)
    assert host(r, "10.0.0.10").host_type == "Linux Host"


def test_plain_linux_host_is_unclassified_for_purdue(tmp_path):
    r = run(Cap().tcp_session(C, S, 50000, 50001, ttl_c=64), tmp_path)
    h = host(r, "10.0.0.5")
    assert h.host_type == "Linux Host" and h.purdue_level == -1  # consultant decides; no guessing


def _office(cap: Cap, n: int, vlan: int, net: str):
    """n Windows PCs on one VLAN browsing an internal web server (ordinary Level 4 hosts)."""
    web = ("00:15:5d:00:00:fe", f"{net}.250")
    for i in range(n):
        pc = (f"3c:52:82:00:{vlan % 256:02x}:{i:02x}", f"{net}.{10 + i}")
        cap.tcp_session(
            pc,
            web,
            50000 + i,
            80,
            [("c", http_get("intranet")), ("s", http_ok())],
            vlan=vlan,
            ttl_c=128,
            ttl_s=128,
        )


def test_business_pc_reaching_a_plc_stays_at_level_4(tmp_path):
    """Moving it to Level 3 would hide the DMZ bypass the assessment is looking for."""
    plc = ("00:1b:1b:00:00:10", "10.50.0.10")
    cap = Cap()
    _office(cap, 5, 100, "10.10.0")
    rogue = ("3c:52:82:00:64:63", "10.10.0.99")
    cap.tcp_session(
        rogue,
        plc,
        50100,
        502,
        [("c", modbus(1, 1, b"\x03\x00\x00\x00\x02")), ("s", modbus(1, 1, b"\x03\x04\x00\x00\x00\x00"))],
        vlan=100,
        ttl_c=128,
    )
    r = run(cap, tmp_path)
    h = host(r, "10.10.0.99")
    assert h.purdue_level == 4
    assert any(e.kind == "segment" and "business segment" in e.detail for e in h.purdue_evidence)


def test_engineering_station_on_a_plant_segment_moves_to_level_3(tmp_path):
    plc = ("00:1b:1b:00:00:10", "10.50.0.10")
    cap = Cap()
    _office(cap, 5, 100, "10.10.0")  # the office exists, but the station isn't on it
    ews = ("00:1c:06:00:00:21", "10.30.0.21")
    cap.tcp_session(
        ews,
        plc,
        50100,
        502,
        [("c", modbus(1, 1, b"\x03\x00\x00\x00\x02")), ("s", modbus(1, 1, b"\x03\x04\x00\x00\x00\x00"))],
        vlan=300,
        ttl_c=128,
    )
    r = run(cap, tmp_path)
    assert host(r, "10.30.0.21").purdue_level == 3


def test_closed_ports_from_a_scan_are_not_services(tmp_path):
    """A port that only answers with a reset is closed: a port scan must not make the target look like a PLC."""
    from scapy.all import IP, TCP, Ether

    scanner, target = ("f0:2f:74:de:ad:01", "10.10.0.200"), ("00:15:5d:30:00:0b", "10.30.0.11")
    cap = Cap()
    for port in (102, 502, 44818, 20000):
        cap.add(
            Ether(src=scanner[0], dst=target[0])
            / IP(src=scanner[1], dst=target[1])
            / TCP(sport=40000 + port % 1000, dport=port, flags="S")
        )
        cap.add(
            Ether(src=target[0], dst=scanner[0])
            / IP(src=target[1], dst=scanner[1], ttl=128)
            / TCP(sport=port, dport=40000 + port % 1000, flags="RA")
        )
    cap.tcp_session(
        ("00:15:5d:20:00:0a", "10.20.0.10"),
        target,
        50000,
        443,
        [("c", b"\x16\x03\x01" + bytes(60)), ("s", b"\x16\x03\x03" + bytes(60))],
    )
    r = run(cap, tmp_path)
    h = host(r, "10.30.0.11")
    assert [s.port for s in h.services] == [443]
    assert h.host_type != "PLC"
    assert {f.server_port for f in r.flows if not f.server_answered} == {102, 502, 44818, 20000}


def test_one_way_tap_still_finds_services(tmp_path):
    """Only client→server packets were captured: a client that keeps talking implies an open port."""
    from scapy.all import IP, TCP, Ether

    c, s = ("00:0c:29:00:00:05", "10.0.0.5"), ("00:1b:1b:00:00:10", "10.0.0.50")
    cap = Cap()
    for i in range(5):
        cap.add(
            Ether(src=c[0], dst=s[0])
            / IP(src=c[1], dst=s[1])
            / TCP(sport=50000, dport=102, flags="S" if i == 0 else "PA")
            / (b"" if i == 0 else b"\x03\x00\x00\x16" + bytes(18))
        )
    r = run(cap, tmp_path)
    assert [x.port for x in host(r, "10.0.0.50").services] == [102]
