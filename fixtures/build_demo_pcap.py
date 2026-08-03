#!/usr/bin/env python3
"""
Build a realistic, richly-varied demo PCAP for pcap-vis-anz.

Generates fixtures/network-capture-demo.pcap: a synthetic capture spanning a
small enterprise + OT network, crafted to exercise as many of the app's
views/panels as practical (Graph, Table, DNS Map, OT Map/Log/Analysis,
VLAN Graph/Matrix, Timeline, Findings/Credentials, File Transfers, Anomalies).

Byte layouts for the deep-inspection protocols (Modbus, MQTT, CoAP, S7comm,
CDP, LLDP, TLS ClientHello) are hand-built to match the exact parsers in
app.py (parse_modbus / parse_mqtt / parse_coap / parse_s7comm /
parse_tls_client_hello, and the inline CDP/LLDP/ARP handling in
analyze_pcap()) byte-for-byte, cross-checked against tests/test_vlan.py,
tests/test_http_mqtt_coap.py and tests/test_credentials.py.

Run:
    python3 fixtures/build_demo_pcap.py
Output:
    fixtures/network-capture-demo.pcap
"""
import struct
import os

from scapy.utils import wrpcap
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

BASE_TS = 1732000000.0  # fixed epoch for reproducibility (2024-11-19T09:46:40Z)

OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network-capture-demo.pcap")

pkts = []
_clock = [0.0]


def adv(dt):
    """Advance the global clock by dt seconds and return the new absolute time."""
    _clock[0] += dt
    return BASE_TS + _clock[0]


def add(layer, dt=0.05):
    """Timestamp *layer* with the current clock (after advancing by dt) and store it."""
    layer.time = adv(dt)
    pkts.append(layer)


# ── Host inventory ────────────────────────────────────────────────────────────
# Untagged backbone
GW_MAC, GW_IP = "00:15:17:aa:bb:01", "10.0.0.1"          # gateway/router (Cisco)
SW1_MAC, SW1_IP = "00:01:2f:aa:bb:02", "10.0.0.2"         # core switch (Cisco) -> CDP
SW2_MAC, SW2_IP = "00:01:42:aa:bb:03", "10.0.0.3"         # access switch (Cisco) -> LLDP

# VLAN 10 (IT / corporate)
WS1_MAC, WS1_IP = "08:00:27:aa:bb:10", "10.0.1.10"        # workstation1 (VirtualBox)
WS2_MAC, WS2_IP = "52:54:00:aa:bb:11", "10.0.1.11"        # workstation2 (QEMU/KVM)
EXF_MAC, EXF_IP = "00:0c:29:aa:bb:12", "10.0.1.12"        # compromised host (VMware) -> exfil
WIN_MAC, WIN_IP = "00:15:5d:aa:bb:20", "10.0.1.20"        # windows host (Microsoft Hyper-V)
WEB_MAC, WEB_IP = "00:0c:29:aa:bb:80", "10.0.1.80"        # web server (VMware)
DNS_MAC, DNS_IP = "00:1c:14:aa:bb:53", "10.0.1.53"        # dns server (VMware)
CAM_MAC, CAM_IP = "18:b4:30:aa:bb:30", "10.0.1.30"        # ip camera (Ring)
MQB_MAC, MQB_IP = "f4:f2:6d:aa:bb:60", "10.0.1.60"        # mqtt broker (Amazon Echo OUI)
THM_MAC, THM_IP = "00:17:f2:aa:bb:41", "10.0.1.41"        # mqtt client / smart thermostat (Nest Labs)
SOIL_MAC, SOIL_IP = "d8:eb:d3:aa:bb:40", "10.0.1.40"      # coap soil sensor (LIFX OUI)
VLAN_IT = 10

# VLAN 20 (OT)
EWS_MAC, EWS_IP = "00:0c:29:aa:bb:c0", "10.0.2.10"        # engineering workstation (VMware VM)
PLCA_MAC, PLCA_IP = "00:a0:87:aa:bb:50", "10.0.2.50"      # PLC-A / Modbus (Schneider Electric)
PLCB_MAC, PLCB_IP = "00:1f:b9:aa:bb:51", "10.0.2.51"      # PLC-B / S7comm (Siemens)
VLAN_OT = 20

# External / Internet
ISP_MAC, ISP_IP = "02:00:00:aa:bb:01", "198.51.100.1"       # BGP peer
EXTCLIENT_MAC, EXTCLIENT_IP = "02:00:00:aa:bb:02", "203.0.113.10"   # browses web server
ATTACKER_MAC, ATTACKER_IP = "02:00:00:aa:bb:03", "198.51.100.77"    # port scanner + telnet
C2_MAC, C2_IP = "02:00:00:aa:bb:04", "203.0.113.66"                 # beacon target (suspicious port)
CLOUD_MAC, CLOUD_IP = "02:00:00:aa:bb:05", "198.51.100.200"         # exfil destination
CAMC2_MAC, CAMC2_IP = "02:00:00:aa:bb:06", "198.51.100.50"          # camera phones home
EXAMPLE_MAC, EXAMPLE_IP = "02:00:00:aa:bb:07", "93.184.216.34"      # example.com (TLS SNI target)

# IPv6 (ULA)
WS1_V6 = "fd12:3456:789a::10"
DNS_V6 = "fd12:3456:789a::53"

# Throwaway "collateral" hosts touched only by the port scan below, so the
# scan's incidental host_type_hints (whichever PORT_MAP service each scanned
# port implies) never land on a narrative host and skew its classification.
_SCAN_FILLER_HOSTS = [
    ("02:00:00:aa:bb:91", "10.0.1.91"),
    ("02:00:00:aa:bb:92", "10.0.1.92"),
    ("02:00:00:aa:bb:93", "10.0.1.93"),
    ("02:00:00:aa:bb:94", "10.0.1.94"),
    ("02:00:00:aa:bb:95", "10.0.1.95"),
]


def eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def tagged(src_mac, dst_mac, vlan, pcp=0):
    return Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=vlan, prio=pcp)


# ═══════════════════════════════════════════════════════════════════════════
# 1. ARP — gateway discovery on both VLANs, plus one untagged ARP on backbone
# ═══════════════════════════════════════════════════════════════════════════
def arp_pair(mac_a, ip_a, mac_b, ip_b, vlan=None):
    req_l2 = tagged(mac_a, "ff:ff:ff:ff:ff:ff", vlan) if vlan else eth(mac_a, "ff:ff:ff:ff:ff:ff")
    add(req_l2 / ARP(op=1, hwsrc=mac_a, psrc=ip_a, hwdst="00:00:00:00:00:00", pdst=ip_b), 0.2)
    rep_l2 = tagged(mac_b, mac_a, vlan) if vlan else eth(mac_b, mac_a)
    add(rep_l2 / ARP(op=2, hwsrc=mac_b, psrc=ip_b, hwdst=mac_a, pdst=ip_a), 0.15)


# Every narrative host ARPs for the gateway first. Beyond being realistic,
# this also matters for the app's mac_vendor lookup: analyze_pcap()'s
# host(ip, mac) helper only records a host's MAC the *first* time that IP is
# seen, and several hosts below are first referenced as the *destination* of
# a client request whose L2 dst is the gateway's MAC (correct for how a real
# LAN capture looks) -- if that happened before the host's own ARP/traffic,
# the app would permanently record the gateway's MAC/vendor for that host
# instead of its own. Doing ARP for all of them up front avoids that.
arp_pair(WS1_MAC, WS1_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(WS2_MAC, WS2_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(EXF_MAC, EXF_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(WIN_MAC, WIN_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(WEB_MAC, WEB_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(DNS_MAC, DNS_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(CAM_MAC, CAM_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(MQB_MAC, MQB_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(THM_MAC, THM_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(SOIL_MAC, SOIL_IP, GW_MAC, GW_IP, VLAN_IT)
arp_pair(EWS_MAC, EWS_IP, GW_MAC, GW_IP, VLAN_OT)
arp_pair(PLCA_MAC, PLCA_IP, EWS_MAC, EWS_IP, VLAN_OT)
arp_pair(PLCB_MAC, PLCB_IP, EWS_MAC, EWS_IP, VLAN_OT)
arp_pair(SW1_MAC, SW1_IP, GW_MAC, GW_IP)   # untagged backbone ARP


# ═══════════════════════════════════════════════════════════════════════════
# 2. CDP (core switch) + LLDP (access switch) — hand-built L2 frames
# ═══════════════════════════════════════════════════════════════════════════
def build_cdp_frame(src_mac, hostname, native_vlan):
    def mac_b(m):
        return bytes(int(x, 16) for x in m.split(":"))

    def tlv_cdp(t, val):
        return struct.pack(">HH", t, 4 + len(val)) + val

    cdp_tlvs = tlv_cdp(0x0001, hostname.encode()) + tlv_cdp(0x000A, struct.pack(">H", native_vlan))
    cdp_hdr = bytes([0x02, 180]) + b"\x00\x00"          # version, ttl, checksum(unverified)
    snap = b"\xAA\xAA\x03" + b"\x00\x00\x0c" + b"\x20\x00"  # LLC DSAP/SSAP/Ctrl + SNAP OUI + PID
    payload = snap + cdp_hdr + cdp_tlvs
    assert len(payload) < 0x0600
    frame = mac_b("01:00:0c:cc:cc:cc") + mac_b(src_mac) + struct.pack(">H", len(payload)) + payload
    return Ether(frame)  # re-dissect so wrpcap can resolve the Ethernet linktype


def build_lldp_frame(src_mac, hostname, pvid):
    def mac_b(m):
        return bytes(int(x, 16) for x in m.split(":"))

    def tlv_lldp(t, val):
        return struct.pack(">H", (t << 9) | len(val)) + val

    chassis = tlv_lldp(1, bytes([4]) + mac_b(src_mac))          # subtype 4 = MAC address
    port = tlv_lldp(2, bytes([7]) + b"Gi0/1")                    # subtype 7 = locally assigned
    ttl = tlv_lldp(3, struct.pack(">H", 120))
    sysname = tlv_lldp(5, hostname.encode())
    pvid_tlv = tlv_lldp(127, b"\x00\x80\xc2" + bytes([1]) + struct.pack(">H", pvid))
    end = tlv_lldp(0, b"")
    payload = chassis + port + ttl + sysname + pvid_tlv + end
    frame = mac_b("01:80:c2:00:00:0e") + mac_b(src_mac) + struct.pack(">H", 0x88CC) + payload
    return Ether(frame)  # re-dissect so wrpcap can resolve the Ethernet linktype


add(build_cdp_frame(SW1_MAC, "core-switch-01", VLAN_IT), 0.3)
add(build_lldp_frame(SW2_MAC, "access-switch-02", VLAN_OT), 0.3)


# ═══════════════════════════════════════════════════════════════════════════
# 3. DNS — IPv4 queries/responses (+ one IPv6 query) with real-looking names
# ═══════════════════════════════════════════════════════════════════════════
def dns_pair(client_mac, client_ip, qname, answer_ip, vlan=None, txid=0x1000):
    l2q = tagged(client_mac, DNS_MAC, vlan) if vlan else eth(client_mac, DNS_MAC)
    add(l2q / IP(src=client_ip, dst=DNS_IP) / UDP(sport=51000 + (txid & 0xff), dport=53) /
        DNS(id=txid, qr=0, qd=DNSQR(qname=qname)), 0.2)
    l2r = tagged(DNS_MAC, client_mac, vlan) if vlan else eth(DNS_MAC, client_mac)
    add(l2r / IP(src=DNS_IP, dst=client_ip) / UDP(sport=53, dport=51000 + (txid & 0xff)) /
        DNS(id=txid, qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, type="A", rdata=answer_ip, ttl=300)),
        0.15)


dns_pair(WS1_MAC, WS1_IP, "erp.corp.local", WEB_IP, VLAN_IT, 0x1001)
dns_pair(WS2_MAC, WS2_IP, "fileserver.corp.local", WIN_IP, VLAN_IT, 0x1002)
dns_pair(WS1_MAC, WS1_IP, "shop.example-corp.com", EXAMPLE_IP, VLAN_IT, 0x1003)
dns_pair(EWS_MAC, EWS_IP, "portal.corp.local", WEB_IP, VLAN_OT, 0x1004)
dns_pair(THM_MAC, THM_IP, "mqtt-broker.iot.local", MQB_IP, VLAN_IT, 0x1005)
dns_pair(WIN_MAC, WIN_IP, "updates.plcvendor.com", EXAMPLE_IP, VLAN_IT, 0x1006)
dns_pair(CAM_MAC, CAM_IP, "ntp.pool.org", ISP_IP, VLAN_IT, 0x1007)

# IPv6 DNS query/response
add(eth(WS1_MAC, DNS_MAC) / IPv6(src=WS1_V6, dst=DNS_V6) / UDP(sport=51100, dport=53) /
    DNS(id=0x2001, qr=0, qd=DNSQR(qname="ipv6-app.corp.local")), 0.2)
add(eth(DNS_MAC, WS1_MAC) / IPv6(src=DNS_V6, dst=WS1_V6) / UDP(sport=53, dport=51100) /
    DNS(id=0x2001, qr=1, qd=DNSQR(qname="ipv6-app.corp.local"),
        an=DNSRR(rrname="ipv6-app.corp.local", type="A", rdata=WEB_IP, ttl=300)), 0.15)


# ═══════════════════════════════════════════════════════════════════════════
# 4. HTTP — plain GET, Basic Auth, form POST login, file download attachment
# ═══════════════════════════════════════════════════════════════════════════
def http_req(client_mac, client_ip, sport, req_bytes, vlan=None):
    l2 = tagged(client_mac, WEB_MAC, vlan) if vlan else eth(client_mac, WEB_MAC)
    add(l2 / IP(src=client_ip, dst=WEB_IP) / TCP(sport=sport, dport=80, flags="S"), 0.05)
    add(l2 / IP(src=client_ip, dst=WEB_IP) / TCP(sport=sport, dport=80, flags="PA") / Raw(load=req_bytes), 0.1)


def http_resp(server_mac, server_ip, client_mac, client_ip, sport, resp_bytes, vlan=None):
    l2 = tagged(server_mac, client_mac, vlan) if vlan else eth(server_mac, client_mac)
    add(l2 / IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=sport, flags="PA") / Raw(load=resp_bytes), 0.1)


# Plain GET from an external client
http_req(EXTCLIENT_MAC, EXTCLIENT_IP, 44001, b"GET / HTTP/1.1\r\nHost: erp.corp.local\r\nUser-Agent: curl/8.0\r\n\r\n")
http_resp(WEB_MAC, WEB_IP, EXTCLIENT_MAC, EXTCLIENT_IP, 44001,
          b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body>Welcome to ERP Portal</body></html>")

# HTTP Basic Auth to /admin/dashboard
import base64
_basic_token = base64.b64encode(b"admin:P@ssw0rd123!").decode()
http_req(WS1_MAC, WS1_IP, 44010,
         f"GET /admin/dashboard HTTP/1.1\r\nHost: erp.corp.local\r\nAuthorization: Basic {_basic_token}\r\n\r\n".encode(),
         VLAN_IT)
http_resp(WEB_MAC, WEB_IP, WS1_MAC, WS1_IP, 44010,
          b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Admin Dashboard</html>", VLAN_IT)

# HTML form POST login (jdoe / Summer2024!)
_form_body = b"username=jdoe&password=Summer2024!"
http_req(WS2_MAC, WS2_IP, 44020,
         b"POST /login HTTP/1.1\r\nHost: erp.corp.local\r\nContent-Type: application/x-www-form-urlencoded\r\n"
         b"Content-Length: " + str(len(_form_body)).encode() + b"\r\n\r\n" + _form_body,
         VLAN_IT)
http_resp(WEB_MAC, WEB_IP, WS2_MAC, WS2_IP, 44020,
          b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nContent-Length: 0\r\n\r\n", VLAN_IT)

# File download with Content-Disposition: attachment
_file_body = (b"%PDF-1.4 demo quarterly report body " * 60)[:2000]
http_req(WS1_MAC, WS1_IP, 44030, b"GET /downloads/report.pdf HTTP/1.1\r\nHost: erp.corp.local\r\n\r\n", VLAN_IT)
_file_resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n"
              b"Content-Disposition: attachment; filename=\"quarterly_report.pdf\"\r\n"
              b"Content-Length: " + str(len(_file_body)).encode() + b"\r\n\r\n" + _file_body)
http_resp(WEB_MAC, WEB_IP, WS1_MAC, WS1_IP, 44030, _file_resp, VLAN_IT)

# FTP USER/PASS (cleartext creds, password reused from the form-post login)
add(tagged(WS1_MAC, WEB_MAC, VLAN_IT) / IP(src=WS1_IP, dst=WEB_IP) / TCP(sport=44040, dport=21, flags="S"), 0.05)
add(tagged(WEB_MAC, WS1_MAC, VLAN_IT) / IP(src=WEB_IP, dst=WS1_IP) / TCP(sport=21, dport=44040, flags="SA"), 0.05)
add(tagged(WEB_MAC, WS1_MAC, VLAN_IT) / IP(src=WEB_IP, dst=WS1_IP) / TCP(sport=21, dport=44040, flags="PA") /
    Raw(load=b"220 corp-ftp ready\r\n"), 0.05)
add(tagged(WS1_MAC, WEB_MAC, VLAN_IT) / IP(src=WS1_IP, dst=WEB_IP) / TCP(sport=44040, dport=21, flags="PA") /
    Raw(load=b"USER ftpadmin\r\n"), 0.1)
add(tagged(WEB_MAC, WS1_MAC, VLAN_IT) / IP(src=WEB_IP, dst=WS1_IP) / TCP(sport=21, dport=44040, flags="PA") /
    Raw(load=b"331 Password required\r\n"), 0.05)
add(tagged(WS1_MAC, WEB_MAC, VLAN_IT) / IP(src=WS1_IP, dst=WEB_IP) / TCP(sport=44040, dport=21, flags="PA") /
    Raw(load=b"PASS Summer2024!\r\n"), 0.1)
add(tagged(WEB_MAC, WS1_MAC, VLAN_IT) / IP(src=WEB_IP, dst=WS1_IP) / TCP(sport=21, dport=44040, flags="PA") /
    Raw(load=b"230 Login successful\r\n"), 0.05)


# ═══════════════════════════════════════════════════════════════════════════
# 5. TLS ClientHello (SNI + JA3) — HTTPS to web server and to example.com
# ═══════════════════════════════════════════════════════════════════════════
def build_tls_client_hello(sni, ciphers=(0xC02B, 0xC02C, 0xC02F, 0xC030, 0x009E, 0x009F, 0xCCA9, 0xCCA8)):
    client_version = 0x0303
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    compression = bytes([0])
    sni_bytes = sni.encode()
    sni_entry = bytes([0]) + struct.pack(">H", len(sni_bytes)) + sni_bytes
    ext_sni_data = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_sni = struct.pack(">HH", 0x0000, len(ext_sni_data)) + ext_sni_data

    curves = struct.pack(">H", 4) + struct.pack(">HH", 0x001D, 0x0017)  # x25519, secp256r1
    ext_groups = struct.pack(">HH", 0x000A, len(curves)) + curves

    point_fmt = bytes([1, 0])  # length=1, format=uncompressed
    ext_points = struct.pack(">HH", 0x000B, len(point_fmt)) + point_fmt

    extensions = ext_sni + ext_groups + ext_points

    ch_body = (struct.pack(">H", client_version) + random_bytes +
               bytes([len(session_id)]) + session_id +
               struct.pack(">H", len(cipher_bytes)) + cipher_bytes +
               bytes([len(compression)]) + compression +
               struct.pack(">H", len(extensions)) + extensions)

    handshake = bytes([0x01]) + len(ch_body).to_bytes(3, "big") + ch_body
    record = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(handshake)) + handshake
    return record


def tls_hello(client_mac, client_ip, sport, dst_mac, dst_ip, sni, vlan=None):
    l2 = tagged(client_mac, dst_mac, vlan) if vlan else eth(client_mac, dst_mac)
    add(l2 / IP(src=client_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="S"), 0.05)
    add(l2 / IP(src=client_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="PA") /
        Raw(load=build_tls_client_hello(sni)), 0.1)


tls_hello(WS1_MAC, WS1_IP, 44100, EXAMPLE_MAC, EXAMPLE_IP, "shop.example-corp.com", VLAN_IT)
tls_hello(EWS_MAC, EWS_IP, 44101, WEB_MAC, WEB_IP, "portal.corp.local", VLAN_OT)   # cross-VLAN edge
# WEB replies tagged with *its own* VLAN (10) -- a connection's "vlans" field
# is the union of tags seen across all packets in that IP pair, so without a
# reply carrying VLAN 10 this edge would only ever show VLAN 20 and never
# actually render as a cross-VLAN-segment edge in the VLAN Graph/Matrix.
add(tagged(WEB_MAC, EWS_MAC, VLAN_IT) / IP(src=WEB_IP, dst=EWS_IP) / TCP(sport=443, dport=44101, flags="SA"),
    0.05)
add(tagged(WEB_MAC, EWS_MAC, VLAN_IT) / IP(src=WEB_IP, dst=EWS_IP) / TCP(sport=443, dport=44101, flags="PA") /
    Raw(load=bytes([0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00])), 0.1)  # ServerHello stub (not deep-parsed)


# ═══════════════════════════════════════════════════════════════════════════
# 6. Windows host — SMB, NetBIOS-NS, RDP
# ═══════════════════════════════════════════════════════════════════════════
add(tagged(WS2_MAC, WIN_MAC, VLAN_IT) / IP(src=WS2_IP, dst=WIN_IP) / TCP(sport=44200, dport=445, flags="S"), 0.05)
add(tagged(WIN_MAC, WS2_MAC, VLAN_IT) / IP(src=WIN_IP, dst=WS2_IP) / TCP(sport=445, dport=44200, flags="SA"), 0.05)
add(tagged(WS2_MAC, WIN_MAC, VLAN_IT) / IP(src=WS2_IP, dst=WIN_IP) / TCP(sport=44200, dport=445, flags="PA") /
    Raw(load=b"\xffSMBr\x00\x00\x00\x00\x18\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x08"),
    0.1)
add(tagged(WS1_MAC, WIN_MAC, VLAN_IT) / IP(src=WS1_IP, dst=WIN_IP) / UDP(sport=137, dport=137) /
    Raw(load=b"\x00\x00\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"),
    0.1)
add(tagged(WS2_MAC, WIN_MAC, VLAN_IT) / IP(src=WS2_IP, dst=WIN_IP) / TCP(sport=44201, dport=3389, flags="S"), 0.05)
add(tagged(WIN_MAC, WS2_MAC, VLAN_IT) / IP(src=WIN_IP, dst=WS2_IP) / TCP(sport=3389, dport=44201, flags="SA"), 0.05)
add(tagged(WS2_MAC, WIN_MAC, VLAN_IT) / IP(src=WS2_IP, dst=WIN_IP) / TCP(sport=44201, dport=3389, flags="PA") /
    Raw(load=b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 7. IP camera — RTSP, plus a call-home to an external IP (iot_camera_exfil)
# ═══════════════════════════════════════════════════════════════════════════
add(tagged(WS1_MAC, CAM_MAC, VLAN_IT) / IP(src=WS1_IP, dst=CAM_IP) / TCP(sport=44300, dport=554, flags="S"), 0.05)
add(tagged(CAM_MAC, WS1_MAC, VLAN_IT) / IP(src=CAM_IP, dst=WS1_IP) / TCP(sport=554, dport=44300, flags="SA"), 0.05)
add(tagged(WS1_MAC, CAM_MAC, VLAN_IT) / IP(src=WS1_IP, dst=CAM_IP) / TCP(sport=44300, dport=554, flags="PA") /
    Raw(load=b"DESCRIBE rtsp://10.0.1.30/stream1 RTSP/1.0\r\nCSeq: 1\r\n\r\n"), 0.1)
add(tagged(CAM_MAC, WS1_MAC, VLAN_IT) / IP(src=CAM_IP, dst=WS1_IP) / TCP(sport=554, dport=44300, flags="PA") /
    Raw(load=b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n\r\n"), 0.1)

add(tagged(CAM_MAC, CAMC2_MAC, VLAN_IT) / IP(src=CAM_IP, dst=CAMC2_IP) / TCP(sport=51000, dport=8554, flags="S"), 0.05)
add(eth(CAMC2_MAC, CAM_MAC) / IP(src=CAMC2_IP, dst=CAM_IP) / TCP(sport=8554, dport=51000, flags="SA"), 0.05)
add(tagged(CAM_MAC, CAMC2_MAC, VLAN_IT) / IP(src=CAM_IP, dst=CAMC2_IP) / TCP(sport=51000, dport=8554, flags="PA") /
    Raw(load=b"firmware-checkin;device=front-door-cam;fw=1.4.2\r\n"), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 8. CoAP — soil sensor GET /sensors/temperature
# ═══════════════════════════════════════════════════════════════════════════
def build_coap(msg_type, code_class, code_detail, msg_id, token=b"", uri_parts=(), payload=b""):
    version = 1
    token_len = len(token)
    first_byte = (version << 6) | (msg_type << 4) | token_len
    code_byte = (code_class << 5) | code_detail
    hdr = bytes([first_byte, code_byte, (msg_id >> 8) & 0xFF, msg_id & 0xFF])
    opts = b""
    prev = 0
    for part in uri_parts:
        pb = part.encode()
        delta = 11 - prev  # Uri-Path option number = 11
        prev = 11
        opts += bytes([(delta << 4) | len(pb)]) + pb
    data = hdr + token + opts
    if payload:
        data += b"\xFF" + payload
    return data


add(tagged(SOIL_MAC, MQB_MAC, VLAN_IT) / IP(src=SOIL_IP, dst=MQB_IP) / UDP(sport=5683, dport=5683) /
    Raw(load=build_coap(0, 0, 1, 0x3001, token=b"\x01", uri_parts=("sensors", "temperature"))), 0.2)
add(tagged(MQB_MAC, SOIL_MAC, VLAN_IT) / IP(src=MQB_IP, dst=SOIL_IP) / UDP(sport=5683, dport=5683) /
    Raw(load=build_coap(2, 2, 5, 0x3001, token=b"\x01", payload=b"22.7C")), 0.15)


# ═══════════════════════════════════════════════════════════════════════════
# 9. MQTT — CONNECT with plaintext username/password, then PUBLISH readings
# ═══════════════════════════════════════════════════════════════════════════
def mqtt_connect(client_id, username=None, password=None):
    proto_name = b"MQTT"
    proto_field = len(proto_name).to_bytes(2, "big") + proto_name
    flags = 0x02  # clean session
    if username:
        flags |= 0x80
    if password:
        flags |= 0x40
    var_hdr = proto_field + bytes([4, flags, 0, 60])
    cid = client_id.encode()
    payload = len(cid).to_bytes(2, "big") + cid
    if username:
        ub = username.encode()
        payload += len(ub).to_bytes(2, "big") + ub
    if password:
        pb = password.encode()
        payload += len(pb).to_bytes(2, "big") + pb
    remaining = len(var_hdr) + len(payload)
    # remaining-length varint (fits in one byte for our small packets)
    return bytes([0x10, remaining]) + var_hdr + payload


def mqtt_publish(topic, message):
    tb = topic.encode()
    topic_field = len(tb).to_bytes(2, "big") + tb
    data = topic_field + message.encode()
    return bytes([0x30, len(data)]) + data


def mqtt_connack(rc=0):
    return bytes([0x20, 0x02, 0x00, rc])


def mqtt_puback():
    return bytes([0x40, 0x02, 0x00, 0x01])


add(tagged(THM_MAC, MQB_MAC, VLAN_IT) / IP(src=THM_IP, dst=MQB_IP) / TCP(sport=44400, dport=1883, flags="S"), 0.05)
add(tagged(MQB_MAC, THM_MAC, VLAN_IT) / IP(src=MQB_IP, dst=THM_IP) / TCP(sport=1883, dport=44400, flags="SA"), 0.05)
add(tagged(THM_MAC, MQB_MAC, VLAN_IT) / IP(src=THM_IP, dst=MQB_IP) / TCP(sport=44400, dport=1883, flags="PA") /
    Raw(load=mqtt_connect("thermostat-01", username="iotuser", password="iotpass123")), 0.1)
add(tagged(MQB_MAC, THM_MAC, VLAN_IT) / IP(src=MQB_IP, dst=THM_IP) / TCP(sport=1883, dport=44400, flags="PA") /
    Raw(load=mqtt_connack(0)), 0.1)
for i, temp in enumerate(["21.4", "21.6", "21.5", "21.9", "22.1"]):
    add(tagged(THM_MAC, MQB_MAC, VLAN_IT) / IP(src=THM_IP, dst=MQB_IP) / TCP(sport=44400, dport=1883, flags="PA") /
        Raw(load=mqtt_publish("home/thermostat/temperature", temp)), 2.0)
    add(tagged(MQB_MAC, THM_MAC, VLAN_IT) / IP(src=MQB_IP, dst=THM_IP) / TCP(sport=1883, dport=44400, flags="PA") /
        Raw(load=mqtt_puback()), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 10. Modbus — EWS -> PLC-A, mix of reads/writes + OT anomaly triggers
# ═══════════════════════════════════════════════════════════════════════════
def modbus_pdu(txid, unit_id, func_code, data):
    length = 2 + len(data)  # unit_id(1) + func_code(1) + data
    return struct.pack(">HHH", txid, 0, length) + bytes([unit_id, func_code]) + data


def modbus_exchange(txid, unit_id, func_code, req_data, resp_data, sport):
    add(tagged(EWS_MAC, PLCA_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCA_IP) / TCP(sport=sport, dport=502, flags="PA") /
        Raw(load=modbus_pdu(txid, unit_id, func_code, req_data)), 0.3)
    if resp_data is not None:
        add(tagged(PLCA_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCA_IP, dst=EWS_IP) / TCP(sport=502, dport=sport, flags="PA") /
            Raw(load=modbus_pdu(txid, unit_id, func_code, resp_data)), 0.1)


# NOTE: no TCP handshake is sent before this connection's first Modbus PDU.
# analyze_anomalies()'s ot_modbus_write check only inspects the FIRST packet
# in the (EWS, PLC-A) connection whose port is 502 (app.py ~line 1509-1532:
# it unconditionally `break`s the packet loop after that one packet, whether
# or not it turned out to be a write) -- so a SYN or a Read sent first would
# silently make the write anomaly never fire. Sending a Write PDU first
# guarantees it's the packet that check inspects.

# Writes (FC6 single register, FC16 multiple registers) -> ot_modbus_write
modbus_exchange(4, 1, 6, struct.pack(">HH", 40001, 1500), struct.pack(">HH", 40001, 1500), 50200)
modbus_exchange(5, 1, 16, struct.pack(">HHB", 40010, 2, 4) + struct.pack(">HH", 111, 222),
                struct.pack(">HH", 40010, 2), 50200)

# Reads (FC3 holding registers, FC1 coils) x a few
modbus_exchange(1, 1, 3, struct.pack(">HH", 0, 10), struct.pack(">B", 20) + b"\x00" * 20, 50200)
modbus_exchange(2, 1, 3, struct.pack(">HH", 10, 5), struct.pack(">B", 10) + b"\x00" * 10, 50200)
modbus_exchange(3, 1, 1, struct.pack(">HH", 0, 16), struct.pack(">B", 2) + bytes([0xFF, 0x00]), 50200)

# Bulk read (>100 registers) -> ot_modbus_bulk_read
modbus_exchange(6, 1, 3, struct.pack(">HH", 0, 125), struct.pack(">B", 250) + b"\x00" * 250, 50200)

# Broadcast (unit_id=0) -> ot_modbus_broadcast
modbus_exchange(7, 0, 6, struct.pack(">HH", 40002, 0), None, 50200)

# Exception response (Illegal Data Address) -> ot_modbus_exception
add(tagged(EWS_MAC, PLCA_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCA_IP) / TCP(sport=50200, dport=502, flags="PA") /
    Raw(load=modbus_pdu(8, 1, 3, struct.pack(">HH", 9999, 5))), 0.2)
add(tagged(PLCA_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCA_IP, dst=EWS_IP) / TCP(sport=502, dport=50200, flags="PA") /
    Raw(load=modbus_pdu(8, 1, 0x83, bytes([2]))), 0.1)

# Multi-unit poll across 6 distinct unit IDs -> ot_multiunit_poll
for uid in range(1, 7):
    modbus_exchange(100 + uid, uid, 3, struct.pack(">HH", 0, 4), struct.pack(">B", 8) + b"\x00" * 8, 50200)


# ═══════════════════════════════════════════════════════════════════════════
# 11. S7comm — EWS -> PLC-B: setup, read/write vars, code download, PLC stop
# ═══════════════════════════════════════════════════════════════════════════
def s7_frame(rosctr, pdu_ref, func_code=None, extra_param=b"", data=b"", error=None):
    if rosctr in (2, 3):
        err_class, err_code = (error or (0, 0))
        hdr_extra = bytes([err_class, err_code])
        param_hdr = hdr_extra
    else:
        param_hdr = b""
    if func_code is not None:
        params = bytes([func_code]) + extra_param
    else:
        params = b""
    s7 = (bytes([0x32, rosctr]) + b"\x00\x00" + struct.pack(">H", pdu_ref) +
          struct.pack(">H", len(params)) + struct.pack(">H", len(data)) +
          param_hdr + params + data)
    cotp = bytes([0x02, 0xF0, 0x80])  # DT data, EOT
    tpkt_len = 4 + len(cotp) + len(s7)
    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", tpkt_len) + cotp + s7
    return tpkt


def s7_download_filename_block(block_type, number, extra=""):
    name = f"{block_type}{number}{extra}"
    assert 6 <= len(name) <= 14, name
    return bytes([len(name)]) + b"\x00\x00" + name.encode()


add(tagged(EWS_MAC, PLCB_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCB_IP) / TCP(sport=50300, dport=102, flags="S"), 0.05)
add(tagged(PLCB_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCB_IP, dst=EWS_IP) / TCP(sport=102, dport=50300, flags="SA"), 0.05)

# Setup Communication
add(tagged(EWS_MAC, PLCB_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCB_IP) / TCP(sport=50300, dport=102, flags="PA") /
    Raw(load=s7_frame(1, 1, func_code=0xF0, extra_param=b"\x00\x00\x01\x00\x01\x00\xf0")), 0.2)
add(tagged(PLCB_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCB_IP, dst=EWS_IP) / TCP(sport=102, dport=50300, flags="PA") /
    Raw(load=s7_frame(3, 1, func_code=0xF0, extra_param=b"\x00\x00\x01\x00\x01\x00\xf0")), 0.1)

# Read Variable x2
for pref in (2, 3):
    add(tagged(EWS_MAC, PLCB_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCB_IP) / TCP(sport=50300, dport=102, flags="PA") /
        Raw(load=s7_frame(1, pref, func_code=0x04, extra_param=b"\x01\x12\x0a\x10\x02\x00\x04\x00\x01\x84\x00")), 0.2)
    add(tagged(PLCB_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCB_IP, dst=EWS_IP) / TCP(sport=102, dport=50300, flags="PA") /
        Raw(load=s7_frame(3, pref, func_code=0x04, data=b"\xff\x04\x00\x08\x00\x00")), 0.1)

# Write Variable x2 -> ot_s7_write
for pref in (4, 5):
    add(tagged(EWS_MAC, PLCB_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCB_IP) / TCP(sport=50300, dport=102, flags="PA") /
        Raw(load=s7_frame(1, pref, func_code=0x05,
                           extra_param=b"\x01\x12\x0a\x10\x02\x00\x01\x00\x01\x84\x00",
                           data=b"\x00\x04\x00\x08\x00\x2a")), 0.2)
    add(tagged(PLCB_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCB_IP, dst=EWS_IP) / TCP(sport=102, dport=50300, flags="PA") /
        Raw(load=s7_frame(3, pref, func_code=0x05, data=b"\xff")), 0.1)

# Request Download (code modification) -> ot_s7_code_download
add(tagged(EWS_MAC, PLCB_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCB_IP) / TCP(sport=50300, dport=102, flags="PA") /
    Raw(load=s7_frame(1, 6, func_code=0x1A, extra_param=s7_download_filename_block("DB", 1, "_LOGIC"))), 0.2)
add(tagged(PLCB_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCB_IP, dst=EWS_IP) / TCP(sport=102, dport=50300, flags="PA") /
    Raw(load=s7_frame(2, 6, error=(0, 0))), 0.1)

# PLC Stop -> ot_s7_critical
add(tagged(EWS_MAC, PLCB_MAC, VLAN_OT) / IP(src=EWS_IP, dst=PLCB_IP) / TCP(sport=50300, dport=102, flags="PA") /
    Raw(load=s7_frame(1, 7, func_code=0x29, extra_param=b"\x00\x00\x09P_PROGRAM")), 0.2)
add(tagged(PLCB_MAC, EWS_MAC, VLAN_OT) / IP(src=PLCB_IP, dst=EWS_IP) / TCP(sport=102, dport=50300, flags="PA") /
    Raw(load=s7_frame(2, 7, error=(0, 0))), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 12. BGP peering -> classifies gateway as "Router"
# ═══════════════════════════════════════════════════════════════════════════
add(eth(ISP_MAC, GW_MAC) / IP(src=ISP_IP, dst=GW_IP) / TCP(sport=52000, dport=179, flags="S"), 0.1)
add(eth(GW_MAC, ISP_MAC) / IP(src=GW_IP, dst=ISP_IP) / TCP(sport=179, dport=52000, flags="SA"), 0.1)
add(eth(ISP_MAC, GW_MAC) / IP(src=ISP_IP, dst=GW_IP) / TCP(sport=52000, dport=179, flags="PA") /
    Raw(load=b"\xff" * 16 + b"\x00\x13\x01\x04\xfd\xe8\x00\xb4\xc6\x33\x64\x01\x00"), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 13. ICMP ping — workstation1 <-> gateway
# ═══════════════════════════════════════════════════════════════════════════
for seq in range(1, 4):
    add(tagged(WS1_MAC, GW_MAC, VLAN_IT) / IP(src=WS1_IP, dst=GW_IP) / ICMP(type=8, code=0, id=1, seq=seq) /
        Raw(load=b"pingdata"), 0.3)
    add(tagged(GW_MAC, WS1_MAC, VLAN_IT) / IP(src=GW_IP, dst=WS1_IP) / ICMP(type=0, code=0, id=1, seq=seq) /
        Raw(load=b"pingdata"), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 14. Telnet — attacker -> IP camera, Mirai-style default creds (iot_telnet +
#     cleartext_credentials)
# ═══════════════════════════════════════════════════════════════════════════
add(eth(ATTACKER_MAC, CAM_MAC) / IP(src=ATTACKER_IP, dst=CAM_IP) / TCP(sport=53000, dport=23, flags="S"), 0.1)
add(tagged(CAM_MAC, ATTACKER_MAC, VLAN_IT) / IP(src=CAM_IP, dst=ATTACKER_IP) / TCP(sport=23, dport=53000, flags="SA"), 0.1)
add(tagged(CAM_MAC, ATTACKER_MAC, VLAN_IT) / IP(src=CAM_IP, dst=ATTACKER_IP) / TCP(sport=23, dport=53000, flags="PA") /
    Raw(load=b"login: "), 0.2)
add(eth(ATTACKER_MAC, CAM_MAC) / IP(src=ATTACKER_IP, dst=CAM_IP) / TCP(sport=53000, dport=23, flags="PA") /
    Raw(load=b"admin\r\n"), 0.2)
add(tagged(CAM_MAC, ATTACKER_MAC, VLAN_IT) / IP(src=CAM_IP, dst=ATTACKER_IP) / TCP(sport=23, dport=53000, flags="PA") /
    Raw(load=b"Password: "), 0.2)
add(eth(ATTACKER_MAC, CAM_MAC) / IP(src=ATTACKER_IP, dst=CAM_IP) / TCP(sport=53000, dport=23, flags="PA") /
    Raw(load=b"admin\r\n"), 0.2)
add(tagged(CAM_MAC, ATTACKER_MAC, VLAN_IT) / IP(src=CAM_IP, dst=ATTACKER_IP) / TCP(sport=23, dport=53000, flags="PA") /
    Raw(load=b"Login successful\r\n"), 0.1)


# ═══════════════════════════════════════════════════════════════════════════
# 15. Port scan — attacker hits gateway on 20 ports + 5 more distinct hosts
# ═══════════════════════════════════════════════════════════════════════════
# NOTE: every scanned dst port that appears in PORT_MAP donates a
# host_type_hints[...] count to the *destination* (the gateway here) --
# and HOST_TYPE_PRIORITY picks by list POSITION, not by hint count. Ports
# that map to high-priority OT/IoT categories (e.g. 502->PLC is priority
# index 0, 1883->IoT Gateway is index 9) would silently outrank the
# gateway's legitimate "Router" hint (index 17, from the BGP peering
# above) even from a single scan packet. Keep scanned ports restricted to
# services whose HOST_TYPE_PRIORITY index is below (worse than) Router's.
_scan_ports = [21, 22, 23, 25, 80, 110, 119, 139, 143, 161, 389, 443, 445,
               993, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 8080]
for p in _scan_ports:
    add(eth(ATTACKER_MAC, GW_MAC) / IP(src=ATTACKER_IP, dst=GW_IP) / TCP(sport=40000 + p, dport=p, flags="S"), 0.05)

# Touch 5 more distinct hosts to clear the port_scan anomaly's ">5 unique
# dst IPs" threshold -- dedicated filler hosts only, so this doesn't add a
# stray "Web Server" hint to WS1/WS2/WIN and outrank their intended
# classification the same way described above.
for _fmac, _fip in _SCAN_FILLER_HOSTS:
    add(eth(ATTACKER_MAC, _fmac) / IP(src=ATTACKER_IP, dst=_fip) / TCP(sport=41080, dport=80, flags="S"), 0.05)


# ═══════════════════════════════════════════════════════════════════════════
# 16. Beaconing to a suspicious port — regular ~30s interval, CV < 0.2
# ═══════════════════════════════════════════════════════════════════════════
# One-directional only: analyze_anomalies' beaconing check computes the
# coefficient of variation over ALL packet.time values stored for this
# connection (both directions merged, app.py ~line 1450-1470). Interleaving
# quick ACK replies would inject a second, much shorter interval into that
# same series and blow the CV past the 0.2 threshold, so the C2 side stays
# silent here -- purely a one-way, evenly-spaced check-in beacon.
_beacon_jitter = [0.0, 0.4, -0.3, 0.2, -0.1, 0.3, -0.4, 0.1, 0.0, -0.2,
                   0.3, -0.3, 0.2, 0.1, -0.1, 0.4, -0.2, 0.0, 0.3, -0.3,
                   0.1, -0.4, 0.2, 0.0, -0.1]
for i, jitter in enumerate(_beacon_jitter):
    add(tagged(WS2_MAC, C2_MAC, VLAN_IT) / IP(src=WS2_IP, dst=C2_IP) / TCP(sport=45000, dport=4444, flags="PA") /
        Raw(load=b"beacon-checkin;id=ws2;v=1"), 30.0 + jitter)


# ═══════════════════════════════════════════════════════════════════════════
# 17. Data exfiltration — compromised host pushes >10MB to an external host
# ═══════════════════════════════════════════════════════════════════════════
_exfil_chunk = (b"BACKUP-BLOB-" * 5000)[:60000]
for i in range(180):
    add(tagged(EXF_MAC, CLOUD_MAC, VLAN_IT) / IP(src=EXF_IP, dst=CLOUD_IP) / TCP(sport=46000, dport=443, flags="PA") /
        Raw(load=_exfil_chunk), 0.02)
    if i % 20 == 0:
        add(eth(CLOUD_MAC, EXF_MAC) / IP(src=CLOUD_IP, dst=EXF_IP) / TCP(sport=443, dport=46000, flags="A"), 0.02)


# ═══════════════════════════════════════════════════════════════════════════
# Write the pcap
# ═══════════════════════════════════════════════════════════════════════════
wrpcap(OUT_PATH, pkts)
print(f"Wrote {len(pkts)} packets spanning {_clock[0]:.1f}s to {OUT_PATH}")
print(f"File size: {os.path.getsize(OUT_PATH) / (1024*1024):.2f} MB")
