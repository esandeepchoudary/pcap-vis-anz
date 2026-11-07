#!/usr/bin/env python3
"""Synthetic plant: big, realistic captures of a made-up water treatment site, plus the ground truth.

Riverside Water Treatment (fictional) has an enterprise network, a DMZ, site operations, supervisory HMIs,
two control cells and a building/IoT segment, each on its own VLAN behind one router. The generator writes
four captures taken at different times and tap points, and ``truth.json`` describing what the app should find:
every device (address, VLANs, Purdue level, identity), who talks to whom, OT writes, and planted problems
(a business PC talking straight to a PLC, a PLC program download, default and cleartext credentials, a port
scan, a camera streaming to the internet, a rogue laptop that only appears in the last capture).

Frames are built with scapy once per template and written as raw pcap records with patched TCP sequence
numbers, so captures with hundreds of thousands of packets take seconds. Deterministic (fixed seed).

    cd backend && uv run python ../fixtures/plant/build_plant.py --out /tmp/plant [--scale 1.0]

Check the app against it with ``check_soundness.py``.
"""

from __future__ import annotations

import argparse
import json
import random
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Dot1Q, Ether, Raw  # noqa: E402

from tests import pcapgen as g  # noqa: E402

DAY = 86_400
T0 = 1_762_502_400.0  # 2025-11-07 08:00:00 UTC
ROUTER_MAC = "00:1b:54:00:00:01"  # one router, a sub-interface per VLAN (router-on-a-stick)


# ── Inventory ────────────────────────────────────────────────────────────────


@dataclass
class Dev:
    name: str
    ip: str
    mac: str
    vlan: int | None
    level: float  # expected Purdue level
    family: str  # expected device family (coarse type)
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None
    hostname: str | None = None
    ttl: int | None = None  # initial IP TTL (OS fingerprint); default by family
    order: str | None = None  # Siemens order number (SZL 0x11)
    seen_in: set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.ttl is None:
            self.ttl = {"control": 64, "iot": 64, "network": 255}.get(self.family, 128)

    @property
    def addr(self):
        return (self.mac, self.ip)


def mac(prefix: str, n: int) -> str:
    return f"{prefix}:{(n >> 8) & 0xFF:02x}:{n & 0xFF:02x}"


DEVICES: dict[str, Dev] = {}


def dev(name, ip, mac_, vlan, level, family, **kw) -> Dev:
    d = Dev(name, ip, mac_, vlan, level, family, **kw)
    DEVICES[name] = d
    return d


# Enterprise, VLAN 100 (L4)
DC = dev("DC01", "10.10.0.10", mac("00:15:5d:10", 10), 100, 4, "server", hostname="DC01")
FS = dev("FS01", "10.10.0.11", mac("00:15:5d:10", 11), 100, 4, "server", hostname="FS01")
ERP = dev("ERP01", "10.10.0.12", mac("00:15:5d:10", 12), 100, 4, "server")
MAIL = dev("MAIL01", "10.10.0.13", mac("00:15:5d:10", 13), 100, 4, "server")
NMS = dev("NMS01", "10.10.0.14", mac("00:15:5d:10", 14), 100, 4, "server")
WS = [
    dev(f"WS-{i:03d}", f"10.10.0.{100 + i}", mac("3c:52:82:10", i), 100, 4, "endpoint", hostname=f"WS-{i:03d}")
    for i in range(1, 31)
]
ROGUE = dev("ROGUE-LAPTOP", "10.10.0.200", "f0:2f:74:de:ad:01", 100, 4, "endpoint", hostname="kali")
# DMZ, VLAN 200 (L3.5)
HIST_DMZ = dev("HIST-DMZ", "10.20.0.10", mac("00:15:5d:20", 10), 200, 3.5, "server")
JUMP = dev("JUMP01", "10.20.0.20", mac("00:15:5d:20", 20), 200, 3.5, "server")
PATCH = dev("WSUS01", "10.20.0.30", mac("00:15:5d:20", 30), 200, 3.5, "server")
# Site operations, VLAN 300 (L3)
SCADA = dev("SCADA01", "10.30.0.10", mac("00:15:5d:30", 10), 300, 3, "supervisory")
HIST = dev("HIST01", "10.30.0.11", mac("00:15:5d:30", 11), 300, 3, "server")
EWS1 = dev("EWS01", "10.30.0.21", mac("00:1c:06:30", 21), 300, 3, "supervisory", hostname="EWS01")
EWS2 = dev("EWS02", "10.30.0.22", mac("00:1c:06:30", 22), 300, 3, "supervisory", hostname="EWS02")
# Supervisory HMIs, VLAN 400 (L2)
HMIS = [dev(f"HMI-{i}", f"10.40.0.{10 + i}", mac("00:0e:8c:40", i), 400, 2, "supervisory") for i in range(1, 7)]
# Control cell A, VLAN 500 (L1): Siemens and Schneider
PLC_A1 = dev(
    "PLC-A1", "10.50.0.10", mac("00:1b:1b:50", 10), 500, 1, "control",
    vendor="Siemens", model="CPU 1516-3 PN/DP", firmware="V2.9.4", order="6ES7 516-3AN01-0AB0", ttl=30,
)
PLC_A2 = dev("PLC-A2", "10.50.0.11", mac("00:1b:1b:50", 11), 500, 1, "control", vendor="Siemens", ttl=30)
M340 = dev(
    "M340-A", "10.50.0.20", mac("00:80:f4:50", 20), 500, 1, "control",
    vendor="Schneider Electric", model="BMX P34 2020", firmware="v3.20",
)
DRIVES = [dev(f"VFD-{i}", f"10.50.0.{30 + i}", mac("00:80:f4:51", i), 500, 1, "control") for i in range(1, 7)]
# Control cell B, VLAN 510 (L1): Rockwell, DNP3 and IEC 104 RTUs
CLX = dev(
    "CLX-B1", "10.51.0.10", mac("00:00:bc:51", 10), 510, 1, "control",
    vendor="Rockwell Automation/Allen-Bradley", model="1769-L33ER", firmware="30.11",
)
RTU = dev("RTU-B1", "10.51.0.20", mac("00:60:35:51", 20), 510, 1, "control")
RTU104 = dev("RTU-B2", "10.51.0.21", mac("00:60:35:51", 21), 510, 1, "control")
# Building and IoT, VLAN 600 (L2)
BROKER = dev("MQTT-BROKER", "10.60.0.10", mac("b8:27:eb:60", 10), 600, 2, "iot")
SENSORS = [dev(f"SENSOR-{i}", f"10.60.0.{20 + i}", mac("b8:27:eb:61", i), 600, 0, "iot") for i in range(1, 9)]
CAMS = [dev(f"CAM-{i}", f"10.60.0.{40 + i}", mac("44:19:b6:60", i), 600, 2, "iot") for i in range(1, 3)]
NVR = dev("NVR01", "10.60.0.50", mac("44:19:b6:61", 50), 600, 2, "server", ttl=64)
# Network gear on the management VLAN 1
SW = [dev(f"SW-{i}", f"10.0.0.{10 + i}", mac("00:1e:bd:00", i), 1, 3, "network") for i in range(1, 4)]
# The router's sub-interfaces: one IP per VLAN, all on ROUTER_MAC
GW = {v: f"10.{v // 100 * 10 if v >= 100 else 0}.0.1" for v in (1, 100, 200, 300, 400, 500, 600)}
GW[510] = "10.51.0.1"
# Internet
NET = {
    "dns": "1.1.1.1",
    "update": "13.107.4.50",
    "saas": "52.96.0.10",
    "c2": "198.51.100.77",
    "cdn": [f"23.45.{i}.{j}" for i in range(1, 4) for j in (10, 20)],
}


# ── Raw pcap writer ──────────────────────────────────────────────────────────


class Pcap:
    def __init__(self, path: Path):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.records: list[tuple[float, bytes]] = []

    def add(self, t: float, frame: bytes):
        self.records.append((t, frame))

    def close(self) -> int:
        self.records.sort(key=lambda r: r[0])
        for t, frame in self.records:
            sec = int(t)
            self.fh.write(struct.pack("<IIII", sec, int((t - sec) * 1e6), len(frame), len(frame)))
            self.fh.write(frame)
        self.fh.close()
        return len(self.records)


def l2(src: Dev | str, dst: Dev | str, access: bool) -> tuple[Ether, int | None]:
    """Ethernet header for a frame from src to dst as a trunk tap sees it on src's VLAN (routed if needed).

    Internet hosts are strings. ``access``: the tap is on an access port, so frames carry no tag."""
    s_dev, d_dev = isinstance(src, Dev), isinstance(dst, Dev)
    vlan = src.vlan if s_dev else dst.vlan if d_dev else None
    same = s_dev and d_dev and src.vlan == dst.vlan
    smac = src.mac if s_dev else ROUTER_MAC
    dmac = dst.mac if (same or not s_dev) and d_dev else ROUTER_MAC
    e = Ether(src=smac, dst=dmac)
    return (e if access or vlan is None else e / Dot1Q(vlan=vlan)), vlan


def ip_of(x: Dev | str) -> str:
    return x.ip if isinstance(x, Dev) else x


def ttl_of(x: Dev | str) -> int:
    return x.ttl if isinstance(x, Dev) else 52  # internet hosts arrive a dozen hops away


class Session:
    """One TCP connection: handshake, then templated segments with correct sequence numbers."""

    _cache: dict[tuple, tuple[bytes, int]] = {}

    def __init__(self, cap: Capture, c: Dev | str, s: Dev | str, sport: int, cport: int | None = None):
        self.cap, self.c, self.s, self.sport = cap, c, s, sport
        self.cport = cport or cap.rnd.randint(49152, 65000)
        self.cseq, self.sseq = cap.rnd.randint(1, 2**31), cap.rnd.randint(1, 2**31)

    def _frame(self, from_client: bool, flags: str, payload: bytes) -> bytearray:
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        key = (ip_of(src), ip_of(dst), sp, dp, flags, payload, self.cap.access)
        hit = Session._cache.get(key)
        if hit is None:
            eth, _ = l2(src, dst, self.cap.access)
            pkt = eth / IP(src=ip_of(src), dst=ip_of(dst), ttl=ttl_of(src)) / TCP(
                sport=sp, dport=dp, flags=flags, window=8192
            )
            if payload:
                pkt = pkt / Raw(payload)
            raw = bytes(pkt)
            off = len(raw) - len(payload) - 20  # TCP header start (no options)
            hit = Session._cache[key] = (raw, off)
            if len(Session._cache) > 200_000:
                Session._cache.clear()
        raw, off = hit
        b = bytearray(raw)
        seq, ack = (self.cseq, self.sseq) if from_client else (self.sseq, self.cseq)
        struct.pack_into("!II", b, off + 4, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF)
        return b

    def send(self, t: float, from_client: bool, payload: bytes = b"", flags: str = "PA"):
        self.cap.mark(self.c if from_client else self.s)
        self.cap.pcap.add(t, bytes(self._frame(from_client, flags, payload)))
        n = len(payload) + (1 if any(f in flags for f in "SF") else 0)
        if from_client:
            self.cseq += n
        else:
            self.sseq += n
        return self

    def open(self, t: float):
        self.send(t, True, flags="S").send(t + 0.0004, False, flags="SA").send(t + 0.0008, True, flags="A")
        return self

    def close(self, t: float):
        self.send(t, True, flags="FA").send(t + 0.0003, False, flags="FA")
        return self

    def rr(self, t: float, req: bytes, resp: bytes | None, rtt: float = 0.004):
        self.send(t, True, req)
        if resp is not None:
            self.send(t + rtt, False, resp)
        return self


class Capture:
    def __init__(self, key: str, path: Path, start: float, hours: float, access: bool, seed: int):
        self.key, self.start, self.end, self.access = key, start, start + hours * 3600, access
        self.pcap = Pcap(path)
        self.rnd = random.Random(seed)

    def ticks(self, period: float, jitter: float = 0.02, start: float | None = None, end: float | None = None):
        t = (start or self.start) + self.rnd.uniform(0, period)
        stop = end or self.end
        while t < stop:
            yield t
            t += period * (1 + self.rnd.uniform(-jitter, jitter))

    def udp(self, t: float, src, dst, sport: int, dport: int, payload: bytes):
        eth, _ = l2(src, dst, self.access)
        self.mark(src, dst)
        self.pcap.add(t, bytes(eth / IP(src=ip_of(src), dst=ip_of(dst), ttl=ttl_of(src)) / UDP(sport=sport, dport=dport) / Raw(payload)))

    def raw_l2(self, t: float, frame):
        self.pcap.add(t, bytes(frame))

    def mark(self, *devs):
        for d in devs:
            if isinstance(d, Dev):
                d.seen_in.add(self.key)


# ── Traffic patterns ─────────────────────────────────────────────────────────


TRUTH_LINKS: list[dict] = []  # expected client→server conversations
TRUTH_WRITES: dict[tuple[str, str], int] = {}  # (client ip, server ip) → OT write requests sent
TRUTH_FINDINGS: list[dict] = []
TRUTH_CREDS: list[dict] = []


def link(cap: Capture, c, s, protocol: str, writes: int = 0):
    TRUTH_LINKS.append({"capture": cap.key, "client": ip_of(c), "server": ip_of(s), "protocol": protocol})
    if writes:
        k = (ip_of(c), ip_of(s))
        TRUTH_WRITES[k] = TRUTH_WRITES.get(k, 0) + writes
    for d in (c, s):
        if isinstance(d, Dev):
            cap.mark(d)


def modbus_read(tid: int, unit: int, start: int, qty: int) -> tuple[bytes, bytes]:
    req = g.modbus(tid, unit, b"\x03" + start.to_bytes(2, "big") + qty.to_bytes(2, "big"))
    resp = g.modbus(tid, unit, b"\x03" + bytes([qty * 2]) + bytes(qty * 2))
    return req, resp


def modbus_write(tid: int, unit: int, reg: int, value: int) -> tuple[bytes, bytes]:
    pdu = b"\x06" + reg.to_bytes(2, "big") + value.to_bytes(2, "big")
    return g.modbus(tid, unit, pdu), g.modbus(tid, unit, pdu)


def s7_session(cap: Capture, c: Dev, plc: Dev, t: float, identity: bool) -> Session:
    s = Session(cap, c, plc, 102).open(t)
    s.rr(t + 0.01, g.s7(1, g.S7_SETUP), g.s7(3, g.S7_SETUP))
    if identity and plc.model:
        s.rr(t + 0.02, g.s7_szl_request(0x11), g.s7_szl_response(0x11, [
            g.szl_0011_record(1, plc.order or plc.model), g.szl_0011_record(7, "", 0, 0x5602, 0x0904)], 28))
        s.rr(t + 0.03, g.s7_szl_request(0x1C), g.s7_szl_response(0x1C, [
            g.szl_001c_record(1, plc.name.replace("-", "_")), g.szl_001c_record(5, "S C-H7L2"),
            g.szl_001c_record(7, plc.model)], 34))
    return s


def poll_s7(cap: Capture, c: Dev, plc: Dev, period: float, writes_every: int = 0, identity: bool = True):
    s = s7_session(cap, c, plc, cap.start + 1, identity)
    n_writes = 0
    for i, t in enumerate(cap.ticks(period, start=cap.start + 2)):
        if writes_every and i % writes_every == writes_every - 1:
            s.rr(t, g.s7(1, g.S7_WRITE_VAR, b"\x00\x04\x00\x10\x00\x01"), g.s7(3, b"\x05\x01", b"\xff"))
            n_writes += 1
        else:
            s.rr(t, g.s7(1, g.S7_READ_VAR), g.s7(3, b"\x04\x01", b"\xff\x04\x00\x10" + bytes(2)))
    s.close(cap.end - 1)
    link(cap, c, plc, "S7comm", n_writes)


def poll_modbus(cap: Capture, c: Dev, srv: Dev, period: float, unit: int = 1, writes_every: int = 0,
                identity: bool = False):
    s = Session(cap, c, srv, 502).open(cap.start + 0.5)
    if identity and srv.vendor:
        s.rr(cap.start + 0.6, g.modbus(1, unit, g.modbus_device_id_request()), g.modbus(1, unit, g.modbus_device_id_response(
            {0: srv.vendor, 1: "BMXP342020", 2: srv.firmware or "", 4: "Modicon M340", 5: srv.model or ""})))
    n_writes = 0
    for i, t in enumerate(cap.ticks(period, start=cap.start + 1)):
        tid = (i % 60000) + 2
        if writes_every and i % writes_every == writes_every - 1:
            req, resp = modbus_write(tid, unit, 400 + i % 8, i % 1000)
            n_writes += 1
        else:
            req, resp = modbus_read(tid, unit, 0, 20)
        s.rr(t, req, resp)
    s.close(cap.end - 1)
    link(cap, c, srv, "Modbus", n_writes)


def poll_enip(cap: Capture, c: Dev, plc: Dev, period: float, writes_every: int = 0):
    s = Session(cap, c, plc, 44818).open(cap.start + 0.7)
    s.rr(cap.start + 0.8, g.enip_cip(0x01, b"\x20\x01\x24\x01"),
         g.enip_cip(0x01, b"", g.cip_identity_attributes(name=plc.model, rev=(30, 11)), response=True))
    n_writes = 0
    for i, t in enumerate(cap.ticks(period, start=cap.start + 1)):
        if writes_every and i % writes_every == writes_every - 1:
            s.rr(t, g.enip_cip(0x4D, g.cip_symbol_path("Setpoint_Flow"), b"\xca\x00\x01\x00\x00\x00\x48\x42"),
                 g.enip_cip(0x4D, b"", response=True))
            n_writes += 1
        else:
            s.rr(t, g.enip_cip(0x4C, g.cip_symbol_path("Flow_PV"), b"\x01\x00"),
                 g.enip_cip(0x4C, b"", b"\xca\x00\x00\x00\x48\x42", response=True))
    s.close(cap.end - 1)
    link(cap, c, plc, "CIP", n_writes)


def poll_dnp3(cap: Capture, master: Dev, rtu: Dev, period: float, operate_every: int = 0):
    s = Session(cap, master, rtu, 20000).open(cap.start + 0.9)
    n_writes = 0
    for i, t in enumerate(cap.ticks(period, start=cap.start + 1)):
        seq = i % 16
        if operate_every and i % operate_every == operate_every - 1:
            app = bytes([0xC0 | seq, 0x05]) + b"\x0c\x01\x28\x01\x00\x00\x00\x01\x01\xe8\x03\x00\x00\x00\x00\x00\x00\x00"
            n_writes += 1
        else:
            app = bytes([0xC0 | seq, 0x01]) + b"\x3c\x02\x06\x3c\x03\x06\x3c\x04\x06"
        s.rr(t, g.dnp3(3, 4, app), g.dnp3(4, 3, bytes([0xC0 | seq, 0x81, 0x00, 0x00]), from_master=False))
    s.close(cap.end - 1)
    link(cap, master, rtu, "DNP3", n_writes)


def poll_iec104(cap: Capture, master: Dev, rtu: Dev, period: float):
    s = Session(cap, master, rtu, 2404).open(cap.start + 1.1)
    s.rr(cap.start + 1.2, b"\x68\x04\x07\x00\x00\x00", b"\x68\x04\x0b\x00\x00\x00")  # STARTDT
    for i, t in enumerate(cap.ticks(period, start=cap.start + 2)):
        s.send(t, False, g.iec104_i(13, 3, ioa=1000 + i % 20, element=b"\x00\x00\x48\x42\x00", send_seq=i % 32767))
        s.send(t + 0.01, True, b"\x68\x04\x01\x00" + ((i + 1) % 32767 * 2).to_bytes(2, "little"))
    s.close(cap.end - 1)
    link(cap, master, rtu, "IEC 60870-5-104", 0)


def opc_ua(cap: Capture, c: Dev, srv: Dev, period: float):
    s = Session(cap, c, srv, 4840).open(cap.start + 0.3)
    hello = b"HELF" + (32).to_bytes(4, "little") + bytes(24)
    s.rr(cap.start + 0.31, hello, b"ACKF" + (28).to_bytes(4, "little") + bytes(20))
    for t in cap.ticks(period, start=cap.start + 1):
        s.rr(t, b"MSGF" + (120).to_bytes(4, "little") + bytes(112), b"MSGF" + (400).to_bytes(4, "little") + bytes(392))
    s.close(cap.end - 1)
    link(cap, c, srv, "OPC UA", 0)


def tls(cap: Capture, c, s, t: float, sni: str, up: int, down: int, port: int = 443):
    x = Session(cap, c, s, port).open(t)
    x.rr(t + 0.01, g.tls_client_hello(sni), b"\x16\x03\x03\x00\x31" + bytes(49), rtt=0.03)
    chunk = 1400
    for i in range(0, down, chunk):
        x.send(t + 0.05 + i / 2e7, False, b"\x17\x03\x03" + min(chunk - 5, down - i).to_bytes(2, "big") + bytes(min(chunk - 5, down - i)))
    for i in range(0, up, chunk):
        x.send(t + 0.06 + i / 2e7, True, b"\x17\x03\x03" + min(chunk - 5, up - i).to_bytes(2, "big") + bytes(min(chunk - 5, up - i)))
    x.close(t + 0.2 + (up + down) / 2e7)


def http(cap: Capture, c, s, t: float, host: str, path: str, body: int, port: int = 80, auth: str | None = None):
    x = Session(cap, c, s, port).open(t)
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n"
    if auth:
        import base64

        req += f"Authorization: Basic {base64.b64encode(auth.encode()).decode()}\r\n"
    x.rr(t + 0.01, (req + "\r\n").encode(), f"HTTP/1.1 200 OK\r\nServer: IIS\r\nContent-Length: {body}\r\n\r\n".encode() + bytes(min(body, 1200)))
    x.close(t + 0.05)


def smb(cap: Capture, c: Dev, s: Dev, t: float, kb: int):
    x = Session(cap, c, s, 445).open(t)
    x.rr(t + 0.01, b"\x00\x00\x00\x45\xfeSMB" + bytes(64), b"\x00\x00\x00\x45\xfeSMB" + bytes(64))
    for i in range(max(1, kb // 60)):
        x.rr(t + 0.02 + i * 0.002, b"\x00\x00\x00\x45\xfeSMB" + bytes(64), b"\x00\x00\xf0\x00\xfeSMB" + bytes(1300))
    x.close(t + 0.1 + kb / 5000)


def dns(cap: Capture, c, s, t: float, name: str, answer: str):
    q = DNS(id=cap.rnd.randint(1, 65535), rd=1, qd=DNSQR(qname=name))
    r = DNS(id=q.id, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=answer, ttl=300))
    eth, _ = l2(c, s, cap.access)
    sport = cap.rnd.randint(49152, 65000)
    cap.mark(c, s)
    cap.pcap.add(t, bytes(eth / IP(src=ip_of(c), dst=ip_of(s), ttl=ttl_of(c)) / UDP(sport=sport, dport=53) / q))
    eth, _ = l2(s, c, cap.access)
    cap.pcap.add(t + 0.002, bytes(eth / IP(src=ip_of(s), dst=ip_of(c), ttl=ttl_of(s)) / UDP(sport=53, dport=sport) / r))


def snmp_poll(cap: Capture, nms: Dev, sw: Dev, period: float, community: str):
    for t in cap.ticks(period):
        cap.udp(t, nms, sw, 50161, 161, g.snmp_get(community))
    link(cap, nms, sw, "SNMP")


def mqtt_sensor(cap: Capture, sensor: Dev, broker: Dev, period: float, user: str, pw: str):
    s = Session(cap, sensor, broker, 1883).open(cap.start + 0.2)
    s.rr(cap.start + 0.21, g.mqtt_connect(sensor.name.lower(), user, pw), b"\x20\x02\x00\x00")
    for t in cap.ticks(period, start=cap.start + 1):
        s.send(t, True, g.mqtt_publish(f"plant/{sensor.name.lower()}/temp", b"21.4"))
    s.close(cap.end - 1)
    link(cap, sensor, broker, "MQTT")


def arp_and_dhcp(cap: Capture, devs: list[Dev]):
    for d in devs:
        t = cap.start + cap.rnd.uniform(0, 60)
        if d.vlan is not None and not cap.access:
            cap.mark(d)
        if d.vlan is not None and not cap.access:
            cap.raw_l2(t, Ether(src=d.mac, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=d.vlan) / ARP(op=1, hwsrc=d.mac, psrc=d.ip, pdst=GW.get(d.vlan, "0.0.0.0")))
        if d.hostname and d.family == "endpoint":
            from scapy.layers.dhcp import BOOTP, DHCP

            frame = Ether(src=d.mac, dst="ff:ff:ff:ff:ff:ff")
            if not cap.access:
                frame = frame / Dot1Q(vlan=d.vlan)
            cap.raw_l2(t + 1, frame / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
                       / BOOTP(chaddr=bytes.fromhex(d.mac.replace(":", "")) + b"\x00" * 10)
                       / DHCP(options=[("message-type", "request"), ("hostname", d.hostname), ("vendor_class_id", "MSFT 5.0"), "end"]))


# ── Scenarios per capture ────────────────────────────────────────────────────


def ot_baseline(cap: Capture, scale: float, writes: bool):
    p = 1.0 / scale
    poll_s7(cap, SCADA, PLC_A1, 1.0 * p, writes_every=600 if writes else 0)
    poll_s7(cap, SCADA, PLC_A2, 1.0 * p, identity=False)
    poll_modbus(cap, SCADA, M340, 1.0 * p, identity=True)
    for i, vfd in enumerate(DRIVES):
        poll_modbus(cap, M340 if cap.access else SCADA, vfd, 2.0 * p, unit=i + 1)
    for i, hmi in enumerate(HMIS):
        target = [PLC_A1, M340, CLX][i % 3]
        if target is PLC_A1:
            poll_s7(cap, hmi, PLC_A1, 2.0 * p, identity=False)
        elif target is M340:
            poll_modbus(cap, hmi, M340, 2.0 * p, writes_every=300 if writes else 0)
        else:
            poll_enip(cap, hmi, CLX, 2.0 * p, writes_every=300 if writes else 0)
    poll_enip(cap, SCADA, CLX, 1.0 * p)
    poll_dnp3(cap, SCADA, RTU, 2.0 * p, operate_every=900 if writes else 0)
    poll_iec104(cap, SCADA, RTU104, 2.0 * p)
    opc_ua(cap, HIST, SCADA, 1.0 * p)


def enterprise(cap: Capture, scale: float):
    rnd = cap.rnd
    for ws in WS:
        for t in cap.ticks(60 / scale, jitter=0.9):
            what = rnd.random()
            if what < 0.35:
                dns(cap, ws, DC, t, "erp.riverside.local", ERP.ip)
                tls(cap, ws, ERP, t + 0.01, "erp.riverside.local", 800, rnd.randint(4_000, 40_000))
            elif what < 0.55:
                smb(cap, ws, FS, t, rnd.randint(20, 400))
            elif what < 0.8:
                cdn = rnd.choice(NET["cdn"])
                dns(cap, ws, DC, t, "cdn.example.com", cdn)
                tls(cap, ws, cdn, t + 0.01, "cdn.example.com", 600, rnd.randint(10_000, 80_000))
            else:
                tls(cap, ws, NET["saas"], t, "outlook.office365.com", 2000, 9000)
        link(cap, ws, DC, "DNS")
    for t in cap.ticks(30):
        dns(cap, DC, NET["dns"], t, "time.windows.com", "52.231.114.183")
    link(cap, DC, NET["dns"], "DNS")
    for t in cap.ticks(600):
        http(cap, PATCH, NET["update"], t, "download.windowsupdate.com", "/c/msdownload/update.cab", 50_000)
    link(cap, PATCH, NET["update"], "HTTP")
    for sw in SW:
        snmp_poll(cap, NMS, sw, 60, "public")
    for t in cap.ticks(300):
        tls(cap, HIST_DMZ, HIST, t, "hist01", 400, 30_000, port=443)  # DMZ replica pulls from the site historian
        tls(cap, ERP, HIST_DMZ, t + 1, "hist-dmz", 400, 20_000, port=443)
    link(cap, HIST_DMZ, HIST, "TLS")
    link(cap, ERP, HIST_DMZ, "TLS")
    for cam in CAMS:  # the NVR records both cameras over RTSP
        x = Session(cap, NVR, cam, 554).open(cap.start + 2)
        x.rr(cap.start + 2.01, f"DESCRIBE rtsp://{cam.ip}/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\n\r\n".encode(),
             b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nServer: Hikvision RTSP Server\r\nContent-Type: application/sdp\r\n\r\n")
        for t in cap.ticks(0.5, start=cap.start + 3):
            x.send(t, False, b"$\x00\x05\xb0" + bytes(1456))
        x.close(cap.end - 1)
        link(cap, NVR, cam, "RTSP")
    for i, cam in enumerate(CAMS):  # CAM-2 also streams out to the internet (planted)
        if i == 1:
            for t in cap.ticks(120):
                tls(cap, cam, NET["c2"], t, "stream.example-cam.net", 400_000, 2000)
            link(cap, cam, NET["c2"], "TLS")
    for s in SENSORS:
        mqtt_sensor(cap, s, BROKER, 5 / scale, "sensor", "sensor123")
    arp_and_dhcp(cap, [d for d in DEVICES.values() if d is not ROGUE])


def planted_c3(cap: Capture):
    """Engineering day: program download to PLC-A1 and a PLC stop, FTP and Telnet logins with weak passwords."""
    t = cap.start + 1800
    s = s7_session(cap, EWS1, PLC_A1, t, identity=False)
    s.rr(t + 1, g.s7(1, g.S7_REQUEST_DOWNLOAD), g.s7(3, b"\x1a"))
    s.rr(t + 5, g.s7(1, g.S7_PLC_STOP), g.s7(3, b"\x29"))
    s.close(t + 10)
    link(cap, EWS1, PLC_A1, "S7comm", 2)
    TRUTH_FINDINGS.append({"rule": "ot_s7_code_download", "src": EWS1.ip, "dst": PLC_A1.ip})
    TRUTH_FINDINGS.append({"rule": "ot_s7_critical", "src": EWS1.ip, "dst": PLC_A1.ip})
    x = Session(cap, EWS1, PLC_A2, 21).open(t + 60)
    for side, p in [("s", b"220 FTP ready\r\n"), ("c", b"USER plcadmin\r\n"), ("s", b"331 pw\r\n"),
                    ("c", b"PASS Siemens1\r\n"), ("s", b"230 ok\r\n")]:
        x.send(t + 61 + 0.01 * len(p), side == "c", p)
    link(cap, EWS1, PLC_A2, "FTP")
    TRUTH_CREDS.append({"protocol": "FTP", "client": EWS1.ip, "server": PLC_A2.ip, "username": "plcadmin"})
    TRUTH_FINDINGS.append({"rule": "cleartext_credentials", "src": EWS1.ip, "dst": PLC_A2.ip})
    x = Session(cap, EWS2, RTU, 23).open(t + 120)
    for i, (side, p) in enumerate([("s", b"\r\nRTU-B1 login: "), ("c", b"admin\r\n"), ("s", b"Password: "),
                                   ("c", b"admin\r\n"), ("s", b"\r\nRTU> ")]):
        x.send(t + 121 + i * 0.3, side == "c", p)
    link(cap, EWS2, RTU, "Telnet")
    TRUTH_CREDS.append({"protocol": "Telnet", "client": EWS2.ip, "server": RTU.ip, "username": "admin"})
    TRUTH_FINDINGS.append({"rule": "default_credentials", "src": EWS2.ip, "dst": RTU.ip})


def planted_c4(cap: Capture):
    """The rogue laptop: scans the SCADA server, then reads PLC-A1 straight from the business network."""
    cap.mark(ROGUE)
    arp_and_dhcp(cap, [ROGUE])
    t = cap.start + 900
    targets = [SCADA, HIST, EWS1, EWS2, PLC_A1, PLC_A2, M340]
    ports = [21, 22, 23, 25, 53, 80, 102, 110, 135, 139, 443, 445, 502, 1433, 3389, 5900, 8080, 20000, 44818]
    for i, tgt in enumerate(targets):
        for j, port in enumerate(ports):
            x = Session(cap, ROGUE, tgt, port)
            x.send(t + i * 2 + j * 0.01, True, flags="S").send(t + i * 2 + j * 0.01 + 0.001, False, flags="RA")
    TRUTH_FINDINGS.append({"rule": "port_scan", "src": ROGUE.ip, "dst": None})
    for k in range(3):
        s = s7_session(cap, ROGUE, PLC_A1, t + 300 + k * 600, identity=True)
        for n in range(30):
            s.rr(t + 301 + k * 600 + n, g.s7(1, g.S7_READ_VAR), g.s7(3, b"\x04\x01", b"\xff\x04\x00\x10" + bytes(2)))
        s.close(t + 340 + k * 600)
    link(cap, ROGUE, PLC_A1, "S7comm")
    for i in range(3):  # a business workstation also reaches the PLC directly (L4 → L1, bypassing the DMZ)
        s = s7_session(cap, WS[16], PLC_A1, cap.start + 2000 + i * 500, identity=False)
        s.rr(cap.start + 2001 + i * 500, g.s7(1, g.S7_READ_VAR), g.s7(3, b"\x04\x01", b"\xff\x04\x00\x10" + bytes(2)))
        s.close(cap.start + 2003 + i * 500)
    link(cap, WS[16], PLC_A1, "S7comm")


# ── Main ─────────────────────────────────────────────────────────────────────

CAPTURES = [
    # key, file, capture point, start, hours, access port (untagged)?
    ("c1", "riverside-core-day1.pcap", "Core switch SPAN (trunk)", T0, 1.0, False),
    ("c2", "riverside-cellA-tap.pcap", "Cell A TAP (access port)", T0 + 5 * 3600, 1.0, True),
    ("c3", "riverside-core-day2.pcap", "Core switch SPAN (trunk)", T0 + DAY, 1.0, False),
    ("c4", "riverside-core-day3.pcap", "Core switch SPAN (trunk)", T0 + 2 * DAY, 1.0, False),
]


def build(out: Path, scale: float) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    stats = {}
    for i, (key, fname, point, start, hours, access) in enumerate(CAPTURES):
        cap = Capture(key, out / fname, start, hours, access, seed=1000 + i)
        if key == "c2":  # only cell A traffic is visible on its access port: HMIs/SCADA to cell A devices
            p = 1.0 / scale
            poll_s7(cap, SCADA, PLC_A1, p)
            poll_s7(cap, SCADA, PLC_A2, p, identity=False)
            poll_modbus(cap, SCADA, M340, p, identity=True)
            for j, vfd in enumerate(DRIVES):
                poll_modbus(cap, M340, vfd, 2 * p, unit=j + 1)
            poll_s7(cap, HMIS[0], PLC_A1, 2 * p, identity=False)
            poll_modbus(cap, HMIS[1], M340, 2 * p, writes_every=300)
        else:
            ot_baseline(cap, scale, writes=key != "c1")
            enterprise(cap, scale)
            if key == "c3":
                planted_c3(cap)
            if key == "c4":
                planted_c4(cap)
        n = cap.pcap.close()
        stats[key] = {"file": fname, "capture_point": point, "packets": n, "start": start, "end": start + hours * 3600}
        print(f"{fname}: {n:,} packets", flush=True)
    TRUTH_FINDINGS.extend([
        {"rule": "iot_camera_exfil", "src": CAMS[1].ip, "dst": NET["c2"]},
        {"rule": "iot_mqtt_cleartext", "src": None, "dst": BROKER.ip},
        {"rule": "ot_cleartext", "src": None, "dst": PLC_A1.ip},
    ])
    TRUTH_CREDS.append({"protocol": "MQTT", "client": SENSORS[0].ip, "server": BROKER.ip, "username": "sensor"})
    TRUTH_CREDS.append({"protocol": "SNMP", "client": NMS.ip, "server": SW[0].ip, "username": None})
    truth = {
        "site": "Riverside Water Treatment (synthetic)",
        "captures": stats,
        "router": {"mac": ROUTER_MAC, "ips": GW},
        "devices": [{**{k: v for k, v in asdict(d).items() if k != "seen_in"}, "seen_in": sorted(d.seen_in)}
                    for d in DEVICES.values() if d.seen_in],
        "internet": NET,
        "links": TRUTH_LINKS,
        "ot_writes": [{"client": c, "server": s, "count": n} for (c, s), n in sorted(TRUTH_WRITES.items())],
        "findings": TRUTH_FINDINGS,
        "credentials": TRUTH_CREDS,
        "dmz_bypass": [{"client": WS[16].ip, "server": PLC_A1.ip}, {"client": ROGUE.ip, "server": PLC_A1.ip}],
        "new_in": {"c4": [ROGUE.ip]},
        "must_not_find": [
            {"rule": "beaconing", "why": "periodic polling between internal OT devices is normal, not C2 beaconing",
             "internal_only": True},
        ],
    }
    (out / "truth.json").write_text(json.dumps(truth, indent=2))
    return truth


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--scale", type=float, default=1.0, help="traffic rate multiplier (1.0 ≈ 150-250k packets per capture)")
    a = ap.parse_args()
    build(a.out, a.scale)
