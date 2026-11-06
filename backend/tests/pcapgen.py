"""Build small, protocol-correct captures for engine tests (scapy writes, tshark reads)."""

import logging
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (  # noqa: E402
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Dot1AD,
    Dot1Q,
    Ether,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
    Raw,
    wrpcap,
)

BCAST = "ff:ff:ff:ff:ff:ff"


class Cap:
    """Accumulates frames with increasing timestamps."""

    def __init__(self, start: float = 1_700_000_000.0, step: float = 0.01):
        self.frames = []
        self.t = start
        self.step = step

    def add(self, frame, dt: float | None = None):
        self.t += self.step if dt is None else dt
        frame.time = self.t
        self.frames.append(frame)
        return frame

    def write(self, path: Path) -> Path:
        wrpcap(str(path), self.frames)
        return path

    # ── L2 helpers ───────────────────────────────────────────────────────
    @staticmethod
    def l2(src_mac, dst_mac, vlan=None, qinq=None, stacked=None, pcp=0):
        """Ethernet header with optional 802.1Q tag, 802.1ad QinQ (outer, inner), or stacked 802.1Q."""
        e = Ether(src=src_mac, dst=dst_mac)
        if qinq:
            return e / Dot1AD(vlan=qinq[0]) / Dot1Q(vlan=qinq[1], prio=pcp)
        if stacked:
            return e / Dot1Q(vlan=stacked[0]) / Dot1Q(vlan=stacked[1], prio=pcp)
        if vlan is not None:
            return e / Dot1Q(vlan=vlan, prio=pcp)
        return e

    # ── L3/L4 conversations ──────────────────────────────────────────────
    def tcp_session(
        self,
        c,
        s,
        cport,
        sport,
        exchanges=(),
        handshake=True,
        vlan=None,
        ttl_c=64,
        ttl_s=64,
        ipv6=False,
        close=True,
        **l2kw,
    ):
        """c and s are (mac, ip). exchanges: list of ("c"|"s", payload bytes)."""
        cmac, cip = c
        smac, sip = s
        L3 = IPv6 if ipv6 else IP
        ttl_field = "hlim" if ipv6 else "ttl"

        def c2s(flags, payload=b"", seq=0, ack=0):
            pkt = (
                self.l2(cmac, smac, vlan, **l2kw)
                / L3(src=cip, dst=sip, **{ttl_field: ttl_c})
                / TCP(sport=cport, dport=sport, flags=flags, seq=seq, ack=ack)
            )
            return self.add(pkt / Raw(payload) if payload else pkt)

        def s2c(flags, payload=b"", seq=0, ack=0):
            pkt = (
                self.l2(smac, cmac, vlan, **l2kw)
                / L3(src=sip, dst=cip, **{ttl_field: ttl_s})
                / TCP(sport=sport, dport=cport, flags=flags, seq=seq, ack=ack)
            )
            return self.add(pkt / Raw(payload) if payload else pkt)

        cseq, sseq = 1000, 5000
        if handshake:
            c2s("S", seq=cseq)
            s2c("SA", seq=sseq, ack=cseq + 1)
            cseq += 1
            sseq += 1
            c2s("A", seq=cseq, ack=sseq)
        for side, payload in exchanges:
            if side == "c":
                c2s("PA", payload, seq=cseq, ack=sseq)
                cseq += len(payload)
            else:
                s2c("PA", payload, seq=sseq, ack=cseq)
                sseq += len(payload)
        if close and handshake:
            c2s("FA", seq=cseq, ack=sseq)
            s2c("FA", seq=sseq, ack=cseq + 1)
        return self

    def udp(self, src, dst, sport, dport, payload=b"x", vlan=None, ttl=64, ipv6=False, **l2kw):
        smac, sip = src
        dmac, dip = dst
        L3 = IPv6(src=sip, dst=dip, hlim=ttl) if ipv6 else IP(src=sip, dst=dip, ttl=ttl)
        pkt = self.l2(smac, dmac, vlan, **l2kw) / L3 / UDP(sport=sport, dport=dport)
        self.add(pkt / (payload if not isinstance(payload, bytes) else Raw(payload)))
        return self

    def ping(self, src, dst, reply_first=False, ipv6=False):
        smac, sip = src
        dmac, dip = dst
        if ipv6:
            req = Ether(src=smac, dst=dmac) / IPv6(src=sip, dst=dip) / ICMPv6EchoRequest(id=1, seq=1)
            rep = Ether(src=dmac, dst=smac) / IPv6(src=dip, dst=sip) / ICMPv6EchoReply(id=1, seq=1)
        else:
            req = Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / ICMP(type=8, id=1, seq=1)
            rep = Ether(src=dmac, dst=smac) / IP(src=dip, dst=sip) / ICMP(type=0, id=1, seq=1)
        for p in (rep, req) if reply_first else (req, rep):
            self.add(p)
        return self

    def arp_reply(self, mac, ip, to_mac="00:00:00:00:00:01", to_ip="10.0.0.254", vlan=None):
        self.add(self.l2(mac, to_mac, vlan) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=to_mac, pdst=to_ip))
        return self

    def arp_request(self, mac, ip, target_ip, vlan=None):
        self.add(self.l2(mac, BCAST, vlan) / ARP(op=1, hwsrc=mac, psrc=ip, pdst=target_ip))
        return self

    def dns(self, client, server, qname, answers=(), vlan=None, txid=0x1234):
        cmac, cip = client
        smac, sip = server
        q = DNS(id=txid, rd=1, qd=DNSQR(qname=qname))
        self.add(self.l2(cmac, smac, vlan) / IP(src=cip, dst=sip) / UDP(sport=53001, dport=53) / q)
        an = None
        for a in answers:
            rr = DNSRR(rrname=qname, type="A", rdata=a, ttl=60)
            an = rr if an is None else an / rr
        r = DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=qname), an=an)
        self.add(self.l2(smac, cmac, vlan) / IP(src=sip, dst=cip) / UDP(sport=53, dport=53001) / r)
        return self

    def lldp(self, mac, system_name, system_desc="Test switch OS 1.0"):
        def tlv(t, val: bytes):
            return bytes([(t << 1) | (len(val) >> 8), len(val) & 0xFF]) + val

        body = (
            tlv(1, b"\x04" + bytes.fromhex(mac.replace(":", "")))
            + tlv(2, b"\x05Gi0/1")
            + tlv(3, b"\x00\x78")
            + tlv(5, system_name.encode())
            + tlv(6, system_desc.encode())
            + tlv(0, b"")
        )
        self.add(Ether(src=mac, dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(body))
        return self

    def cdp(self, mac, device_id, platform="cisco WS-C2960", native_vlan=1):
        def tlv(t, val: bytes):
            return t.to_bytes(2, "big") + (len(val) + 4).to_bytes(2, "big") + val

        payload = (
            b"\x02\xb4\x00\x00"
            + tlv(1, device_id.encode())
            + tlv(6, platform.encode())
            + tlv(0x0A, native_vlan.to_bytes(2, "big"))
        )
        llc_snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
        frame = Ether(src=mac, dst="01:00:0c:cc:cc:cc", type=len(llc_snap) + len(payload)) / Raw(
            llc_snap + payload
        )
        self.add(frame)
        return self

    def dhcp_request(self, mac, hostname, vendor_class="MSFT 5.0"):
        from scapy.layers.dhcp import BOOTP, DHCP

        pkt = (
            Ether(src=mac, dst=BCAST)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10)
            / DHCP(
                options=[
                    ("message-type", "request"),
                    ("hostname", hostname),
                    ("vendor_class_id", vendor_class),
                    "end",
                ]
            )
        )
        self.add(pkt)
        return self


def http_get(host: str, path: str = "/", ua: str = "test-agent/1.0") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n\r\n".encode()


def http_ok(body: bytes = b"ok", server: str = "nginx", ctype: str = "text/plain", extra: str = "") -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
        f"{extra}\r\n"
    ).encode() + body


def tls_client_hello(sni: str) -> bytes:
    """Minimal TLS 1.2 ClientHello with an SNI extension (enough for tshark's JA3/JA4)."""
    name = sni.encode()
    sni_ext = (
        b"\x00\x00"
        + (len(name) + 5).to_bytes(2, "big")
        + (len(name) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(name).to_bytes(2, "big")
        + name
    )
    groups = b"\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18"
    formats = b"\x00\x0b\x00\x02\x01\x00"
    exts = sni_ext + groups + formats
    ciphers = b"\xc0\x2b\xc0\x2f\x00\x9e\x00\x2f"
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + len(ciphers).to_bytes(2, "big")
        + ciphers
        + b"\x01\x00"
        + len(exts).to_bytes(2, "big")
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def modbus(trans_id: int, unit: int, pdu: bytes) -> bytes:
    return trans_id.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit]) + pdu
