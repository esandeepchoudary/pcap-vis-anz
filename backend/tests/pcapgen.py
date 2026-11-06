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


# ── OT / IoT payload builders (byte-accurate so tshark fully dissects them) ──────────────


def _dnp3_crc(data: bytes) -> bytes:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc & 0xFFFF).to_bytes(2, "little")


def dnp3(src: int, dst: int, app: bytes, from_master: bool = True) -> bytes:
    """DNP3 frame: link header + transport byte + application data, with per-block CRCs."""
    user = b"\xc0" + app  # transport: FIR|FIN, seq 0
    ctrl = (0x80 if from_master else 0x00) | 0x40 | 0x04  # DIR, PRM, unconfirmed user data
    header = (
        b"\x05\x64" + bytes([5 + len(user), ctrl]) + dst.to_bytes(2, "little") + src.to_bytes(2, "little")
    )
    out = header + _dnp3_crc(header)
    for i in range(0, len(user), 16):
        block = user[i : i + 16]
        out += block + _dnp3_crc(block)
    return out


def s7(
    rosctr: int, param: bytes, data: bytes = b"", pdu_ref: int = 1, err: tuple[int, int] | None = None
) -> bytes:
    """TPKT + COTP DT + S7comm PDU."""
    hdr = (
        bytes([0x32, rosctr, 0, 0])
        + pdu_ref.to_bytes(2, "big")
        + len(param).to_bytes(2, "big")
        + len(data).to_bytes(2, "big")
    )
    if rosctr in (2, 3):
        hdr += bytes(err or (0, 0))
    pdu = b"\x02\xf0\x80" + hdr + param + data
    return b"\x03\x00" + (len(pdu) + 4).to_bytes(2, "big") + pdu


S7_SETUP = bytes.fromhex("f0000001000103c0")
S7_READ_VAR = bytes.fromhex("0401120a10020001000184000000")
S7_WRITE_VAR = bytes.fromhex("0501120a10020001000184000000")
S7_REQUEST_DOWNLOAD = b"\x1a\x00\x01\x00\x00\x00\x00\x00\x09_0800001P\x0d1000144000144"
S7_PLC_STOP = b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"


def enip_list_identity_response(
    name: str = "1756-L83E/B",
    vendor: int = 1,
    devtype: int = 14,
    product: int = 166,
    serial: int = 0x60C0FFEE,
    rev=(33, 11),
) -> bytes:
    nm = name.encode()
    ident = (
        b"\x01\x00"
        + b"\x00\x02\xaf\x12"
        + bytes([10, 0, 0, 50])
        + b"\x00" * 8
        + vendor.to_bytes(2, "little")
        + devtype.to_bytes(2, "little")
        + product.to_bytes(2, "little")
        + bytes(rev)
        + b"\x60\x30"
        + serial.to_bytes(4, "little")
        + bytes([len(nm)])
        + nm
        + b"\x03"
    )
    data = b"\x01\x00" + b"\x0c\x00" + len(ident).to_bytes(2, "little") + ident
    return b"\x63\x00" + len(data).to_bytes(2, "little") + b"\x00" * 20 + data


def enip_cip(
    service: int,
    path: bytes,
    cip_data: bytes = b"",
    response: bool = False,
    status: int = 0,
    session: int = 0x11223344,
) -> bytes:
    """SendRRData carrying one unconnected CIP request (or its response)."""
    if response:
        cip = bytes([service | 0x80, 0, status, 0]) + cip_data
    else:
        cip = bytes([service, len(path) // 2]) + path + cip_data
    items = b"\x02\x00" + b"\x00\x00\x00\x00" + b"\xb2\x00" + len(cip).to_bytes(2, "little") + cip
    data = b"\x00\x00\x00\x00" + b"\x0a\x00" + items
    return b"\x6f\x00" + len(data).to_bytes(2, "little") + session.to_bytes(4, "little") + b"\x00" * 16 + data


def cip_symbol_path(tag: str) -> bytes:
    t = tag.encode()
    p = b"\x91" + bytes([len(t)]) + t
    return p + (b"\x00" if len(t) % 2 else b"")


def iec104_i(
    typeid: int,
    cot: int,
    ca: int = 1,
    ioa: int = 100,
    element: bytes = b"\x01",
    send_seq: int = 0,
    negative: bool = False,
) -> bytes:
    asdu = (
        bytes([typeid, 1, cot | (0x40 if negative else 0), 0])
        + ca.to_bytes(2, "little")
        + ioa.to_bytes(3, "little")
        + element
    )
    apci = (send_seq << 1).to_bytes(2, "little") + b"\x00\x00"
    return b"\x68" + bytes([len(apci) + len(asdu)]) + apci + asdu


def bacnet_confirmed(
    service: int, payload: bytes = b"\x0c\x00\x00\x00\x01\x19\x55", invoke: int = 1
) -> bytes:
    apdu = bytes([0x00, 0x05, invoke, service]) + payload
    npdu = b"\x01\x04"
    return b"\x81\x0a" + (4 + len(npdu) + len(apdu)).to_bytes(2, "big") + npdu + apdu


def bacnet_iam(instance: int = 1234, vendor: int = 5) -> bytes:
    obj = ((8 << 22) | instance).to_bytes(4, "big")
    apdu = b"\x10\x00" + b"\xc4" + obj + b"\x22\x05\xc4" + b"\x91\x00" + b"\x21" + bytes([vendor])
    npdu = b"\x01\x00"
    return b"\x81\x0b" + (4 + len(npdu) + len(apdu)).to_bytes(2, "big") + npdu + apdu


def bacnet_error(service: int = 15) -> bytes:
    apdu = bytes([0x50, 0x01, service]) + b"\x91\x02\x91\x1f"
    npdu = b"\x01\x00"
    return b"\x81\x0a" + (4 + len(npdu) + len(apdu)).to_bytes(2, "big") + npdu + apdu


def mqtt_connect(client_id: str, username: str | None = None, password: str | None = None) -> bytes:
    def s(x: str) -> bytes:
        return len(x.encode()).to_bytes(2, "big") + x.encode()

    flags = 0x02 | (0x80 if username else 0) | (0x40 if password else 0)
    body = s("MQTT") + bytes([4, flags]) + b"\x00\x3c" + s(client_id)
    if username:
        body += s(username)
    if password:
        body += s(password)
    return bytes([0x10, len(body)]) + body


def mqtt_publish(topic: str, message: bytes) -> bytes:
    body = len(topic).to_bytes(2, "big") + topic.encode() + message
    return bytes([0x30, len(body)]) + body


def coap_get(path_parts: list[str], msg_id: int = 1) -> bytes:
    out = bytes([0x40, 0x01]) + msg_id.to_bytes(2, "big")
    prev = 0
    for part in path_parts:
        delta = 11 - prev
        out += bytes([(delta << 4) | len(part)]) + part.encode()
        prev = 11
    return out


def snmp_get(community: str) -> bytes:
    from scapy.asn1.asn1 import ASN1_OID
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

    return bytes(
        SNMP(
            version=1,
            community=community,
            PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]),
        )
    )


# ── Device identity (passive fingerprinting, M5) ─────────────────────────────────────────


def modbus_device_id_request() -> bytes:
    """FC 43 / MEI 14 Read Device Identification, basic objects."""
    return b"\x2b\x0e\x01\x00"


def modbus_device_id_response(objects: dict[int, str]) -> bytes:
    """FC 43 / MEI 14 response: object id → string (0 vendor, 1 product code, 2 revision, 4 product, 5 model)."""
    body = b"".join(bytes([oid, len(v.encode())]) + v.encode() for oid, v in objects.items())
    return b"\x2b\x0e\x01\x01\x00\x00" + bytes([len(objects)]) + body


S7_SZL_REQUEST_PARAM = bytes.fromhex("000112041144010" + "0")


def s7_szl_request(szl_id: int, index: int = 0) -> bytes:
    data = b"\xff\x09\x00\x04" + szl_id.to_bytes(2, "big") + index.to_bytes(2, "big")
    return s7(7, S7_SZL_REQUEST_PARAM, data)


def s7_szl_response(szl_id: int, records: list[bytes], record_len: int) -> bytes:
    """Userdata response carrying a partial SZL list (records must already be record_len bytes)."""
    param = bytes.fromhex("000112081284010100000000")
    szl = (
        szl_id.to_bytes(2, "big")
        + b"\x00\x00"
        + record_len.to_bytes(2, "big")
        + len(records).to_bytes(2, "big")
    )
    payload = szl + b"".join(records)
    data = b"\xff\x09" + len(payload).to_bytes(2, "big") + payload
    return s7(7, param, data)


def szl_0011_record(index: int, mlfb: str, bgtyp: int = 0, ausbg: int = 0, ausbe: int = 0) -> bytes:
    """SZL 0x0011 module identification record (28 bytes)."""
    return (
        index.to_bytes(2, "big")
        + mlfb.encode().ljust(20, b" ")[:20]
        + bgtyp.to_bytes(2, "big")
        + ausbg.to_bytes(2, "big")
        + ausbe.to_bytes(2, "big")
    )


def szl_001c_record(index: int, text: str) -> bytes:
    """SZL 0x001C component identification record (34 bytes)."""
    return index.to_bytes(2, "big") + text.encode().ljust(32, b"\x00")[:32]


def profinet_dcp_identify_response(
    name: str, type_of_station: str, vendor_id: int, device_id: int, ip: str, role: int | None = None
) -> bytes:
    """PROFINET DCP Identify response payload (after the Ethernet header, EtherType 0x8892)."""

    def block(opt: int, sub: int, data: bytes, info: int = 0) -> bytes:
        body = info.to_bytes(2, "big") + data
        out = bytes([opt, sub]) + len(body).to_bytes(2, "big") + body
        return out + (b"\x00" if len(body) % 2 else b"")

    import ipaddress as _ip

    blocks = (
        block(2, 1, type_of_station.encode())
        + block(2, 2, name.encode())
        + block(2, 3, vendor_id.to_bytes(2, "big") + device_id.to_bytes(2, "big"))
        + (block(2, 4, bytes([role, 0])) if role is not None else b"")
        + block(1, 2, _ip.ip_address(ip).packed + bytes([255, 255, 255, 0]) + b"\x00\x00\x00\x00", info=1)
    )
    return (
        b"\xfe\xff"
        + bytes([5, 1])
        + b"\x00\x00\x00\x01"
        + b"\x00\x00"
        + len(blocks).to_bytes(2, "big")
        + blocks
    )


def cip_identity_attributes(
    name: str = "1769-L33ER",
    vendor: int = 1,
    devtype: int = 14,
    product: int = 103,
    rev=(30, 11),
    serial: int = 0x40ABCDEF,
) -> bytes:
    """Identity object Get_Attributes_All response data (instance attributes 1-7)."""
    nm = name.encode()
    return (
        vendor.to_bytes(2, "little")
        + devtype.to_bytes(2, "little")
        + product.to_bytes(2, "little")
        + bytes(rev)
        + b"\x60\x00"
        + serial.to_bytes(4, "little")
        + bytes([len(nm)])
        + nm
    )


def bacnet_read_property_ack_object_name(instance: int, name: str, invoke: int = 1) -> bytes:
    """BACnet/IP complex ACK to readProperty(device, object-name) with a character string."""
    obj = ((8 << 22) | instance).to_bytes(4, "big")
    s = b"\x00" + name.encode()
    tag = bytes([0x75, len(s)]) if len(s) > 4 else bytes([0x70 | len(s)])
    apdu = bytes([0x30, invoke, 0x0C]) + b"\x0c" + obj + b"\x19\x4d" + b"\x3e" + tag + s + b"\x3f"
    npdu = b"\x01\x00"
    bvlc_len = 4 + len(npdu) + len(apdu)
    return b"\x81\x0a" + bvlc_len.to_bytes(2, "big") + npdu + apdu
