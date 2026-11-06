"""Aggregate decoded packets into directional flows and hosts, then classify hosts with evidence.

Order independence: every "first seen" choice uses packet timestamps (ties broken by value), flows are
numbered at the end by first appearance, and lists are sorted deterministically. So an Aggregator fed
the whole capture and several Aggregators fed host-pair partitions then ``merge``d produce the same
result. That is what makes parallel analysis (parallel.py) safe.
"""

from collections import Counter, defaultdict

from pcapvis.engine import knowledge as K
from pcapvis.engine import ot
from pcapvis.engine.apps import FlowNotes
from pcapvis.engine.credentials import MAX_CREDENTIALS, CredentialTracker
from pcapvis.engine.model import Credential, Evidence, Flow, Host, HostName, OtCommand, Service
from pcapvis.engine.packet import Packet
from pcapvis.engine.tshark_env import TsharkEnv

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MAX_DNS_QUERIES_PER_HOST = 500
MAX_SET_ITEMS = 200
MAX_NAMES = 20
# A MAC that is the L2 source for this many distinct IPs is a router/gateway, not the hosts' NIC.
GATEWAY_MAC_MIN_IPS = 3
ICMP_ECHO_REQUEST = {8, 128}  # ICMPv4, ICMPv6
ICMP_ECHO_REPLY = {0, 129}
MAX_OT_COMMANDS = 200_000
MAX_FLOW_TIMES = 64  # per flow
MAX_TIMED_FLOWS = 200_000  # bound memory on huge captures
_L234_PREFIXES = ("frame_", "eth_", "sll_", "vlan_", "ieee8021ad_", "ip_", "ipv6_", "tcp_", "udp_", "_ws")
MAX_TRACKED_SEGMENTS = 500_000  # data segments of OT/credential/app protocols; bounds memory
OT_DISSECTORS = {"modbus", "dnp3", "s7comm", "enip", "cip", "iec60870_asdu", "bacapp"}
APP_DISSECTORS = {"http", "mqtt", "coap"}
CRED_DISSECTORS = {"ftp", "pop", "imap", "smtp", "http", "mqtt", "snmp", "telnet", "urlencoded-form"}


def _is_group_mac(mac: str) -> bool:
    """Broadcast/multicast MACs have the I/G bit set in the first octet."""
    try:
        return bool(int(mac[:2], 16) & 1)
    except ValueError:
        return True


def _add_capped(s: set, value, cap: int = MAX_SET_ITEMS) -> None:
    if value is not None and len(s) < cap:
        s.add(value)


def _first(store: dict, key, ts: float, value) -> None:
    """Keep the earliest observation of ``key`` (ties: smallest value), as (ts, value)."""
    cur = store.get(key)
    if cur is None or (ts, value) < cur:
        store[key] = (ts, value)


def _merge_first(dst: dict, src: dict) -> None:
    for k, (ts, v) in src.items():
        _first(dst, k, ts, v)


class FlowAcc:
    __slots__ = (
        "key",
        "transport",
        "client",
        "client_port",
        "server",
        "server_port",
        "basis",
        "pkts_c2s",
        "pkts_s2c",
        "bytes_c2s",
        "bytes_s2c",
        "first",
        "last",
        "vlans",
        "detected",
        "syn_seen",
        "resets",
        "ot_reads",
        "ot_writes",
        "ot_errors",
        "fc_counts",
        "times",
        "cmd_seq",
    )

    def __init__(self, key, transport, client, cport, server, sport, basis, ts):
        self.key = key
        self.transport = transport
        self.client, self.client_port = client, cport
        self.server, self.server_port = server, sport
        self.basis = basis
        self.pkts_c2s = self.pkts_s2c = self.bytes_c2s = self.bytes_s2c = 0
        self.first = self.last = ts
        self.vlans: set[int] = set()
        self.detected: Counter[str] = Counter()
        self.syn_seen = False
        self.resets = 0
        self.ot_reads = self.ot_writes = self.ot_errors = 0
        self.fc_counts: Counter[str] = Counter()
        self.times: list[float] = []  # first client→server packet times, for beacon detection
        self.cmd_seq = 0  # OT commands recorded on this flow so far (orders commands within a flow)

    def flip(self, basis: str) -> None:
        """Swap client and server (a later SYN proved the first guess wrong)."""
        self.client, self.server = self.server, self.client
        self.client_port, self.server_port = self.server_port, self.client_port
        self.pkts_c2s, self.pkts_s2c = self.pkts_s2c, self.pkts_c2s
        self.bytes_c2s, self.bytes_s2c = self.bytes_s2c, self.bytes_c2s
        self.basis = basis

    def protocol_label(self) -> str:
        return flow_label(self.transport, self.server_port, self.client_port, self.detected)

    def sort_key(self):
        return (self.first, self.transport, self.client, self.client_port, self.server, self.server_port)


def flow_label(transport: str, server_port: int, client_port: int, detected: Counter) -> str:
    """tshark-identified application protocol first, then the port table, then the transport."""
    for proto, _ in sorted(detected.items(), key=lambda kv: (-kv[1], kv[0])):
        if proto == "TLS":
            if server_port in K.TLS_WEB_PORTS:
                return "HTTPS"
            if server_port in K.PORT_MAP:
                return K.PORT_MAP[server_port][0]
            continue
        return proto
    if server_port in K.PORT_MAP:
        return K.PORT_MAP[server_port][0]
    if client_port in K.PORT_MAP:
        return K.PORT_MAP[client_port][0]
    if "TLS" in detected:
        return "TLS"
    return {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6"}.get(transport, transport.upper())


class HostAcc:
    __slots__ = (
        "ip",
        "macs",
        "dst_macs",
        "ttls",
        "pkts_sent",
        "pkts_recv",
        "bytes_sent",
        "bytes_recv",
        "first",
        "last",
        "vlans",
        "vlan_outer",
        "pcps",
        "untagged",
        "qinq",
        "protocols",
        "hostnames",
        "dns_queries",
        "tls_sni",
        "tls_ja3",
        "tls_ja4",
        "identity",
        "extra_hints",
        "broadcast_dst",
        "modbus_units",
        "dnp3_addrs",
        "ot_master",
        "ot_outstation",
    )

    def __init__(self, ip: str):
        self.ip = ip
        self.macs: Counter[str] = Counter()
        self.dst_macs: Counter[str] = Counter()  # MACs this IP was *sent to* (fallback for silent hosts)
        self.ttls: Counter[int] = Counter()
        self.pkts_sent = self.pkts_recv = self.bytes_sent = self.bytes_recv = 0
        self.first = self.last = None
        self.vlans: set[int] = set()
        self.vlan_outer: set[int] = set()
        self.pcps: set[int] = set()
        self.untagged = False
        self.qinq = False
        self.protocols: set[str] = set()
        self.hostnames: dict[str, tuple[float, str]] = {}  # name → (first ts, source)
        self.dns_queries: set[str] = set()
        self.tls_sni: set[str] = set()
        self.tls_ja3: set[str] = set()
        self.tls_ja4: set[str] = set()
        self.identity: dict[str, tuple[float, str]] = {}  # key → (first ts, value)
        self.extra_hints: dict[str, tuple[float, tuple[str, Evidence]]] = {}  # kind → (ts, (type, evidence))
        self.broadcast_dst = False
        self.modbus_units: set[int] = set()
        self.dnp3_addrs: set[int] = set()
        self.ot_master = False
        self.ot_outstation = False

    def seen(self, ts: float) -> None:
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts

    def add_name(self, name: str | None, source: str, ts: float) -> None:
        if name and (len(self.hostnames) < MAX_NAMES or name.rstrip(".") in self.hostnames):
            _first(self.hostnames, name.rstrip("."), ts, source)

    def merge(self, o: "HostAcc") -> None:
        self.macs.update(o.macs)
        self.dst_macs.update(o.dst_macs)
        self.ttls.update(o.ttls)
        self.pkts_sent += o.pkts_sent
        self.pkts_recv += o.pkts_recv
        self.bytes_sent += o.bytes_sent
        self.bytes_recv += o.bytes_recv
        for ts in (o.first, o.last):
            if ts is not None:
                self.seen(ts)
        for mine, theirs, cap in (
            (self.vlans, o.vlans, MAX_SET_ITEMS),
            (self.vlan_outer, o.vlan_outer, MAX_SET_ITEMS),
            (self.tls_sni, o.tls_sni, MAX_SET_ITEMS),
            (self.tls_ja3, o.tls_ja3, MAX_SET_ITEMS),
            (self.tls_ja4, o.tls_ja4, MAX_SET_ITEMS),
            (self.modbus_units, o.modbus_units, MAX_SET_ITEMS),
            (self.dnp3_addrs, o.dnp3_addrs, MAX_SET_ITEMS),
            (self.dns_queries, o.dns_queries, MAX_DNS_QUERIES_PER_HOST),
        ):
            for v in sorted(theirs):
                _add_capped(mine, v, cap)
        self.pcps |= o.pcps
        self.protocols |= o.protocols
        self.untagged |= o.untagged
        self.qinq |= o.qinq
        self.broadcast_dst |= o.broadcast_dst
        self.ot_master |= o.ot_master
        self.ot_outstation |= o.ot_outstation
        _merge_first(self.hostnames, o.hostnames)
        _merge_first(self.identity, o.identity)
        for kind, (ts, hint) in o.extra_hints.items():
            cur = self.extra_hints.get(kind)
            if cur is None or ts < cur[0]:
                self.extra_hints[kind] = (ts, hint)


class Aggregator:
    """Feed packets with ``add``; combine partition aggregators with ``merge``; then ``finish``."""

    def __init__(self, env: TsharkEnv | None = None):
        self.env = env
        self.notes = FlowNotes()
        self.creds = CredentialTracker()
        self._ot_raw: list[tuple[OtCommand, tuple, int]] = []  # (command, flow key, per-flow seq)
        self.ot_truncated = False
        self._creds_raw: dict[tuple, tuple[Credential, tuple]] = {}  # key → (credential, flow key)
        self.app_protocols_seen: set[str] = set()
        self._seen_segments: set[tuple] = set()
        self.retransmissions = 0
        self.hosts: dict[str, HostAcc] = {}
        self.flows: dict[tuple, FlowAcc] = {}
        self.mac_src_ips: dict[str, set[str]] = defaultdict(set)
        self.mac_dst_ips: dict[str, set[str]] = defaultdict(set)
        self.arp_ip_for_mac: dict[str, set[str]] = defaultdict(set)
        self.mac_names: dict[str, dict[str, tuple[float, str]]] = defaultdict(dict)  # mac → name → (ts, src)
        self.mac_identity: dict[str, dict[str, tuple[float, str]]] = defaultdict(dict)
        self.mac_vendor: dict[str, str] = {}
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.malformed = 0
        self.link_types: Counter[str] = Counter()
        self.vlan_packets: Counter = Counter()  # VLAN id (None = untagged) → frames
        self.vlan_broadcast: Counter = Counter()  # VLAN id → frames to ff:ff:ff:ff:ff:ff
        self.arp_claims: dict[tuple, set[str]] = defaultdict(set)  # (VLAN, IP) → MACs claiming it
        # Filled by finish():
        self.ot_commands: list[OtCommand] = []
        self.credentials: list[Credential] = []

    # ── helpers ────────────────────────────────────────────────────────────
    def host(self, ip: str) -> HostAcc:
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = HostAcc(ip)
        return h

    def _flow_for(self, p: Packet) -> tuple[FlowAcc, bool]:
        """Find or create the flow for this packet. Returns (flow, packet_is_client_to_server)."""
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (p.transport, *a, *b) if a <= b else (p.transport, *b, *a)
        f = self.flows.get(key)
        if f is None:
            client_is_src, basis = self._initial_direction(p)
            if client_is_src:
                f = FlowAcc(key, p.transport, p.src, p.sport, p.dst, p.dport, basis, p.ts)
            else:
                f = FlowAcc(key, p.transport, p.dst, p.dport, p.src, p.sport, basis, p.ts)
            self.flows[key] = f
        elif p.transport == "tcp" and p.syn and f.basis != "handshake":
            # A handshake packet is authoritative: SYN comes from the client, SYN-ACK from the server.
            client = (p.src, p.sport) if not p.ack else (p.dst, p.dport)
            if client != (f.client, f.client_port):
                f.flip("handshake")
            else:
                f.basis = "handshake"
        return f, (p.src == f.client and p.sport == f.client_port)

    @staticmethod
    def _initial_direction(p: Packet) -> tuple[bool, str]:
        if p.transport == "tcp" and p.syn:
            return (not p.ack), "handshake"
        if p.transport in ("icmp", "icmpv6") and p.icmp_type is not None:
            if p.icmp_type in ICMP_ECHO_REQUEST:
                return True, "request"
            if p.icmp_type in ICMP_ECHO_REPLY:
                return False, "request"
        if p.transport in ("tcp", "udp"):
            s_known = p.sport in K.PORT_MAP or p.sport < 1024
            d_known = p.dport in K.PORT_MAP or p.dport < 1024
            if d_known and not s_known:
                return True, "port"
            if s_known and not d_known:
                return False, "port"
            if d_known and s_known and p.sport != p.dport:
                return p.dport < p.sport, "port"
        return True, "first_packet"

    # ── per packet ─────────────────────────────────────────────────────────
    def add(self, p: Packet) -> None:
        self.packets += 1
        self.bytes += p.length
        if self.first_ts is None or p.ts < self.first_ts:
            self.first_ts = p.ts
        if self.last_ts is None or p.ts > self.last_ts:
            self.last_ts = p.ts
        if p.malformed:
            self.malformed += 1
        if p.protocols:
            self.link_types[p.protocols[0]] += 1
        if p.src_mac and p.src_vendor:
            self.mac_vendor.setdefault(p.src_mac, p.src_vendor)

        vlan_key = p.vlan_ids[-1] if p.vlan_ids else None
        self.vlan_packets[vlan_key] += 1
        if p.dst_mac == BROADCAST_MAC:
            self.vlan_broadcast[vlan_key] += 1

        layers = p.layers
        self._discovery(p, layers)

        if p.src is None or p.transport is None:
            return  # non-IP (ARP, LLDP, CDP, STP...) handled by _discovery

        sh = self.host(p.src)
        dh = self.host(p.dst)
        sh.seen(p.ts)
        dh.seen(p.ts)
        sh.pkts_sent += 1
        sh.bytes_sent += p.length
        dh.pkts_recv += 1
        dh.bytes_recv += p.length
        if p.ttl is not None:
            sh.ttls[p.ttl] += 1
        if p.src_mac:
            sh.macs[p.src_mac] += 1
            self.mac_src_ips[p.src_mac].add(p.src)
        if p.dst_mac and not _is_group_mac(p.dst_mac):
            dh.dst_macs[p.dst_mac] += 1
            self.mac_dst_ips[p.dst_mac].add(p.dst)
        if p.dst_mac == BROADCAST_MAC or p.dst == "255.255.255.255":
            dh.broadcast_dst = True

        # VLANs: innermost 802.1Q tag is the host's VLAN; an S-tag or stacked tag is "outer".
        if p.vlan_ids or p.outer_vlan is not None:
            if p.outer_vlan is not None:
                outer, inner = p.outer_vlan, (p.vlan_ids[-1] if p.vlan_ids else None)
            elif len(p.vlan_ids) >= 2:
                outer, inner = p.vlan_ids[0], p.vlan_ids[-1]
            else:
                outer, inner = None, p.vlan_ids[0]
            for h in (sh, dh):
                _add_capped(h.vlans, inner)
                if outer is not None:
                    _add_capped(h.vlan_outer, outer)
                    h.qinq = True
            if p.pcp is not None:
                sh.pcps.add(p.pcp)
        else:
            sh.untagged = True

        f, c2s = self._flow_for(p)
        if c2s:
            f.pkts_c2s += 1
            f.bytes_c2s += p.length
            if len(f.times) < MAX_FLOW_TIMES and len(self.flows) <= MAX_TIMED_FLOWS:
                f.times.append(p.ts)
        else:
            f.pkts_s2c += 1
            f.bytes_s2c += p.length
        if p.ts < f.first:
            f.first = p.ts
        if p.ts > f.last:
            f.last = p.ts
        if p.vlan_ids:
            _add_capped(f.vlans, p.vlan_ids[-1])
        if p.transport == "tcp":
            if p.syn:
                f.syn_seen = True
            if p.rst:
                f.resets += 1
        protos = set(p.protocols)
        for proto in protos:
            mapped = K.TSHARK_PROTOCOLS.get(proto)
            if mapped:
                f.detected[mapped[0]] += 1
        self.app_protocols_seen |= protos

        self._names_and_tls(p, sh, dh, layers)
        if protos & (OT_DISSECTORS | CRED_DISSECTORS | APP_DISSECTORS) and self._is_retransmission(p, f, c2s):
            return  # already extracted from the original segment
        if self.env is not None and protos & OT_DISSECTORS:
            self._ot(p, f, c2s, sh, dh)
        if protos & APP_DISSECTORS:
            for k, v in self.notes.extract(p, f.key).items():
                _first(sh.identity, k, p.ts, v)
        if protos & CRED_DISSECTORS:
            for hit in self.creds.extract(p, f.key, c2s):
                self._credential(hit, f, p.ts)

    def _is_retransmission(self, p: Packet, f: FlowAcc, c2s: bool) -> bool:
        """Same flow, direction, raw sequence number and length as an earlier data segment."""
        # Real TCP stacks pick random initial sequence numbers, so seq 0 on a data segment means a
        # hand-built/synthetic capture that never set them; de-duplicating there would drop real data.
        if p.transport != "tcp" or not p.seq_raw or p.payload_len == 0:
            return False
        # Include the decoded application fields: a true retransmission repeats them exactly, while
        # different data that happens to reuse a sequence number (broken or synthetic captures) does not.
        app = hash(
            tuple(sorted((k, tuple(v)) for k, v in p.layers.items() if not k.startswith(_L234_PREFIXES)))
        )
        key = (f.key, c2s, p.seq_raw, p.payload_len, app)
        if key in self._seen_segments:
            self.retransmissions += 1
            return True
        if len(self._seen_segments) < MAX_TRACKED_SEGMENTS:
            self._seen_segments.add(key)
        return False

    def _ot(self, p: Packet, f: FlowAcc, c2s: bool, sh: HostAcc, dh: HostAcc) -> None:
        for ev in ot.extract(p, self.env, c2s):
            label = f"{ev.protocol}: {ev.function}"
            if ev.kind == "error":
                f.ot_errors += 1
                f.fc_counts[label + " (error)"] += 1
            elif ev.is_request:
                f.fc_counts[label] += 1
                if ev.kind == "write":
                    f.ot_writes += 1
                elif ev.kind == "read":
                    f.ot_reads += 1
                # The side sending requests is the master/client of the OT conversation.
                if ev.protocol != "DNP3":
                    sh.ot_master = True
                    dh.ot_outstation = True
                if ev.protocol == "Modbus" and ev.unit is not None:
                    _add_capped(dh.modbus_units, ev.unit)
            if ev.protocol == "DNP3":
                from_master = p.layers.get("dnp3_ctl_dir", ["False"])[0] == "True"
                _add_capped(sh.dnp3_addrs, ev.master_addr if from_master else ev.outstation_addr)
                if from_master:
                    sh.ot_master = True
                    dh.ot_outstation = True
                else:
                    sh.ot_outstation = True
                    dh.ot_master = True
            if ev.s7_download:
                hint = (
                    "Engineering Workstation",
                    Evidence(
                        kind="s7_download",
                        detail=f"Downloads PLC program blocks to {p.dst} over S7comm",
                        weight=10,
                    ),
                )
                cur = sh.extra_hints.get("s7_download")
                if cur is None or p.ts < cur[0]:
                    sh.extra_hints["s7_download"] = (p.ts, hint)
            if ev.identity:
                for k, v in ev.identity.items():
                    _first(sh.identity, k, p.ts, v)
            if ev.is_request or ev.kind == "error" or ev.identity:
                if len(self._ot_raw) < MAX_OT_COMMANDS:
                    cmd = OtCommand(
                        time=p.ts,
                        flow_id=0,  # assigned in finish()
                        src=p.src,
                        dst=p.dst,
                        protocol=ev.protocol,
                        function_code=ev.function_code,
                        function=ev.function,
                        kind=ev.kind,
                        is_request=ev.is_request,
                        unit=ev.unit,
                        address=ev.address,
                        quantity=ev.quantity,
                        detail=ev.detail,
                    )
                    self._ot_raw.append((cmd, f.key, f.cmd_seq))
                    f.cmd_seq += 1
                else:
                    self.ot_truncated = True

    def _credential(self, hit, f: FlowAcc, ts: float) -> None:
        key = (hit.protocol, f.client, f.server, hit.username, hit.secret)
        cur = self._creds_raw.get(key)
        if cur is not None:
            cur[0].count += 1
            if ts < cur[0].first_seen:
                cur[0].first_seen = ts
                self._creds_raw[key] = (cur[0], f.key)
        elif len(self._creds_raw) < MAX_CREDENTIALS:
            c = Credential(
                protocol=hit.protocol,
                kind=hit.kind,
                client=f.client,
                server=f.server,
                server_port=f.server_port,
                username=hit.username,
                secret=hit.secret,
                flow_id=0,  # assigned in finish()
                first_seen=ts,
            )
            self._creds_raw[key] = (c, f.key)

    def _discovery(self, p: Packet, layers: dict) -> None:
        """ARP, LLDP, CDP, DHCP: tie MACs to IPs and names."""
        if "arp_src_proto_ipv4" in layers:
            mac = (layers.get("arp_src_hw_mac") or [None])[0]
            ip = layers["arp_src_proto_ipv4"][0]
            if mac and ip and ip != "0.0.0.0":  # noqa: S104 - ARP probe source, not a bind address
                self.arp_ip_for_mac[mac].add(ip)
                if len(self.arp_claims) < 100_000:
                    self.arp_claims[(p.vlan_ids[-1] if p.vlan_ids else None, ip)].add(mac)
                h = self.host(ip)
                h.seen(p.ts)
                h.macs[mac] += 1
                if p.vlan_ids:
                    _add_capped(h.vlans, p.vlan_ids[-1])
                else:
                    h.untagged = True
        if p.src_mac:
            for key, source, ident in (
                ("lldp_tlv_system_name", "lldp", None),
                ("cdp_deviceid", "cdp", None),
                ("lldp_tlv_system_desc", None, "lldp_system_description"),
                ("cdp_platform", None, "cdp_platform"),
                ("cdp_software_version", None, "cdp_software"),
                ("dhcp_option_vendor_class_id", None, "dhcp_vendor_class"),
            ):
                vals = layers.get(key)
                if not vals:
                    continue
                if source:
                    _first(self.mac_names[p.src_mac], vals[0], p.ts, source)
                else:
                    _first(self.mac_identity[p.src_mac], ident, p.ts, vals[0][:300])
            if "cdp_native_vlan" in layers:
                _first(self.mac_identity[p.src_mac], "cdp_native_vlan", p.ts, layers["cdp_native_vlan"][0])
            if "dhcp_option_hostname" in layers:
                mac = (layers.get("dhcp_hw_mac_addr") or [p.src_mac])[0]
                _first(self.mac_names[mac], layers["dhcp_option_hostname"][0], p.ts, "dhcp")

    def _names_and_tls(self, p: Packet, sh: HostAcc, dh: HostAcc, layers: dict) -> None:
        if "dns_qry_name" in layers:
            is_response = (layers.get("dns_flags_response") or ["False"])[0] in ("True", "1")
            qname = layers["dns_qry_name"][0].rstrip(".")
            if not is_response:
                if len(sh.dns_queries) < MAX_DNS_QUERIES_PER_HOST:
                    sh.dns_queries.add(qname)
            else:
                for ip in layers.get("dns_a", []) + layers.get("dns_aaaa", []):
                    self.host(ip).add_name(qname, "dns", p.ts)
        if "tls_handshake_extensions_server_name" in layers:
            _add_capped(sh.tls_sni, layers["tls_handshake_extensions_server_name"][0])
            # The server's name is what the client asked for.
            if p.dst:
                _add_capped(dh.tls_sni, layers["tls_handshake_extensions_server_name"][0])
        if "tls_handshake_ja3" in layers:
            _add_capped(sh.tls_ja3, layers["tls_handshake_ja3"][0])
        if "tls_handshake_ja4" in layers:
            _add_capped(sh.tls_ja4, layers["tls_handshake_ja4"][0])

    # ── merge (parallel partitions) ────────────────────────────────────────
    def merge(self, o: "Aggregator") -> None:
        """Fold another partition's aggregator into this one. Partitions never share a flow."""
        self.packets += o.packets
        self.bytes += o.bytes
        for ts in (o.first_ts, o.last_ts):
            if ts is not None:
                self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
                self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        self.malformed += o.malformed
        self.retransmissions += o.retransmissions
        self.link_types.update(o.link_types)
        self.vlan_packets.update(o.vlan_packets)
        self.vlan_broadcast.update(o.vlan_broadcast)
        self.app_protocols_seen |= o.app_protocols_seen
        for mac, vendor in o.mac_vendor.items():
            self.mac_vendor.setdefault(mac, vendor)
        for src, dst in (
            (o.mac_src_ips, self.mac_src_ips),
            (o.mac_dst_ips, self.mac_dst_ips),
            (o.arp_ip_for_mac, self.arp_ip_for_mac),
        ):
            for mac, ips in src.items():
                dst[mac] |= ips
        for key, macs in o.arp_claims.items():
            self.arp_claims[key] |= macs
        for src, dst in ((o.mac_names, self.mac_names), (o.mac_identity, self.mac_identity)):
            for mac, entries in src.items():
                _merge_first(dst[mac], entries)
        for ip, h in o.hosts.items():
            if ip in self.hosts:
                self.hosts[ip].merge(h)
            else:
                self.hosts[ip] = h
        for key, f in o.flows.items():
            if key in self.flows:  # cannot happen with host-pair partitioning
                raise ValueError(f"flow {key} appears in two partitions")
            self.flows[key] = f
        self.notes.merge(o.notes)
        self._ot_raw.extend(o._ot_raw)
        self.ot_truncated |= o.ot_truncated
        if len(self._ot_raw) > MAX_OT_COMMANDS:
            self._ot_raw.sort(key=lambda t: (t[0].time, t[1], t[2]))
            del self._ot_raw[MAX_OT_COMMANDS:]
            self.ot_truncated = True
        for key, (c, fkey) in o._creds_raw.items():
            cur = self._creds_raw.get(key)
            if cur is None:
                self._creds_raw[key] = (c, fkey)
            else:
                cur[0].count += c.count
                if c.first_seen < cur[0].first_seen:
                    cur[0].first_seen = c.first_seen
                    self._creds_raw[key] = (cur[0], fkey)

    # ── finish ─────────────────────────────────────────────────────────────
    def finish(self) -> tuple[list[Host], list[Flow]]:
        gateway_macs = {
            mac
            for table in (self.mac_src_ips, self.mac_dst_ips)
            for mac, ips in table.items()
            if len(ips) >= GATEWAY_MAC_MIN_IPS or any(not K.ip_info(ip)[1] for ip in ips)
        }
        ordered = sorted(self.flows.values(), key=FlowAcc.sort_key)
        flow_ids = {f.key: i for i, f in enumerate(ordered, start=1)}
        flows = [self._flow_out(f, flow_ids[f.key]) for f in ordered]

        commands = sorted(self._ot_raw, key=lambda t: (t[0].time, flow_ids[t[1]], t[2]))
        self.ot_commands = []
        for cmd, fkey, _seq in commands:
            cmd.flow_id = flow_ids[fkey]
            self.ot_commands.append(cmd)
        self.credentials = []
        for c, fkey in self._creds_raw.values():
            c.flow_id = flow_ids[fkey]
            self.credentials.append(c)
        self.credentials.sort(
            key=lambda c: (c.first_seen, c.flow_id, c.protocol, c.username or "", c.secret or "")
        )

        served: dict[str, dict[tuple[str, int], dict]] = defaultdict(dict)
        for f in flows:
            for ip in (f.client, f.server):
                self.hosts[ip].protocols.add(f.protocol)
            if f.transport in ("tcp", "udp"):
                # UDP protocols where both peers use the well-known port (CoAP, BACnet, NTP…): both speak it.
                speakers = [(f.server, f.client)]
                if (
                    f.transport == "udp"
                    and f.client_port == f.server_port
                    and f.protocol in K.SYMMETRIC_PEER_PROTOCOLS
                    and not (f.ot_reads or f.ot_writes)  # a side issuing commands is the master, not a device
                ):
                    speakers.append((f.client, f.server))
                for ip, peer in speakers:
                    svc = served[ip].setdefault(
                        (f.transport, f.server_port),
                        {"protocol": f.protocol, "packets": 0, "clients": set(), "detected": set()},
                    )
                    svc["packets"] += f.packets
                    svc["clients"].add(peer)
                    svc["detected"].update(f.detected_protocols)

        hosts = [self._host_out(h, served.get(h.ip, {}), gateway_macs) for h in self.hosts.values()]
        hosts.sort(key=lambda h: (h.ip_version, _ip_sort_key(h.ip)))
        return hosts, flows

    def _flow_out(self, f: FlowAcc, fid: int) -> Flow:
        return Flow(
            id=fid,
            transport=f.transport,
            client=f.client,
            client_port=f.client_port,
            server=f.server,
            server_port=f.server_port,
            protocol=f.protocol_label(),
            detected_protocols=sorted(f.detected),
            direction_basis=f.basis,
            packets_c2s=f.pkts_c2s,
            packets_s2c=f.pkts_s2c,
            bytes_c2s=f.bytes_c2s,
            bytes_s2c=f.bytes_s2c,
            first_seen=f.first,
            last_seen=f.last,
            vlans=sorted(f.vlans),
            syn_seen=f.syn_seen,
            resets=f.resets,
            ot_reads=f.ot_reads,
            ot_writes=f.ot_writes,
            ot_errors=f.ot_errors,
            function_counts=dict(sorted(f.fc_counts.items())),
            notes=self.notes.notes.get(f.key, {}),
            c2s_times=f.times,
        )

    def _host_out(self, h: HostAcc, served: dict, gateway_macs: set[str]) -> Host:
        version, is_private, is_multicast = K.ip_info(h.ip)
        is_broadcast = h.ip == "255.255.255.255" or (h.broadcast_dst and h.pkts_sent == 0)

        # MAC: ARP-claimed MACs are authoritative; a gateway MAC is not this host's NIC
        # unless the host itself claimed it in ARP (i.e. it *is* the gateway).
        by_count = lambda m: (-h.macs[m], m)  # noqa: E731
        arp_macs = sorted((m for m, ips in self.arp_ip_for_mac.items() if h.ip in ips), key=by_count)
        candidates = sorted(h.macs, key=by_count)
        own = [m for m in candidates if m not in gateway_macs or m in arp_macs]
        # A host that never sends (e.g. a scan target) is still reachable at the MAC frames were sent to.
        own_dst = [m for m in sorted(h.dst_macs, key=lambda m: (-h.dst_macs[m], m)) if m not in gateway_macs]
        mac = arp_macs[0] if arp_macs else (own[0] if own else (own_dst[0] if own_dst else None))
        mac_is_gateway = mac is None and bool(candidates or h.dst_macs)

        name_entries = dict(h.hostnames)
        if mac:
            for n, (ts, src) in self.mac_names.get(mac, {}).items():
                _first(name_entries, n, ts, src)
        ordered_names = sorted(name_entries.items(), key=lambda kv: (kv[1][0], kv[0]))[:MAX_NAMES]
        names = [HostName(name=n, source=src) for n, (_ts, src) in ordered_names]

        ident_entries = dict(self.mac_identity.get(mac, {})) if mac else {}
        _merge_first(ident_entries, h.identity)
        identity = {k: v for k, (_ts, v) in sorted(ident_entries.items())}

        services = sorted(
            (
                Service(
                    transport=t,
                    port=port,
                    protocol=v["protocol"],
                    packets=v["packets"],
                    clients=len(v["clients"]),
                )
                for (t, port), v in served.items()
            ),
            key=lambda s: (-s.packets, s.port, s.transport),
        )
        ttl = min(h.ttls, key=lambda t: (-h.ttls[t], t)) if h.ttls else None
        os_hint = K.os_from_ttl(ttl) if ttl is not None else None

        host = Host(
            ip=h.ip,
            ip_version=version,
            is_private=is_private,
            is_multicast=is_multicast,
            is_broadcast=is_broadcast,
            mac=mac,
            macs=candidates[:10],
            mac_vendor=self.mac_vendor.get(mac) if mac else None,
            mac_is_gateway=mac_is_gateway,
            hostname=names[0].name if names else None,
            hostnames=names,
            dns_queries=sorted(h.dns_queries),
            protocols=sorted(h.protocols),
            services=services,
            os_hint=os_hint,
            ttl=ttl,
            vlans=sorted(h.vlans),
            vlan_outer=sorted(h.vlan_outer),
            vlan_pcps=sorted(h.pcps),
            vlan_untagged=h.untagged,
            vlan_qinq=h.qinq,
            packets_sent=h.pkts_sent,
            packets_recv=h.pkts_recv,
            bytes_sent=h.bytes_sent,
            bytes_recv=h.bytes_recv,
            first_seen=h.first,
            last_seen=h.last,
            tls_sni=sorted(h.tls_sni),
            tls_ja3=sorted(h.tls_ja3),
            tls_ja4=sorted(h.tls_ja4),
            ot_role=(
                "both"
                if h.ot_master and h.ot_outstation
                else "master"
                if h.ot_master
                else "outstation"
                if h.ot_outstation
                else "unknown"
            ),
            modbus_unit_ids=sorted(h.modbus_units),
            dnp3_addresses=sorted(h.dnp3_addrs),
            identity=identity,
        )
        self._classify(host, h, served, mac, gateway_macs)
        return host

    def _classify(
        self, host: Host, h: HostAcc, served: dict, mac: str | None, gateway_macs: set[str]
    ) -> None:
        if host.is_broadcast:
            host.host_type, host.host_type_confidence = "Broadcast", "high"
            host.host_type_evidence = [Evidence(kind="address", detail="Broadcast destination")]
            host.purdue_level = -1
            return
        if host.is_multicast:
            host.host_type, host.host_type_confidence = "Multicast", "high"
            host.host_type_evidence = [Evidence(kind="address", detail="Multicast group address")]
            host.purdue_level = -1
            return

        hints: dict[str, list[Evidence]] = defaultdict(list)
        strong: set[str] = set()  # types backed by tshark-identified protocols
        for (transport, port), v in sorted(served.items()):
            hint = None
            detected = v["detected"]
            for proto in sorted(
                detected, key=lambda x: (K.priority_rank(K.SERVER_TYPE_BY_LABEL.get(x) or ""), x)
            ):
                if K.SERVER_TYPE_BY_LABEL.get(proto):
                    hint = K.SERVER_TYPE_BY_LABEL[proto]
                    strong.add(hint)
                    break
            if hint is None and port in K.PORT_MAP:
                hint = K.PORT_MAP[port][1]
            if hint:
                how = "identified by tshark" if detected and hint in strong else "by port number"
                hints[hint].append(
                    Evidence(
                        kind="serves",
                        detail=f"Serves {v['protocol']} on {transport}/{port} to {len(v['clients'])} "
                        f"host(s), {v['packets']} packets ({how})",
                        weight=v["packets"],
                    )
                )
        lldp_cdp = (
            sorted((ts, n, s) for n, (ts, s) in self.mac_names.get(mac, {}).items() if s in ("lldp", "cdp"))
            if mac
            else []
        )
        if lldp_cdp:
            _ts, name, src = lldp_cdp[0]
            hints["Network Device"].append(
                Evidence(kind=src, detail=f"Announces itself via {src.upper()} as '{name}'", weight=5)
            )
            strong.add("Network Device")
        if mac and mac in gateway_macs and h.ip in self.arp_ip_for_mac.get(mac, set()):
            n = len(self.mac_src_ips[mac])
            hints["Router"].append(
                Evidence(
                    kind="gateway_mac",
                    detail=f"Its MAC forwards traffic for {n} other IP addresses",
                    weight=n,
                )
            )
            strong.add("Router")
        for _kind, (_ts, (t, ev)) in sorted(h.extra_hints.items()):
            hints[t].append(ev)
            strong.add(t)

        if hints:
            best = min(hints, key=lambda t: (K.priority_rank(t), t))
            host.host_type = best
            host.host_type_evidence = sorted(hints[best], key=lambda e: (-e.weight, e.detail))
            others = [t for t in hints if t != best]
            if others:
                host.host_type_evidence.append(
                    Evidence(
                        kind="also_suggested",
                        detail="Also looks like: "
                        + ", ".join(sorted(others, key=lambda t: (K.priority_rank(t), t))),
                        weight=0,
                    )
                )
            host.host_type_confidence = "high" if best in strong else "medium"
        elif host.os_hint:
            host.host_type = {"Windows": "Windows Host", "Linux/Unix/macOS": "Linux Host"}.get(
                host.os_hint, "Network Device"
            )
            host.host_type_evidence = [
                Evidence(kind="os_ttl", detail=f"TTL {host.ttl} suggests {host.os_hint}")
            ]
            host.host_type_confidence = "low"
        elif not host.is_private:
            host.host_type = "Internet Host"
            host.host_type_evidence = [Evidence(kind="address", detail="Publicly routable address")]
            host.host_type_confidence = "medium"
        else:
            host.host_type = "Unknown Host"
            host.host_type_evidence = [Evidence(kind="none", detail="No services or OS hints observed")]

        self._purdue(host)

    @staticmethod
    def _purdue(host: Host) -> None:
        if not host.is_private:
            host.purdue_level = 6
            host.purdue_evidence = [Evidence(kind="address", detail="Publicly routable address (internet)")]
            return
        level = K.PURDUE_LEVELS.get(host.host_type)
        if level is None and host.ot_role in ("master", "both"):
            host.purdue_level = 3
            host.purdue_evidence = [
                Evidence(
                    kind="ot_master",
                    detail="Sends commands to OT devices, so placed at Level 3 (supervisory)",
                )
            ]
            return
        if level is None:
            host.purdue_level = -1
            host.purdue_evidence = [
                Evidence(kind="host_type", detail=f"No Purdue level defined for '{host.host_type}'")
            ]
            return
        ev = [Evidence(kind="host_type", detail=f"{host.host_type} → Level {level:g}")]
        ot_seen = sorted(set(host.protocols) & K.OT_PROTOCOLS)
        if level == 4 and (ot_seen or host.ot_role != "unknown"):
            level = 3
            ev.append(
                Evidence(
                    kind="ot_protocols",
                    detail="Talks OT protocols ("
                    + ", ".join(ot_seen or [host.ot_role])
                    + "), so placed at Level 3 (supervisory)",
                )
            )
        host.purdue_level = level
        host.purdue_evidence = ev


def _ip_sort_key(ip: str):
    try:
        import ipaddress

        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0
