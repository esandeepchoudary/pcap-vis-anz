"""Anomaly rules. Each rule is a function over the analysis result, registered with its metadata.

Rules group their hits per (rule, source, destination) so a PLC write storm is one finding with a count,
not thousands of rows. Thresholds are ported from the legacy app unless noted.
"""

import hashlib
import math
import statistics
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from pcapvis.engine import knowledge as K
from pcapvis.engine.model import AnalysisResult, Anomaly, Flow, Host

# ── thresholds ────────────────────────────────────────────────────────────────
PORT_SCAN_MIN_HOSTS = 6  # legacy: >5 hosts …
PORT_SCAN_MIN_PORTS = 16  # … and >15 ports
EXFIL_BYTES = 10 * 1024 * 1024
BEACON_MIN_INTERVALS = 19  # ≥20 events
BEACON_MIN_MEAN_S = 1.0
BEACON_MAX_CV = 0.2
MODBUS_BULK_READ = 100
MULTIUNIT_POLL_MIN = 5
BCAST_THRESHOLD = 0.10
BCAST_MIN_PKTS = 50
HIGH_PCP = 6  # PCP 6 (internetwork control) and 7 (network control) are for network gear
PASSWORD_MIN_LEN = 4
MAX_EVIDENCE = 5
CAMERA_EXFIL_BYTES = 1024 * 1024

KNOWN_BAD_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit Meterpreter",
    "6734f37431670b3ab4292b8f60f29984": "Cobalt Strike",
    "b386946a5a44d1ddcc843bc75336dfce": "Dridex",
    "a0e9f5d64349fb13191bc781f81f42e1": "AgentTesla",
    "c12f54a3f91dc7bafd92cb59fe009a35": "Cobalt Strike Beacon",
    "ada79f3a9e63d0f1f4c6cb3ba9e99fa0": "Emotet",
    "72a589da586844d7f0818ce684948eea": "TLS Anomaly (ABUSE.CH)",
    "de350869b8c85de67a350c8d186f11e6": "Trickbot",
    "51c64c77e60f3980eea90869b68c58a8": "AsyncRAT",
    "fd4bc6cea4bef9aea6295ac5b3fd65a9": "Cobalt Strike (alt)",
    "6bca5a6d9bf5b08f9cd95feefc1c2c7e": "QakBot",
    "a106ce68aee22e2f5d82ee41fb5fb22a": "IcedID",
}
DEFAULT_PASSWORDS = {
    "admin",
    "password",
    "1234",
    "12345",
    "123456",
    "root",
    "toor",
    "default",
    "guest",
    "public",
    "private",
    "manager",
    "operator",
    "supervisor",
    "changeme",
    "pass",
    "test",
    "plc",
    "siemens",
    "rockwell",
    "schneider",
    "abb",
    "honeywell",
    "wago",
    "user",
    "service",
    "maintenance",
    "engineer",
    "1111",
    "0000",
}

OT_TYPES = {
    "PLC",
    "RTU",
    "IED",
    "DCS",
    "SCADA Server",
    "Building Controller",
    "Field Device",
    "HMI",
    "Engineering Workstation",
    "Historian",
}
IOT_TYPES = {
    "IP Camera",
    "Smart Home Hub",
    "Smart Meter",
    "IoT Sensor",
    "Smart Speaker",
    "IoT Gateway",
    "CPE Device",
}
ROUTING_TYPES = {"Router", "Network Device", "VPN Gateway"}
END_HOST_TYPES = {
    "Windows Host",
    "Linux Host",
    "Unknown Host",
    "IP Camera",
    "IoT Sensor",
    "Smart Meter",
    "Smart Home Hub",
    "Smart Speaker",
    "CPE Device",
    "Field Device",
}
CLEARTEXT_OT = {
    "Modbus",
    "DNP3",
    "S7comm",
    "BACnet",
    "EtherNet/IP",
    "IEC-104",
    "OMRON-FINS",
    "GE-SRTP",
    "HART-IP",
}

# Per-protocol OT write rules: protocol → (rule id, title, ATT&CK for ICS)
OT_WRITE_RULES = {
    "Modbus": ("ot_modbus_write", "Modbus write to PLC", ["T0855", "T0836"]),
    "DNP3": ("ot_dnp3_control", "DNP3 control command", ["T0855", "T0831"]),
    "S7comm": ("ot_s7_write", "S7comm write to PLC", ["T0855", "T0836"]),
    "EtherNet/IP": ("ot_enip_write", "EtherNet/IP tag or attribute write", ["T0855", "T0836"]),
    "IEC-104": ("ot_iec104_command", "IEC-104 control command", ["T0855", "T0831"]),
    "BACnet": ("ot_bacnet_write", "BACnet write to building controller", ["T0855", "T0836"]),
}
S7_CRITICAL = {0x28, 0x29}  # PI service (start/stop program), PLC stop
S7_DOWNLOAD = {0x1A}
DNP3_DISRUPTIVE = {
    13,
    14,
    15,
    18,
    21,
}  # cold/warm restart, initialize data, stop application, disable unsolicited


# ── registry ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RuleInfo:
    id: str
    category: str
    severity: str
    title: str
    attack: tuple[str, ...] = ()


RULES: dict[str, RuleInfo] = {}
_FUNCS: list[Callable[["Ctx"], Iterable[Anomaly]]] = []


def rule(id: str, category: str, severity: str, title: str, attack: Iterable[str] = ()):  # noqa: A002
    RULES[id] = RuleInfo(id, category, severity, title, tuple(attack))

    def deco(fn):
        _FUNCS.append(fn)
        return fn

    return deco


def _register_meta(id: str, category: str, severity: str, title: str, attack: Iterable[str] = ()) -> None:  # noqa: A002
    RULES[id] = RuleInfo(id, category, severity, title, tuple(attack))


for _proto, (_rid, _title, _att) in OT_WRITE_RULES.items():
    _register_meta(_rid, "ot", "high", _title, _att)
_register_meta("ot_s7_critical", "ot", "critical", "S7comm PLC stop / program control", ["T0881", "T0858"])
_register_meta("ot_s7_code_download", "ot", "critical", "PLC program download (S7comm)", ["T0843"])


# ── context & helpers ─────────────────────────────────────────────────────────


@dataclass
class Ctx:
    r: AnalysisResult
    hosts: dict[str, Host] = field(init=False)
    flows_by_host: dict[str, list[Flow]] = field(init=False)
    flows: dict[int, Flow] = field(init=False)

    def __post_init__(self):
        self.hosts = {h.ip: h for h in self.r.hosts}
        self.flows = {f.id: f for f in self.r.flows}
        self.flows_by_host = defaultdict(list)
        for f in self.r.flows:
            self.flows_by_host[f.client].append(f)
            self.flows_by_host[f.server].append(f)

    def private(self, ip: str) -> bool:
        h = self.hosts.get(ip)
        return h.is_private if h else K.ip_info(ip)[1]


class Group:
    """Accumulates hits for one (rule, src, dst, key) into a single Anomaly."""

    def __init__(
        self,
        rule_id: str,
        src: str | None,
        dst: str | None,
        description: str,
        key: str = "",
        severity: str | None = None,
        title: str | None = None,
    ):
        info = RULES[rule_id]
        self.rule, self.info = rule_id, info
        self.src, self.dst, self.key = src, dst, key
        self.description = description
        self.severity = severity or info.severity
        self.title = title or info.title
        self.flow_ids: set[int] = set()
        self.first: float | None = None
        self.last: float | None = None
        self.count = 0
        self.evidence: list[str] = []

    def hit(
        self, t: float | None = None, flow_id: int | None = None, evidence: str | None = None, n: int = 1
    ):
        self.count += n
        if flow_id is not None:
            self.flow_ids.add(flow_id)
        if t is not None:
            self.first = t if self.first is None else min(self.first, t)
            self.last = t if self.last is None else max(self.last, t)
        if evidence and evidence not in self.evidence and len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(evidence)
        return self

    def build(self) -> Anomaly:
        ident = hashlib.sha1(f"{self.rule}|{self.src}|{self.dst}|{self.key}".encode(), usedforsecurity=False)
        return Anomaly(
            id=ident.hexdigest()[:16],
            rule=self.rule,
            category=self.info.category,
            severity=self.severity,
            title=self.title,
            description=self.description,
            src=self.src,
            dst=self.dst,
            flow_ids=sorted(self.flow_ids)[:200],
            first_seen=self.first,
            last_seen=self.last,
            count=max(self.count, 1),
            evidence=self.evidence,
            attack=list(self.info.attack),
        )


class Groups(dict):
    def get_or_add(self, key, factory: Callable[[], Group]) -> Group:
        g = self.get(key)
        if g is None:
            g = self[key] = factory()
        return g

    def anomalies(self) -> list[Anomaly]:
        return [g.build() for g in self.values()]


def _fmt_bytes(n: int) -> str:
    return f"{n / 1048576:.1f} MB"


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


# ── network rules ─────────────────────────────────────────────────────────────


@rule("port_scan", "network", "high", "Port scan", ["T0846", "T1046"])
def port_scan(ctx: Ctx):
    """Direction-aware: the scanner is the host *initiating* connections to many hosts and ports."""
    targets, ports, first = defaultdict(set), defaultdict(set), {}
    for f in ctx.r.flows:
        if f.transport not in ("tcp", "udp") or f.direction_basis == "first_packet":
            continue
        targets[f.client].add(f.server)
        ports[f.client].add(f.server_port)
        first[f.client] = min(first.get(f.client, f.first_seen), f.first_seen)
    for ip, hosts in targets.items():
        if len(hosts) >= PORT_SCAN_MIN_HOSTS and len(ports[ip]) >= PORT_SCAN_MIN_PORTS:
            g = Group(
                "port_scan",
                ip,
                None,
                f"{ip} opened connections to {len(hosts)} hosts on {len(ports[ip])} different ports",
            )
            g.hit(
                first[ip], evidence="Ports: " + ", ".join(map(str, sorted(ports[ip])[:20])), n=len(ports[ip])
            )
            yield g.build()


@rule("exfiltration", "network", "high", "Large upload to the internet", ["T1041", "T0882"])
def exfiltration(ctx: Ctx):
    """Bytes *sent by* an internal host to one external host (legacy summed both directions)."""
    sent = defaultdict(lambda: [0, set(), None])
    for f in ctx.r.flows:
        cp, sp = ctx.private(f.client), ctx.private(f.server)
        if cp == sp:
            continue
        internal, external, out_bytes = (
            (f.client, f.server, f.bytes_c2s) if cp else (f.server, f.client, f.bytes_s2c)
        )
        s = sent[(internal, external)]
        s[0] += out_bytes
        s[1].add(f.id)
        s[2] = f.first_seen if s[2] is None else min(s[2], f.first_seen)
    for (internal, external), (n, flow_ids, t) in sent.items():
        if n > EXFIL_BYTES:
            g = Group(
                "exfiltration",
                internal,
                external,
                f"{internal} sent {_fmt_bytes(n)} to internet host {external}",
            )
            for fid in flow_ids:
                g.hit(t, fid)
            g.count = 1
            yield g.build()


@rule("beaconing", "network", "medium", "Regular beaconing", ["T1071", "T0869"])
def beaconing(ctx: Ctx):
    """Very regular timing, either of packets within a flow or of repeated connections."""
    series: dict[tuple, tuple[list[float], set[int]]] = {}
    for f in ctx.r.flows:
        if len(f.c2s_times) > BEACON_MIN_INTERVALS:
            series[(f.client, f.server, f.server_port, f.id)] = (f.c2s_times, {f.id})
    conn_starts = defaultdict(lambda: ([], set()))
    for f in ctx.r.flows:
        if f.transport == "tcp":
            entry = conn_starts[(f.client, f.server, f.server_port, None)]
            entry[0].append(f.first_seen)
            entry[1].add(f.id)
    series.update({k: v for k, v in conn_starts.items() if len(v[0]) > BEACON_MIN_INTERVALS})
    seen = set()
    for (client, server, port, _), (times, fids) in series.items():
        ts = sorted(times)
        gaps = [b - a for a, b in zip(ts, ts[1:], strict=False)]
        if len(gaps) < BEACON_MIN_INTERVALS:
            continue
        mean = statistics.fmean(gaps)
        if mean < BEACON_MIN_MEAN_S:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv < BEACON_MAX_CV and (client, server, port) not in seen:
            seen.add((client, server, port))
            g = Group(
                "beaconing",
                client,
                server,
                f"{client} contacts {server}:{port} every {mean:.1f}s with very regular timing (CV {cv:.0%})",
                key=str(port),
            )
            for fid in fids:
                g.flow_ids.add(fid)
            g.hit(ts[0], n=len(ts))
            g.hit(ts[-1], n=0)
            yield g.build()


@rule("suspicious_port", "network", "high", "Known attack-tool port", ["T1571"])
def suspicious_port(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        if f.transport in ("tcp", "udp") and f.server_port in K.SUSPICIOUS_PORTS:
            groups.get_or_add(
                (f.client, f.server, f.server_port),
                lambda f=f: Group(
                    "suspicious_port",
                    f.client,
                    f.server,
                    f"{f.client} connected to {f.server} on port {f.server_port}, used by attack tools and C2",
                    key=str(f.server_port),
                ),
            ).hit(f.first_seen, f.id)
    return groups.anomalies()


@rule("unusual_ja3", "credentials", "high", "Known-malicious TLS fingerprint", ["T1071.001"])
def unusual_ja3(ctx: Ctx):
    for h in ctx.r.hosts:
        for ja3 in h.tls_ja3:
            if ja3 in KNOWN_BAD_JA3:
                yield (
                    Group(
                        "unusual_ja3",
                        h.ip,
                        None,
                        f"{h.ip} used a TLS fingerprint matching {KNOWN_BAD_JA3[ja3]}",
                        key=ja3,
                    )
                    .hit(h.first_seen, evidence=f"JA3 {ja3}")
                    .build()
                )


@rule("dns_tunneling", "network", "high", "DNS tunneling indicators", ["T1071.004"])
def dns_tunneling(ctx: Ctx):
    for h in ctx.r.hosts:
        q = h.dns_queries
        if len(q) < 3:
            continue
        reason = None
        for name in q:
            for label in name.split(".")[:-2]:
                if len(label) > 24 and _entropy(label) > 4.5:
                    reason = f"high-entropy subdomain '{label[:24]}…'"
                    break
            if reason:
                break
        if not reason:
            avg = sum(map(len, q)) / len(q)
            if avg > 60 and len(q) >= 5:
                reason = f"very long query names (average {avg:.0f} characters)"
        if not reason:
            subs = defaultdict(set)
            for name in q:
                parts = name.split(".")
                if len(parts) >= 3:
                    # Whole prefix, so data encoded deeper (x1.tunnel.example.org) still counts as unique.
                    subs[".".join(parts[-2:])].add(".".join(parts[:-2]))
            for parent, labels in subs.items():
                if len(labels) > 20:
                    reason = f"{len(labels)} different subdomains under {parent}"
                    break
        if reason:
            yield (
                Group("dns_tunneling", h.ip, None, f"{h.ip} shows DNS tunneling indicators: {reason}")
                .hit(h.first_seen, n=len(q), evidence=reason)
                .build()
            )


# ── credentials ───────────────────────────────────────────────────────────────


@rule("cleartext_credentials", "credentials", "high", "Credentials sent in cleartext", ["T0859", "T1552"])
def cleartext_credentials(ctx: Ctx):
    groups = Groups()
    for c in ctx.r.credentials:
        sev = "medium" if c.kind == "community" else "high"
        what = "SNMP community string" if c.kind == "community" else f"{c.protocol} credentials"
        user = f" for user '{c.username}'" if c.username else ""
        groups.get_or_add(
            (c.protocol, c.client, c.server),
            lambda c=c, sev=sev, what=what, user=user: Group(
                "cleartext_credentials",
                c.client,
                c.server,
                f"{what}{user} sent in cleartext from {c.client} to {c.server}:{c.server_port}",
                key=c.protocol,
                severity=sev,
            ),
        ).hit(c.first_seen, c.flow_id, n=c.count)
    return groups.anomalies()


@rule("default_credentials", "credentials", "critical", "Default or trivial password in use", ["T0812"])
def default_credentials(ctx: Ctx):
    """New in v2: vendor defaults and trivial passwords (also 'public'/'private' SNMP communities)."""
    for c in ctx.r.credentials:
        secret = (c.secret or "").strip().lower()
        if secret and (secret in DEFAULT_PASSWORDS or (c.username and secret == c.username.lower())):
            why = (
                "same as the username"
                if c.username and secret == c.username.lower()
                else "a well-known default"
            )
            yield (
                Group(
                    "default_credentials",
                    c.client,
                    c.server,
                    f"{c.protocol} login to {c.server} uses a password that is {why}",
                    key=f"{c.protocol}|{c.username}",
                )
                .hit(c.first_seen, c.flow_id, n=c.count)
                .build()
            )


@rule("password_reuse", "credentials", "high", "Password reused across services", ["T1078"])
def password_reuse(ctx: Ctx):
    by_secret = defaultdict(set)
    first = {}
    for c in ctx.r.credentials:
        if c.kind != "community" and c.secret and len(c.secret) >= PASSWORD_MIN_LEN:
            by_secret[c.secret].add((c.protocol, c.server))
            first[c.secret] = min(first.get(c.secret, c.first_seen), c.first_seen)
    for secret, services in by_secret.items():
        if len(services) >= 2:
            names = sorted(f"{p}@{s}" for p, s in services)
            digest = hashlib.sha256(secret.encode()).hexdigest()[:12]
            yield (
                Group(
                    "password_reuse",
                    None,
                    None,
                    f"The same password is used on {len(services)} services: " + ", ".join(names[:5]),
                    key=digest,
                )
                .hit(first[secret], n=len(services))
                .build()
            )


# ── OT rules ──────────────────────────────────────────────────────────────────


@rule("ot_writes", "ot", "high", "OT write commands")  # umbrella: emits the per-protocol rule ids
def ot_writes(ctx: Ctx):
    groups = Groups()
    for c in ctx.r.ot_commands:
        if not c.is_request:
            continue
        if c.protocol == "S7comm" and c.function_code in S7_DOWNLOAD:
            groups.get_or_add(
                ("dl", c.src, c.dst),
                lambda c=c: Group(
                    "ot_s7_code_download",
                    c.src,
                    c.dst,
                    f"{c.src} downloaded program blocks to PLC {c.dst}: PLC logic is being changed",
                ),
            ).hit(c.time, c.flow_id, evidence=c.detail or c.function)
            continue
        if c.protocol == "S7comm" and c.function_code in S7_CRITICAL:
            groups.get_or_add(
                ("crit", c.src, c.dst, c.function),
                lambda c=c: Group(
                    "ot_s7_critical",
                    c.src,
                    c.dst,
                    f"{c.src} sent '{c.function}' to PLC {c.dst}",
                    key=c.function,
                ),
            ).hit(c.time, c.flow_id, evidence=c.detail or None)
            continue
        if c.kind == "write" and c.protocol in OT_WRITE_RULES:
            rid = OT_WRITE_RULES[c.protocol][0]
            g = groups.get_or_add(
                (rid, c.src, c.dst),
                lambda c=c, rid=rid: Group(
                    rid, c.src, c.dst, f"{c.src} sent {c.protocol} write/control commands to {c.dst}"
                ),
            )
            where = f" at {c.address}" if c.address is not None else ""
            g.hit(c.time, c.flow_id, evidence=f"{c.function}{where}" + (f" ({c.detail})" if c.detail else ""))
    for g in groups.values():
        if g.rule in {r[0] for r in OT_WRITE_RULES.values()}:
            g.description += f" ({g.count} command{'s' if g.count != 1 else ''})"
    return groups.anomalies()


RULES.pop("ot_writes")  # umbrella function; it reports under the per-protocol rule ids registered above


@rule("ot_modbus_bulk_read", "ot", "medium", "Large Modbus register read", ["T0801", "T0802"])
def ot_modbus_bulk_read(ctx: Ctx):
    groups = Groups()
    for c in ctx.r.ot_commands:
        if (
            c.protocol == "Modbus"
            and c.is_request
            and c.function_code in (3, 4)
            and (c.quantity or 0) > MODBUS_BULK_READ
        ):
            groups.get_or_add(
                (c.src, c.dst),
                lambda c=c: Group(
                    "ot_modbus_bulk_read", c.src, c.dst, f"{c.src} read large register blocks from {c.dst}"
                ),
            ).hit(c.time, c.flow_id, evidence=f"{c.quantity} registers from {c.address}")
    return groups.anomalies()


@rule("ot_modbus_broadcast", "ot", "high", "Modbus broadcast (unit 0)", ["T0855"])
def ot_modbus_broadcast(ctx: Ctx):
    groups = Groups()
    for c in ctx.r.ot_commands:
        if c.protocol == "Modbus" and c.is_request and c.unit == 0:
            groups.get_or_add(
                (c.src, c.dst),
                lambda c=c: Group(
                    "ot_modbus_broadcast",
                    c.src,
                    c.dst,
                    f"{c.src} sent Modbus commands to unit 0 via {c.dst}: broadcast reaches every device behind it",
                ),
            ).hit(c.time, c.flow_id, evidence=c.function)
    return groups.anomalies()


@rule("ot_modbus_exception", "ot", "medium", "Modbus exception responses", ["T0888"])
def ot_modbus_exception(ctx: Ctx):
    groups = Groups()
    for c in ctx.r.ot_commands:
        if c.protocol == "Modbus" and c.kind == "error":
            # Error responses travel device → client; report it from the client's point of view.
            groups.get_or_add(
                (c.dst, c.src),
                lambda c=c: Group(
                    "ot_modbus_exception", c.dst, c.src, f"{c.src} rejected Modbus requests from {c.dst}"
                ),
            ).hit(c.time, c.flow_id, evidence=c.detail)
    return groups.anomalies()


@rule("ot_dnp3_unusual_fc", "ot", "medium", "Disruptive DNP3 function", ["T0816", "T0814"])
def ot_dnp3_unusual_fc(ctx: Ctx):
    groups = Groups()
    for c in ctx.r.ot_commands:
        if c.protocol == "DNP3" and c.is_request and c.function_code in DNP3_DISRUPTIVE:
            groups.get_or_add(
                (c.src, c.dst, c.function),
                lambda c=c: Group(
                    "ot_dnp3_unusual_fc",
                    c.src,
                    c.dst,
                    f"{c.src} sent DNP3 '{c.function}' to {c.dst}",
                    key=c.function,
                ),
            ).hit(c.time, c.flow_id)
    return groups.anomalies()


@rule("ot_multiunit_poll", "ot", "medium", "Polling many Modbus unit IDs", ["T0846"])
def ot_multiunit_poll(ctx: Ctx):
    units, first = defaultdict(set), {}
    for c in ctx.r.ot_commands:
        if c.protocol == "Modbus" and c.is_request and c.unit:
            units[c.src].add(c.unit)
            first[c.src] = min(first.get(c.src, c.time), c.time)
    for src, u in units.items():
        if len(u) >= MULTIUNIT_POLL_MIN:
            yield (
                Group(
                    "ot_multiunit_poll",
                    src,
                    None,
                    f"{src} polled {len(u)} different Modbus unit IDs: mapping the devices behind gateways",
                )
                .hit(first[src], n=len(u), evidence="Units: " + ", ".join(map(str, sorted(u)[:20])))
                .build()
            )


def _is_ot(h: Host | None) -> bool:
    return bool(h) and (h.host_type in OT_TYPES or h.ot_role != "unknown")


@rule("ot_internet_exposure", "ot", "critical", "OT device talks to the internet", ["T0883", "T0822"])
def ot_internet_exposure(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        for ot_ip, peer in ((f.client, f.server), (f.server, f.client)):
            h = ctx.hosts.get(ot_ip)
            if _is_ot(h) and h.is_private and not ctx.private(peer):
                groups.get_or_add(
                    (ot_ip, peer),
                    lambda ot_ip=ot_ip, peer=peer, h=h: Group(
                        "ot_internet_exposure",
                        ot_ip,
                        peer,
                        f"OT device {ot_ip} ({h.host_type}) exchanged traffic with internet host {peer}",
                    ),
                ).hit(f.first_seen, f.id, evidence=f"{f.protocol} {f.client}→{f.server}:{f.server_port}")
    return groups.anomalies()


@rule("ot_cleartext", "ot", "medium", "Unencrypted OT protocol")
def ot_cleartext(ctx: Ctx):
    """Grouped per server and protocol (legacy emitted one per host pair)."""
    groups = Groups()
    for f in ctx.r.flows:
        if f.protocol in CLEARTEXT_OT:
            g = groups.get_or_add(
                (f.server, f.protocol),
                lambda f=f: Group(
                    "ot_cleartext",
                    None,
                    f.server,
                    f"{f.protocol} to {f.server} is unencrypted and unauthenticated",
                    key=f.protocol,
                ),
            )
            g.hit(f.first_seen, f.id, evidence=f"client {f.client}")
    return groups.anomalies()


# ── IoT rules ─────────────────────────────────────────────────────────────────


@rule("iot_mqtt_cleartext", "iot", "medium", "Unencrypted MQTT")
def iot_mqtt_cleartext(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        if f.protocol == "MQTT":
            groups.get_or_add(
                (f.client, f.server),
                lambda f=f: Group(
                    "iot_mqtt_cleartext",
                    f.client,
                    f.server,
                    f"MQTT between {f.client} and broker {f.server} is unencrypted (port {f.server_port})",
                ),
            ).hit(f.first_seen, f.id)
    return groups.anomalies()


@rule("iot_telnet", "iot", "high", "Telnet to an IoT device", ["T0886"])
def iot_telnet(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        h = ctx.hosts.get(f.server)
        if f.server_port == 23 and h and h.host_type in IOT_TYPES:
            groups.get_or_add(
                (f.client, f.server),
                lambda f=f, h=h: Group(
                    "iot_telnet",
                    f.client,
                    f.server,
                    f"{f.client} used Telnet on {h.host_type} {f.server}: a common botnet entry point",
                ),
            ).hit(f.first_seen, f.id)
    return groups.anomalies()


@rule("iot_camera_exfil", "iot", "high", "Camera streams to the internet", ["T1041"])
def iot_camera_exfil(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        for cam, peer, sent, initiated in (
            (f.client, f.server, f.bytes_c2s, True),
            (f.server, f.client, f.bytes_s2c, False),
        ):
            h = ctx.hosts.get(cam)
            # Outbound connections, or large volumes; answering an inbound session is exposure, not exfil.
            if (
                h
                and h.host_type == "IP Camera"
                and h.is_private
                and not ctx.private(peer)
                and sent > 0
                and (initiated or sent > CAMERA_EXFIL_BYTES)
            ):
                groups.get_or_add(
                    (cam, peer),
                    lambda cam=cam, peer=peer: Group(
                        "iot_camera_exfil", cam, peer, f"IP camera {cam} sent data to internet host {peer}"
                    ),
                ).hit(f.first_seen, f.id, evidence=_fmt_bytes(sent))
    return groups.anomalies()


@rule("iot_tr069", "iot", "medium", "TR-069 remote management")
def iot_tr069(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        if f.server_port == 7547:
            groups.get_or_add(
                (f.client, f.server),
                lambda f=f: Group(
                    "iot_tr069", f.client, f.server, f"TR-069 (port 7547) between {f.client} and {f.server}"
                ),
            ).hit(f.first_seen, f.id)
    return groups.anomalies()


# ── VLAN rules ────────────────────────────────────────────────────────────────


def _l2_local(h: Host) -> bool:
    """VLAN facts describe this host's own NIC (not a router's interface it was seen through)."""
    return h.is_private and not h.mac_is_gateway and not h.is_broadcast and not h.is_multicast


@rule("vlan_hopping", "vlan", "medium", "Host on several VLANs", ["T0885"])
def vlan_hopping(ctx: Ctx):
    for h in ctx.r.hosts:
        if len(h.vlans) > 1 and h.host_type not in ROUTING_TYPES and not h.vlan_qinq and _l2_local(h):
            yield (
                Group(
                    "vlan_hopping",
                    h.ip,
                    None,
                    f"{h.ip} ({h.host_type}) appears on VLANs {', '.join(map(str, h.vlans))} but is not a router",
                )
                .hit(h.first_seen)
                .build()
            )


@rule("vlan_native_leak", "vlan", "low", "Tagged and untagged frames from one host")
def vlan_native_leak(ctx: Ctx):
    for h in ctx.r.hosts:
        if (
            h.vlan_untagged
            and h.vlans
            and h.packets_sent
            and h.host_type not in ROUTING_TYPES
            and _l2_local(h)
        ):
            yield (
                Group(
                    "vlan_native_leak",
                    h.ip,
                    None,
                    f"{h.ip} sends both untagged frames and frames tagged VLAN {', '.join(map(str, h.vlans))}",
                )
                .hit(h.first_seen)
                .build()
            )


@rule("vlan_qinq", "vlan", "medium", "Double-tagged (QinQ) frames", ["T0885"])
def vlan_qinq(ctx: Ctx):
    for h in ctx.r.hosts:
        if h.vlan_qinq and _l2_local(h):
            yield (
                Group(
                    "vlan_qinq",
                    h.ip,
                    None,
                    f"{h.ip} sent double-tagged frames (outer VLAN {', '.join(map(str, h.vlan_outer))})",
                )
                .hit(h.first_seen)
                .build()
            )


@rule("vlan_cross_segment_ot", "vlan", "high", "OT traffic crosses VLANs")
def vlan_cross_segment_ot(ctx: Ctx):
    groups = Groups()
    for f in ctx.r.flows:
        a, b = ctx.hosts.get(f.client), ctx.hosts.get(f.server)
        if not a or not b or not (_is_ot(a) or _is_ot(b)) or f.protocol not in K.OT_PROTOCOLS:
            continue
        if a.vlans and b.vlans and set(a.vlans).isdisjoint(b.vlans):
            groups.get_or_add(
                (f.client, f.server),
                lambda f=f, a=a, b=b: Group(
                    "vlan_cross_segment_ot",
                    f.client,
                    f.server,
                    f"{f.protocol} from {f.client} (VLAN {','.join(map(str, a.vlans))}) to {f.server} "
                    f"(VLAN {','.join(map(str, b.vlans))}) crosses segments",
                ),
            ).hit(f.first_seen, f.id)
    return groups.anomalies()


@rule("pcp_abuse", "vlan", "low", "End host uses network-control priority")
def pcp_abuse(ctx: Ctx):
    for h in ctx.r.hosts:
        high = [p for p in h.vlan_pcps if p >= HIGH_PCP]
        if high and h.host_type in END_HOST_TYPES and _l2_local(h):
            yield (
                Group(
                    "pcp_abuse",
                    h.ip,
                    None,
                    f"{h.ip} ({h.host_type}) tags frames with priority {', '.join(map(str, high))}, "
                    "reserved for network control",
                )
                .hit(h.first_seen)
                .build()
            )


@rule("arp_spoofing", "vlan", "high", "Several MACs claim one IP", ["T0830", "T1557.002"])
def arp_spoofing(ctx: Ctx):
    for claim in ctx.r.arp_claims:
        if len(claim.macs) > 1:
            where = f"VLAN {claim.vlan}" if claim.vlan is not None else "the untagged network"
            yield (
                Group(
                    "arp_spoofing",
                    claim.ip,
                    None,
                    f"{len(claim.macs)} MAC addresses claimed {claim.ip} on {where}: possible ARP spoofing",
                    key=str(claim.vlan),
                )
                .hit(evidence="MACs: " + ", ".join(claim.macs))
                .build()
            )


@rule("broadcast_storm", "vlan", "medium", "Broadcast storm")
def broadcast_storm(ctx: Ctx):
    for v in ctx.r.vlan_stats:
        if v.broadcast >= BCAST_MIN_PKTS and v.packets and v.broadcast / v.packets > BCAST_THRESHOLD:
            where = f"VLAN {v.vlan}" if v.vlan is not None else "untagged network"
            yield Group(
                "broadcast_storm",
                None,
                None,
                f"{v.broadcast / v.packets:.0%} of frames on {where} are broadcasts ({v.broadcast} of {v.packets})",
                key=str(v.vlan),
            ).build()


# ── run ───────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run_rules(result: AnalysisResult) -> list[Anomaly]:
    ctx = Ctx(result)
    out: list[Anomaly] = []
    for fn in _FUNCS:
        out.extend(fn(ctx))
    out.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen or 0, a.rule))
    return out
