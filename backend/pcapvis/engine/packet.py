"""Turn one tshark EK record into a compact, typed Packet."""

from dataclasses import dataclass


def _first(layers: dict, key: str) -> str | None:
    v = layers.get(key)
    return v[0] if v else None


def _int(layers: dict, key: str) -> int | None:
    v = layers.get(key)
    if not v:
        return None
    try:
        return int(v[0], 0)
    except ValueError:
        try:
            return int(float(v[0]))
        except ValueError:
            return None


def _ints(layers: dict, key: str) -> list[int]:
    out = []
    for s in layers.get(key, ()):
        try:
            out.append(int(s, 0))
        except ValueError:
            continue
    return out


def _bool(layers: dict, key: str) -> bool:
    v = layers.get(key)
    return bool(v) and v[0] in ("True", "1", "true")


@dataclass(slots=True)
class Packet:
    num: int
    ts: float
    length: int
    protocols: list[str]
    src_mac: str | None
    dst_mac: str | None
    src_vendor: str | None
    vlan_ids: list[int]  # all 802.1Q tags, outermost first
    outer_vlan: int | None  # 802.1ad S-tag, when present
    pcp: int | None
    src: str | None
    dst: str | None
    ip_version: int | None
    ttl: int | None
    transport: str | None  # "tcp" | "udp" | "icmp" | "icmpv6" | "ip-<n>" | None for non-IP
    sport: int
    dport: int
    syn: bool
    ack: bool
    rst: bool
    fin: bool
    payload_len: int
    seq_raw: int | None
    icmp_type: int | None
    malformed: bool
    layers: dict  # the raw EK layers, for protocol extractors


def decode(layers: dict) -> Packet:
    protocols = (_first(layers, "frame_protocols") or "").split(":")
    src = _first(layers, "ip_src")
    dst = _first(layers, "ip_dst")
    ip_version = 4 if src else None
    ttl = _int(layers, "ip_ttl")
    proto_num = _int(layers, "ip_proto")
    if src is None:
        src = _first(layers, "ipv6_src")
        dst = _first(layers, "ipv6_dst")
        if src is not None:
            ip_version = 6
            ttl = _int(layers, "ipv6_hlim")
            proto_num = _int(layers, "ipv6_nxt")

    transport = None
    sport = dport = 0
    payload_len = 0
    icmp_type = None
    if src is not None:
        if "tcp_srcport" in layers:
            transport = "tcp"
            sport = _int(layers, "tcp_srcport") or 0
            dport = _int(layers, "tcp_dstport") or 0
            payload_len = _int(layers, "tcp_len") or 0
        elif "udp_srcport" in layers:
            transport = "udp"
            sport = _int(layers, "udp_srcport") or 0
            dport = _int(layers, "udp_dstport") or 0
            payload_len = max((_int(layers, "udp_length") or 8) - 8, 0)
        elif "icmp_type" in layers:
            transport = "icmp"
            icmp_type = _int(layers, "icmp_type")
        elif "icmpv6_type" in layers:
            transport = "icmpv6"
            icmp_type = _int(layers, "icmpv6_type")
        else:
            transport = f"ip-{proto_num}" if proto_num is not None else "ip"

    vlan_ids = _ints(layers, "vlan_id")
    pcps = _ints(layers, "vlan_priority")
    return Packet(
        num=_int(layers, "frame_number") or 0,
        ts=float(_first(layers, "frame_time_epoch") or 0.0),
        length=_int(layers, "frame_len") or 0,
        protocols=protocols,
        src_mac=_first(layers, "eth_src") or _first(layers, "sll_src_eth"),
        dst_mac=_first(layers, "eth_dst"),
        src_vendor=_first(layers, "eth_src_oui_resolved"),
        vlan_ids=vlan_ids,
        outer_vlan=_int(layers, "ieee8021ad_id"),
        pcp=pcps[0] if pcps else None,
        src=src,
        dst=dst,
        ip_version=ip_version,
        ttl=ttl,
        transport=transport,
        sport=sport,
        dport=dport,
        syn=_bool(layers, "tcp_flags_syn"),
        ack=_bool(layers, "tcp_flags_ack"),
        rst=_bool(layers, "tcp_flags_reset"),
        fin=_bool(layers, "tcp_flags_fin"),
        payload_len=payload_len,
        seq_raw=_int(layers, "tcp_seq_raw") if transport == "tcp" else None,
        icmp_type=icmp_type,
        malformed="_ws_malformed" in layers or "_ws.malformed" in protocols or "_ws_malformed" in protocols,
        layers=layers,
    )
