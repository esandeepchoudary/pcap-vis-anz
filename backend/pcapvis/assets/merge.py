"""Merge capture results into an engagement's asset inventory.

Identity: a host's own MAC address identifies it across captures (an IP can change with DHCP). When
the MAC is missing or belongs to a router forwarding the traffic, the IP address is used instead. An
IP-only asset adopts a MAC once one is seen, but an asset never takes a MAC or IP away from another
MAC-identified asset.

Each host becomes a *sighting* (capture, IP, the engine's Host) linked to its asset. Automatic values
and observed facts are recomputed from all of an asset's sightings, so removing or re-analysing a
capture is exact. Manual overrides are never touched here.
"""

import gzip
import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from pcapvis.assets.fields import EMPTY, FIELDS
from pcapvis.db.base import utcnow
from pcapvis.db.models import (
    Asset,
    AssetChange,
    AssetLink,
    AssetOrigin,
    AssetOtOp,
    AssetSighting,
    Capture,
    CaptureStatus,
    Engagement,
    FindingHit,
)
from pcapvis.engine.model import AnalysisResult, Host

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
# A MAC carrying more distinct (non-link-local) IPs than this in one capture is treated as a router,
# even if the engine didn't flag it, so we never merge a whole subnet into one asset.
MAX_IPS_PER_MAC = 16
UNKNOWN_TYPES = {"Unknown Host", ""}
# Identity keys (from protocol fingerprints) that feed the editable fields, best first.
IDENTITY_SOURCES = {
    "vendor": ("enip_vendor", "modbus_vendor", "bacnet_vendor", "s7_vendor"),
    "model": (
        "enip_product_name",
        "modbus_model",
        "modbus_product",
        "s7_module_type",
        "s7_module_name",
        "s7_order_number",
        "pn_type_of_station",
        "cdp_platform",
    ),
    "firmware": ("enip_revision", "modbus_revision", "s7_firmware", "cdp_software"),
    "serial": ("enip_serial", "s7_serial"),
    "location": ("snmp_sys_location",),
}
# Names a device gives itself, used when no DNS/DHCP/LLDP name is known.
SELF_NAMES = ("s7_plc_name", "pn_name_of_station", "snmp_sys_name", "bacnet_device_name")
SOURCE_LABELS = {
    "enip_": "EtherNet/IP identity",
    "modbus_": "Modbus device identification",
    "s7_": "S7 identification (SZL)",
    "pn_": "PROFINET DCP",
    "snmp_": "SNMP",
    "bacnet_": "BACnet",
    "cdp_": "CDP",
    "lldp_": "LLDP",
    "dhcp_": "DHCP",
}


def source_label(key: str) -> str:
    return next((label for prefix, label in SOURCE_LABELS.items() if key.startswith(prefix)), key)


MAX_LIST = 200


def lock_engagement(db: Session, eid: int) -> None:
    """Serialise merges and edits per engagement (row lock on PostgreSQL, write lock on SQLite)."""
    db.execute(
        update(Engagement)
        .where(Engagement.id == eid)
        .values(revision=Engagement.revision + 1, updated_at=utcnow())
        .execution_options(synchronize_session=False)
    )


def _include(h: Host) -> bool:
    if h.is_multicast or h.is_broadcast:
        return False
    try:
        ip = ipaddress.ip_address(h.ip)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_multicast or ip.is_loopback)


def _is_link_local(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return False


def _usable_macs(hosts: Iterable[Host]) -> dict[str, str]:
    """IP → MAC for hosts whose MAC identifies the host itself (not a router in front of it)."""
    by_mac: dict[str, set[str]] = defaultdict(set)
    out = {}
    for h in hosts:
        if h.mac and not h.mac_is_gateway:
            mac = h.mac.lower()
            out[h.ip] = mac
            if not _is_link_local(h.ip):
                by_mac[mac].add(h.ip)
    crowded = {m for m, ips in by_mac.items() if len(ips) > MAX_IPS_PER_MAC}
    return {ip: m for ip, m in out.items() if m not in crowded}


class _Index:
    def __init__(self, assets: list[Asset]):
        self.by_mac: dict[str, Asset] = {}
        self.by_ip: dict[str, list[Asset]] = defaultdict(list)
        for a in assets:
            self.add(a)

    def add(self, a: Asset) -> None:
        for m in a.macs or []:
            self.by_mac.setdefault(m, a)
        for ip in a.ips or []:
            if a not in self.by_ip[ip]:
                self.by_ip[ip].append(a)

    def find(self, ip: str, mac: str | None) -> Asset | None:
        if mac and mac in self.by_mac:
            return self.by_mac[mac]
        candidates = self.by_ip.get(ip, [])
        if mac:
            # Only an asset without its own MAC may adopt this one.
            candidates = [a for a in candidates if not a.macs]
        if not candidates:
            return None
        return max(candidates, key=lambda a: ((a.observed or {}).get("last_seen") or 0, -(a.id or 0)))


def ingest_capture(
    db: Session,
    cap: Capture,
    result: AnalysisResult,
    *,
    keep_existing: bool = False,
    actor: str | None = None,
    record_auto: bool = True,
) -> dict[str, int]:
    """Merge one capture's hosts into the engagement's assets. Caller commits.

    ``keep_existing``: leave this capture's existing sightings alone and only add hosts that have none
    (used after importing a bundle that already carries the asset mapping). ``record_auto``: record
    automatic value changes in history (off for imports, which carry their own history).
    """
    eid = cap.engagement_id
    actor = actor or f"capture {cap.file_name}"
    lock_engagement(db, eid)
    assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eid)))
    old = list(db.scalars(select(AssetSighting).where(AssetSighting.capture_id == cap.id)))
    touched: set[int] = {s.asset_id for s in old}
    had_sightings = set(
        db.scalars(select(AssetSighting.asset_id).join(Asset).where(Asset.engagement_id == eid).distinct())
    )
    seen_ips: set[str] = set()
    if keep_existing:
        seen_ips = {s.ip for s in old}
    elif old:
        db.execute(delete(AssetSighting).where(AssetSighting.capture_id == cap.id))
        db.expire_all()
        assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eid)))

    index = _Index(assets)
    hosts = [h for h in result.hosts if _include(h) and h.ip not in seen_ips]
    macs = _usable_macs(hosts)
    created = 0
    new_assets: list[Asset] = []
    matched: list[tuple[Asset, Host, str | None]] = []
    for h in sorted(hosts, key=lambda h: (h.ip_version, h.ip)):
        mac = macs.get(h.ip)
        asset = index.find(h.ip, mac)
        if asset is None:
            asset = Asset(engagement_id=eid, origin=AssetOrigin.observed, macs=[], ips=[], declared={})
            asset.auto, asset.observed, asset.overrides = {}, {}, {}
            db.add(asset)
            new_assets.append(asset)
            created += 1
        if mac and mac not in asset.macs:
            asset.macs = sorted({*asset.macs, mac})
        if h.ip not in asset.ips:
            asset.ips = sorted({*asset.ips, h.ip})
        index.add(asset)
        matched.append((asset, h, mac))
    db.flush()  # ids for new assets
    by_id = {a.id: a for a in [*assets, *new_assets]}
    for asset, h, mac in matched:
        db.add(
            AssetSighting(
                asset_id=asset.id, capture_id=cap.id, ip=h.ip, mac=mac, host=h.model_dump(mode="json")
            )
        )
        touched.add(asset.id)
    db.flush()
    for a in new_assets:
        db.add(AssetChange(asset_id=a.id, engagement_id=eid, actor=actor, kind="created", reason=""))
    new_ids = {a.id for a in new_assets}
    quiet = set(touched) if not record_auto else new_ids | (touched - had_sightings)
    recompute(db, [by_id[i] for i in touched if i in by_id], actor=actor, quiet=quiet)
    build_links(db, cap, result)
    build_findings(db, cap, result)
    removed = prune(db, eid)
    cap.assets_merged_at = utcnow()
    return {"created": created, "updated": len(touched - new_ids), "removed": removed}


def remove_capture(db: Session, cap: Capture) -> None:
    """Drop a capture's sightings (before deleting it) and update the assets it fed. Caller commits."""
    lock_engagement(db, cap.engagement_id)
    aids = set(db.scalars(select(AssetSighting.asset_id).where(AssetSighting.capture_id == cap.id)))
    if not aids:
        return
    _drop_links(db, cap.id)
    db.execute(delete(FindingHit).where(FindingHit.capture_id == cap.id))
    db.execute(delete(AssetSighting).where(AssetSighting.capture_id == cap.id))
    db.expire_all()
    assets = list(db.scalars(select(Asset).where(Asset.id.in_(aids))))
    recompute(db, assets, actor=f"capture {cap.file_name} removed")
    prune(db, cap.engagement_id)


MAX_PORTS = 20


def build_findings(db: Session, cap: Capture, result: AnalysisResult) -> None:
    """The capture's rule findings, with their source/destination mapped to assets. Rebuilt each merge."""
    db.execute(delete(FindingHit).where(FindingHit.capture_id == cap.id))
    owner = dict(
        db.execute(
            select(AssetSighting.ip, AssetSighting.asset_id).where(AssetSighting.capture_id == cap.id)
        ).all()
    )
    seen: set[str] = set()
    for a in result.anomalies:
        if a.id in seen:
            continue
        seen.add(a.id)
        data = a.model_dump(mode="json")
        data["src_asset"], data["dst_asset"] = owner.get(a.src), owner.get(a.dst)
        db.add(FindingHit(engagement_id=cap.engagement_id, capture_id=cap.id, key=a.id[:64], data=data))
    db.flush()


def _drop_links(db: Session, cid: int) -> None:
    db.execute(delete(AssetLink).where(AssetLink.capture_id == cid))
    db.execute(delete(AssetOtOp).where(AssetOtOp.capture_id == cid))


def build_links(db: Session, cap: Capture, result: AnalysisResult) -> None:
    """Asset-to-asset traffic and OT operations for one capture, from its flows and commands.

    Rebuilt from scratch for the capture each time, so re-merging is idempotent. Traffic to addresses that
    aren't assets (multicast, broadcast) and an asset talking to itself are left out.
    """
    _drop_links(db, cap.id)
    owner = dict(
        db.execute(
            select(AssetSighting.ip, AssetSighting.asset_id).where(AssetSighting.capture_id == cap.id)
        ).all()
    )
    links: dict[tuple[int, int, str], dict] = {}
    for f in result.flows:
        src, dst = owner.get(f.client), owner.get(f.server)
        if src is None or dst is None or src == dst:
            continue
        k = (src, dst, f.protocol[:64])
        link = links.get(k)
        if link is None:
            link = links[k] = {
                "ports": [],
                "flows": 0,
                "packets": 0,
                "bytes": 0,
                "ot_reads": 0,
                "ot_writes": 0,
                "ot_errors": 0,
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
            }
        port = f"{f.transport}/{f.server_port}"
        if port not in link["ports"] and len(link["ports"]) < MAX_PORTS:
            link["ports"].append(port)
        link["flows"] += 1
        link["packets"] += f.packets_c2s + f.packets_s2c
        link["bytes"] += f.bytes_c2s + f.bytes_s2c
        link["ot_reads"] += f.ot_reads
        link["ot_writes"] += f.ot_writes
        link["ot_errors"] += f.ot_errors
        link["first_seen"] = min(link["first_seen"], f.first_seen)
        link["last_seen"] = max(link["last_seen"], f.last_seen)
    eid = cap.engagement_id
    db.add_all(
        AssetLink(engagement_id=eid, capture_id=cap.id, src_asset_id=s, dst_asset_id=d, protocol=p, **v)
        for (s, d, p), v in links.items()
    )
    ops: dict[tuple, dict] = {}
    for c in result.ot_commands:
        if not c.is_request and c.kind != "error":
            continue
        # Orient everything master → device: an error response comes back from the device.
        a, b = (c.src, c.dst) if c.is_request else (c.dst, c.src)
        src, dst = owner.get(a), owner.get(b)
        if src is None or dst is None:
            continue
        k = (src, dst, c.protocol[:64], c.function[:128], c.function_code, c.kind)
        op = ops.get(k)
        if op is None:
            op = ops[k] = {"count": 0, "first_seen": c.time, "last_seen": c.time, "sample": ""}
        op["count"] += 1
        op["first_seen"] = min(op["first_seen"], c.time)
        op["last_seen"] = max(op["last_seen"], c.time)
        if not op["sample"] and c.detail:
            op["sample"] = c.detail[:300]
    db.add_all(
        AssetOtOp(
            engagement_id=eid,
            capture_id=cap.id,
            src_asset_id=s,
            dst_asset_id=d,
            protocol=p,
            function=fn,
            function_code=code,
            kind=kind,
            **v,
        )
        for (s, d, p, fn, code, kind), v in ops.items()
    )
    db.flush()


def prune(db: Session, eid: int) -> int:
    """Delete observed assets that no capture shows any more and nobody edited."""
    orphans = list(
        db.scalars(
            select(Asset).where(
                Asset.engagement_id == eid,
                Asset.origin == AssetOrigin.observed,
                ~select(AssetSighting.id).where(AssetSighting.asset_id == Asset.id).exists(),
            )
        )
    )
    n = 0
    for a in orphans:
        if not a.overrides and not (a.declared or {}).get("ips") and not (a.declared or {}).get("macs"):
            db.delete(a)
            n += 1
    if n:
        db.flush()
    return n


# ── recomputation ────────────────────────────────────────────────────────────


def _sightings(db: Session, asset: Asset) -> list[tuple[Host, str | None, int]]:
    """(host, identifying MAC, capture id) for each sighting, most recently seen first."""
    rows = db.execute(
        select(AssetSighting.host, AssetSighting.mac, AssetSighting.capture_id).where(
            AssetSighting.asset_id == asset.id
        )
    )
    out = [(Host.model_validate(h), mac, cid) for h, mac, cid in rows]
    out.sort(key=lambda r: (r[0].last_seen or 0, r[0].ip), reverse=True)  # newer observations win ties
    return out


def _first(values: Iterable[Any]) -> Any:
    return next((v for v in values if v not in (None, "", [])), None)


def derive(hosts: list[Host]) -> tuple[dict, dict]:
    """(auto values, observed facts) from an asset's sightings, most recent first."""
    if not hosts:
        return {}, {"last_seen": None}
    by_conf = sorted(
        hosts,
        key=lambda h: (h.host_type not in UNKNOWN_TYPES, CONFIDENCE_RANK.get(h.host_type_confidence, 0)),
        reverse=True,
    )  # stable: recency breaks ties
    best = by_conf[0]
    leveled = next((h for h in by_conf if h.purdue_level >= 0), None)
    identity: dict[str, str] = {}
    for h in reversed(hosts):  # oldest first so newer values overwrite
        identity.update(h.identity)
    if any(k.startswith("s7_") for k in identity):
        identity.setdefault("s7_vendor", "Siemens")  # only Siemens CPUs answer S7 SZL reads
    sources: dict[str, str] = {}
    named = next(
        ((h.hostname, h.hostnames[0].source if h.hostnames else "hostname") for h in hosts if h.hostname),
        None,
    )
    auto: dict[str, Any] = {
        "name": named[0] if named else None,
        "asset_type": best.host_type if best.host_type not in UNKNOWN_TYPES else None,
        "purdue_level": _num(leveled.purdue_level) if leveled else -1,
    }
    if named:
        sources["name"] = named[1].upper()
    else:
        key = next((k for k in SELF_NAMES if identity.get(k)), None)
        if key:
            auto["name"], sources["name"] = identity[key], source_label(key)
    if auto["asset_type"]:
        sources["asset_type"] = "classification"
    for field, keys in IDENTITY_SOURCES.items():
        key = next((k for k in keys if identity.get(k)), None)
        auto[field] = identity[key] if key else None
        if key:
            sources[field] = source_label(key)
    if not auto["vendor"]:
        auto["vendor"] = _first(h.mac_vendor for h in hosts)
        if auto["vendor"]:
            sources["vendor"] = "MAC address vendor (OUI)"
    auto = {k: v for k, v in auto.items() if v is not None and v != EMPTY.get(k)}
    sources = {k: v for k, v in sources.items() if k in auto}

    services: dict[tuple, dict] = {}
    for h in hosts:
        for s in h.services:
            k = (s.transport, s.port, s.protocol)
            cur = services.setdefault(k, {**s.model_dump(), "packets": 0, "clients": 0})
            cur["packets"] += s.packets
            cur["clients"] = max(cur["clients"], s.clients)
    roles = {h.ot_role for h in hosts} - {"unknown"}
    ot_role = (
        "both"
        if "both" in roles or roles == {"master", "outstation"}
        else (roles.pop() if roles else "unknown")
    )
    hostnames: dict[tuple, dict] = {}
    for h in hosts:
        for n in h.hostnames:
            hostnames.setdefault((n.name, n.source), n.model_dump())
    first = [h.first_seen for h in hosts if h.first_seen is not None]
    last = [h.last_seen for h in hosts if h.last_seen is not None]
    observed = {
        "mac_vendor": _first(h.mac_vendor for h in hosts),
        "is_private": any(h.is_private for h in hosts),
        "os_hint": _first(h.os_hint for h in hosts),
        "ttl": _first(h.ttl for h in hosts),
        "protocols": _union(h.protocols for h in hosts),
        "services": sorted(services.values(), key=lambda s: (s["port"], s["transport"]))[:MAX_LIST],
        "vlans": sorted({v for h in hosts for v in h.vlans}),
        "ot_role": ot_role,
        "modbus_unit_ids": sorted({v for h in hosts for v in h.modbus_unit_ids})[:MAX_LIST],
        "dnp3_addresses": sorted({v for h in hosts for v in h.dnp3_addresses})[:MAX_LIST],
        "identity": identity,
        "hostnames": list(hostnames.values())[:MAX_LIST],
        "tls_sni": _union(h.tls_sni for h in hosts),
        "packets": sum(h.packets_sent + h.packets_recv for h in hosts),
        "bytes": sum(h.bytes_sent + h.bytes_recv for h in hosts),
        "first_seen": min(first) if first else None,
        "last_seen": max(last) if last else None,
        "type_confidence": best.host_type_confidence,
        "type_evidence": [e.model_dump() for e in best.host_type_evidence],
        "purdue_evidence": [e.model_dump() for e in (leveled or best).purdue_evidence],
        "auto_sources": sources,
    }
    return auto, observed


def _num(v: float) -> int | float:
    return int(v) if float(v).is_integer() else float(v)


def _union(lists: Iterable[list[str]]) -> list[str]:
    out: dict[str, None] = {}
    for lst in lists:
        for v in lst:
            out.setdefault(v, None)
    return sorted(out)[:MAX_LIST]


def recompute(db: Session, assets: list[Asset], *, actor: str, quiet: set[int] = frozenset()) -> None:
    """Re-derive auto values, identifiers and facts from sightings. Records auto-value changes in
    history, except for assets in ``quiet`` (just created, so there's nothing to compare against).

    An asset left with no sightings keeps its last known values and identifiers, so an edited asset
    is matched again when a later capture sees it.
    """
    for a in assets:
        if a.id is None:
            continue
        rows = _sightings(db, a)
        if not rows:
            a.observed = {**(a.observed or {}), "captures": 0}
            continue
        hosts = [h for h, _m, _c in rows]
        auto, observed = derive(hosts)
        observed["captures"] = len({c for _h, _m, c in rows})
        if a.id not in quiet:
            for field in FIELDS:
                before, after = (a.auto or {}).get(field), auto.get(field)
                if before != after:
                    db.add(
                        AssetChange(
                            asset_id=a.id,
                            engagement_id=a.engagement_id,
                            actor=actor,
                            kind="auto",
                            field=field,
                            old=before,
                            new=after,
                            reason="",
                        )
                    )
        declared = a.declared or {}
        a.auto = auto
        a.observed = observed
        a.macs = sorted({*declared.get("macs", []), *(m for _h, m, _c in rows if m)})
        a.ips = sorted({*declared.get("ips", []), *(h.ip for h in hosts)})
    db.flush()


def merge_pending(db: Session, storage, *, limit: int = 1000) -> int:
    """Merge done captures whose hosts aren't in the inventory yet (upgrades, imports). Commits."""
    ids = list(
        db.scalars(
            select(Capture.id)
            .where(Capture.status == CaptureStatus.done, Capture.assets_merged_at.is_(None))
            .order_by(Capture.id)
            .limit(limit)
        )
    )
    n = 0
    for cid in ids:
        cap = db.get(Capture, cid)
        path = storage.result_path(cap.engagement_id, cap.id)
        if not path.is_file():
            cap.assets_merged_at = utcnow()  # nothing to merge
            db.commit()
            continue
        with gzip.open(path, "rb") as fh:
            result = AnalysisResult.model_validate_json(fh.read())
        ingest_capture(db, cap, result)
        db.commit()
        n += 1
    return n
