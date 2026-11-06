"""IEC 62443 zones and conduits, violation detection, and network inference (M6)."""

import ipaddress
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.schemas import NetworkOut, ViolationOut, ZoneOut
from pcapvis.assets import fields as F
from pcapvis.assets import service
from pcapvis.assets.links import aggregate_links
from pcapvis.db.models import Asset, Conduit, User, Zone

GATEWAY_TYPES = {"Router", "Firewall", "VPN Gateway", "Data Diode"}
MAX_PROTOCOLS = 50


def asset_zone(a: Asset) -> str | None:
    return F.effective(a.auto or {}, a.overrides or {}, "zone")


def list_zones(db: Session, eid: int) -> list[ZoneOut]:
    assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eid)))
    members: dict[str, list[int]] = defaultdict(list)
    for a in assets:
        if z := asset_zone(a):
            members[z].append(a.id)
    out = []
    defined = list(db.scalars(select(Zone).where(Zone.engagement_id == eid).order_by(Zone.name)))
    for z in defined:
        out.append(
            ZoneOut(
                id=z.id,
                name=z.name,
                defined=True,
                purdue_level=z.purdue_level,
                security_level=z.security_level,
                description=z.description,
                x=z.x,
                y=z.y,
                asset_ids=sorted(members.get(z.name, [])),
            )
        )
    names = {z.name for z in defined}
    for name in sorted(set(members) - names):
        out.append(
            ZoneOut(
                id=None,
                name=name,
                defined=False,
                purdue_level=None,
                security_level=None,
                description="",
                x=None,
                y=None,
                asset_ids=sorted(members[name]),
            )
        )
    return out


def clean_name(name: str) -> str:
    v = F.validate("zone", name)
    if not v:
        raise F.FieldError("A zone needs a name.")
    return v


def check_level(level: float | None) -> float | None:
    if level is None:
        return None
    return F.validate("purdue_level", level)


def rename_zone(db: Session, eid: int, old: str, new: str, user: User | None) -> int:
    """Move every asset in zone ``old`` to ``new`` (recorded in each asset's history). Caller commits."""
    n = 0
    for a in db.scalars(select(Asset).where(Asset.engagement_id == eid)):
        if asset_zone(a) == old:
            service.edit(
                db,
                a,
                user,
                set_={"zone": new},
                reset=[],
                reason=f"Zone renamed from {old}",
                expected_version=None,
            )
            n += 1
    return n


def clean_protocols(protocols: list[str]) -> list[str]:
    out: list[str] = []
    for p in protocols:
        p = p.strip()
        if not p:
            continue
        if len(p) > 64 or any(c in p for c in "\r\n\t\x00"):
            raise F.FieldError("Protocol names must be short single-line text.")
        if p.lower() not in {x.lower() for x in out}:
            out.append(p)
    return out[:MAX_PROTOCOLS]


def violations(db: Session, eid: int) -> list[ViolationOut]:
    """Cross-zone traffic not covered by a conduit (or using a protocol the conduit doesn't allow)."""
    zone_of = {a.id: asset_zone(a) for a in db.scalars(select(Asset).where(Asset.engagement_id == eid))}
    zid = {z.name: z.id for z in db.scalars(select(Zone).where(Zone.engagement_id == eid))}
    conduits: dict[frozenset, Conduit] = {}
    for c in db.scalars(select(Conduit).where(Conduit.engagement_id == eid).order_by(Conduit.id)):
        conduits.setdefault(frozenset((c.zone_a_id, c.zone_b_id)), c)
    out: list[ViolationOut] = []
    for link in aggregate_links(db, eid):
        za, zb = zone_of.get(link.src), zone_of.get(link.dst)
        if not za or not zb or za == zb:
            continue
        conduit = conduits.get(frozenset((zid.get(za), zid.get(zb)))) if za in zid and zb in zid else None
        base = {"src": link.src, "dst": link.dst, "src_zone": za, "dst_zone": zb}
        if conduit is None:
            protos = link.protocols
            kind = "no_conduit"
        else:
            allowed = {p.lower() for p in conduit.allowed or []}
            if not allowed:
                continue
            protos = [p for p in link.protocols if p.protocol.lower() not in allowed]
            if not protos:
                continue
            kind = "protocol_not_allowed"
        out.append(
            ViolationOut(
                kind=kind,
                conduit_id=conduit.id if conduit else None,
                protocols=[p.protocol for p in protos],
                flows=sum(p.flows for p in protos),
                packets=sum(p.packets for p in protos),
                ot_writes=sum(p.ot_writes for p in protos),
                first_seen=link.first_seen,
                last_seen=link.last_seen,
                **base,
            )
        )
    out.sort(key=lambda v: (-v.ot_writes, v.src_zone, v.dst_zone, v.src, v.dst))
    return out


def networks(db: Session, eid: int) -> list[NetworkOut]:
    nets: dict[str, dict] = {}
    for a in db.scalars(select(Asset).where(Asset.engagement_id == eid).order_by(Asset.id)):
        for ip in a.ips or []:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or not addr.is_private:
                continue
            cidr = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            n = nets.setdefault(
                cidr, {"vlans": set(), "assets": [], "gateways": [], "zones": set(), "levels": set()}
            )
            if a.id in n["assets"]:
                continue
            n["assets"].append(a.id)
            n["vlans"] |= set((a.observed or {}).get("vlans", []))
            eff = F.effective_all(a.auto or {}, a.overrides or {})
            if eff["asset_type"] in GATEWAY_TYPES:
                n["gateways"].append(a.id)
            if eff["zone"]:
                n["zones"].add(eff["zone"])
            n["levels"].add(float(eff["purdue_level"]))
    return [
        NetworkOut(
            cidr=c,
            vlans=sorted(n["vlans"]),
            asset_ids=n["assets"],
            gateways=n["gateways"],
            zones=sorted(n["zones"]),
            purdue_levels=sorted(n["levels"]),
        )
        for c, n in sorted(nets.items(), key=lambda kv: ipaddress.ip_network(kv[0]))
    ]
