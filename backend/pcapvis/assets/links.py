"""Asset-to-asset traffic merged across captures (shared by the Purdue map and zone checks)."""

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.schemas import LinkOut, LinkProtocolOut
from pcapvis.db.models import AssetLink
from pcapvis.engine import knowledge as K

COUNTS = ("flows", "packets", "bytes", "ot_reads", "ot_writes", "ot_errors")


def _min(a, b):
    return b if a is None else a if b is None else min(a, b)


def _max(a, b):
    return b if a is None else a if b is None else max(a, b)


def aggregate_links(db: Session, eid: int) -> list[LinkOut]:
    """All asset-to-asset traffic of an engagement, merged across captures."""
    per_proto: dict[tuple[int, int, str], dict] = {}
    for r in db.scalars(select(AssetLink).where(AssetLink.engagement_id == eid)):
        k = (r.src_asset_id, r.dst_asset_id, r.protocol)
        p = per_proto.get(k)
        if p is None:
            p = per_proto[k] = {
                "ports": [],
                **dict.fromkeys(COUNTS, 0),
                "first": None,
                "last": None,
                "caps": set(),
            }
        for c in COUNTS:
            p[c] += getattr(r, c)
        p["ports"] = sorted({*p["ports"], *r.ports})[:20]
        p["first"], p["last"] = _min(p["first"], r.first_seen), _max(p["last"], r.last_seen)
        p["caps"].add(r.capture_id)
    pairs: dict[tuple[int, int], list[tuple[str, dict]]] = defaultdict(list)
    for (s, d, proto), p in per_proto.items():
        pairs[(s, d)].append((proto, p))
    out = []
    for (s, d), protos in sorted(pairs.items()):
        protos.sort(key=lambda x: (-x[1]["packets"], x[0]))
        tot = {c: sum(p[c] for _n, p in protos) for c in COUNTS}
        out.append(
            LinkOut(
                src=s,
                dst=d,
                protocols=[
                    LinkProtocolOut(protocol=n, ports=p["ports"], **{c: p[c] for c in COUNTS})
                    for n, p in protos
                ],
                is_ot=any(n in K.OT_PROTOCOLS for n, _p in protos) or tot["ot_reads"] + tot["ot_writes"] > 0,
                **tot,
                first_seen=min((p["first"] for _n, p in protos if p["first"] is not None), default=None),
                last_seen=max((p["last"] for _n, p in protos if p["last"] is not None), default=None),
                captures=sorted(set().union(*(p["caps"] for _n, p in protos))),
            )
        )
    return out
