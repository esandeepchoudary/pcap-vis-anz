"""Who talks to whom: asset-to-asset links and OT operations, merged across captures (M4)."""

from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select

from pcapvis.api.routes_engagements import as_viewer
from pcapvis.api.schemas import LinkOut, LinkProtocolOut, OtOperationOut
from pcapvis.db.models import AssetLink, AssetOtOp
from pcapvis.engine import knowledge as K

router = APIRouter(prefix="/api", tags=["purdue"])
COUNTS = ("flows", "packets", "bytes", "ot_reads", "ot_writes", "ot_errors")
KIND_ORDER = {"write": 0, "error": 1, "other": 2, "read": 3}


def _min(a, b):
    return b if a is None else a if b is None else min(a, b)


def _max(a, b):
    return b if a is None else a if b is None else max(a, b)


@router.get("/engagements/{engagement_id}/links", response_model=list[LinkOut])
def links(ctx=Depends(as_viewer)) -> list[LinkOut]:
    eng, _role, _user, db = ctx
    per_proto: dict[tuple[int, int, str], dict] = {}
    for r in db.scalars(select(AssetLink).where(AssetLink.engagement_id == eng.id)):
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


@router.get("/engagements/{engagement_id}/ot-operations", response_model=list[OtOperationOut])
def ot_operations(ctx=Depends(as_viewer)) -> list[OtOperationOut]:
    eng, _role, _user, db = ctx
    groups: dict[tuple, dict] = {}
    for r in db.scalars(select(AssetOtOp).where(AssetOtOp.engagement_id == eng.id).order_by(AssetOtOp.id)):
        k = (r.src_asset_id, r.dst_asset_id, r.protocol, r.function, r.function_code, r.kind)
        g = groups.get(k)
        if g is None:
            g = groups[k] = {
                "count": 0,
                "first": r.first_seen,
                "last": r.last_seen,
                "sample": r.sample,
                "caps": set(),
            }
        g["count"] += r.count
        g["first"], g["last"] = min(g["first"], r.first_seen), max(g["last"], r.last_seen)
        g["sample"] = g["sample"] or r.sample
        g["caps"].add(r.capture_id)
    ops = [
        OtOperationOut(
            src=s,
            dst=d,
            protocol=p,
            function=fn,
            function_code=code,
            kind=kind,
            count=g["count"],
            first_seen=g["first"],
            last_seen=g["last"],
            sample=g["sample"],
            captures=sorted(g["caps"]),
        )
        for (s, d, p, fn, code, kind), g in groups.items()
    ]
    ops.sort(key=lambda o: (KIND_ORDER.get(o.kind, 9), -o.count, o.src, o.dst, o.function))
    return ops
