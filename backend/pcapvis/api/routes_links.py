"""Who talks to whom: asset-to-asset links and OT operations, merged across captures (M4)."""

from fastapi import APIRouter, Depends
from sqlalchemy import select

from pcapvis.api.routes_engagements import as_viewer
from pcapvis.api.schemas import LinkOut, OtOperationOut
from pcapvis.assets.links import aggregate_links
from pcapvis.db.models import AssetOtOp

router = APIRouter(prefix="/api", tags=["purdue"])
KIND_ORDER = {"write": 0, "error": 1, "other": 2, "read": 3}


@router.get("/engagements/{engagement_id}/links", response_model=list[LinkOut])
def links(ctx=Depends(as_viewer)) -> list[LinkOut]:
    eng, _role, _user, db = ctx
    return aggregate_links(db, eng.id)


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
