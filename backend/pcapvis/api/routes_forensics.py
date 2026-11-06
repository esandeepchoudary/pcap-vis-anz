"""Engagement dashboard, capture diff, and the packet inspector (M7)."""

from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy import select

from pcapvis.api.routes_captures import _capture
from pcapvis.api.routes_engagements import as_editor, as_viewer, storage
from pcapvis.api.schemas import (
    DashboardOut,
    DiffLinkOut,
    DiffOut,
    ErrorOut,
    PacketDetailOut,
    PacketListOut,
    PacketRowOut,
)
from pcapvis.assets import fields as F
from pcapvis.assets.links import aggregate_links
from pcapvis.db.models import Asset, AssetLink, AssetOtOp, AssetSighting, CaptureStatus, Conduit, Zone
from pcapvis.engagements.storage import Storage
from pcapvis.engine.inspect import InspectError, InspectorBusy, list_packets, packet_detail
from pcapvis.zones import violations

router = APIRouter(prefix="/api", tags=["forensics"])
SEVERITIES = ("critical", "high", "medium", "low", "info")


@router.get("/engagements/{engagement_id}/dashboard", response_model=DashboardOut)
def dashboard(ctx=Depends(as_viewer)) -> DashboardOut:
    eng, _r, _u, db = ctx
    caps = list(eng.captures)
    done = [c for c in caps if c.status == CaptureStatus.done and c.summary]
    assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eng.id)))
    eff = [F.effective_all(a.auto or {}, a.overrides or {}) for a in assets]
    by_level = Counter(f"{float(e['purdue_level']):g}" for e in eff)
    by_type = Counter(e["asset_type"] or "Unknown" for e in eff)
    findings = dict.fromkeys(SEVERITIES, 0)
    for c in done:
        for s in SEVERITIES:
            findings[s] += (c.summary.get("findings") or {}).get(s, 0)
    writes = sum(
        o.count
        for o in db.scalars(
            select(AssetOtOp).where(AssetOtOp.engagement_id == eng.id, AssetOtOp.kind == "write")
        )
    )
    return DashboardOut(
        captures=len(caps),
        captures_done=len(done),
        packets=sum(c.summary.get("packets", 0) for c in done),
        assets=len(assets),
        assets_edited=sum(1 for a in assets if a.overrides),
        assets_by_level=dict(sorted(by_level.items(), key=lambda kv: float(kv[0]))),
        assets_by_type=dict(by_type.most_common(10)),
        ot_connections=sum(1 for link in aggregate_links(db, eng.id) if link.is_ot),
        ot_writes=writes,
        zones=len(list(db.scalars(select(Zone.id).where(Zone.engagement_id == eng.id)))),
        conduits=len(list(db.scalars(select(Conduit.id).where(Conduit.engagement_id == eng.id)))),
        violations=len(violations(db, eng.id)),
        findings=findings,
        credentials=sum(c.summary.get("credentials", 0) for c in done),
        files=sum(c.summary.get("files", 0) for c in done),
    )


def _links(db, cid: int) -> dict[tuple, int]:
    out: dict[tuple, int] = {}
    for r in db.scalars(select(AssetLink).where(AssetLink.capture_id == cid)):
        out[(r.src_asset_id, r.dst_asset_id, r.protocol)] = r.packets
    return out


@router.get("/engagements/{engagement_id}/diff", response_model=DiffOut, responses={404: {"model": ErrorOut}})
def diff(base: int = Query(ge=1), compare: int = Query(ge=1), ctx=Depends(as_viewer)) -> DiffOut:
    """Assets and connections that appear or disappear between a baseline capture and another."""
    eng, _r, _u, db = ctx
    b, c = _capture(eng, db, base), _capture(eng, db, compare)
    seen = {
        cid: set(db.scalars(select(AssetSighting.asset_id).where(AssetSighting.capture_id == cid)))
        for cid in (b.id, c.id)
    }
    lb, lc = _links(db, b.id), _links(db, c.id)

    def links(keys, src):
        return [DiffLinkOut(src=s, dst=d, protocol=p, packets=src[(s, d, p)]) for s, d, p in sorted(keys)]

    return DiffOut(
        new_assets=sorted(seen[c.id] - seen[b.id]),
        gone_assets=sorted(seen[b.id] - seen[c.id]),
        new_links=links(lc.keys() - lb.keys(), lc),
        gone_links=links(lb.keys() - lc.keys(), lb),
    )


def _capture_path(eng, db, store: Storage, cid: int):
    c = _capture(eng, db, cid)
    path = store.capture_file(eng.id, c.id, c.file_name)
    if not path.is_file():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "The original capture file isn't stored (imported without it?)."
        )
    return path


@router.get(
    "/engagements/{engagement_id}/captures/{capture_id}/packets",
    response_model=PacketListOut,
    responses={400: {"model": ErrorOut}, 404: {"model": ErrorOut}, 429: {"model": ErrorOut}},
)
def packets(
    request: Request,
    capture_id: int = Path(ge=1),
    filter: str = Query(default="", max_length=500),  # noqa: A002 - the Wireshark term
    limit: int = Query(default=500, ge=1, le=5000),
    ctx=Depends(as_editor),
    store: Storage = Depends(storage),
) -> PacketListOut:
    """Packets matching a Wireshark display filter. Editors only: raw packets include unmasked secrets."""
    eng, _r, _u, db = ctx
    path = _capture_path(eng, db, store, capture_id)
    try:
        rows, truncated = list_packets(request.app.state.settings.tshark_path, path, filter, limit=limit)
    except InspectorBusy as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
    except InspectError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return PacketListOut(packets=[PacketRowOut(**r.__dict__) for r in rows], truncated=truncated)


@router.get(
    "/engagements/{engagement_id}/captures/{capture_id}/packets/{number}",
    response_model=PacketDetailOut,
    responses={400: {"model": ErrorOut}, 404: {"model": ErrorOut}, 429: {"model": ErrorOut}},
)
def packet(
    request: Request,
    capture_id: int = Path(ge=1),
    number: int = Path(ge=1, le=2**31),
    ctx=Depends(as_editor),
    store: Storage = Depends(storage),
) -> PacketDetailOut:
    eng, _r, _u, db = ctx
    path = _capture_path(eng, db, store, capture_id)
    try:
        text = packet_detail(request.app.state.settings.tshark_path, path, number)
    except InspectorBusy as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
    except InspectError as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND if "No packet" in str(exc) else status.HTTP_400_BAD_REQUEST, str(exc)
        ) from exc
    return PacketDetailOut(number=number, text=text)
