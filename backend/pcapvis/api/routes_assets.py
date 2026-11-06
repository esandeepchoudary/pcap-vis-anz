"""Asset inventory: list, detail, edit (single and bulk), manual assets, history, CSV register."""

import csv
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.routes_engagements import as_editor, as_viewer
from pcapvis.api.schemas import (
    AssetBulkEdit,
    AssetBulkResult,
    AssetChangeOut,
    AssetCreate,
    AssetDetail,
    AssetEdit,
    AssetFieldOut,
    AssetFieldsOut,
    AssetOut,
    ErrorOut,
    SightingOut,
)
from pcapvis.assets import fields as F
from pcapvis.assets import service
from pcapvis.assets.fields import FieldError
from pcapvis.db.models import Asset, AssetChange, AssetSighting, Capture, Engagement
from pcapvis.engagements import audit
from pcapvis.engine import knowledge as K

router = APIRouter(prefix="/api", tags=["assets"])
CONFLICT = "Someone else changed this asset while you were editing. Review their change and try again."


def asset_out(a: Asset) -> AssetOut:
    return AssetOut(**_base(a))


def _base(a: Asset) -> dict:
    auto, ov, obs = a.auto or {}, a.overrides or {}, a.observed or {}
    values = F.effective_all(auto, ov)
    return {
        "id": a.id,
        "origin": a.origin,
        "version": a.version,
        "ips": a.ips or [],
        "macs": a.macs or [],
        **values,
        "overridden": sorted(ov),
        "type_confidence": obs.get("type_confidence") if "asset_type" not in ov else None,
        "mac_vendor": obs.get("mac_vendor"),
        "is_private": obs.get("is_private", True),
        "protocols": obs.get("protocols", []),
        "ot_role": obs.get("ot_role", "unknown"),
        "os_hint": obs.get("os_hint"),
        "packets": obs.get("packets", 0),
        "bytes": obs.get("bytes", 0),
        "first_seen": obs.get("first_seen"),
        "last_seen": obs.get("last_seen"),
        "capture_count": obs.get("captures", 0),
        "updated_at": a.updated_at,
    }


def asset_detail(db: Session, a: Asset) -> AssetDetail:
    obs = a.observed or {}
    rows = db.execute(
        select(AssetSighting, Capture)
        .join(Capture, Capture.id == AssetSighting.capture_id)
        .where(AssetSighting.asset_id == a.id)
        .order_by(Capture.id, AssetSighting.ip)
    ).all()
    sightings = [
        SightingOut(
            capture_id=c.id,
            file_name=c.file_name,
            capture_point=c.capture_point.name if c.capture_point else None,
            ip=s.ip,
            mac=s.mac,
            first_seen=s.host.get("first_seen"),
            last_seen=s.host.get("last_seen"),
            packets=s.host.get("packets_sent", 0) + s.host.get("packets_recv", 0),
            host_type=s.host.get("host_type", ""),
            purdue_level=s.host.get("purdue_level", -1),
        )
        for s, c in rows
    ]
    return AssetDetail(
        **_base(a),
        auto={k: v for k, v in (a.auto or {}).items() if k in F.FIELDS},
        overrides=a.overrides or {},
        auto_sources={k: v for k, v in obs.get("auto_sources", {}).items() if k in F.FIELDS},
        services=obs.get("services", []),
        vlans=obs.get("vlans", []),
        identity=obs.get("identity", {}),
        hostnames=obs.get("hostnames", []),
        tls_sni=obs.get("tls_sni", []),
        modbus_unit_ids=obs.get("modbus_unit_ids", []),
        dnp3_addresses=obs.get("dnp3_addresses", []),
        ttl=obs.get("ttl"),
        type_evidence=obs.get("type_evidence", []),
        purdue_evidence=obs.get("purdue_evidence", []),
        sightings=sightings,
    )


def _asset(eng: Engagement, db: Session, aid: int) -> Asset:
    a = db.get(Asset, aid)
    if a is None or a.engagement_id != eng.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found.")
    return a


def _bad(exc: FieldError) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


@router.get("/asset-fields", response_model=AssetFieldsOut)
def asset_fields() -> AssetFieldsOut:
    """What can be edited on an asset, and the allowed values."""
    return AssetFieldsOut(
        fields=[
            AssetFieldOut(name=f.name, label=f.label, kind=f.kind, max_len=f.max_len, auto=f.auto)
            for f in F.FIELDS.values()
        ],
        purdue_levels=list(F.PURDUE_LEVELS),
        purdue_names={f"{k:g}": v for k, v in F.PURDUE_NAMES.items()},
        criticalities=list(F.CRITICALITIES),
        asset_types=sorted({*K.HOST_TYPE_PRIORITY, *K.PURDUE_LEVELS, "Firewall", "Data Diode", "Switch"}),
    )


@router.get("/engagements/{engagement_id}/assets", response_model=list[AssetOut])
def list_assets(ctx=Depends(as_viewer)) -> list[AssetOut]:
    eng, _role, _user, db = ctx
    assets = db.scalars(select(Asset).where(Asset.engagement_id == eng.id).order_by(Asset.id))
    return [asset_out(a) for a in assets]


@router.post(
    "/engagements/{engagement_id}/assets",
    response_model=AssetDetail,
    status_code=201,
    responses={422: {"model": ErrorOut}},
)
def create_asset(body: AssetCreate, ctx=Depends(as_editor)) -> AssetDetail:
    """Add an asset by hand, e.g. a firewall or data diode never seen on the wire."""
    eng, _role, user, db = ctx
    if not body.ips and not body.macs and not body.values.get("name"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Give the asset a name or an address.")
    try:
        a = service.create_manual(
            db, eng.id, user, ips=body.ips, macs=body.macs, values=dict(body.values), reason=body.reason
        )
    except FieldError as exc:
        db.rollback()
        raise _bad(exc) from exc
    audit.record(db, user, "asset.create", engagement_id=eng.id, target=service.label(a))
    db.commit()
    return asset_detail(db, a)


@router.get("/engagements/{engagement_id}/assets/export")
def export_assets(ctx=Depends(as_viewer)):
    """The asset register as CSV (opens in Excel)."""
    eng, _role, _user, db = ctx
    assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eng.id).order_by(Asset.id)))
    buf = io.StringIO()
    buf.write("﻿")  # BOM so Excel reads UTF-8
    w = csv.writer(buf)
    cols = [*F.FIELDS]
    w.writerow(
        [
            "asset_id",
            *cols,
            "ip_addresses",
            "mac_addresses",
            "mac_vendor",
            "protocols",
            "first_seen_utc",
            "last_seen_utc",
            "captures",
            "manually_set",
            "origin",
        ]
    )
    for a in assets:
        o = asset_out(a)
        vals = F.effective_all(a.auto or {}, a.overrides or {})
        row = [a.id]
        for c in cols:
            v = vals[c]
            row.append(
                "; ".join(v)
                if isinstance(v, list)
                else ("" if v is None else f"{v:g}" if isinstance(v, float) else v)
            )
        row += [
            " ".join(o.ips),
            " ".join(o.macs),
            o.mac_vendor or "",
            " ".join(o.protocols),
            _iso(o.first_seen),
            _iso(o.last_seen),
            o.capture_count,
            " ".join(o.overridden),
            o.origin.value,
        ]
        w.writerow([csv_safe(x) for x in row])
    name = "".join(c if c.isalnum() or c in "-_" else "_" for c in eng.name)[:60] or "engagement"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}-assets.csv"'},
    )


def _iso(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def csv_safe(v) -> str | int:
    """Neutralise spreadsheet formulas: hostnames and identity strings come from untrusted traffic."""
    if isinstance(v, int):
        return v
    s = str(v)
    if s and s[0] in "=+-@\t\r|":
        return "'" + s
    return s


@router.post(
    "/engagements/{engagement_id}/assets/bulk",
    response_model=AssetBulkResult,
    responses={422: {"model": ErrorOut}, 404: {"model": ErrorOut}},
)
def bulk_edit(body: AssetBulkEdit, ctx=Depends(as_editor)) -> AssetBulkResult:
    """Set or reset fields on many assets at once (last write wins; every change is in history)."""
    eng, _role, user, db = ctx
    ids = set(body.asset_ids)
    assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eng.id, Asset.id.in_(ids))))
    if len(assets) != len(ids):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Some of those assets don't exist in this engagement.")
    if not body.set and not body.reset:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Nothing to change.")
    total, changed = 0, 0
    try:
        for a in assets:
            for _attempt in range(3):  # a concurrent single edit bumps the version; re-read and retry
                try:
                    n = service.edit(
                        db,
                        a,
                        user,
                        set_=dict(body.set),
                        reset=list(body.reset),
                        reason=body.reason,
                        expected_version=None,
                    )
                    break
                except service.EditConflict:
                    db.refresh(a)
            else:
                raise HTTPException(status.HTTP_409_CONFLICT, CONFLICT)
            total += n
            changed += 1 if n else 0
    except FieldError as exc:
        db.rollback()
        raise _bad(exc) from exc
    if total:
        audit.record(
            db,
            user,
            "asset.bulk_edit",
            engagement_id=eng.id,
            target=f"{changed} assets",
            details={"set": sorted(body.set), "reset": sorted(body.reset), "reason": body.reason[:200]},
        )
    db.commit()
    return AssetBulkResult(assets=changed, changes=total)


@router.get("/engagements/{engagement_id}/assets/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: int = Path(ge=1), ctx=Depends(as_viewer)) -> AssetDetail:
    eng, _role, _user, db = ctx
    return asset_detail(db, _asset(eng, db, asset_id))


@router.patch(
    "/engagements/{engagement_id}/assets/{asset_id}",
    response_model=AssetDetail,
    responses={409: {"model": ErrorOut}, 422: {"model": ErrorOut}},
)
def edit_asset(body: AssetEdit, asset_id: int = Path(ge=1), ctx=Depends(as_editor)) -> AssetDetail:
    eng, _role, user, db = ctx
    a = _asset(eng, db, asset_id)
    try:
        n = service.edit(
            db,
            a,
            user,
            set_=dict(body.set),
            reset=list(body.reset),
            reason=body.reason,
            expected_version=body.version,
        )
    except FieldError as exc:
        db.rollback()
        raise _bad(exc) from exc
    except service.EditConflict as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, CONFLICT) from exc
    if n:
        audit.record(
            db,
            user,
            "asset.edit",
            engagement_id=eng.id,
            target=service.label(a),
            details={"set": sorted(body.set), "reset": sorted(body.reset)},
        )
    db.commit()
    return asset_detail(db, a)


@router.delete(
    "/engagements/{engagement_id}/assets/{asset_id}", status_code=204, responses={409: {"model": ErrorOut}}
)
def delete_asset(asset_id: int = Path(ge=1), ctx=Depends(as_editor)) -> None:
    """Delete a manual asset, or one no capture shows any more. Observed assets would just come back."""
    eng, _role, user, db = ctx
    a = _asset(eng, db, asset_id)
    if service.has_sightings(db, a):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This asset is seen in captures and would come back. Delete those captures first, or tag it instead.",
        )
    lbl = service.label(a)
    db.delete(a)
    eng.touch()
    audit.record(db, user, "asset.delete", engagement_id=eng.id, target=lbl)
    db.commit()


@router.get("/engagements/{engagement_id}/assets/{asset_id}/history", response_model=list[AssetChangeOut])
def asset_history(
    asset_id: int = Path(ge=1), limit: int = Query(default=500, ge=1, le=5000), ctx=Depends(as_viewer)
) -> list[AssetChange]:
    eng, _role, _user, db = ctx
    a = _asset(eng, db, asset_id)
    return list(
        db.scalars(
            select(AssetChange)
            .where(AssetChange.asset_id == a.id)
            .order_by(AssetChange.at.desc(), AssetChange.id.desc())
            .limit(limit)
        )
    )
