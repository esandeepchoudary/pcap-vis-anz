"""Merge a .pcapvis bundle into an existing engagement (laptop → team server, M9).

The bundle is imported into a temporary engagement first (all of ``bundle.py``'s validation applies), then
folded into the target:

- captures: skipped when the target already has the same SHA-256; otherwise moved over and merged into
  the target's inventory (assets are matched by MAC/IP like any new capture);
- asset edits: a field edited in the bundle is applied when the target has no manual value for it; when both
  sides edited it differently, the target's value is kept and the clash is reported (never overwritten);
- assets added by hand, zones, conduits and finding triage: added when the target doesn't have them.

The temporary engagement is always removed afterwards.
"""

import shutil
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.schemas import MergeConflictOut, MergeReportOut
from pcapvis.assets import fields as F
from pcapvis.assets import merge as asset_merge
from pcapvis.assets.service import label
from pcapvis.db.base import utcnow
from pcapvis.db.models import (
    Asset,
    AssetChange,
    AssetOrigin,
    Capture,
    CapturePoint,
    CaptureStatus,
    Conduit,
    Engagement,
    Finding,
    User,
    Zone,
)
from pcapvis.engagements import audit
from pcapvis.engagements.bundle import _load_result, import_bundle
from pcapvis.engagements.storage import Storage


def merge_bundle(
    db: Session,
    storage: Storage,
    user: User,
    target: Engagement,
    bundle: Path,
    *,
    max_total: int,
    source_name: str,
) -> MergeReportOut:
    tmp = import_bundle(db, storage, user, bundle, max_total=max_total)
    tmp.is_quicklook = True  # keep it out of everyone's lists for the few seconds it exists
    db.commit()
    moved: list[Path] = []
    try:
        report = _merge(db, storage, user, tmp, target, moved, source_name)
        audit.record(
            db,
            user,
            "engagement.merge",
            engagement_id=target.id,
            target=source_name[:200],
            details=report.model_dump(exclude={"conflicts"}) | {"conflicts": len(report.conflicts)},
        )
        target.touch()
        db.commit()
    except BaseException:
        db.rollback()
        for p in moved:  # undo file moves into the target
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
        raise
    finally:
        tmp_id = tmp.id
        leftover = db.get(Engagement, tmp_id)
        if leftover is not None:
            db.delete(leftover)
            db.commit()
        storage.delete_engagement(tmp_id)
    return report


def _merge(
    db, storage: Storage, user: User, tmp: Engagement, target: Engagement, moved: list[Path], source: str
) -> MergeReportOut:
    asset_merge.lock_engagement(db, target.id)
    actor = f"import from {source}"[:255]
    r = {
        "captures_added": 0,
        "captures_skipped": 0,
        "assets_created": 0,
        "assets_updated": 0,
        "fields_applied": 0,
        "zones_added": 0,
        "conduits_added": 0,
        "findings_added": 0,
    }
    conflicts: list[MergeConflictOut] = []

    # ── captures ──────────────────────────────────────────────────────────
    have = set(db.scalars(select(Capture.sha256).where(Capture.engagement_id == target.id)))
    points = {
        p.name: p for p in db.scalars(select(CapturePoint).where(CapturePoint.engagement_id == target.id))
    }
    to_merge: list[Capture] = []
    for c in list(tmp.captures):
        if c.sha256 in have:
            r["captures_skipped"] += 1
            continue
        point_id = None
        if c.capture_point is not None:
            p = points.get(c.capture_point.name)
            if p is None:
                p = points[c.capture_point.name] = CapturePoint(
                    engagement_id=target.id,
                    name=c.capture_point.name,
                    description=c.capture_point.description,
                )
                db.add(p)
                db.flush()
            point_id = p.id
        new = Capture(
            engagement_id=target.id,
            capture_point_id=point_id,
            file_name=c.file_name,
            size=c.size,
            sha256=c.sha256,
            status=c.status,
            progress=c.progress,
            error=c.error,
            uploaded_by=user.id,
            uploaded_at=c.uploaded_at,
            finished_at=c.finished_at,
            summary=c.summary,
            engine_version=c.engine_version,
        )
        db.add(new)
        db.flush()
        for src, dst in (
            (storage.capture_dir(tmp.id, c.id), storage.capture_dir(target.id, new.id)),
            (storage.result_path(tmp.id, c.id), storage.result_path(target.id, new.id)),
        ):
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(src, dst)
                moved.append(dst)
        have.add(c.sha256)
        r["captures_added"] += 1
        if new.status == CaptureStatus.done and storage.result_path(target.id, new.id).is_file():
            to_merge.append(new)
    src_files, dst_files = storage.files_dir(tmp.id), storage.files_dir(target.id)
    if src_files.is_dir():
        dst_files.mkdir(parents=True, exist_ok=True)
        for f in src_files.iterdir():
            if f.is_file() and not (dst_files / f.name).exists():
                shutil.copy2(f, dst_files / f.name)
                moved.append(dst_files / f.name)
    for cap in to_merge:
        asset_merge.ingest_capture(db, cap, _load_result(storage, cap), actor=actor)

    # ── assets ────────────────────────────────────────────────────────────
    targets = list(db.scalars(select(Asset).where(Asset.engagement_id == target.id)))
    index = asset_merge._Index(targets)
    mapping: dict[int, int] = {}
    for a in db.scalars(select(Asset).where(Asset.engagement_id == tmp.id).order_by(Asset.id)):
        match = _find(index, a)
        if match is None:
            if not a.overrides and a.origin != AssetOrigin.manual:
                continue  # nothing of the consultant's to carry over
            match = Asset(
                engagement_id=target.id,
                origin=a.origin,
                macs=list(a.macs or []),
                ips=list(a.ips or []),
                declared=dict(a.declared or {}),
                auto=dict(a.auto or {}),
                observed=dict(a.observed or {}),
                overrides=dict(a.overrides or {}),
            )
            db.add(match)
            db.flush()
            index.add(match)
            db.add(
                AssetChange(asset_id=match.id, engagement_id=target.id, actor=actor, kind="import", reason="")
            )
            r["assets_created"] += 1
            mapping[a.id] = match.id
            continue
        mapping[a.id] = match.id
        mine = dict(match.overrides or {})
        applied = 0
        for field, ov in (a.overrides or {}).items():
            if field not in F.FIELDS:
                continue
            if field in mine:
                if mine[field]["value"] != ov["value"]:
                    conflicts.append(
                        MergeConflictOut(
                            asset_id=match.id,
                            asset=label(match),
                            field=field,
                            kept=mine[field]["value"],
                            imported=ov["value"],
                        )
                    )
                continue
            old = F.effective(match.auto or {}, mine, field)
            mine[field] = {**ov, "reason": (ov.get("reason") or "")[: F.MAX_REASON]}
            db.add(
                AssetChange(
                    asset_id=match.id,
                    engagement_id=target.id,
                    actor=actor,
                    kind="import",
                    field=field,
                    old=old,
                    new=ov["value"],
                    reason=ov.get("reason", ""),
                )
            )
            applied += 1
        if applied:
            match.overrides = mine
            match.version = (match.version or 1) + 1
            match.updated_at = utcnow()
            r["assets_updated"] += 1
            r["fields_applied"] += applied
    db.flush()

    # ── zones and conduits ────────────────────────────────────────────────
    zones = {z.name: z for z in db.scalars(select(Zone).where(Zone.engagement_id == target.id))}
    zone_map: dict[int, int] = {}
    for z in db.scalars(select(Zone).where(Zone.engagement_id == tmp.id)):
        mine = zones.get(z.name)
        if mine is None:
            mine = zones[z.name] = Zone(
                engagement_id=target.id,
                name=z.name,
                purdue_level=z.purdue_level,
                security_level=z.security_level,
                description=z.description,
                x=z.x,
                y=z.y,
            )
            db.add(mine)
            db.flush()
            r["zones_added"] += 1
        else:
            mine.purdue_level = mine.purdue_level if mine.purdue_level is not None else z.purdue_level
            mine.security_level = mine.security_level or z.security_level
            mine.description = mine.description or z.description
        zone_map[z.id] = mine.id
    pairs = {
        frozenset((c.zone_a_id, c.zone_b_id))
        for c in db.scalars(select(Conduit).where(Conduit.engagement_id == target.id))
    }
    for c in db.scalars(select(Conduit).where(Conduit.engagement_id == tmp.id)):
        a, b = zone_map.get(c.zone_a_id), zone_map.get(c.zone_b_id)
        if a is None or b is None or frozenset((a, b)) in pairs:
            continue
        db.add(
            Conduit(
                engagement_id=target.id,
                zone_a_id=a,
                zone_b_id=b,
                name=c.name,
                allowed=list(c.allowed or []),
                description=c.description,
            )
        )
        pairs.add(frozenset((a, b)))
        r["conduits_added"] += 1

    # ── findings (triage and manual) ──────────────────────────────────────
    keys = set(db.scalars(select(Finding.key).where(Finding.engagement_id == target.id)))
    for f in db.scalars(select(Finding).where(Finding.engagement_id == tmp.id)):
        if f.key in keys:
            continue
        db.add(
            Finding(
                engagement_id=target.id,
                key=f.key,
                source=f.source,
                title=f.title,
                description=f.description,
                severity=f.severity,
                severity_override=f.severity_override,
                status=f.status,
                notes=f.notes,
                recommendation=f.recommendation,
                include_in_report=f.include_in_report,
                asset_ids=sorted({mapping[i] for i in f.asset_ids or [] if i in mapping}),
                updated_by=f.updated_by,
            )
        )
        keys.add(f.key)
        r["findings_added"] += 1
    db.flush()
    return MergeReportOut(**r, conflicts=conflicts)


def _find(index, a: Asset) -> Asset | None:
    for mac in a.macs or []:
        if mac in index.by_mac:
            return index.by_mac[mac]
    for ip in a.ips or []:
        found = index.find(ip, None)
        if found is not None and (not found.macs or not a.macs or set(found.macs) & set(a.macs)):
            return found
    return None
