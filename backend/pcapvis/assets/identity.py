"""Manual identity fixes: merge assets the matcher kept apart, split one it joined wrongly.

Both are remembered as pins on the asset (``declared``), so re-analysis and later captures keep the
consultant's decision:

- merged assets' MACs join the target's declared MACs and their IPs its ``pinned_ips``;
- split-off IPs become the new asset's ``pinned_ips`` and leave the original's.

A pinned IP wins over MAC matching (see ``merge._Index``): that is what keeps a split apart when both
addresses share one MAC (a host with two IPs, a NAT, a gateway).
"""

from __future__ import annotations

import gzip

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from pcapvis.assets import fields as F
from pcapvis.assets import merge as M
from pcapvis.assets.service import MAX_IDENTIFIERS, EditConflict, _change, label
from pcapvis.db.base import utcnow
from pcapvis.db.models import (
    Asset,
    AssetChange,
    AssetLink,
    AssetOrigin,
    AssetOtOp,
    AssetSighting,
    Capture,
    Finding,
    FindingHit,
    User,
)
from pcapvis.engine.model import AnalysisResult

MAX_MERGE = 50


def _declared(a: Asset) -> dict:
    d = dict(a.declared or {})
    return {k: list(d.get(k, [])) for k in ("ips", "macs", "pinned_ips")} | {
        k: v for k, v in d.items() if k not in ("ips", "macs", "pinned_ips")
    }


def _bump(db: Session, a: Asset, expected_version: int | None) -> None:
    if expected_version is not None and expected_version != a.version:
        raise EditConflict
    res = db.execute(
        update(Asset)
        .where(Asset.id == a.id, Asset.version == a.version)
        .values(version=a.version + 1, updated_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        raise EditConflict
    db.refresh(a)


def merge_assets(
    db: Session,
    target: Asset,
    sources: list[Asset],
    user: User | None,
    *,
    reason: str,
    expected_version: int | None,
) -> Asset:
    """Fold ``sources`` into ``target``: sightings, traffic, findings and history move; sources are deleted.

    The target's manual values win; a source's manual value fills a field the target hasn't set. Caller commits.
    """
    reason = F.validate_reason(reason)
    sources = [s for s in sources if s.id != target.id]
    if not sources:
        raise F.FieldError("Pick at least one other asset to merge into this one.")
    if len(sources) > MAX_MERGE:
        raise F.FieldError(f"Merge at most {MAX_MERGE} assets at a time.")
    eid = target.engagement_id
    M.lock_engagement(db, eid)
    _bump(db, target, expected_version)
    ids = {s.id for s in sources}
    t = target.id

    decl = _declared(target)
    macs = sorted({*decl["macs"], *(m for s in sources for m in (s.macs or []))})
    pinned = sorted({*decl["pinned_ips"], *(ip for s in sources for ip in (s.ips or []))})
    if len(macs) + len(pinned) + len(decl["ips"]) > MAX_IDENTIFIERS:
        raise F.FieldError(f"A merged asset can carry at most {MAX_IDENTIFIERS} addresses.")
    decl["macs"], decl["pinned_ips"] = macs, pinned
    target.declared = decl

    overrides = dict(target.overrides or {})
    for s in sources:
        for f, o in (s.overrides or {}).items():
            overrides.setdefault(f, o)
    target.overrides = overrides

    db.execute(update(AssetSighting).where(AssetSighting.asset_id.in_(ids)).values(asset_id=t))
    _repoint_links(db, eid, ids, t)
    _repoint_findings(db, eid, ids, t)
    db.execute(update(AssetChange).where(AssetChange.asset_id.in_(ids)).values(asset_id=t))
    db.add(
        _change(
            target,
            user,
            "merge",
            None,
            sorted(label(s) for s in sources),
            sorted(
                {*(ip for s in sources for ip in s.ips or []), *(m for s in sources for m in s.macs or [])}
            ),
            reason,
        )
    )
    db.flush()
    for s in sources:
        db.delete(s)
    db.flush()
    M.recompute(db, [target], actor="merge", quiet={t})
    db.refresh(target)
    return target


def _opt(fn, a, b):
    vals = [x for x in (a, b) if x is not None]
    return fn(vals) if vals else None


def _repoint_links(db: Session, eid: int, ids: set[int], t: int) -> None:
    """Point links of merged assets at the target, folding rows that now share a key; drop self-links."""

    def mapped(x: int) -> int:
        return t if x in ids else x

    involved = ids | {t}
    rows = list(
        db.scalars(
            select(AssetLink).where(
                AssetLink.engagement_id == eid,
                AssetLink.src_asset_id.in_(involved) | AssetLink.dst_asset_id.in_(involved),
            )
        )
    )
    keep: dict[tuple, AssetLink] = {}
    for r in sorted(rows, key=lambda r: r.id):
        s, d = mapped(r.src_asset_id), mapped(r.dst_asset_id)
        if s == d:
            db.delete(r)
            continue
        k = (r.capture_id, s, d, r.protocol)
        first = keep.get(k)
        if first is None:
            r.src_asset_id, r.dst_asset_id = s, d
            keep[k] = r
            continue
        first.ports = sorted({*first.ports, *r.ports})[: M.MAX_PORTS]
        for c in ("flows", "packets", "bytes", "ot_reads", "ot_writes", "ot_errors"):
            setattr(first, c, getattr(first, c) + getattr(r, c))
        first.first_seen = _opt(min, first.first_seen, r.first_seen)
        first.last_seen = _opt(max, first.last_seen, r.last_seen)
        db.delete(r)
    db.flush()  # deletes first, so updated rows don't collide with the unique key
    ops = list(
        db.scalars(
            select(AssetOtOp).where(
                AssetOtOp.engagement_id == eid,
                AssetOtOp.src_asset_id.in_(involved) | AssetOtOp.dst_asset_id.in_(involved),
            )
        )
    )
    keep_ops: dict[tuple, AssetOtOp] = {}
    for o in sorted(ops, key=lambda o: o.id):
        s, d = mapped(o.src_asset_id), mapped(o.dst_asset_id)
        k = (o.capture_id, s, d, o.protocol, o.function, o.function_code, o.kind)
        first = keep_ops.get(k)
        if first is None:
            o.src_asset_id, o.dst_asset_id = s, d
            keep_ops[k] = o
            continue
        first.count += o.count
        first.first_seen, first.last_seen = (
            min(first.first_seen, o.first_seen),
            max(first.last_seen, o.last_seen),
        )
        first.sample = first.sample or o.sample
        db.delete(o)
    db.flush()


def _repoint_findings(db: Session, eid: int, ids: set[int], t: int) -> None:
    for h in db.scalars(select(FindingHit).where(FindingHit.engagement_id == eid)):
        data = dict(h.data or {})
        changed = False
        for k in ("src_asset", "dst_asset"):
            if data.get(k) in ids:
                data[k], changed = t, True
        if changed:
            h.data = data
    for f in db.scalars(select(Finding).where(Finding.engagement_id == eid)):
        if any(i in ids for i in f.asset_ids or []):
            f.asset_ids = sorted({t if i in ids else i for i in f.asset_ids})


def split_asset(
    db: Session,
    storage,
    a: Asset,
    ips: list[str],
    user: User | None,
    *,
    reason: str,
    expected_version: int | None,
) -> Asset:
    """Move ``ips`` (and their sightings) off ``a`` into a new asset; rebuild the affected captures' traffic.

    Returns the new asset. Caller commits.
    """
    reason = F.validate_reason(reason)
    moving = sorted(set(ips))
    if not moving:
        raise F.FieldError("Pick the addresses that belong to another device.")
    unknown = [ip for ip in moving if ip not in (a.ips or [])]
    if unknown:
        raise F.FieldError(f"{unknown[0]} isn't one of this asset's addresses.")
    if len(moving) >= len(a.ips or []):
        raise F.FieldError("Leave at least one IP address on the original asset.")
    eid = a.engagement_id
    M.lock_engagement(db, eid)
    _bump(db, a, expected_version)

    decl = _declared(a)
    decl["ips"] = [ip for ip in decl["ips"] if ip not in moving]
    decl["pinned_ips"] = [ip for ip in decl["pinned_ips"] if ip not in moving]
    a.declared = decl
    new = Asset(
        engagement_id=eid,
        origin=AssetOrigin.observed,
        ips=moving,
        macs=[],
        declared={"ips": [], "macs": [], "pinned_ips": moving},
        auto={},
        observed={"captures": 0},
        overrides={},
    )
    db.add(new)
    db.flush()
    rows = list(
        db.scalars(select(AssetSighting).where(AssetSighting.asset_id == a.id, AssetSighting.ip.in_(moving)))
    )
    captures = sorted({r.capture_id for r in rows})
    for r in rows:
        r.asset_id = new.id
    db.add(_change(a, user, "split", None, moving, None, reason))
    db.add(_change(new, user, "split", None, None, moving, reason))
    db.flush()
    M.recompute(db, [a, new], actor="split", quiet={a.id, new.id})
    # Traffic was counted per asset: rebuild it for the captures that saw the moved addresses.
    for cid in captures:
        cap = db.get(Capture, cid)
        path = storage.result_path(eid, cid)
        if cap is None or not path.is_file():
            continue
        with gzip.open(path, "rb") as fh:
            result = AnalysisResult.model_validate_json(fh.read())
        M.build_links(db, cap, result)
        M.build_findings(db, cap, result)
    db.flush()
    db.refresh(a)
    db.refresh(new)
    return new
