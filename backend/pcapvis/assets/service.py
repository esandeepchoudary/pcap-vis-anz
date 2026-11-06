"""Manual asset edits: overrides with reasons, resets, manual assets, and per-field history."""

import ipaddress
import re
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from pcapvis.assets import fields as F
from pcapvis.assets.merge import lock_engagement
from pcapvis.db.base import utcnow
from pcapvis.db.models import Asset, AssetChange, AssetOrigin, AssetSighting, User

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MAX_IDENTIFIERS = 32


class EditConflict(Exception):
    """The asset changed since the client loaded it."""


def label(a: Asset) -> str:
    name = F.effective(a.auto or {}, a.overrides or {}, "name")
    ident = (a.ips or a.macs or [f"asset {a.id}"])[0]
    return f"{name} ({ident})" if name else ident


def actor_name(user: User | None) -> str:
    return user.username if user else "system"


def plan_changes(
    a: Asset, set_: dict[str, Any], reset: list[str], reason: str, user: User | None
) -> tuple[dict, list[AssetChange]]:
    """New overrides dict and the history rows it implies (validates everything first)."""
    reason = F.validate_reason(reason)
    for f in reset:
        if f not in F.FIELDS:
            raise F.FieldError(f"Unknown asset field: {f!r}.")
    clean = {f: F.validate(f, v) for f, v in set_.items()}
    overlap = set(clean) & set(reset)
    if overlap:
        raise F.FieldError(f"Can't both set and reset: {', '.join(sorted(overlap))}.")
    overrides = dict(a.overrides or {})
    auto = a.auto or {}
    now = utcnow()
    actor = actor_name(user)
    changes: list[AssetChange] = []
    for f, v in clean.items():
        old = F.effective(auto, overrides, f)
        if f in overrides and overrides[f]["value"] == v:
            if overrides[f].get("reason") != reason and reason:
                overrides[f] = {**overrides[f], "reason": reason}
            continue
        overrides[f] = {"value": v, "reason": reason, "by": actor, "at": now.isoformat()}
        changes.append(_change(a, user, "override", f, old, v, reason))
    for f in reset:
        if f not in overrides:
            continue
        old = overrides.pop(f)["value"]
        changes.append(_change(a, user, "reset", f, old, auto.get(f, F.EMPTY[f]), reason))
    return overrides, changes


def _change(a: Asset, user: User | None, kind: str, field: str | None, old, new, reason: str) -> AssetChange:
    return AssetChange(
        asset_id=a.id,
        engagement_id=a.engagement_id,
        user_id=user.id if user else None,
        actor=actor_name(user),
        kind=kind,
        field=field,
        old=old,
        new=new,
        reason=reason,
    )


def edit(
    db: Session,
    a: Asset,
    user: User | None,
    *,
    set_: dict[str, Any],
    reset: list[str],
    reason: str,
    expected_version: int | None,
) -> int:
    """Apply one asset edit with optimistic locking. Returns the number of field changes. Caller commits."""
    if expected_version is not None and expected_version != a.version:
        raise EditConflict
    overrides, changes = plan_changes(a, set_, reset, reason, user)
    if not changes and overrides == (a.overrides or {}):
        return 0
    lock_engagement(db, a.engagement_id)
    res = db.execute(
        update(Asset)
        .where(Asset.id == a.id, Asset.version == a.version)
        .values(overrides=overrides, version=a.version + 1, updated_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    if res.rowcount != 1:
        raise EditConflict
    db.add_all(changes)
    db.flush()
    db.refresh(a)
    return len(changes)


def parse_identifiers(
    ips: list[str], macs: list[str], *, limit: int = MAX_IDENTIFIERS
) -> tuple[list[str], list[str]]:
    if len(ips) + len(macs) > limit:
        raise F.FieldError(f"At most {limit} addresses per asset.")
    out_ips, out_macs = [], []
    for ip in ips:
        try:
            out_ips.append(str(ipaddress.ip_address(ip.strip())))
        except ValueError as exc:
            raise F.FieldError(f"Not an IP address: {ip[:60]!r}.") from exc
    for mac in macs:
        m = mac.strip().lower().replace("-", ":")
        if not MAC_RE.match(m):
            raise F.FieldError(f"Not a MAC address: {mac[:60]!r}.")
        out_macs.append(m)
    return sorted(set(out_ips)), sorted(set(out_macs))


def create_manual(
    db: Session, eid: int, user: User | None, *, ips: list[str], macs: list[str], values: dict, reason: str
) -> Asset:
    """Add an asset by hand (a device never seen on the wire). Caller commits."""
    ips, macs = parse_identifiers(ips, macs)
    clean = {f: F.validate(f, v) for f, v in values.items()}
    reason = F.validate_reason(reason)
    lock_engagement(db, eid)
    taken = {m for m in macs if _mac_owner(db, eid, m)}
    if taken:
        raise F.FieldError(f"Another asset already has MAC {sorted(taken)[0]}.")
    now = utcnow().isoformat()
    actor = actor_name(user)
    a = Asset(
        engagement_id=eid,
        origin=AssetOrigin.manual,
        macs=macs,
        ips=ips,
        declared={"ips": ips, "macs": macs},
        auto={},
        observed={"captures": 0},
        overrides={f: {"value": v, "reason": reason, "by": actor, "at": now} for f, v in clean.items()},
    )
    db.add(a)
    db.flush()
    db.add(_change(a, user, "created", None, None, None, reason))
    for f, v in clean.items():
        db.add(_change(a, user, "override", f, F.EMPTY[f], v, reason))
    db.flush()
    return a


def _mac_owner(db: Session, eid: int, mac: str) -> Asset | None:
    for a in db.scalars(select(Asset).where(Asset.engagement_id == eid)):
        if mac in (a.macs or []):
            return a
    return None


def has_sightings(db: Session, a: Asset) -> bool:
    return db.scalar(select(AssetSighting.id).where(AssetSighting.asset_id == a.id).limit(1)) is not None
