"""Findings workspace: rule findings merged across captures, analyst triage, manual findings (M8)."""

import uuid
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.schemas import FindingOut
from pcapvis.db.base import utcnow
from pcapvis.db.models import Asset, Finding, FindingHit, User

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
NOT_REPORTED = {"false_positive"}


def _merge_hits(hits: list[FindingHit]) -> dict[str, dict]:
    merged: dict[str, dict] = {}
    for h in sorted(hits, key=lambda h: (h.capture_id, h.id)):
        d = h.data
        m = merged.get(h.key)
        if m is None:
            m = merged[h.key] = {
                **d,
                "evidence": list(d.get("evidence", [])),
                "captures": [],
                "count": 0,
                "assets": set(),
            }
        m["count"] += d.get("count", 1)
        m["captures"].append(h.capture_id)
        for k, pick in (("first_seen", min), ("last_seen", max)):
            vals = [v for v in (m.get(k), d.get(k)) if v is not None]
            m[k] = pick(vals) if vals else None
        for e in d.get("evidence", []):
            if e not in m["evidence"] and len(m["evidence"]) < 20:
                m["evidence"].append(e)
        m["assets"] |= {a for a in (d.get("src_asset"), d.get("dst_asset")) if a}
    return merged


def list_findings(db: Session, eid: int) -> list[FindingOut]:
    hits = list(db.scalars(select(FindingHit).where(FindingHit.engagement_id == eid)))
    merged = _merge_hits(hits)
    triage = {f.key: f for f in db.scalars(select(Finding).where(Finding.engagement_id == eid))}
    out: list[FindingOut] = []
    for key, m in merged.items():
        t = triage.get(key)
        status = t.status if t else "open"
        out.append(
            FindingOut(
                key=key,
                source="rule",
                rule=m.get("rule"),
                category=m.get("category"),
                title=m.get("title", ""),
                description=m.get("description", ""),
                severity=(t.severity_override if t and t.severity_override else m["severity"]),
                detected_severity=m["severity"],
                attack=m.get("attack", []),
                evidence=m["evidence"],
                asset_ids=sorted(m["assets"] | set(t.asset_ids if t else [])),
                src=m.get("src"),
                dst=m.get("dst"),
                count=m["count"],
                first_seen=m.get("first_seen"),
                last_seen=m.get("last_seen"),
                captures=m["captures"],
                status=status,
                notes=t.notes if t else "",
                recommendation=t.recommendation if t else "",
                include_in_report=_included(t, status),
                updated_by=t.updated_by if t else "",
                updated_at=t.updated_at if t else None,
            )
        )
    for t in triage.values():
        if t.source != "manual":
            continue
        out.append(
            FindingOut(
                key=t.key,
                source="manual",
                rule=None,
                category=None,
                title=t.title,
                description=t.description,
                severity=t.severity_override or t.severity or "info",
                detected_severity=None,
                attack=[],
                evidence=[],
                asset_ids=sorted(t.asset_ids or []),
                src=None,
                dst=None,
                count=1,
                first_seen=None,
                last_seen=None,
                captures=[],
                status=t.status,
                notes=t.notes,
                recommendation=t.recommendation,
                include_in_report=_included(t, t.status),
                updated_by=t.updated_by,
                updated_at=t.updated_at,
            )
        )
    out.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.status in NOT_REPORTED, -(f.count or 0), f.title))
    return out


def _included(t: Finding | None, status: str) -> bool:
    if t is not None and t.include_in_report is not None:
        return t.include_in_report
    return status not in NOT_REPORTED


def known_rule_key(db: Session, eid: int, key: str) -> bool:
    return (
        db.scalar(
            select(FindingHit.id).where(FindingHit.engagement_id == eid, FindingHit.key == key).limit(1)
        )
        is not None
    )


def valid_assets(db: Session, eid: int, ids: list[int]) -> list[int]:
    found = (
        set(db.scalars(select(Asset.id).where(Asset.engagement_id == eid, Asset.id.in_(ids))))
        if ids
        else set()
    )
    if found != set(ids):
        raise ValueError("Some of those assets don't exist in this engagement.")
    return sorted(found)


def triage_row(db: Session, eid: int, key: str) -> Finding:
    t = db.scalar(select(Finding).where(Finding.engagement_id == eid, Finding.key == key))
    if t is None:
        t = Finding(engagement_id=eid, key=key, source="rule", asset_ids=[])
        db.add(t)
    return t


def new_manual(eid: int, user: User | None) -> Finding:
    return Finding(
        engagement_id=eid,
        key=f"manual-{uuid.uuid4().hex[:16]}",
        source="manual",
        updated_by=user.username if user else "",
        updated_at=utcnow(),
    )


def counts_by_severity(findings: list[FindingOut]) -> dict[str, int]:
    c: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.include_in_report:
            c[f.severity] += 1
    return {s: c.get(s, 0) for s in SEVERITY_ORDER}
