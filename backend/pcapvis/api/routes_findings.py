"""Findings workspace: list, triage, manual findings (M8)."""

from fastapi import APIRouter, Depends, HTTPException, Path, status

from pcapvis import findings as FN
from pcapvis.api.routes_engagements import as_editor, as_viewer
from pcapvis.api.schemas import ErrorOut, FindingCreate, FindingOut, FindingUpdate
from pcapvis.db.base import utcnow
from pcapvis.db.models import Finding
from pcapvis.engagements import audit

router = APIRouter(prefix="/api", tags=["findings"])
KEY = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def _out(db, eid: int, key: str) -> FindingOut:
    return next(f for f in FN.list_findings(db, eid) if f.key == key)


@router.get("/engagements/{engagement_id}/findings", response_model=list[FindingOut])
def list_findings(ctx=Depends(as_viewer)) -> list[FindingOut]:
    eng, _r, _u, db = ctx
    return FN.list_findings(db, eng.id)


@router.post(
    "/engagements/{engagement_id}/findings",
    response_model=FindingOut,
    status_code=201,
    responses={422: {"model": ErrorOut}},
)
def create_finding(body: FindingCreate, ctx=Depends(as_editor)) -> FindingOut:
    eng, _r, user, db = ctx
    try:
        assets = FN.valid_assets(db, eng.id, body.asset_ids)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    f = FN.new_manual(eng.id, user)
    f.title, f.description, f.severity = body.title.strip(), body.description, body.severity
    f.recommendation, f.asset_ids = body.recommendation, assets
    db.add(f)
    eng.touch()
    audit.record(db, user, "finding.create", engagement_id=eng.id, target=f.title)
    db.commit()
    return _out(db, eng.id, f.key)


@router.patch(
    "/engagements/{engagement_id}/findings/{key}",
    response_model=FindingOut,
    responses={404: {"model": ErrorOut}, 422: {"model": ErrorOut}},
)
def update_finding(body: FindingUpdate, key: str = KEY, ctx=Depends(as_editor)) -> FindingOut:
    eng, _r, user, db = ctx
    existing = db.query(Finding).filter(Finding.engagement_id == eng.id, Finding.key == key).one_or_none()
    if existing is None and not FN.known_rule_key(db, eng.id, key):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found.")
    t = existing or FN.triage_row(db, eng.id, key)
    manual_only = {"title", "description", "asset_ids"} & body.model_fields_set
    if manual_only and t.source != "manual":
        if body.asset_ids is None or manual_only != {"asset_ids"}:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "Title and description of rule findings come from the rule.",
            )
    if body.status is not None:
        t.status = body.status
    if body.clear_severity_override:
        t.severity_override = None
    elif body.severity_override is not None:
        t.severity_override = body.severity_override
    for field in ("notes", "recommendation"):
        if getattr(body, field) is not None:
            setattr(t, field, getattr(body, field))
    if "include_in_report" in body.model_fields_set:
        t.include_in_report = body.include_in_report
    if body.title is not None:
        t.title = body.title.strip()
    if body.description is not None:
        t.description = body.description
    if body.asset_ids is not None:
        try:
            t.asset_ids = FN.valid_assets(db, eng.id, body.asset_ids)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    t.updated_by, t.updated_at = user.username, utcnow()
    eng.touch()
    audit.record(
        db,
        user,
        "finding.update",
        engagement_id=eng.id,
        target=t.title or key,
        details={
            k: v
            for k, v in body.model_dump(exclude_unset=True).items()
            if k in ("status", "severity_override", "include_in_report")
        },
    )
    db.commit()
    return _out(db, eng.id, key)


@router.delete(
    "/engagements/{engagement_id}/findings/{key}", status_code=204, responses={409: {"model": ErrorOut}}
)
def delete_finding(key: str = KEY, ctx=Depends(as_editor)) -> None:
    """Delete a manual finding. Rule findings can't be deleted (mark them false positive instead)."""
    eng, _r, user, db = ctx
    f = db.query(Finding).filter(Finding.engagement_id == eng.id, Finding.key == key).one_or_none()
    if f is None and not FN.known_rule_key(db, eng.id, key):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found.")
    if f is None or f.source != "manual":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Rule findings come back with every analysis; mark it false positive instead.",
        )
    db.delete(f)
    eng.touch()
    audit.record(db, user, "finding.delete", engagement_id=eng.id, target=f.title)
    db.commit()
