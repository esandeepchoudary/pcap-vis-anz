"""Zones and conduits (IEC 62443), violations, and inferred networks (M6)."""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from pcapvis import zones as Z
from pcapvis.api.routes_engagements import as_editor, as_viewer
from pcapvis.api.schemas import (
    ConduitIn,
    ConduitOut,
    ConduitUpdate,
    ErrorOut,
    NetworkOut,
    ViolationOut,
    ZoneIn,
    ZoneOut,
    ZoneUpdate,
)
from pcapvis.assets.fields import FieldError
from pcapvis.db.models import Conduit, Engagement, Zone
from pcapvis.engagements import audit

router = APIRouter(prefix="/api", tags=["zones"])
E422 = {422: {"model": ErrorOut}, 409: {"model": ErrorOut}}


def _zone(eng: Engagement, db, zid: int) -> Zone:
    z = db.get(Zone, zid)
    if z is None or z.engagement_id != eng.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zone not found.")
    return z


def _conduit(eng: Engagement, db, cid: int) -> Conduit:
    c = db.get(Conduit, cid)
    if c is None or c.engagement_id != eng.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conduit not found.")
    return c


def _bad(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


def _one(db, eid: int, name: str) -> ZoneOut:
    return next(z for z in Z.list_zones(db, eid) if z.name == name)


@router.get("/engagements/{engagement_id}/zones", response_model=list[ZoneOut])
def list_zones(ctx=Depends(as_viewer)) -> list[ZoneOut]:
    eng, _r, _u, db = ctx
    return Z.list_zones(db, eng.id)


@router.post("/engagements/{engagement_id}/zones", response_model=ZoneOut, status_code=201, responses=E422)
def create_zone(body: ZoneIn, ctx=Depends(as_editor)) -> ZoneOut:
    eng, _r, user, db = ctx
    try:
        z = Zone(
            engagement_id=eng.id,
            name=Z.clean_name(body.name),
            purdue_level=Z.check_level(body.purdue_level),
            security_level=body.security_level,
            description=body.description,
        )
    except FieldError as exc:
        raise _bad(exc) from exc
    db.add(z)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A zone with that name already exists.") from exc
    eng.touch()
    audit.record(db, user, "zone.create", engagement_id=eng.id, target=z.name)
    db.commit()
    return _one(db, eng.id, z.name)


@router.patch("/engagements/{engagement_id}/zones/{zone_id}", response_model=ZoneOut, responses=E422)
def update_zone(body: ZoneUpdate, zone_id: int = Path(ge=1), ctx=Depends(as_editor)) -> ZoneOut:
    eng, _r, user, db = ctx
    z = _zone(eng, db, zone_id)
    fields = body.model_fields_set
    try:
        if body.name is not None and body.name.strip() != z.name:
            new = Z.clean_name(body.name)
            if db.scalar(select(Zone.id).where(Zone.engagement_id == eng.id, Zone.name == new)):
                raise HTTPException(status.HTTP_409_CONFLICT, "A zone with that name already exists.")
            moved = Z.rename_zone(db, eng.id, z.name, new, user)
            audit.record(
                db,
                user,
                "zone.rename",
                engagement_id=eng.id,
                target=new,
                details={"from": z.name, "assets": moved},
            )
            z.name = new
        if "purdue_level" in fields:
            z.purdue_level = Z.check_level(body.purdue_level)
    except FieldError as exc:
        db.rollback()
        raise _bad(exc) from exc
    if "security_level" in fields:
        z.security_level = body.security_level
    if body.description is not None:
        z.description = body.description
    if "x" in fields and "y" in fields:
        z.x, z.y = body.x, body.y
    eng.touch()
    db.commit()
    return _one(db, eng.id, z.name)


@router.delete("/engagements/{engagement_id}/zones/{zone_id}", status_code=204)
def delete_zone(zone_id: int = Path(ge=1), ctx=Depends(as_editor)) -> None:
    """Removes the zone and its conduits. Assets keep the zone name (it shows as an undefined zone)."""
    eng, _r, user, db = ctx
    z = _zone(eng, db, zone_id)
    for c in db.scalars(select(Conduit).where((Conduit.zone_a_id == z.id) | (Conduit.zone_b_id == z.id))):
        db.delete(c)
    db.delete(z)
    eng.touch()
    audit.record(db, user, "zone.delete", engagement_id=eng.id, target=z.name)
    db.commit()


@router.get("/engagements/{engagement_id}/conduits", response_model=list[ConduitOut])
def list_conduits(ctx=Depends(as_viewer)) -> list[Conduit]:
    eng, _r, _u, db = ctx
    return list(db.scalars(select(Conduit).where(Conduit.engagement_id == eng.id).order_by(Conduit.id)))


@router.post(
    "/engagements/{engagement_id}/conduits", response_model=ConduitOut, status_code=201, responses=E422
)
def create_conduit(body: ConduitIn, ctx=Depends(as_editor)) -> Conduit:
    eng, _r, user, db = ctx
    a, b = _zone(eng, db, body.zone_a_id), _zone(eng, db, body.zone_b_id)
    if a.id == b.id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A conduit connects two different zones.")
    pair = {a.id, b.id}
    if any(
        {c.zone_a_id, c.zone_b_id} == pair
        for c in db.scalars(select(Conduit).where(Conduit.engagement_id == eng.id))
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "These zones already have a conduit; edit it instead.")
    try:
        allowed = Z.clean_protocols(body.allowed)
    except FieldError as exc:
        raise _bad(exc) from exc
    c = Conduit(
        engagement_id=eng.id,
        zone_a_id=a.id,
        zone_b_id=b.id,
        name=body.name.strip(),
        allowed=allowed,
        description=body.description,
    )
    db.add(c)
    eng.touch()
    audit.record(db, user, "conduit.create", engagement_id=eng.id, target=f"{a.name} ↔ {b.name}")
    db.commit()
    return c


@router.patch("/engagements/{engagement_id}/conduits/{conduit_id}", response_model=ConduitOut, responses=E422)
def update_conduit(body: ConduitUpdate, conduit_id: int = Path(ge=1), ctx=Depends(as_editor)) -> Conduit:
    eng, _r, user, db = ctx
    c = _conduit(eng, db, conduit_id)
    if body.allowed is not None:
        try:
            c.allowed = Z.clean_protocols(body.allowed)
        except FieldError as exc:
            raise _bad(exc) from exc
    if body.name is not None:
        c.name = body.name.strip()
    if body.description is not None:
        c.description = body.description
    eng.touch()
    audit.record(db, user, "conduit.update", engagement_id=eng.id, target=c.name or f"conduit {c.id}")
    db.commit()
    return c


@router.delete("/engagements/{engagement_id}/conduits/{conduit_id}", status_code=204)
def delete_conduit(conduit_id: int = Path(ge=1), ctx=Depends(as_editor)) -> None:
    eng, _r, user, db = ctx
    c = _conduit(eng, db, conduit_id)
    db.delete(c)
    eng.touch()
    audit.record(db, user, "conduit.delete", engagement_id=eng.id, target=c.name or f"conduit {c.id}")
    db.commit()


@router.get("/engagements/{engagement_id}/violations", response_model=list[ViolationOut])
def violations(ctx=Depends(as_viewer)) -> list[ViolationOut]:
    eng, _r, _u, db = ctx
    return Z.violations(db, eng.id)


@router.get("/engagements/{engagement_id}/networks", response_model=list[NetworkOut])
def networks(ctx=Depends(as_viewer)) -> list[NetworkOut]:
    eng, _r, _u, db = ctx
    return Z.networks(db, eng.id)
