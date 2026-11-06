"""Engagements, members, capture points, audit log."""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pcapvis.api.deps import current_user, get_db, get_settings_dep
from pcapvis.api.schemas import (
    AuditEventOut,
    CapturePointIn,
    CapturePointOut,
    CapturePointUpdate,
    DirectoryUser,
    EngagementCreate,
    EngagementOut,
    EngagementUpdate,
    ErrorOut,
    MemberOut,
    MemberSet,
)
from pcapvis.config import Settings
from pcapvis.db.models import (
    MAX_MEMBER_ROLE,
    AuditEvent,
    Capture,
    CapturePoint,
    Engagement,
    EngagementMember,
    EngagementStatus,
    MemberRole,
    User,
)
from pcapvis.engagements import access, audit
from pcapvis.engagements.storage import Storage

router = APIRouter(prefix="/api", tags=["engagements"])
NOT_FOUND = "Engagement not found."


class EngagementAccess:
    """Dependency: load the engagement from the path and require at least ``minimum`` role in it."""

    def __init__(self, minimum: MemberRole):
        self.minimum = minimum

    def __call__(
        self,
        engagement_id: int = Path(ge=1),
        user: User = Depends(current_user),
        db: Session = Depends(get_db),
    ) -> tuple[Engagement, MemberRole, User, Session]:
        eng = db.get(Engagement, engagement_id)
        role = access.member_role(db, user, eng) if eng else None
        if eng is None or role is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)  # don't reveal it exists
        if not role.at_least(self.minimum):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"This needs the {self.minimum.value} role in the engagement."
            )
        return eng, role, user, db


as_viewer = EngagementAccess(MemberRole.viewer)
as_editor = EngagementAccess(MemberRole.editor)
as_lead = EngagementAccess(MemberRole.lead)


def storage(request: Request) -> Storage:
    return Storage(request.app.state.settings.data_dir)


def engagement_out(db: Session, eng: Engagement, role: MemberRole) -> EngagementOut:
    captures = (
        db.scalar(select(func.count()).select_from(Capture).where(Capture.engagement_id == eng.id)) or 0
    )
    members = (
        db.scalar(
            select(func.count()).select_from(EngagementMember).where(EngagementMember.engagement_id == eng.id)
        )
        or 0
    )
    return EngagementOut(
        id=eng.id,
        name=eng.name,
        client=eng.client,
        site=eng.site,
        description=eng.description,
        status=eng.status,
        is_quicklook=eng.is_quicklook,
        created_at=eng.created_at,
        updated_at=eng.updated_at,
        revision=eng.revision,
        my_role=role,
        capture_count=captures,
        member_count=members,
    )


def create_engagement(
    db: Session, user: User, body: EngagementCreate, *, quicklook: bool = False
) -> Engagement:
    eng = Engagement(
        name=body.name.strip(),
        client=body.client.strip(),
        site=body.site.strip(),
        description=body.description,
        is_quicklook=quicklook,
        created_by=user.id,
    )
    db.add(eng)
    db.flush()
    db.add(EngagementMember(engagement_id=eng.id, user_id=user.id, role=MemberRole.lead))
    audit.record(
        db, user, "engagement.create", engagement_id=eng.id, target=eng.name, details={"quicklook": quicklook}
    )
    db.commit()
    return eng


# ── engagements ───────────────────────────────────────────────────────────────


@router.get("/engagements", response_model=list[EngagementOut])
def list_engagements(
    include_archived: bool = False,
    quicklook: bool = Query(default=False, description="List Quick looks instead of engagements"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[EngagementOut]:
    q = access.visible_engagements(db, user).where(Engagement.is_quicklook.is_(quicklook))
    if quicklook:
        q = q.where(Engagement.created_by == user.id)  # Quick looks are personal
    if not include_archived:
        q = q.where(Engagement.status == EngagementStatus.active)
    out = []
    for eng in db.scalars(q.order_by(Engagement.updated_at.desc())):
        out.append(engagement_out(db, eng, access.member_role(db, user, eng)))
    return out


@router.post(
    "/engagements", response_model=EngagementOut, status_code=201, responses={403: {"model": ErrorOut}}
)
def create(
    body: EngagementCreate, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> EngagementOut:
    if not access.can_create_engagement(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only leads and admins can create engagements.")
    eng = create_engagement(db, user, body)
    return engagement_out(db, eng, MemberRole.lead)


@router.get(
    "/engagements/{engagement_id}", response_model=EngagementOut, responses={404: {"model": ErrorOut}}
)
def get_engagement(ctx=Depends(as_viewer)) -> EngagementOut:
    eng, role, _user, db = ctx
    return engagement_out(db, eng, role)


@router.patch("/engagements/{engagement_id}", response_model=EngagementOut)
def update_engagement(body: EngagementUpdate, ctx=Depends(as_lead)) -> EngagementOut:
    eng, role, user, db = ctx
    changes = body.model_dump(exclude_unset=True)
    if eng.is_quicklook and changes.get("is_quicklook") is False and not access.can_create_engagement(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Only leads and admins can turn a Quick look into an engagement."
        )
    for key, value in changes.items():
        setattr(eng, key, value.strip() if isinstance(value, str) and key != "description" else value)
    eng.touch()
    audit.record(
        db,
        user,
        "engagement.update",
        engagement_id=eng.id,
        target=eng.name,
        details={k: str(v) for k, v in changes.items()},
    )
    db.commit()
    return engagement_out(db, eng, role)


@router.delete("/engagements/{engagement_id}", status_code=204)
def delete_engagement(ctx=Depends(as_lead), store: Storage = Depends(storage)) -> None:
    eng, _role, user, db = ctx
    if any(c.status.value in ("queued", "processing") for c in eng.captures):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Cancel running analyses before deleting the engagement."
        )
    eid, name = eng.id, eng.name
    db.delete(eng)
    audit.record(db, user, "engagement.delete", target=name, details={"engagement_id": eid})
    db.commit()
    store.delete_engagement(eid)


# ── members (server mode) ─────────────────────────────────────────────────────


def _server_only(settings: Settings = Depends(get_settings_dep)) -> None:
    if not settings.auth_required:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Members are only used in server mode.")


def member_out(m: EngagementMember) -> MemberOut:
    return MemberOut(
        user_id=m.user_id,
        username=m.user.username,
        display_name=m.user.display_name,
        role=m.role,
        global_role=m.user.role,
        max_role=MAX_MEMBER_ROLE[m.user.role],
    )


@router.get("/engagements/{engagement_id}/members", response_model=list[MemberOut])
def list_members(ctx=Depends(as_viewer)) -> list[MemberOut]:
    eng, _role, _user, _db = ctx
    return sorted((member_out(m) for m in eng.members), key=lambda m: (-m.role.rank, m.username))


@router.put(
    "/engagements/{engagement_id}/members/{user_id}",
    response_model=MemberOut,
    dependencies=[Depends(_server_only)],
    responses={400: {"model": ErrorOut}},
)
def set_member(body: MemberSet, user_id: int = Path(ge=1), ctx=Depends(as_lead)) -> MemberOut:
    eng, _role, actor, db = ctx
    target = db.get(User, user_id)
    if target is None or not target.is_active or target.password_hash is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    if eng.is_quicklook:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Quick looks are personal. Promote it to an engagement first."
        )
    cap = MAX_MEMBER_ROLE[target.role]
    if not cap.at_least(body.role):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{target.username} is a {target.role.value}; the highest engagement role they can hold is {cap.value}.",
        )
    m = db.get(EngagementMember, (eng.id, user_id))
    if m is None:
        m = EngagementMember(engagement_id=eng.id, user_id=user_id, role=body.role)
        db.add(m)
    else:
        if (
            m.role == MemberRole.lead
            and body.role != MemberRole.lead
            and _lead_count(eng, exclude=user_id) == 0
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "An engagement needs at least one lead.")
        m.role = body.role
    eng.touch()
    audit.record(
        db, actor, "member.set", engagement_id=eng.id, target=target.username, details={"role": body.role}
    )
    db.commit()
    db.refresh(m)
    return member_out(m)


@router.delete(
    "/engagements/{engagement_id}/members/{user_id}", status_code=204, dependencies=[Depends(_server_only)]
)
def remove_member(user_id: int = Path(ge=1), ctx=Depends(as_lead)) -> None:
    eng, _role, actor, db = ctx
    m = db.get(EngagementMember, (eng.id, user_id))
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not a member.")
    if m.role == MemberRole.lead and _lead_count(eng, exclude=user_id) == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "An engagement needs at least one lead.")
    name = m.user.username
    db.delete(m)
    eng.touch()
    audit.record(db, actor, "member.remove", engagement_id=eng.id, target=name)
    db.commit()


def _lead_count(eng: Engagement, exclude: int) -> int:
    return sum(
        1 for m in eng.members if m.role == MemberRole.lead and m.user_id != exclude and m.user.is_active
    )


@router.get("/directory", response_model=list[DirectoryUser], dependencies=[Depends(_server_only)])
def directory(user: User = Depends(current_user), db: Session = Depends(get_db)) -> list[DirectoryUser]:
    """Active accounts, for leads choosing engagement members."""
    if not access.can_create_engagement(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only leads and admins can browse the user directory.")
    users = db.scalars(
        select(User).where(User.is_active.is_(True), User.password_hash.is_not(None)).order_by(User.username)
    )
    return [
        DirectoryUser(id=u.id, username=u.username, display_name=u.display_name, role=u.role) for u in users
    ]


# ── capture points ────────────────────────────────────────────────────────────


@router.get("/engagements/{engagement_id}/capture-points", response_model=list[CapturePointOut])
def list_points(ctx=Depends(as_viewer)) -> list[CapturePoint]:
    return list(ctx[0].capture_points)


@router.post(
    "/engagements/{engagement_id}/capture-points",
    response_model=CapturePointOut,
    status_code=201,
    responses={409: {"model": ErrorOut}},
)
def create_point(body: CapturePointIn, ctx=Depends(as_editor)) -> CapturePoint:
    eng, _role, user, db = ctx
    point = CapturePoint(engagement_id=eng.id, name=body.name.strip(), description=body.description)
    db.add(point)
    eng.touch()
    audit.record(db, user, "capture_point.create", engagement_id=eng.id, target=point.name)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A capture point with that name already exists."
        ) from None
    return point


def _point(eng: Engagement, db: Session, point_id: int) -> CapturePoint:
    p = db.get(CapturePoint, point_id)
    if p is None or p.engagement_id != eng.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture point not found.")
    return p


@router.patch("/engagements/{engagement_id}/capture-points/{point_id}", response_model=CapturePointOut)
def update_point(
    body: CapturePointUpdate, point_id: int = Path(ge=1), ctx=Depends(as_editor)
) -> CapturePoint:
    eng, _role, user, db = ctx
    p = _point(eng, db, point_id)
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(p, key, value.strip() if key == "name" else value)
    eng.touch()
    audit.record(db, user, "capture_point.update", engagement_id=eng.id, target=p.name)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "A capture point with that name already exists."
        ) from None
    return p


@router.delete("/engagements/{engagement_id}/capture-points/{point_id}", status_code=204)
def delete_point(point_id: int = Path(ge=1), ctx=Depends(as_editor)) -> None:
    eng, _role, user, db = ctx
    p = _point(eng, db, point_id)
    name = p.name
    db.delete(p)  # captures keep existing; their capture point becomes empty
    eng.touch()
    audit.record(db, user, "capture_point.delete", engagement_id=eng.id, target=name)
    db.commit()


# ── audit log ─────────────────────────────────────────────────────────────────


@router.get("/engagements/{engagement_id}/audit", response_model=list[AuditEventOut])
def audit_log(limit: int = Query(default=100, ge=1, le=1000), ctx=Depends(as_viewer)) -> list[AuditEventOut]:
    eng, _role, _user, db = ctx
    rows = db.execute(
        select(AuditEvent, User.username)
        .outerjoin(User, User.id == AuditEvent.user_id)
        .where(AuditEvent.engagement_id == eng.id)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
    )
    return [
        AuditEventOut(id=e.id, at=e.at, user=name, action=e.action, target=e.target, details=e.details)
        for e, name in rows
    ]
