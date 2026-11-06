from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.deps import get_db, get_settings_dep, require_role
from pcapvis.api.schemas import ErrorOut, UserCreate, UserOut, UserUpdate
from pcapvis.auth import service as auth
from pcapvis.config import Settings
from pcapvis.db.models import Role, User

router = APIRouter(prefix="/api/users", tags=["users"])
admin_only = require_role(Role.admin)


def _server_only(settings: Settings = Depends(get_settings_dep)) -> None:
    if not settings.auth_required:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User accounts are only used in server mode.")


@router.get("", response_model=list[UserOut], dependencies=[Depends(_server_only)])
def list_users(_: User = Depends(admin_only), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).where(User.password_hash.is_not(None)).order_by(User.username)))


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_server_only)],
    responses={400: {"model": ErrorOut}},
)
def create_user(body: UserCreate, _: User = Depends(admin_only), db: Session = Depends(get_db)) -> User:
    try:
        return auth.create_user(db, body.username, body.password, body.role, body.display_name)
    except auth.AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.patch(
    "/{user_id}",
    response_model=UserOut,
    dependencies=[Depends(_server_only)],
    responses={400: {"model": ErrorOut}, 404: {"model": ErrorOut}},
)
def update_user(
    user_id: int, body: UserUpdate, admin: User = Depends(admin_only), db: Session = Depends(get_db)
) -> User:
    user = db.get(User, user_id)
    if user is None or user.password_hash is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    losing_admin = (body.role is not None and body.role != Role.admin) or body.is_active is False
    last_admin = auth.count_active_admins(db, exclude_user_id=user.id) == 0
    if user.role == Role.admin and losing_admin and last_admin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "There must be at least one active admin.")
    if body.display_name is not None:
        user.display_name = body.display_name.strip() or user.username
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password is not None:
        try:
            auth.validate_password(body.password)
        except auth.AuthError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        user.password_hash = auth.hash_password(body.password)
    db.commit()
    if body.password is not None or body.is_active is False or body.role is not None:
        auth.delete_user_sessions(db, user.id)  # force re-login with the new access
    return user
