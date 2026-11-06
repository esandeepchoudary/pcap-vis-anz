"""Shared FastAPI dependencies: settings, DB session, current user, role checks."""

from collections.abc import Callable, Iterator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from pcapvis.auth import service as auth
from pcapvis.config import Settings
from pcapvis.db.models import Role, User

SESSION_COOKIE = "pcapvis_session"


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


def current_user(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)
) -> User:
    if not settings.auth_required:
        return auth.ensure_local_user(db)
    user = auth.user_for_token(db, request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in.")
    return user


def require_role(minimum: Role) -> Callable[[User], User]:
    def _check(user: User = Depends(current_user)) -> User:
        if not user.role.at_least(minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have permission to do that.")
        return user

    return _check
