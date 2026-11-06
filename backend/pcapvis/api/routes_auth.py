from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from pcapvis.api.deps import SESSION_COOKIE, current_user, get_db, get_settings_dep
from pcapvis.api.schemas import ErrorOut, LoginRequest, PasswordChange, UserOut
from pcapvis.auth import service as auth
from pcapvis.config import Settings
from pcapvis.db.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=UserOut, responses={401: {"model": ErrorOut}, 429: {"model": ErrorOut}})
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> User:
    if not settings.auth_required:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sign-in is not used in laptop mode.")
    throttle: auth.LoginThrottle = request.app.state.login_throttle
    client = _client(request)
    if throttle.is_blocked(body.username, client):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Too many failed sign-in attempts. Try again in 15 minutes.")
    user = auth.authenticate(db, body.username, body.password)
    if user is None:
        throttle.record_failure(body.username, client)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password.")
    throttle.reset(body.username, client)
    token = auth.create_session(db, user, settings.session_ttl_hours, request.headers.get("user-agent", ""))
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True, samesite="strict", secure=settings.cookie_secure, path="/",
    )
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> None:
    auth.delete_session(db, request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/me", response_model=UserOut, responses={401: {"model": ErrorOut}})
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT, responses={400: {"model": ErrorOut}})
def change_password(
    body: PasswordChange,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> None:
    if user.password_hash is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This account has no password.")
    if not auth.verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is wrong.")
    try:
        auth.validate_password(body.new_password)
    except auth.AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    user.password_hash = auth.hash_password(body.new_password)
    db.commit()
    # Sign out every other session for this user.
    auth.delete_user_sessions(db, user.id, keep_token=request.cookies.get(SESSION_COOKIE))
