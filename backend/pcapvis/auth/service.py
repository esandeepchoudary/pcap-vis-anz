"""Local accounts: password hashing, users, login sessions, and login throttling.

Kept behind plain functions so an SSO provider (Entra ID, Okta, LDAP) can be added later
as another way to produce an authenticated User without touching the routes.
"""

import hashlib
import re
import secrets
import threading
import time
from datetime import timedelta

from pwdlib import PasswordHash
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from pcapvis.db.base import utcnow
from pcapvis.db.models import AuthSession, Role, User

LOCAL_USERNAME = "local"  # built-in laptop-mode user
MIN_PASSWORD_LENGTH = 10
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")

_hasher = PasswordHash.recommended()  # argon2id
# Verified against when the username doesn't exist, so timing doesn't reveal valid usernames.
_DUMMY_HASH = _hasher.hash("timing-equaliser-not-a-real-password")


class AuthError(Exception):
    """Raised for invalid input to account operations (message is safe to show)."""


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_username(username: str) -> str:
    name = normalize_username(username)
    if not USERNAME_RE.fullmatch(name):
        raise AuthError(
            "Username must be 2-64 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit."
        )
    if name == LOCAL_USERNAME:
        raise AuthError(f"'{LOCAL_USERNAME}' is reserved.")
    return name


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > 1024:
        raise AuthError("Password is too long.")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        _hasher.verify(password, _DUMMY_HASH)
        return False
    return _hasher.verify(password, password_hash)


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == normalize_username(username)))


def count_users(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


def create_user(db: Session, username: str, password: str, role: Role, display_name: str = "") -> User:
    name = validate_username(username)
    validate_password(password)
    if get_user_by_username(db, name):
        raise AuthError(f"User '{name}' already exists.")
    user = User(
        username=name,
        display_name=display_name.strip()[:128] or name,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    return user


def ensure_local_user(db: Session) -> User:
    """Laptop mode: a single built-in admin user that never needs a password."""
    user = db.scalar(select(User).where(User.username == LOCAL_USERNAME))
    if user is None:
        user = User(
            username=LOCAL_USERNAME,
            display_name="Local user",
            password_hash=None,
            role=Role.admin,
            is_active=True,
        )
        db.add(user)
        db.commit()
    return user


def count_active_admins(db: Session, exclude_user_id: int | None = None) -> int:
    q = (
        select(func.count())
        .select_from(User)
        .where(User.role == Role.admin, User.is_active.is_(True), User.password_hash.is_not(None))
    )
    if exclude_user_id is not None:
        q = q.where(User.id != exclude_user_id)
    return db.scalar(q) or 0


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = get_user_by_username(db, username)
    if user is None or not user.is_active:
        verify_password(password, None)  # same cost as a real check
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


# ── Sessions ───────────────────────────────────────────────────────────────────


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, ttl_hours: int, user_agent: str = "") -> str:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(
        AuthSession(
            token_hash=_hash_token(token),
            user_id=user.id,
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
            user_agent=user_agent[:256],
        )
    )
    user.last_login_at = now
    db.commit()
    return token


def user_for_token(db: Session, token: str | None) -> User | None:
    if not token:
        return None
    sess = db.get(AuthSession, _hash_token(token))
    if sess is None:
        return None
    if sess.expires_at <= utcnow() or not sess.user.is_active:
        db.delete(sess)
        db.commit()
        return None
    return sess.user


def delete_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(
            delete(AuthSession).where(AuthSession.token_hash == _hash_token(token)),
            execution_options={"synchronize_session": False},
        )
        db.commit()


def delete_user_sessions(db: Session, user_id: int, keep_token: str | None = None) -> None:
    q = delete(AuthSession).where(AuthSession.user_id == user_id)
    if keep_token:
        q = q.where(AuthSession.token_hash != _hash_token(keep_token))
    db.execute(q, execution_options={"synchronize_session": False})
    db.expire_all()
    db.commit()


def purge_expired_sessions(db: Session) -> int:
    result = db.execute(
        delete(AuthSession).where(AuthSession.expires_at <= utcnow()),
        execution_options={"synchronize_session": False},
    )
    db.expire_all()
    db.commit()
    return result.rowcount or 0


# ── Login throttling ───────────────────────────────────────────────────────────


class LoginThrottle:
    """Limits failed sign-ins, in memory, within a sliding window:

    - per (username, client): ``max_failures`` (guessing one account);
    - per client: ``max_client_failures`` across all usernames (password spraying).

    ``begin()`` checks and counts an attempt in one step, so parallel guesses can't all slip past the check
    while the slow password hash runs; ``reset()`` un-counts it when the sign-in succeeds. Memory is bounded
    by ``max_keys``.
    """

    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 900,
        clock=time.monotonic,
        max_client_failures: int = 30,
        max_keys: int = 10_000,
    ):
        self.max_failures = max_failures
        self.max_client_failures = max_client_failures
        self.window = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._failures: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _keys(username: str, client: str) -> tuple[tuple[str, str], tuple[str, str]]:
        return (normalize_username(username), client), ("\x00client", client)

    def _recent(self, key: tuple[str, str]) -> list[float]:
        cutoff = self._clock() - self.window
        recent = [t for t in self._failures.get(key, []) if t > cutoff]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def _blocked(self, user_key, client_key) -> bool:
        return (
            len(self._recent(user_key)) >= self.max_failures
            or len(self._recent(client_key)) >= self.max_client_failures
        )

    def _add(self, *keys) -> None:
        now = self._clock()
        for key in keys:
            self._failures.setdefault(key, []).append(now)
        if len(self._failures) > self.max_keys:
            for key in list(self._failures):
                self._recent(key)  # drop expired entries
            while len(self._failures) > self.max_keys:  # still full: forget the oldest keys
                del self._failures[next(iter(self._failures))]

    def is_blocked(self, username: str, client: str) -> bool:
        with self._lock:
            return self._blocked(*self._keys(username, client))

    def begin(self, username: str, client: str) -> bool:
        """Count a sign-in attempt as a failure up front. False (and nothing counted) when blocked."""
        with self._lock:
            keys = self._keys(username, client)
            if self._blocked(*keys):
                return False
            self._add(*keys)
            return True

    def record_failure(self, username: str, client: str) -> None:
        with self._lock:
            self._add(*self._keys(username, client))

    def reset(self, username: str, client: str) -> None:
        """A successful sign-in: clear the account's failures and un-count this attempt for the client."""
        with self._lock:
            user_key, client_key = self._keys(username, client)
            self._failures.pop(user_key, None)
            attempts = self._failures.get(client_key)
            if attempts:
                attempts.pop()
                if not attempts:
                    del self._failures[client_key]
