from datetime import timedelta

import pytest

from pcapvis.auth import service as svc
from pcapvis.db.models import AuthSession, Role


def test_create_and_authenticate(db):
    svc.create_user(db, "Alice", "correct horse battery", Role.consultant)
    user = svc.authenticate(db, "alice", "correct horse battery")
    assert user is not None and user.username == "alice"  # stored lowercase
    assert user.password_hash != "correct horse battery"
    assert user.password_hash.startswith("$argon2id$")


def test_username_case_insensitive_login(db):
    svc.create_user(db, "bob", "correct horse battery", Role.viewer)
    assert svc.authenticate(db, "  BOB ", "correct horse battery") is not None


@pytest.mark.parametrize("bad", ["", "a", "has space", "UPPER!", "-leading", "x" * 65, "local", "Local"])
def test_invalid_usernames(db, bad):
    with pytest.raises(svc.AuthError):
        svc.create_user(db, bad, "correct horse battery", Role.viewer)


@pytest.mark.parametrize("bad", ["", "short", "123456789", "x" * 1025])
def test_invalid_passwords(db, bad):
    with pytest.raises(svc.AuthError):
        svc.create_user(db, "carol", bad, Role.viewer)


def test_duplicate_user_rejected(db):
    svc.create_user(db, "dave", "correct horse battery", Role.viewer)
    with pytest.raises(svc.AuthError, match="already exists"):
        svc.create_user(db, "DAVE", "another password1", Role.viewer)


def test_wrong_password_and_unknown_user(db):
    svc.create_user(db, "erin", "correct horse battery", Role.viewer)
    assert svc.authenticate(db, "erin", "wrong password!") is None
    assert svc.authenticate(db, "nobody", "correct horse battery") is None


def test_inactive_user_cannot_login(db):
    u = svc.create_user(db, "frank", "correct horse battery", Role.viewer)
    u.is_active = False
    db.commit()
    assert svc.authenticate(db, "frank", "correct horse battery") is None


def test_local_user_cannot_login_with_password(db):
    svc.ensure_local_user(db)
    assert svc.authenticate(db, "local", "") is None
    assert svc.authenticate(db, "local", "anything at all") is None


def test_ensure_local_user_idempotent(db):
    a = svc.ensure_local_user(db)
    b = svc.ensure_local_user(db)
    assert a.id == b.id and a.role == Role.admin and a.password_hash is None
    assert svc.count_users(db) == 1


def test_session_roundtrip_and_token_not_stored(db):
    u = svc.create_user(db, "gina", "correct horse battery", Role.viewer)
    token = svc.create_session(db, u, ttl_hours=1)
    assert svc.user_for_token(db, token).id == u.id
    stored = db.query(AuthSession).one()
    assert stored.token_hash != token and len(stored.token_hash) == 64
    assert u.last_login_at is not None


def test_bad_and_missing_tokens(db):
    assert svc.user_for_token(db, None) is None
    assert svc.user_for_token(db, "") is None
    assert svc.user_for_token(db, "not-a-real-token") is None


def test_expired_session_rejected_and_removed(db):
    u = svc.create_user(db, "hank", "correct horse battery", Role.viewer)
    token = svc.create_session(db, u, ttl_hours=1)
    sess = db.query(AuthSession).one()
    sess.expires_at = sess.created_at - timedelta(seconds=1)
    db.commit()
    assert svc.user_for_token(db, token) is None
    assert db.query(AuthSession).count() == 0


def test_session_of_deactivated_user_rejected(db):
    u = svc.create_user(db, "ivy", "correct horse battery", Role.viewer)
    token = svc.create_session(db, u, ttl_hours=1)
    u.is_active = False
    db.commit()
    assert svc.user_for_token(db, token) is None


def test_logout_and_delete_other_sessions(db):
    u = svc.create_user(db, "jack", "correct horse battery", Role.viewer)
    t1 = svc.create_session(db, u, 1)
    t2 = svc.create_session(db, u, 1)
    t3 = svc.create_session(db, u, 1)
    svc.delete_session(db, t1)
    assert svc.user_for_token(db, t1) is None
    svc.delete_user_sessions(db, u.id, keep_token=t2)
    assert svc.user_for_token(db, t2) is not None
    assert svc.user_for_token(db, t3) is None


def test_purge_expired(db):
    u = svc.create_user(db, "kim", "correct horse battery", Role.viewer)
    svc.create_session(db, u, 1)
    svc.create_session(db, u, 1)
    for s in db.query(AuthSession):
        s.expires_at = s.created_at - timedelta(hours=1)
    db.commit()
    assert svc.purge_expired_sessions(db) == 2


def test_deleting_user_cascades_sessions(db):
    u = svc.create_user(db, "leo", "correct horse battery", Role.viewer)
    svc.create_session(db, u, 1)
    db.delete(u)
    db.commit()
    assert db.query(AuthSession).count() == 0


def test_count_active_admins_ignores_local_user(db):
    svc.ensure_local_user(db)
    assert svc.count_active_admins(db) == 0
    a = svc.create_user(db, "root1", "correct horse battery", Role.admin)
    assert svc.count_active_admins(db) == 1
    assert svc.count_active_admins(db, exclude_user_id=a.id) == 0


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_throttle_blocks_after_max_failures():
    clock = FakeClock()
    th = svc.LoginThrottle(max_failures=3, window_seconds=60, clock=clock)
    for _ in range(2):
        th.record_failure("Alice", "1.2.3.4")
    assert not th.is_blocked("alice", "1.2.3.4")
    th.record_failure("alice", "1.2.3.4")
    assert th.is_blocked("ALICE", "1.2.3.4")
    assert not th.is_blocked("alice", "5.6.7.8")  # other client unaffected
    assert not th.is_blocked("bob", "1.2.3.4")  # other user unaffected


def test_throttle_window_expires_and_reset():
    clock = FakeClock()
    th = svc.LoginThrottle(max_failures=2, window_seconds=60, clock=clock)
    th.record_failure("a", "c")
    th.record_failure("a", "c")
    assert th.is_blocked("a", "c")
    clock.t += 61
    assert not th.is_blocked("a", "c")
    th.record_failure("a", "c")
    th.record_failure("a", "c")
    th.reset("a", "c")
    assert not th.is_blocked("a", "c")


def test_throttle_begin_counts_up_front_so_parallel_guesses_cannot_race():
    th = svc.LoginThrottle(max_failures=3, window_seconds=60, clock=FakeClock())
    # Ten guesses arrive together: begin() is checked and counted atomically, so only three get through.
    assert [th.begin("alice", "c") for _ in range(10)].count(True) == 3
    th.reset("alice", "c")  # one of them succeeded
    assert th.begin("alice", "c")


def test_throttle_limits_password_spraying_from_one_client():
    th = svc.LoginThrottle(max_failures=5, max_client_failures=4, window_seconds=60, clock=FakeClock())
    assert all(th.begin(f"user{i}", "1.2.3.4") for i in range(4))
    assert not th.begin("user99", "1.2.3.4")  # every username now blocked from this client
    assert th.begin("user99", "5.6.7.8")


def test_throttle_success_uncounts_the_attempt_for_the_client():
    th = svc.LoginThrottle(max_failures=5, max_client_failures=3, window_seconds=60, clock=FakeClock())
    for _ in range(10):  # a busy shared client signing in successfully never gets blocked
        assert th.begin("alice", "proxy")
        th.reset("alice", "proxy")


def test_throttle_memory_is_bounded():
    clock = FakeClock()
    th = svc.LoginThrottle(max_keys=50, window_seconds=60, clock=clock)
    for i in range(1000):
        th.record_failure(f"u{i}", f"c{i}")
    assert len(th._failures) <= 50
