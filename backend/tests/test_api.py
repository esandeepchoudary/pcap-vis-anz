import pytest
from fastapi.testclient import TestClient

from pcapvis.app import StartupError, create_app
from pcapvis.config import Settings

H = {"X-PcapVis-Client": "1"}
PW = "correct horse battery"


def make_client(settings: Settings) -> TestClient:
    app = create_app(settings)
    return TestClient(app)


@pytest.fixture
def laptop(settings):
    with make_client(settings) as c:
        yield c


@pytest.fixture
def server(make_settings):
    s = make_settings(mode="server", admin_username="admin", admin_password=PW)
    with make_client(s) as c:
        yield c


def login(c, username="admin", password=PW):
    return c.post("/api/auth/login", json={"username": username, "password": password}, headers=H)


def make_user(c, username, role="consultant", password=PW):
    r = c.post("/api/users", json={"username": username, "password": password, "role": role}, headers=H)
    assert r.status_code == 201, r.text
    return r.json()


# ── system ────────────────────────────────────────────────────────────────────


def test_health(laptop):
    r = laptop.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_system_info_laptop(laptop):
    from pcapvis import __version__

    body = laptop.get("/api/system").json()
    assert body["version"] == __version__
    assert body["mode"] == "laptop" and body["auth_required"] is False
    assert set(body["tshark"]) == {"ok", "path", "version", "min_version", "message"}


def test_system_info_server_needs_no_login(server):
    body = server.get("/api/system").json()
    assert body["mode"] == "server" and body["auth_required"] is True


def test_unknown_api_route_is_json_404(laptop):
    r = laptop.get("/api/does-not-exist")
    assert r.status_code == 404 and r.json() == {"detail": "Not found."}


def test_security_headers(laptop):
    r = laptop.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_openapi_and_docs_served(laptop):
    assert "/api/auth/login" in laptop.get("/api/openapi.json").json()["paths"]
    assert laptop.get("/api/docs").status_code == 200


# ── tshark startup gate ───────────────────────────────────────────────────────


def test_startup_refused_without_tshark(tmp_path):
    s = Settings(data_dir=tmp_path, tshark_path=str(tmp_path / "missing-tshark"), require_tshark=True)
    with pytest.raises(StartupError) as exc:
        create_app(s)
    assert "not found" in str(exc.value) and "docker run" in str(exc.value)


def test_startup_refused_with_old_tshark(tmp_path):
    fake = tmp_path / "tshark"
    fake.write_text("#!/bin/sh\necho 'TShark (Wireshark) 3.4.0.'\n")
    fake.chmod(0o755)
    with pytest.raises(StartupError, match="too old"):
        create_app(Settings(data_dir=tmp_path / "d", tshark_path=str(fake), require_tshark=True))


def test_startup_allowed_when_check_disabled(make_settings, tmp_path):
    s = make_settings(tshark_path=str(tmp_path / "missing"))
    with make_client(s) as c:
        assert c.get("/api/system").json()["tshark"]["ok"] is False


# ── laptop mode ───────────────────────────────────────────────────────────────


def test_laptop_me_is_local_admin_without_login(laptop):
    me = laptop.get("/api/auth/me").json()
    assert me["username"] == "local" and me["role"] == "admin"


def test_laptop_login_and_user_admin_disabled(laptop):
    assert login(laptop).status_code == 400
    assert laptop.get("/api/users").status_code == 400
    r = laptop.post("/api/users", json={"username": "x1", "password": PW}, headers=H)
    assert r.status_code == 400


# ── CSRF ──────────────────────────────────────────────────────────────────────


def test_unsafe_request_without_csrf_header_rejected(server):
    r = server.post("/api/auth/login", json={"username": "admin", "password": PW})
    assert r.status_code == 403 and "X-PcapVis-Client" in r.json()["detail"]


def test_wrong_csrf_header_value_rejected(server):
    r = server.post(
        "/api/auth/login", json={"username": "admin", "password": PW}, headers={"X-PcapVis-Client": "yes"}
    )
    assert r.status_code == 403


def test_safe_requests_need_no_csrf_header(server):
    assert server.get("/api/system").status_code == 200


# ── server mode: login/logout ─────────────────────────────────────────────────


def test_server_requires_login(server):
    assert server.get("/api/auth/me").status_code == 401
    assert server.get("/api/users").status_code == 401


def test_login_sets_secure_cookie_and_me_works(server):
    r = login(server)
    assert r.status_code == 200 and r.json()["username"] == "admin"
    cookie = r.headers["set-cookie"].lower()
    assert "pcapvis_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "password" not in r.text and "hash" not in r.text
    assert server.get("/api/auth/me").json()["role"] == "admin"


def test_secure_flag_when_configured(make_settings):
    s = make_settings(mode="server", cookie_secure=True, admin_username="admin", admin_password=PW)
    with make_client(s) as c:
        assert "secure" in login(c).headers["set-cookie"].lower()


def test_wrong_password_gives_generic_error(server):
    r1 = login(server, password="wrong password!")
    r2 = login(server, username="ghost", password="wrong password!")
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()  # doesn't reveal whether the user exists


def test_logout_invalidates_session(server):
    login(server)
    token = server.cookies.get("pcapvis_session")
    assert server.post("/api/auth/logout", headers=H).status_code == 204
    server.cookies.set("pcapvis_session", token)  # replay the old token
    assert server.get("/api/auth/me").status_code == 401


def test_forged_cookie_rejected(server):
    server.cookies.set("pcapvis_session", "forged-token-value")
    assert server.get("/api/auth/me").status_code == 401


def test_login_throttled_after_repeated_failures(server):
    for _ in range(5):
        assert login(server, password="wrong password!").status_code == 401
    r = login(server)  # even the right password is blocked now
    assert r.status_code == 429


def test_login_input_validation(server):
    r = server.post("/api/auth/login", json={"username": "", "password": ""}, headers=H)
    assert r.status_code == 422
    r = server.post("/api/auth/login", json={"username": "a" * 65, "password": "x"}, headers=H)
    assert r.status_code == 422


# ── server mode: users and roles ─────────────────────────────────────────────


def test_admin_creates_and_lists_users(server):
    login(server)
    make_user(server, "alice", "consultant")
    names = [u["username"] for u in server.get("/api/users").json()]
    assert names == ["admin", "alice"]  # built-in local user never listed


def test_create_user_validation_errors(server):
    login(server)
    bad = server.post("/api/users", json={"username": "Bad Name", "password": PW}, headers=H)
    assert bad.status_code == 400
    short = server.post("/api/users", json={"username": "bob", "password": "short"}, headers=H)
    assert short.status_code == 400 and "10 characters" in short.json()["detail"]
    make_user(server, "carol")
    dup = server.post("/api/users", json={"username": "CAROL", "password": PW}, headers=H)
    assert dup.status_code == 400
    role = server.post("/api/users", json={"username": "dan", "password": PW, "role": "god"}, headers=H)
    assert role.status_code == 422


@pytest.mark.parametrize("role", ["lead", "consultant", "viewer"])
def test_non_admins_cannot_manage_users(server, role):
    login(server)
    make_user(server, "someone", role)
    server.post("/api/auth/logout", headers=H)
    assert login(server, "someone").status_code == 200
    assert server.get("/api/users").status_code == 403
    r = server.post("/api/users", json={"username": "evil", "password": PW, "role": "admin"}, headers=H)
    assert r.status_code == 403


def test_last_admin_cannot_be_demoted_or_disabled(server):
    me = login(server).json()
    r = server.patch(f"/api/users/{me['id']}", json={"role": "viewer"}, headers=H)
    assert r.status_code == 400 and "at least one active admin" in r.json()["detail"]
    r = server.patch(f"/api/users/{me['id']}", json={"is_active": False}, headers=H)
    assert r.status_code == 400


def test_admin_can_be_demoted_when_another_exists(server):
    me = login(server).json()
    make_user(server, "admin2", "admin")
    r = server.patch(f"/api/users/{me['id']}", json={"role": "lead"}, headers=H)
    assert r.status_code == 200 and r.json()["role"] == "lead"


def test_deactivating_user_kills_their_sessions(server):
    login(server)
    u = make_user(server, "frank")
    other = TestClient(server.app)
    assert login(other, "frank").status_code == 200
    assert other.get("/api/auth/me").status_code == 200
    assert server.patch(f"/api/users/{u['id']}", json={"is_active": False}, headers=H).status_code == 200
    assert other.get("/api/auth/me").status_code == 401
    assert login(other, "frank").status_code == 401


def test_role_change_takes_effect_immediately(server):
    login(server)
    u = make_user(server, "gina", "admin")
    other = TestClient(server.app)
    login(other, "gina")
    assert other.get("/api/users").status_code == 200
    server.patch(f"/api/users/{u['id']}", json={"role": "viewer"}, headers=H)
    assert other.get("/api/users").status_code == 401  # session revoked, must sign in again
    login(other, "gina")
    assert other.get("/api/users").status_code == 403


def test_admin_password_reset(server):
    login(server)
    u = make_user(server, "hank")
    r = server.patch(f"/api/users/{u['id']}", json={"password": "a brand new password"}, headers=H)
    assert r.status_code == 200
    other = TestClient(server.app)
    assert login(other, "hank").status_code == 401
    assert login(other, "hank", "a brand new password").status_code == 200
    r = server.patch(f"/api/users/{u['id']}", json={"password": "short"}, headers=H)
    assert r.status_code == 400


def test_update_unknown_or_local_user_404(server):
    login(server)
    assert server.patch("/api/users/9999", json={"role": "viewer"}, headers=H).status_code == 404


def test_change_own_password_signs_out_other_sessions(server):
    login(server)
    make_user(server, "ivy")
    a, b = TestClient(server.app), TestClient(server.app)
    login(a, "ivy")
    login(b, "ivy")
    wrong = a.post(
        "/api/auth/password", json={"current_password": "nope nope nope", "new_password": "x" * 12}, headers=H
    )
    assert wrong.status_code == 400
    weak = a.post("/api/auth/password", json={"current_password": PW, "new_password": "short"}, headers=H)
    assert weak.status_code == 400
    ok = a.post(
        "/api/auth/password", json={"current_password": PW, "new_password": "ivy's new password"}, headers=H
    )
    assert ok.status_code == 204
    assert a.get("/api/auth/me").status_code == 200  # current session kept
    assert b.get("/api/auth/me").status_code == 401  # other session signed out


def test_server_without_admin_env_starts_with_no_users(make_settings):
    s = make_settings(mode="server")
    with make_client(s) as c:
        assert login(c).status_code == 401


def test_admin_bootstrap_only_once(make_settings):
    s = make_settings(mode="server", admin_username="admin", admin_password=PW)
    create_app(s).state.engine.dispose()
    # Second start with the same env must not fail on "already exists".
    with make_client(s) as c:
        assert login(c).status_code == 200


# ── frontend serving ──────────────────────────────────────────────────────────


@pytest.fixture
def dist(tmp_path):
    d = tmp_path / "dist"
    (d / "assets").mkdir(parents=True)
    (d / "index.html").write_text("<!doctype html><title>pcapvis</title>")
    (d / "assets" / "app.js").write_text("console.log(1)")
    (d / "favicon.svg").write_text("<svg/>")
    (tmp_path / "secret.txt").write_text("top secret")
    return d


def test_spa_serving(make_settings, dist):
    s = make_settings(frontend_dist=dist)
    with make_client(s) as c:
        assert "pcapvis" in c.get("/").text
        assert "pcapvis" in c.get("/engagements/42/assets").text  # client-side route
        assert c.get("/assets/app.js").text == "console.log(1)"
        assert c.get("/favicon.svg").text == "<svg/>"
        assert c.get("/api/nope").status_code == 404  # API 404s are not swallowed by the SPA


def test_spa_blocks_path_traversal(make_settings, dist):
    s = make_settings(frontend_dist=dist)
    with make_client(s) as c:
        for path in ("/..%2fsecret.txt", "/%2e%2e/secret.txt", "/assets/..%2f..%2fsecret.txt"):
            assert "top secret" not in c.get(path).text


def test_missing_frontend_gives_503(make_settings, tmp_path):
    s = make_settings(frontend_dist=tmp_path / "nowhere")
    with make_client(s) as c:
        assert c.get("/").status_code == 503


def test_openapi_has_no_python_version_dependent_texts(laptop):
    """Python 3.13 renamed some HTTP status phrases (413, 416, 422). Responses for those codes must
    carry explicit descriptions, or the generated frontend types differ between Python versions."""
    schema = laptop.get("/api/openapi.json").json()
    for path, ops in schema["paths"].items():
        for op in ops.values():
            for code, resp in op.get("responses", {}).items():
                if code in ("413", "416"):
                    assert resp["description"] not in (
                        "Content Too Large",
                        "Request Entity Too Large",
                        "Range Not Satisfiable",
                        "Requested Range Not Satisfiable",
                    ), f"{path} {code}: give this response an explicit description"
