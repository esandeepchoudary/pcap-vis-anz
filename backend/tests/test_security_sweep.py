"""Access-control sweep over every API operation (from the OpenAPI schema), so new routes can't slip through.

- Signed out (team server): every operation except the public allowlist answers 401.
- Signed in but not a member: every engagement-scoped operation answers 404 (never 403, never data).
"""

import re

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from tests.test_asset_links import HMI, PLC, cmd, flow, ingest, res
from tests.test_captures_api import PW, H

PUBLIC = {
    ("GET", "/api/health"),
    ("GET", "/api/system"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),
}


def operations(app):
    schema = app.openapi()
    for path, ops in schema["paths"].items():
        for method in ops:
            yield method.upper(), path


def fill(path: str, eid: int) -> str:
    values = {"engagement_id": eid, "sha256": "0" * 64, "key": "a1", "user_id": 1}
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), 1)), path)


@pytest.fixture
def world(make_settings):
    app = create_app(
        make_settings(mode="server", admin_username="admin", admin_password=PW, run_jobs_in_app=False)
    )
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        c.post("/api/users", json={"username": "olly", "password": PW, "role": "lead"}, headers=H)
        eid = c.post("/api/engagements", json={"name": "Secret plant"}, headers=H).json()["id"]
        r = res([flow(1, HMI, PLC)], [cmd(HMI, PLC)])
        ingest(app, eid, r, "a.pcap")
        c.post("/api/auth/logout", headers=H)
        yield app, c, eid


def test_every_operation_requires_sign_in(world):
    app, c, eid = world
    checked = 0
    for method, path in operations(app):
        if (method, path) in PUBLIC:
            continue
        r = c.request(
            method, fill(path, eid), headers=H, json={} if method in ("POST", "PATCH", "PUT") else None
        )
        assert r.status_code == 401, f"{method} {path} answered {r.status_code} without signing in"
        checked += 1
    assert checked > 60  # the sweep really covered the API


def test_outsiders_get_404_on_every_engagement_operation(world):
    app, c, eid = world
    c.post(
        "/api/auth/login", json={"username": "olly", "password": PW}, headers=H
    )  # a lead, but not a member
    checked = 0
    for method, path in operations(app):
        if "{engagement_id}" not in path:
            continue
        r = c.request(
            method, fill(path, eid), headers=H, json={} if method in ("POST", "PATCH", "PUT") else None
        )
        assert r.status_code == 404, f"{method} {path} answered {r.status_code} to a non-member"
        assert "Secret plant" not in r.text
        checked += 1
    assert checked > 50
    assert all(e["name"] != "Secret plant" for e in c.get("/api/engagements").json())


def test_unsafe_requests_need_the_csrf_header(world):
    app, c, eid = world
    c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
    for method, path in operations(app):
        if method in ("GET", "HEAD") or (method, path) == ("POST", "/api/auth/login"):
            continue
        r = c.request(method, fill(path, eid), json={})
        assert r.status_code == 403, f"{method} {path} accepted a request without the CSRF header"


def test_oversized_json_bodies_are_refused(world):
    _app, c, eid = world
    c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
    big = b'{"name": "' + b"x" * (3 * 1024 * 1024) + b'"}'
    r = c.post("/api/engagements", content=big, headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 413
    r = c.post(
        "/api/engagements",
        content=iter([b'{"name": "x"}']),
        headers={**H, "Content-Type": "application/json"},
    )
    assert r.status_code == 411  # chunked body without a length
    assert c.post("/api/engagements", json={"name": "fine"}, headers=H).status_code == 201


def test_security_headers(world):
    _app, c, _eid = world
    r = c.get("/api/health")
    for h in (
        "Content-Security-Policy",
        "X-Frame-Options",
        "Permissions-Policy",
        "Referrer-Policy",
        "X-Content-Type-Options",
    ):
        assert h in r.headers
    assert r.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in r.headers  # plain HTTP in tests


def test_hsts_when_served_over_https(make_settings):
    app = create_app(make_settings(mode="laptop", cookie_secure=True))
    with TestClient(app) as c:
        assert c.get("/api/health").headers["Strict-Transport-Security"] == "max-age=31536000"


def test_packet_inspector_concurrency_is_bounded(monkeypatch, tmp_path):
    from pcapvis.engine import inspect

    for _ in range(inspect.MAX_CONCURRENT):
        assert inspect._slots.acquire(timeout=1)
    try:
        monkeypatch.setattr(inspect._slots, "acquire", lambda timeout=None: False)
        with pytest.raises(inspect.InspectorBusy):
            inspect.list_packets("tshark", tmp_path / "x.pcap", "")
    finally:
        for _ in range(inspect.MAX_CONCURRENT):
            inspect._slots.release()
