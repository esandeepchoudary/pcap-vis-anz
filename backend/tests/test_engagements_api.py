"""Engagements, members, capture points, audit: behaviour and the permission matrix."""

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app

H = {"X-PcapVis-Client": "1"}
PW = "correct horse battery"


@pytest.fixture
def server(make_settings):
    s = make_settings(mode="server", admin_username="admin", admin_password=PW)
    with TestClient(create_app(s)) as c:
        yield c


@pytest.fixture
def laptop(make_settings):
    with TestClient(create_app(make_settings(mode="laptop"))) as c:
        yield c


def login(c, username="admin", password=PW):
    r = c.post("/api/auth/login", json={"username": username, "password": password}, headers=H)
    assert r.status_code == 200, r.text
    return c


def as_user(server, username, role):
    """Create a user (as admin) and return a client signed in as them, plus their id."""
    admin = login(TestClient(server.app))
    r = admin.post("/api/users", json={"username": username, "password": PW, "role": role}, headers=H)
    assert r.status_code == 201, r.text
    return login(TestClient(server.app), username), r.json()["id"]


def new_engagement(c, name="ACME Plant 3", **kw):
    r = c.post("/api/engagements", json={"name": name, **kw}, headers=H)
    assert r.status_code == 201, r.text
    return r.json()


# ── laptop mode ───────────────────────────────────────────────────────────────


def test_laptop_crud_and_listing(laptop):
    e = new_engagement(laptop, client="ACME", site="Plant 3", description="SPAN on core switch")
    assert e["my_role"] == "lead" and e["capture_count"] == 0 and e["member_count"] == 1
    assert [x["id"] for x in laptop.get("/api/engagements").json()] == [e["id"]]
    r = laptop.patch(
        f"/api/engagements/{e['id']}", json={"name": "  ACME P3  ", "site": "Plant 3B"}, headers=H
    )
    assert r.json()["name"] == "ACME P3" and r.json()["revision"] > e["revision"]
    assert laptop.get(f"/api/engagements/{e['id']}").json()["site"] == "Plant 3B"
    assert laptop.delete(f"/api/engagements/{e['id']}", headers=H).status_code == 204
    assert laptop.get(f"/api/engagements/{e['id']}").status_code == 404


def test_validation(laptop):
    assert laptop.post("/api/engagements", json={"name": ""}, headers=H).status_code == 422
    assert laptop.post("/api/engagements", json={"name": "x" * 201}, headers=H).status_code == 422
    e = new_engagement(laptop)
    assert (
        laptop.patch(f"/api/engagements/{e['id']}", json={"status": "deleted"}, headers=H).status_code == 422
    )
    assert (
        laptop.patch(f"/api/engagements/{e['id']}", json={"is_quicklook": True}, headers=H).status_code == 422
    )
    assert laptop.get("/api/engagements/0").status_code == 422
    assert laptop.get("/api/engagements/99999").status_code == 404


def test_archive_hides_from_default_list(laptop):
    e = new_engagement(laptop)
    laptop.patch(f"/api/engagements/{e['id']}", json={"status": "archived"}, headers=H)
    assert laptop.get("/api/engagements").json() == []
    assert [x["id"] for x in laptop.get("/api/engagements?include_archived=true").json()] == [e["id"]]


def test_members_endpoints_are_server_only(laptop):
    e = new_engagement(laptop)
    assert (
        laptop.put(f"/api/engagements/{e['id']}/members/1", json={"role": "editor"}, headers=H).status_code
        == 400
    )
    assert laptop.get("/api/directory").status_code == 400


def test_csrf_header_required(laptop):
    assert laptop.post("/api/engagements", json={"name": "x"}).status_code == 403


# ── creation rights ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "role,allowed", [("admin", True), ("lead", True), ("consultant", False), ("viewer", False)]
)
def test_who_can_create(server, role, allowed):
    c, _ = as_user(server, f"u{role}", role)
    r = c.post("/api/engagements", json={"name": "x"}, headers=H)
    assert (r.status_code == 201) is allowed


def test_creator_becomes_lead_member(server):
    lead, lead_id = as_user(server, "lea", "lead")
    e = new_engagement(lead)
    members = lead.get(f"/api/engagements/{e['id']}/members").json()
    assert [(m["user_id"], m["role"]) for m in members] == [(lead_id, "lead")]
    assert lead.get(f"/api/engagements/{e['id']}/audit").json()[0]["action"] == "engagement.create"


# ── visibility and the role matrix ────────────────────────────────────────────


def test_non_members_cannot_see_or_probe(server):
    lead, _ = as_user(server, "lea", "lead")
    outsider, _ = as_user(server, "out", "consultant")
    e = new_engagement(lead, name="Secret Plant")
    assert outsider.get("/api/engagements").json() == []
    for method, url in (
        ("get", ""),
        ("patch", ""),
        ("delete", ""),
        ("get", "/members"),
        ("get", "/capture-points"),
        ("get", "/audit"),
    ):
        r = getattr(outsider, method)(
            f"/api/engagements/{e['id']}{url}",
            **(
                {"headers": H, "json": {}}
                if method == "patch"
                else {"headers": H}
                if method == "delete"
                else {}
            ),
        )
        assert r.status_code == 404 and "Secret" not in r.text  # same answer as a missing engagement


def test_admin_sees_everything(server):
    lead, _ = as_user(server, "lea", "lead")
    e = new_engagement(lead)
    admin = login(TestClient(server.app))
    assert e["id"] in [x["id"] for x in admin.get("/api/engagements").json()]
    assert admin.get(f"/api/engagements/{e['id']}").json()["my_role"] == "lead"


@pytest.mark.parametrize(
    "member_role,can_view,can_edit,can_lead",
    [("viewer", True, False, False), ("editor", True, True, False), ("lead", True, True, True)],
)
def test_engagement_role_matrix(server, member_role, can_view, can_edit, can_lead):
    lead, _ = as_user(server, "lea", "lead")
    other_global = "lead" if member_role == "lead" else "consultant"
    other, other_id = as_user(server, "oth", other_global)
    e = new_engagement(lead)
    lead.put(f"/api/engagements/{e['id']}/members/{other_id}", json={"role": member_role}, headers=H)
    eid = e["id"]
    assert (other.get(f"/api/engagements/{eid}").status_code == 200) is can_view
    r = other.post(f"/api/engagements/{eid}/capture-points", json={"name": "SPAN 1"}, headers=H)
    assert (r.status_code == 201) is can_edit
    r = other.patch(f"/api/engagements/{eid}", json={"site": "x"}, headers=H)
    assert (r.status_code == 200) is can_lead
    r = other.put(f"/api/engagements/{eid}/members/{other_id}", json={"role": member_role}, headers=H)
    assert (r.status_code == 200) is can_lead
    if not can_edit:
        assert (
            "editor role"
            in other.post(f"/api/engagements/{eid}/capture-points", json={"name": "y"}, headers=H).text
        )


@pytest.mark.parametrize(
    "global_role,requested,ok",
    [
        ("viewer", "viewer", True),
        ("viewer", "editor", False),
        ("consultant", "editor", True),
        ("consultant", "lead", False),
        ("lead", "lead", True),
    ],
)
def test_global_role_caps_engagement_role(server, global_role, requested, ok):
    lead, _ = as_user(server, "lea", "lead")
    _, uid = as_user(server, "cap", global_role)
    e = new_engagement(lead)
    r = lead.put(f"/api/engagements/{e['id']}/members/{uid}", json={"role": requested}, headers=H)
    assert (r.status_code == 200) is ok
    if not ok:
        assert "highest engagement role" in r.json()["detail"]


def test_global_demotion_caps_existing_membership(server):
    lead, _ = as_user(server, "lea", "lead")
    bob, bob_id = as_user(server, "bob", "lead")
    e = new_engagement(lead)
    lead.put(f"/api/engagements/{e['id']}/members/{bob_id}", json={"role": "lead"}, headers=H)
    admin = login(TestClient(server.app))
    admin.patch(f"/api/users/{bob_id}", json={"role": "viewer"}, headers=H)  # signs bob out
    bob = login(TestClient(server.app), "bob")
    assert bob.get(f"/api/engagements/{e['id']}").json()["my_role"] == "viewer"
    assert (
        bob.post(f"/api/engagements/{e['id']}/capture-points", json={"name": "z"}, headers=H).status_code
        == 403
    )


def test_last_lead_protected(server):
    lead, lead_id = as_user(server, "lea", "lead")
    e = new_engagement(lead)
    r = lead.put(f"/api/engagements/{e['id']}/members/{lead_id}", json={"role": "viewer"}, headers=H)
    assert r.status_code == 400 and "at least one lead" in r.json()["detail"]
    assert lead.delete(f"/api/engagements/{e['id']}/members/{lead_id}", headers=H).status_code == 400
    _, other_id = as_user(server, "two", "lead")
    lead.put(f"/api/engagements/{e['id']}/members/{other_id}", json={"role": "lead"}, headers=H)
    assert lead.delete(f"/api/engagements/{e['id']}/members/{lead_id}", headers=H).status_code == 204


def test_member_removal_revokes_access(server):
    lead, _ = as_user(server, "lea", "lead")
    con, con_id = as_user(server, "con", "consultant")
    e = new_engagement(lead)
    lead.put(f"/api/engagements/{e['id']}/members/{con_id}", json={"role": "editor"}, headers=H)
    assert con.get(f"/api/engagements/{e['id']}").status_code == 200
    lead.delete(f"/api/engagements/{e['id']}/members/{con_id}", headers=H)
    assert con.get(f"/api/engagements/{e['id']}").status_code == 404


def test_cannot_add_unknown_or_disabled_user(server):
    lead, _ = as_user(server, "lea", "lead")
    _, gone_id = as_user(server, "gone", "consultant")
    admin = login(TestClient(server.app))
    admin.patch(f"/api/users/{gone_id}", json={"is_active": False}, headers=H)
    e = new_engagement(lead)
    for uid in (gone_id, 99999):
        assert (
            lead.put(
                f"/api/engagements/{e['id']}/members/{uid}", json={"role": "viewer"}, headers=H
            ).status_code
            == 404
        )


def test_directory_for_leads_only(server):
    lead, _ = as_user(server, "lea", "lead")
    con, _ = as_user(server, "con", "consultant")
    names = [u["username"] for u in lead.get("/api/directory").json()]
    assert names == ["admin", "con", "lea"]  # no built-in local user, sorted
    assert con.get("/api/directory").status_code == 403


# ── capture points ────────────────────────────────────────────────────────────


def test_capture_points_crud_and_unique_names(laptop):
    e = new_engagement(laptop)
    base = f"/api/engagements/{e['id']}/capture-points"
    p = laptop.post(base, json={"name": "Core SPAN Gi0/24", "description": "Cell A uplink"}, headers=H).json()
    assert laptop.post(base, json={"name": "Core SPAN Gi0/24"}, headers=H).status_code == 409
    laptop.post(base, json={"name": "Aardvark TAP"}, headers=H)
    assert [x["name"] for x in laptop.get(base).json()] == ["Aardvark TAP", "Core SPAN Gi0/24"]  # sorted
    r = laptop.patch(f"{base}/{p['id']}", json={"name": "Aardvark TAP"}, headers=H)
    assert r.status_code == 409
    r = laptop.patch(f"{base}/{p['id']}", json={"description": "moved"}, headers=H)
    assert r.json()["description"] == "moved"
    assert laptop.delete(f"{base}/{p['id']}", headers=H).status_code == 204
    assert laptop.delete(f"{base}/{p['id']}", headers=H).status_code == 404


def test_capture_point_of_other_engagement_is_404(laptop):
    a, b = new_engagement(laptop, name="A"), new_engagement(laptop, name="B")
    p = laptop.post(f"/api/engagements/{a['id']}/capture-points", json={"name": "x"}, headers=H).json()
    assert (
        laptop.patch(
            f"/api/engagements/{b['id']}/capture-points/{p['id']}", json={"name": "y"}, headers=H
        ).status_code
        == 404
    )


def test_audit_log_records_actions(laptop):
    e = new_engagement(laptop)
    laptop.post(f"/api/engagements/{e['id']}/capture-points", json={"name": "TAP"}, headers=H)
    laptop.patch(f"/api/engagements/{e['id']}", json={"site": "S"}, headers=H)
    log = laptop.get(f"/api/engagements/{e['id']}/audit").json()
    assert [x["action"] for x in log] == ["engagement.update", "capture_point.create", "engagement.create"]
    assert log[0]["user"] == "local" and log[0]["details"] == {"site": "S"}
