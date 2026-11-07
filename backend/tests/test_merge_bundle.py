"""Merging a .pcapvis bundle into an existing engagement (laptop → team server, M9)."""

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from tests.test_assets_merge import host
from tests.test_bundles import _seed_with_result, export
from tests.test_captures_api import PW, H, engagement

PLC_MAC, HMI_MAC = "00:1b:1b:00:00:51", "00:0c:29:00:00:10"


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def by_ip(c, eid):
    return {ip: a for a in c.get(f"/api/engagements/{eid}/assets").json() for ip in a["ips"]}


def edit(c, eid, aid, **values):
    v = c.get(f"/api/engagements/{eid}/assets/{aid}").json()["version"]
    assert (
        c.patch(
            f"/api/engagements/{eid}/assets/{aid}",
            json={"version": v, "set": values, "reason": "laptop"},
            headers=H,
        ).status_code
        == 200
    )


def merge(c, eid, data: bytes, name="laptop.pcapvis"):
    return c.post(f"/api/engagements/{eid}/merge", files={"file": (name, data)}, headers=H)


def laptop_bundle(app, c) -> bytes:
    eid = engagement(c, "Laptop")
    _seed_with_result(
        app,
        eid,
        host("10.0.2.51", PLC_MAC, host_type="PLC"),
        host("10.0.2.10", HMI_MAC),
        name="laptop-day1.pcap",
    )
    a = by_ip(c, eid)
    edit(c, eid, a["10.0.2.51"]["id"], zone="Cell 1", name="Filler PLC")
    c.post(
        f"/api/engagements/{eid}/assets",
        json={"ips": ["10.0.2.254"], "values": {"name": "FW-1", "asset_type": "Firewall"}},
        headers=H,
    )
    z1 = c.post(f"/api/engagements/{eid}/zones", json={"name": "Cell 1", "purdue_level": 1}, headers=H).json()
    z2 = c.post(f"/api/engagements/{eid}/zones", json={"name": "Control"}, headers=H).json()
    c.post(
        f"/api/engagements/{eid}/conduits",
        json={"zone_a_id": z1["id"], "zone_b_id": z2["id"], "allowed": ["S7comm"]},
        headers=H,
    )
    c.post(
        f"/api/engagements/{eid}/findings",
        json={"title": "No asset owner", "severity": "low", "asset_ids": [a["10.0.2.51"]["id"]]},
        headers=H,
    )
    return export(c, eid, captures=False)


def test_laptop_work_merges_into_a_server_engagement(ac):
    app, c = ac
    bundle = laptop_bundle(app, c)
    server = engagement(c, "Server")
    _seed_with_result(app, server, host("10.0.2.51", PLC_MAC, host_type="PLC"), name="server-day2.pcap")
    plc = by_ip(c, server)["10.0.2.51"]
    edit(c, server, plc["id"], name="PLC-LINE2", owner="Controls team")

    r = merge(c, server, bundle)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert (rep["captures_added"], rep["captures_skipped"]) == (1, 0)
    assert rep["zones_added"] == 2 and rep["conduits_added"] == 1 and rep["findings_added"] == 1
    assert rep["assets_created"] == 1  # FW-1, added by hand on the laptop
    assert [(x["field"], x["kept"], x["imported"]) for x in rep["conflicts"]] == [
        ("name", "PLC-LINE2", "Filler PLC")
    ]

    assets = by_ip(c, server)
    merged = assets["10.0.2.51"]
    assert merged["id"] == plc["id"]  # same device, same asset
    assert (merged["name"], merged["zone"], merged["owner"]) == ("PLC-LINE2", "Cell 1", "Controls team")
    assert merged["capture_count"] == 2 and "10.0.2.10" in assets and assets["10.0.2.254"]["name"] == "FW-1"
    hist = c.get(f"/api/engagements/{server}/assets/{plc['id']}/history").json()
    assert any(
        h["kind"] == "import" and h["field"] == "zone" and h["actor"] == "import from laptop.pcapvis"
        for h in hist
    )
    f = next(x for x in c.get(f"/api/engagements/{server}/findings").json() if x["title"] == "No asset owner")
    assert f["asset_ids"] == [plc["id"]]  # remapped to the server's asset
    assert c.get(f"/api/engagements/{server}/conduits").json()[0]["allowed"] == ["S7comm"]

    # Merging the same bundle again changes nothing.
    again = merge(c, server, bundle).json()
    assert (again["captures_added"], again["captures_skipped"], again["fields_applied"]) == (0, 1, 0)
    assert (
        again["zones_added"]
        == again["conduits_added"]
        == again["findings_added"]
        == again["assets_created"]
        == 0
    )
    assert len(by_ip(c, server)) == len(assets)
    # The temporary engagement is gone.
    assert {e["name"] for e in c.get("/api/engagements").json()} == {"Laptop", "Server"}
    assert c.get("/api/engagements", params={"quicklook": True}).json() == []
    assert any(e["action"] == "engagement.merge" for e in c.get(f"/api/engagements/{server}/audit").json())


def test_bad_bundle_leaves_nothing_behind(ac):
    app, c = ac
    server = engagement(c, "Server")
    before = c.get(f"/api/engagements/{server}").json()["revision"]
    r = merge(c, server, b"not a zip")
    assert r.status_code == 400
    assert [e["name"] for e in c.get("/api/engagements").json()] == ["Server"]
    assert c.get("/api/engagements", params={"quicklook": True}).json() == []
    assert c.get(f"/api/engagements/{server}").json()["revision"] == before
    data_dir = app.state.settings.data_dir / "engagements"
    assert not data_dir.exists() or sorted(p.name for p in data_dir.iterdir()) in ([], [str(server)])


def test_only_leads_can_merge(make_settings):
    app = create_app(
        make_settings(mode="server", admin_username="admin", admin_password=PW, run_jobs_in_app=False)
    )
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        c.post("/api/users", json={"username": "ed", "password": PW, "role": "consultant"}, headers=H)
        eid = engagement(c)
        uid = next(u["id"] for u in c.get("/api/directory").json() if u["username"] == "ed")
        c.put(f"/api/engagements/{eid}/members/{uid}", json={"role": "editor"}, headers=H)
        other = engagement(c, "Other")
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "ed", "password": PW}, headers=H)
        assert merge(c, eid, b"x").status_code == 403
        assert merge(c, other, b"x").status_code == 404
