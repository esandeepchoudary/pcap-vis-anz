"""Asset inventory API: list, detail, edits, conflicts, bulk, manual assets, history, CSV, permissions."""

import csv
import hashlib
import io
import shutil

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from pcapvis.assets import merge
from pcapvis.db.models import Capture, CaptureStatus
from pcapvis.jobs.runner import JobRunner
from tests.test_assets_merge import MAC_A, MAC_B, host, result
from tests.test_captures_api import PW, H, engagement, small_pcap, upload

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def seed(app, eid, *hosts, name="a.pcap") -> int:
    with app.state.session_factory() as db:
        cap = Capture(
            engagement_id=eid,
            file_name=name,
            size=1,
            sha256=hashlib.sha256(name.encode()).hexdigest(),
            status=CaptureStatus.done,
        )
        db.add(cap)
        db.flush()
        merge.ingest_capture(db, cap, result(*hosts))
        db.commit()
        return cap.id


def plc():
    return host(
        "10.0.0.5",
        MAC_A,
        host_type="PLC",
        host_type_confidence="high",
        purdue_level=1,
        hostname='=HYPERLINK("http://evil")',
        protocols=["Modbus"],
    )


def first(c, eid) -> dict:
    return c.get(f"/api/engagements/{eid}/assets").json()[0]


def test_list_and_detail(ac):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc(), host("10.0.0.6", MAC_B, host_type="HMI", purdue_level=2))
    rows = c.get(f"/api/engagements/{eid}/assets").json()
    assert [r["ips"] for r in rows] == [["10.0.0.5"], ["10.0.0.6"]]
    r = rows[0]
    assert r["asset_type"] == "PLC" and r["purdue_level"] == 1 and r["overridden"] == []
    assert r["type_confidence"] == "high" and r["protocols"] == ["Modbus"] and r["capture_count"] == 1
    d = c.get(f"/api/engagements/{eid}/assets/{r['id']}").json()
    assert d["auto"]["asset_type"] == "PLC" and d["overrides"] == {}
    assert d["sightings"][0]["file_name"] == "a.pcap" and d["sightings"][0]["ip"] == "10.0.0.5"
    assert c.get(f"/api/engagements/{eid}/assets/999999").status_code == 404


def test_edit_reset_history_and_revision(ac):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc())
    a = first(c, eid)
    rev = c.get(f"/api/engagements/{eid}/revision").json()["revision"]
    r = c.patch(
        f"/api/engagements/{eid}/assets/{a['id']}",
        json={
            "version": 1,
            "set": {"purdue_level": 2, "zone": "Cell 1", "criticality": "high"},
            "reason": "Walkdown",
        },
        headers=H,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["version"] == 2 and d["purdue_level"] == 2 and d["auto"]["purdue_level"] == 1
    assert sorted(d["overridden"]) == ["criticality", "purdue_level", "zone"]
    assert d["overrides"]["zone"]["reason"] == "Walkdown" and d["overrides"]["zone"]["by"] == "local"
    assert d["type_confidence"] == "high"
    assert c.get(f"/api/engagements/{eid}/revision").json()["revision"] > rev  # live update signal
    r = c.patch(
        f"/api/engagements/{eid}/assets/{a['id']}", json={"version": 2, "reset": ["purdue_level"]}, headers=H
    )
    assert r.json()["purdue_level"] == 1 and "purdue_level" not in r.json()["overridden"]
    hist = c.get(f"/api/engagements/{eid}/assets/{a['id']}/history").json()
    assert [(h["kind"], h["field"]) for h in hist] == [
        ("reset", "purdue_level"),
        ("override", "criticality"),
        ("override", "zone"),
        ("override", "purdue_level"),
        ("created", None),
    ]
    assert hist[0]["old"] == 2 and hist[0]["new"] == 1 and hist[-1]["kind"] == "created"
    audit = c.get(f"/api/engagements/{eid}/audit").json()
    assert any(e["action"] == "asset.edit" for e in audit)


def test_stale_version_conflicts(ac):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc())
    a = first(c, eid)
    url = f"/api/engagements/{eid}/assets/{a['id']}"
    assert c.patch(url, json={"version": 1, "set": {"zone": "A"}}, headers=H).status_code == 200
    r = c.patch(url, json={"version": 1, "set": {"zone": "B"}}, headers=H)
    assert r.status_code == 409 and "Someone else changed" in r.json()["detail"]
    assert c.get(url).json()["zone"] == "A"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"version": 1, "set": {"purdue_level": 9}}, 422),
        ({"version": 1, "set": {"name": "a\nb"}}, 422),
        ({"version": 1, "set": {"owner": 5}}, 422),
        ({"version": 1, "set": {"bogus": "x"}}, 422),
        ({"version": 1, "set": {"zone": "x"}, "reset": ["zone"]}, 422),
        ({"version": 1, "reason": "x" * 1001}, 422),
        ({"set": {"zone": "x"}}, 422),
    ],
)
def test_invalid_edits_are_rejected(ac, body, code):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc())
    a = first(c, eid)
    r = c.patch(f"/api/engagements/{eid}/assets/{a['id']}", json=body, headers=H)
    assert r.status_code == code
    assert first(c, eid)["version"] == 1


def test_bulk_edit(ac):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc(), host("10.0.0.6", MAC_B), host("10.0.0.7", "00:0c:29:00:00:0c"))
    ids = [a["id"] for a in c.get(f"/api/engagements/{eid}/assets").json()]
    r = c.post(
        f"/api/engagements/{eid}/assets/bulk",
        json={"asset_ids": ids[:2], "set": {"zone": "Cell 1", "purdue_level": 1}, "reason": "Same panel"},
        headers=H,
    )
    assert r.status_code == 200 and r.json() == {"assets": 2, "changes": 4}  # pinning L1 on the PLC counts
    rows = {a["id"]: a for a in c.get(f"/api/engagements/{eid}/assets").json()}
    assert rows[ids[0]]["zone"] == rows[ids[1]]["zone"] == "Cell 1" and rows[ids[2]]["zone"] is None
    r = c.post(f"/api/engagements/{eid}/assets/bulk", json={"asset_ids": ids, "reset": ["zone"]}, headers=H)
    assert r.json() == {"assets": 2, "changes": 2}
    # Invalid value: nothing changes.
    r = c.post(
        f"/api/engagements/{eid}/assets/bulk",
        json={"asset_ids": ids, "set": {"zone": "x", "purdue_level": 8}},
        headers=H,
    )
    assert r.status_code == 422
    assert all(a["zone"] is None for a in c.get(f"/api/engagements/{eid}/assets").json())
    assert (
        c.post(f"/api/engagements/{eid}/assets/bulk", json={"asset_ids": ids}, headers=H).status_code == 422
    )


def test_bulk_edit_cannot_reach_other_engagements(ac):
    app, c = ac
    e1, e2 = engagement(c, "One"), engagement(c, "Two")
    seed(app, e1, plc())
    other = first(c, e1)["id"]
    r = c.post(
        f"/api/engagements/{e2}/assets/bulk", json={"asset_ids": [other], "set": {"zone": "x"}}, headers=H
    )
    assert r.status_code == 404
    assert c.get(f"/api/engagements/{e2}/assets/{other}").status_code == 404
    assert (
        c.patch(
            f"/api/engagements/{e2}/assets/{other}", json={"version": 1, "set": {"zone": "x"}}, headers=H
        ).status_code
        == 404
    )


def test_manual_asset_create_and_delete(ac):
    app, c = ac
    eid = engagement(c)
    r = c.post(
        f"/api/engagements/{eid}/assets",
        json={
            "ips": ["10.0.0.254"],
            "values": {"name": "FW-1", "asset_type": "Firewall", "purdue_level": 3.5},
            "reason": "From the site network diagram",
        },
        headers=H,
    )
    assert r.status_code == 201, r.text
    a = r.json()
    assert (
        a["origin"] == "manual"
        and a["name"] == "FW-1"
        and a["purdue_level"] == 3.5
        and a["capture_count"] == 0
    )
    assert c.post(f"/api/engagements/{eid}/assets", json={}, headers=H).status_code == 422
    assert c.post(f"/api/engagements/{eid}/assets", json={"ips": ["nope"]}, headers=H).status_code == 422
    assert c.delete(f"/api/engagements/{eid}/assets/{a['id']}", headers=H).status_code == 204
    assert c.get(f"/api/engagements/{eid}/assets").json() == []


def test_observed_asset_cannot_be_deleted(ac):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc())
    r = c.delete(f"/api/engagements/{eid}/assets/{first(c, eid)['id']}", headers=H)
    assert r.status_code == 409


def test_csv_register_escapes_formulas(ac):
    app, c = ac
    eid = engagement(c, "ACME / Plant 3")
    seed(app, eid, plc())
    a = first(c, eid)
    c.patch(
        f"/api/engagements/{eid}/assets/{a['id']}",
        json={"version": 1, "set": {"tags": ["safety", "sis"], "notes": "+1 spare", "zone": "Cell 1"}},
        headers=H,
    )
    r = c.get(f"/api/engagements/{eid}/assets/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="ACME___Plant_3-assets.csv"' in r.headers["content-disposition"]
    text = r.content.decode("utf-8")
    assert text.startswith("﻿")
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    row = rows[0]
    assert row["name"].startswith("'=HYPERLINK")  # formula neutralised
    assert row["notes"] == "'+1 spare"
    assert row["tags"] == "safety; sis" and row["purdue_level"] == "1" and row["ip_addresses"] == "10.0.0.5"
    assert row["manually_set"] == "notes tags zone" and row["origin"] == "observed"


def test_asset_fields_endpoint(ac):
    _app, c = ac
    f = c.get("/api/asset-fields").json()
    assert [x["name"] for x in f["fields"]][:3] == ["name", "asset_type", "purdue_level"]
    assert 3.5 in f["purdue_levels"] and f["purdue_names"]["3.5"].startswith("Level 3.5")
    assert "PLC" in f["asset_types"] and "Firewall" in f["asset_types"]


def test_permissions(make_settings):
    app = create_app(make_settings(mode="server", admin_username="admin", admin_password=PW))
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        for name, role in (("vic", "viewer"), ("olly", "consultant")):
            c.post("/api/users", json={"username": name, "password": PW, "role": role}, headers=H)
        eid = engagement(c)
        vic = c.get("/api/directory").json()
        vid = next(u["id"] for u in vic if u["username"] == "vic")
        c.put(f"/api/engagements/{eid}/members/{vid}", json={"role": "viewer"}, headers=H)
        seed(app, eid, plc())
        aid = first(c, eid)["id"]
        c.post("/api/auth/logout", headers=H)

        c.post("/api/auth/login", json={"username": "vic", "password": PW}, headers=H)
        assert c.get(f"/api/engagements/{eid}/assets").status_code == 200
        assert c.get(f"/api/engagements/{eid}/assets/export").status_code == 200
        assert (
            c.patch(
                f"/api/engagements/{eid}/assets/{aid}", json={"version": 1, "set": {"zone": "x"}}, headers=H
            ).status_code
            == 403
        )
        assert (
            c.post(
                f"/api/engagements/{eid}/assets/bulk",
                json={"asset_ids": [aid], "set": {"zone": "x"}},
                headers=H,
            ).status_code
            == 403
        )
        assert (
            c.post(f"/api/engagements/{eid}/assets", json={"values": {"name": "x"}}, headers=H).status_code
            == 403
        )
        c.post("/api/auth/logout", headers=H)

        c.post("/api/auth/login", json={"username": "olly", "password": PW}, headers=H)  # not a member
        assert c.get(f"/api/engagements/{eid}/assets").status_code == 404
        assert c.get(f"/api/engagements/{eid}/assets/{aid}/history").status_code == 404
        assert c.get(f"/api/engagements/{eid}/assets/export").status_code == 404


def test_csrf_header_required_for_edits(ac):
    app, c = ac
    eid = engagement(c)
    seed(app, eid, plc())
    aid = first(c, eid)["id"]
    r = c.patch(f"/api/engagements/{eid}/assets/{aid}", json={"version": 1, "set": {"zone": "x"}})
    assert r.status_code == 403


@needs_tshark
def test_analysis_feeds_the_inventory_and_deleting_the_capture_removes_it(ac, tmp_path):
    app, c = ac
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    JobRunner(app.state.settings, app.state.session_factory).run_once()
    rows = c.get(f"/api/engagements/{eid}/assets").json()
    assert sorted(ip for r in rows for ip in r["ips"]) == ["10.0.0.5", "10.0.0.80"]
    assert all(r["capture_count"] == 1 for r in rows)
    server = next(r for r in rows if r["ips"] == ["10.0.0.80"])
    assert server["macs"] == ["00:0c:29:00:00:80"]
    assert c.delete(f"/api/engagements/{eid}/captures/{cid}", headers=H).status_code == 204
    assert c.get(f"/api/engagements/{eid}/assets").json() == []


@needs_tshark
def test_merge_failure_keeps_the_analysis_and_is_retried(ac, tmp_path, monkeypatch):
    app, c = ac
    eid = engagement(c)
    upload(c, eid, small_pcap(tmp_path))
    real = merge.ingest_capture

    def boom(*a, **kw):
        raise RuntimeError("merge bug")

    monkeypatch.setattr(merge, "ingest_capture", boom)
    JobRunner(app.state.settings, app.state.session_factory).run_once()
    cap = c.get(f"/api/engagements/{eid}/captures").json()[0]
    assert cap["status"] == "done"  # analysis kept
    assert c.get(f"/api/engagements/{eid}/assets").json() == []
    monkeypatch.setattr(merge, "ingest_capture", real)
    assert JobRunner(app.state.settings, app.state.session_factory).merge_pending() == 1
    assert len(c.get(f"/api/engagements/{eid}/assets").json()) == 2
