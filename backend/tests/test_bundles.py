"""Engagement export/import (.pcapvis): round trip, and rejection of unsafe or corrupt bundles."""

import io
import json
import shutil
import zipfile

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from pcapvis.jobs.runner import JobRunner
from tests.test_captures_api import EXE, H, engagement, small_pcap, upload

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def run_jobs(app):
    r = JobRunner(app.state.settings, app.state.session_factory)
    while r.run_once():
        pass


def export(c, eid, **params) -> bytes:
    r = c.get(f"/api/engagements/{eid}/export", params=params)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert ".pcapvis" in r.headers["content-disposition"]
    return r.content


def import_(c, data: bytes, name="b.pcapvis"):
    return c.post("/api/engagements/import", files={"file": (name, data)}, headers=H)


def make_bundle(entries: dict[str, bytes], compress=zipfile.ZIP_STORED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def manifest(**over) -> dict:
    m = {
        "format": "pcapvis-engagement",
        "format_version": 1,
        "app_version": "0.3.0",
        "exported_at": "2026-11-06T10:00:00Z",
        "engagement": {"name": "Imported"},
        "capture_points": [],
        "captures": [],
        "files": [],
    }
    m.update(over)
    return m


# ── round trip ────────────────────────────────────────────────────────────────


@needs_tshark
def test_round_trip_preserves_everything(ac, tmp_path):
    app, c = ac
    eid = engagement(c, "ACME Plant 3")
    c.patch(
        f"/api/engagements/{eid}",
        json={"client": "ACME", "site": "Plant 3", "description": "Line 2"},
        headers=H,
    )
    pid = c.post(
        f"/api/engagements/{eid}/capture-points",
        json={"name": "Core SPAN", "description": "Gi0/24"},
        headers=H,
    ).json()["id"]
    cid = upload(c, eid, small_pcap(tmp_path), point=pid).json()[0]["capture"]["id"]
    run_jobs(app)
    original = c.get(f"/api/engagements/{eid}/captures/{cid}/result").json()

    r = import_(c, export(c, eid))
    assert r.status_code == 201, r.text
    new = r.json()
    assert new["name"] == "ACME Plant 3 (imported)" and new["client"] == "ACME" and new["site"] == "Plant 3"
    assert new["id"] != eid and new["my_role"] == "lead"
    points = c.get(f"/api/engagements/{new['id']}/capture-points").json()
    assert [(p["name"], p["description"]) for p in points] == [("Core SPAN", "Gi0/24")]
    caps = c.get(f"/api/engagements/{new['id']}/captures").json()
    assert len(caps) == 1 and caps[0]["status"] == "done" and caps[0]["capture_point"] == "Core SPAN"
    assert caps[0]["summary"]["packets"] == 7
    assert c.get(f"/api/engagements/{new['id']}/captures/{caps[0]['id']}/result").json() == original
    dl = c.get(f"/api/engagements/{new['id']}/captures/{caps[0]['id']}/download")
    assert dl.content == small_pcap(tmp_path, "again.pcap").read_bytes()
    exe = next(f for f in original["files"] if f["filename"] == "tool.exe")
    assert c.get(f"/api/engagements/{new['id']}/files/{exe['sha256']}").content == EXE
    assert c.get(f"/api/engagements/{new['id']}/audit").json()[0]["action"] == "engagement.import"


@needs_tshark
def test_export_without_captures_keeps_results(ac, tmp_path):
    app, c = ac
    eid = engagement(c)
    upload(c, eid, small_pcap(tmp_path))
    run_jobs(app)
    data = export(c, eid, captures=False, files=False)
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert not any(n.startswith(("captures/", "files/")) for n in names)
    new = import_(c, data).json()
    cap = c.get(f"/api/engagements/{new['id']}/captures").json()[0]
    assert cap["status"] == "done"
    assert c.get(f"/api/engagements/{new['id']}/captures/{cap['id']}/download").status_code == 404


def test_unanalysed_capture_is_requeued_on_import(ac, tmp_path):
    app, c = ac
    eid = engagement(c)
    upload(c, eid, small_pcap(tmp_path))  # still queued
    new = import_(c, export(c, eid)).json()
    assert c.get(f"/api/engagements/{new['id']}/captures").json()[0]["status"] == "queued"


def test_import_names_never_collide(ac):
    _app, c = ac
    data = make_bundle({"manifest.json": json.dumps(manifest(engagement={"name": "Plant"})).encode()})
    names = [import_(c, data).json()["name"] for _ in range(3)]
    assert names == ["Plant", "Plant (imported)", "Plant (imported 3)"]


# ── unsafe / corrupt bundles ──────────────────────────────────────────────────


def _assert_rejected(c, data, msg):
    before = c.get("/api/engagements").json()
    r = import_(c, data)
    assert r.status_code == 400, r.text
    assert msg in r.json()["detail"]
    assert c.get("/api/engagements").json() == before  # nothing created


def test_rejects_non_zip(ac):
    _assert_rejected(ac[1], b"definitely not a zip", "not a zip")


def test_rejects_missing_manifest(ac):
    _assert_rejected(ac[1], make_bundle({"results/1.json.gz": b"x"}), "no manifest")


@pytest.mark.parametrize(
    "name", ["../evil.txt", "/etc/passwd", "captures/1/../../x", "notes.txt", "files/xyz"]
)
def test_rejects_unexpected_paths(ac, name):
    data = make_bundle({"manifest.json": json.dumps(manifest()).encode(), name: b"x"})
    _assert_rejected(ac[1], data, "Unexpected entry")


def test_rejects_zip_bomb(ac):
    data = make_bundle(
        {"manifest.json": json.dumps(manifest()).encode(), "files/" + "a" * 64: b"\0" * 5_000_000},
        compress=zipfile.ZIP_DEFLATED,
    )
    _assert_rejected(ac[1], data, "suspiciously compressed")


@pytest.mark.parametrize(
    "bad",
    [
        {"format": "something-else"},
        {"format_version": 99},
        {"engagement": {"name": ""}},
        {"captures": [{"key": 1}]},
        {"capture_points": [{"key": 1, "name": "a"}, {"key": 1, "name": "b"}]},
    ],
)
def test_rejects_invalid_manifest(ac, bad):
    _assert_rejected(ac[1], make_bundle({"manifest.json": json.dumps(manifest(**bad)).encode()}), "manifest")


def _capture_entry(sha="0" * 64, has_file=True, has_result=False):
    return {
        "key": 7,
        "file_name": "x.pcap",
        "size": 3,
        "sha256": sha,
        "status": "queued",
        "has_file": has_file,
        "has_result": has_result,
    }


def test_rejects_tampered_capture(ac):
    m = manifest(captures=[_capture_entry(sha="1" * 64)])
    data = make_bundle({"manifest.json": json.dumps(m).encode(), "captures/7/x.pcap": b"abc"})
    _assert_rejected(ac[1], data, "doesn't match its recorded hash")


def test_rejects_missing_listed_capture(ac):
    data = make_bundle({"manifest.json": json.dumps(manifest(captures=[_capture_entry()])).encode()})
    _assert_rejected(ac[1], data, "missing the capture file")


def test_rejects_garbage_result(ac):
    import gzip
    import hashlib

    sha = hashlib.sha256(b"abc").hexdigest()
    m = manifest(captures=[_capture_entry(sha=sha, has_result=True)])
    data = make_bundle(
        {
            "manifest.json": json.dumps(m).encode(),
            "captures/7/x.pcap": b"abc",
            "results/7.json.gz": gzip.compress(b'{"not": "a result"}'),
        }
    )
    _assert_rejected(ac[1], data, "Invalid analysis result")


def test_failed_import_leaves_no_files(ac):
    app, c = ac
    m = manifest(captures=[_capture_entry(sha="1" * 64)])
    import_(c, make_bundle({"manifest.json": json.dumps(m).encode(), "captures/7/x.pcap": b"abc"}))
    root = app.state.settings.data_dir / "engagements"
    assert not root.exists() or list(root.iterdir()) == []
    assert list((app.state.settings.data_dir / "tmp").iterdir()) == []


def test_import_size_limit(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False, max_upload_bytes=1000))
    with TestClient(app) as c:
        r = import_(c, b"PK" + b"\0" * 2000)
        assert r.status_code == 413


def test_import_requires_create_rights(make_settings):
    pw = "correct horse battery"
    s = make_settings(mode="server", run_jobs_in_app=False, admin_username="admin", admin_password=pw)
    with TestClient(create_app(s)) as admin:
        admin.post("/api/auth/login", json={"username": "admin", "password": pw}, headers=H)
        admin.post("/api/users", json={"username": "con", "password": pw, "role": "consultant"}, headers=H)
        con = TestClient(admin.app)
        con.post("/api/auth/login", json={"username": "con", "password": pw}, headers=H)
        data = make_bundle({"manifest.json": json.dumps(manifest()).encode()})
        assert import_(con, data).status_code == 403
        assert import_(admin, data).status_code == 201


def test_export_file_is_cleaned_up(ac, tmp_path):
    app, c = ac
    eid = engagement(c)
    export(c, eid)
    assert list((app.state.settings.data_dir / "tmp").iterdir()) == []


# ── asset inventory in bundles (format v2) ────────────────────────────────────


def _seed_with_result(app, eid, *hosts, name="a.pcap"):
    """A finished capture with a stored result (no capture file), merged into the inventory."""
    import gzip
    import hashlib

    from pcapvis.assets import merge
    from pcapvis.db.models import Capture, CaptureStatus
    from pcapvis.engagements.storage import Storage
    from tests.test_assets_merge import result

    res = result(*hosts)
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
        path = Storage(app.state.settings.data_dir).result_path(eid, cap.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(res.model_dump_json().encode()))
        merge.ingest_capture(db, cap, res)
        db.commit()


def test_round_trip_keeps_asset_edits_history_and_manual_assets(ac):
    from tests.test_assets_merge import MAC_A, MAC_B, host

    app, c = ac
    eid = engagement(c, "Assets")
    _seed_with_result(
        app, eid, host("10.0.0.5", MAC_A, host_type="PLC", purdue_level=1), host("10.0.0.6", MAC_B)
    )
    plc = next(a for a in c.get(f"/api/engagements/{eid}/assets").json() if a["ips"] == ["10.0.0.5"])
    c.patch(
        f"/api/engagements/{eid}/assets/{plc['id']}",
        json={
            "version": 1,
            "set": {"name": "Filler PLC", "zone": "Cell 1", "tags": ["sis"]},
            "reason": "Walkdown",
        },
        headers=H,
    )
    c.post(
        f"/api/engagements/{eid}/assets",
        json={
            "ips": ["10.0.0.254"],
            "values": {"name": "FW-1", "asset_type": "Firewall"},
            "reason": "Diagram",
        },
        headers=H,
    )
    data = export(c, eid, captures=False)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        m = json.loads(z.read("manifest.json"))
    assert m["format_version"] == 2 and len(m["assets"]) == 3

    r = import_(c, data)
    assert r.status_code == 201, r.text
    new = r.json()["id"]
    rows = {tuple(a["ips"]): a for a in c.get(f"/api/engagements/{new}/assets").json()}
    assert set(rows) == {("10.0.0.5",), ("10.0.0.6",), ("10.0.0.254",)}
    p = rows[("10.0.0.5",)]
    assert (p["name"], p["zone"], p["tags"], p["asset_type"], p["purdue_level"]) == (
        "Filler PLC",
        "Cell 1",
        ["sis"],
        "PLC",
        1,
    )
    assert p["macs"] == [MAC_A] and p["capture_count"] == 1 and p["version"] == 1
    d = c.get(f"/api/engagements/{new}/assets/{p['id']}").json()
    assert d["overrides"]["zone"]["reason"] == "Walkdown" and d["overrides"]["zone"]["by"] == "local"
    hist = c.get(f"/api/engagements/{new}/assets/{p['id']}/history").json()
    assert {h["field"] for h in hist if h["kind"] == "override"} == {"name", "zone", "tags"}
    assert not any(h["kind"] == "auto" for h in hist)  # importing doesn't invent history
    fw = rows[("10.0.0.254",)]
    assert fw["origin"] == "manual" and fw["name"] == "FW-1" and fw["capture_count"] == 0


def test_v1_bundle_derives_the_inventory_from_results(ac):
    import gzip
    import hashlib

    from tests.test_assets_merge import MAC_A, host, result

    sha = hashlib.sha256(b"abc").hexdigest()
    m = manifest(captures=[_capture_entry(sha=sha, has_result=True)])
    res = result(host("10.0.0.5", MAC_A, host_type="HMI", purdue_level=2))
    data = make_bundle(
        {
            "manifest.json": json.dumps(m).encode(),
            "captures/7/x.pcap": b"abc",
            "results/7.json.gz": gzip.compress(res.model_dump_json().encode()),
        }
    )
    r = import_(ac[1], data)
    assert r.status_code == 201, r.text
    (a,) = ac[1].get(f"/api/engagements/{r.json()['id']}/assets").json()
    assert a["asset_type"] == "HMI" and a["macs"] == [MAC_A]


def _asset(**over):
    a = {"key": 1, "origin": "manual", "ips": ["10.0.0.1"], "declared_ips": ["10.0.0.1"]}
    a.update(over)
    return a


@pytest.mark.parametrize(
    ("asset", "msg"),
    [
        (_asset(overrides={"purdue_level": {"value": 42}}), "Invalid asset value"),
        (_asset(overrides={"bogus": {"value": "x"}}), "Unknown asset field"),
        (_asset(auto={"name": "a\nb"}), "Invalid asset automatic value"),
        (_asset(ips=["10.0.0.999"]), "Invalid asset address"),
        (_asset(declared_macs=["nope"]), "Invalid asset address"),
        (
            _asset(history=[{"at": "2026-11-06T10:00:00Z", "kind": "override", "field": "evil"}]),
            "unknown field",
        ),
        (_asset(history=[{"at": "2026-11-06T10:00:00Z", "kind": "pwned"}]), "manifest"),
    ],
)
def test_rejects_bad_asset_data(ac, asset, msg):
    m = manifest(format_version=2, assets=[asset])
    _assert_rejected(ac[1], make_bundle({"manifest.json": json.dumps(m).encode()}), msg)


def test_rejects_duplicate_asset_keys(ac):
    m = manifest(format_version=2, assets=[_asset(), _asset(ips=["10.0.0.2"], declared_ips=["10.0.0.2"])])
    _assert_rejected(ac[1], make_bundle({"manifest.json": json.dumps(m).encode()}), "duplicate asset keys")


def test_imported_history_values_are_trimmed(ac):
    m = manifest(
        format_version=2,
        assets=[
            _asset(
                history=[
                    {
                        "at": "2026-11-06T10:00:00Z",
                        "kind": "override",
                        "field": "notes",
                        "old": {"x": 1},
                        "new": "y" * 20_000,
                    }
                ]
            )
        ],
    )
    r = import_(ac[1], make_bundle({"manifest.json": json.dumps(m).encode()}))
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    (a,) = ac[1].get(f"/api/engagements/{eid}/assets").json()
    h = [
        x
        for x in ac[1].get(f"/api/engagements/{eid}/assets/{a['id']}/history").json()
        if x["field"] == "notes"
    ][0]
    assert h["old"] == "{'x': 1}" and len(h["new"]) == 10_000
