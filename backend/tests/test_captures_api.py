"""Captures: uploads, analysis jobs, results, downloads, Quick look, live updates."""

import gzip
import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from pcapvis.db.models import Capture, CaptureStatus
from pcapvis.jobs.runner import STALE_AFTER, JobRunner
from tests.pcapgen import Cap, http_get, http_ok

H = {"X-PcapVis-Client": "1"}
PW = "correct horse battery"
DEMO = Path(__file__).resolve().parents[2] / "fixtures" / "network-capture-demo.pcap"
needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")
EXE = b"MZ\x90\x00" + b"\x00" * 300


@pytest.fixture
def app_and_client(make_settings):
    """Laptop mode with jobs NOT auto-running, so tests drive the runner step by step."""
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False, events_poll_s=0.05))
    with TestClient(app) as c:
        yield app, c


@pytest.fixture
def client(app_and_client):
    return app_and_client[1]


def runner(app) -> JobRunner:
    return JobRunner(app.state.settings, app.state.session_factory)


def engagement(c, name="Plant"):
    return c.post("/api/engagements", json={"name": name}, headers=H).json()["id"]


def small_pcap(tmp_path, name="small.pcap") -> Path:
    cap = Cap().tcp_session(
        ("00:0c:29:00:00:01", "10.0.0.5"),
        ("00:0c:29:00:00:80", "10.0.0.80"),
        50000,
        80,
        [("c", http_get("hmi", "/tool.exe")), ("s", http_ok(EXE, ctype="application/octet-stream"))],
    )
    return cap.write(tmp_path / name)


def upload(c, eid, *paths, point=None, name=None):
    files = [("files", (name or p.name, p.read_bytes(), "application/octet-stream")) for p in paths]
    data = {"capture_point_id": str(point)} if point else {}
    return c.post(f"/api/engagements/{eid}/captures", files=files, data=data, headers=H)


# ── uploads ───────────────────────────────────────────────────────────────────


def test_upload_queues_capture_and_hashes(client, tmp_path, app_and_client):
    import hashlib

    eid = engagement(client)
    p = small_pcap(tmp_path)
    r = upload(client, eid, p)
    assert r.status_code == 201
    cap = r.json()[0]["capture"]
    assert r.json()[0]["duplicate"] is False
    assert cap["status"] == "queued" and cap["size"] == p.stat().st_size
    assert cap["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
    assert cap["uploaded_by"] == "local"
    stored = (
        app_and_client[0].state.settings.data_dir
        / "engagements"
        / str(eid)
        / "captures"
        / str(cap["id"])
        / p.name
    )
    assert stored.read_bytes() == p.read_bytes()
    assert client.get(f"/api/engagements/{eid}").json()["capture_count"] == 1


def test_duplicate_upload_detected_per_engagement(client, tmp_path):
    e1, e2 = engagement(client, "A"), engagement(client, "B")
    p = small_pcap(tmp_path)
    first = upload(client, e1, p).json()[0]
    again = upload(client, e1, p, name="renamed.pcap").json()[0]
    assert again["duplicate"] and again["capture"]["id"] == first["capture"]["id"]
    assert upload(client, e2, p).json()[0]["duplicate"] is False  # other engagement: fine


def test_multiple_files_in_one_upload(client, tmp_path):
    eid = engagement(client)
    a = small_pcap(tmp_path, "a.pcap")
    b = (
        Cap()
        .udp(("00:0c:29:00:00:01", "10.0.0.5"), ("00:0c:29:00:00:02", "10.0.0.6"), 1, 161)
        .write(tmp_path / "b.pcap")
    )
    r = upload(client, eid, a, b)
    assert [x["capture"]["file_name"] for x in r.json()] == ["a.pcap", "b.pcap"]


@pytest.mark.parametrize(
    "content,code,msg",
    [
        (b"PK\x03\x04 not a capture", 400, "not a pcap"),
        (b"", 400, "empty"),
    ],
)
def test_rejects_non_captures(client, content, code, msg):
    eid = engagement(client)
    r = client.post(f"/api/engagements/{eid}/captures", files=[("files", ("x.pcap", content))], headers=H)
    assert r.status_code == code and msg in r.json()["detail"]
    assert client.get(f"/api/engagements/{eid}/captures").json() == []


def test_size_limit(make_settings, tmp_path):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False, max_upload_bytes=100))
    with TestClient(app) as c:
        eid = engagement(c)
        r = upload(c, eid, small_pcap(tmp_path))
        assert r.status_code == 413
        leftovers = list((app.state.settings.data_dir / "engagements" / str(eid)).glob(".upload-*"))
        assert leftovers == []  # partial upload cleaned up


def test_path_traversal_in_filename_is_neutralised(client, tmp_path, app_and_client):
    eid = engagement(client)
    r = upload(client, eid, small_pcap(tmp_path), name="../../../etc/passwd.pcap")
    cap = r.json()[0]["capture"]
    assert cap["file_name"] == "passwd.pcap"
    root = app_and_client[0].state.settings.data_dir / "engagements" / str(eid)
    assert (root / "captures" / str(cap["id"]) / "passwd.pcap").is_file()


def test_capture_point_must_belong_to_engagement(client, tmp_path):
    a, b = engagement(client, "A"), engagement(client, "B")
    pa = client.post(f"/api/engagements/{a}/capture-points", json={"name": "SPAN"}, headers=H).json()["id"]
    assert upload(client, b, small_pcap(tmp_path), point=pa).status_code == 400
    r = upload(client, a, small_pcap(tmp_path), point=pa)
    assert r.json()[0]["capture"]["capture_point"] == "SPAN"


# ── jobs ──────────────────────────────────────────────────────────────────────


@needs_tshark
def test_job_analyses_and_stores_result(app_and_client, tmp_path):
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    rev_before = c.get(f"/api/engagements/{eid}/revision").json()["revision"]
    assert runner(app).run_once() is True
    assert runner(app).run_once() is False  # queue empty
    cap = c.get(f"/api/engagements/{eid}/captures/{cid}").json()
    assert cap["status"] == "done" and cap["progress"] == 1.0 and cap["finished_at"]
    s = cap["summary"]
    assert (
        s["packets"] == 7
        and s["hosts"] == 2
        and s["files"] == 1
        and set(s["findings"]) >= {"critical", "high"}
    )
    assert c.get(f"/api/engagements/{eid}/revision").json()["revision"] > rev_before
    r = c.get(f"/api/engagements/{eid}/captures/{cid}/result")
    assert r.status_code == 200 and r.headers["content-encoding"] == "gzip"
    result = r.json()
    assert result["capture"]["packets"] == 7 and len(result["hosts"]) == 2
    exe = next(f for f in result["files"] if f["filename"] == "tool.exe")
    assert exe["interesting"]
    d = c.get(f"/api/engagements/{eid}/files/{exe['sha256']}?name=tool.exe")
    assert d.content == EXE
    assert d.headers["content-type"] == "application/octet-stream"
    assert (
        "attachment" in d.headers["content-disposition"]
        and "tool.exe.bin" in d.headers["content-disposition"]
    )


@needs_tshark
def test_result_not_available_until_done(app_and_client, tmp_path):
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    assert c.get(f"/api/engagements/{eid}/captures/{cid}/result").status_code == 409


@needs_tshark
def test_corrupt_capture_fails_with_message(app_and_client):
    app, c = app_and_client
    eid = engagement(c)
    bad = b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00" * 16 + b"\xff" * 4000
    cid = c.post(f"/api/engagements/{eid}/captures", files=[("files", ("bad.pcap", bad))], headers=H).json()[
        0
    ]["capture"]["id"]
    runner(app).run_once()
    cap = c.get(f"/api/engagements/{eid}/captures/{cid}").json()
    assert cap["status"] == "failed" and "tshark" in cap["error"]
    # Re-analysis is allowed after a failure.
    assert c.post(f"/api/engagements/{eid}/captures/{cid}/reanalyze", headers=H).json()["status"] == "queued"


def test_cancel_queued(client, tmp_path):
    eid = engagement(client)
    cid = upload(client, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    assert (
        client.post(f"/api/engagements/{eid}/captures/{cid}/cancel", headers=H).json()["status"]
        == "cancelled"
    )
    assert client.post(f"/api/engagements/{eid}/captures/{cid}/cancel", headers=H).status_code == 409


@needs_tshark
def test_cancel_while_processing(app_and_client, tmp_path):
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    r = runner(app)
    assert r.claim() == cid
    assert c.get(f"/api/engagements/{eid}/captures/{cid}").json()["status"] == "processing"
    assert c.post(f"/api/engagements/{eid}/captures/{cid}/cancel", headers=H).json()["status"] == "processing"
    assert c.delete(f"/api/engagements/{eid}/captures/{cid}", headers=H).status_code == 409  # still running
    r.process(cid)
    assert c.get(f"/api/engagements/{eid}/captures/{cid}").json()["status"] == "cancelled"


@needs_tshark
def test_reanalyze_and_delete(app_and_client, tmp_path):
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    assert c.post(f"/api/engagements/{eid}/captures/{cid}/reanalyze", headers=H).status_code == 409  # queued
    runner(app).run_once()
    assert c.post(f"/api/engagements/{eid}/captures/{cid}/reanalyze", headers=H).json()["status"] == "queued"
    runner(app).run_once()
    assert c.get(f"/api/engagements/{eid}/captures/{cid}").json()["status"] == "done"
    root = app.state.settings.data_dir / "engagements" / str(eid)
    assert (root / "results" / f"{cid}.json.gz").is_file()
    assert c.delete(f"/api/engagements/{eid}/captures/{cid}", headers=H).status_code == 204
    assert not (root / "results" / f"{cid}.json.gz").exists() and not (root / "captures" / str(cid)).exists()
    assert c.get(f"/api/engagements/{eid}/captures/{cid}").status_code == 404


def test_two_runners_never_claim_the_same_job(app_and_client, tmp_path):
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    a, b = runner(app), runner(app)
    assert {a.claim(), b.claim()} == {cid, None}


def test_stale_jobs_are_requeued(app_and_client, tmp_path):
    from pcapvis.db.base import utcnow

    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    r = runner(app)
    r.claim()
    assert r.recover_stale() == 0  # fresh heartbeat
    with app.state.session_factory() as db:
        db.get(Capture, cid).heartbeat_at = utcnow() - STALE_AFTER * 2
        db.commit()
    assert r.recover_stale() == 1
    assert c.get(f"/api/engagements/{eid}/captures/{cid}").json()["status"] == "queued"


@needs_tshark
def test_shutdown_requeues_running_job(app_and_client, tmp_path):
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    r = runner(app)
    r.claim()
    r._stop.set()  # as if the process were shutting down
    r.process(cid)
    assert c.get(f"/api/engagements/{eid}/captures/{cid}").json()["status"] == "queued"


@needs_tshark
def test_in_app_runner_processes_uploads_automatically(make_settings, tmp_path):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=True))
    with TestClient(app) as c:
        eid = engagement(c)
        shutil.copy(DEMO, tmp_path / "demo.pcap")
        cid = upload(c, eid, tmp_path / "demo.pcap").json()[0]["capture"]["id"]
        for _ in range(200):
            cap = c.get(f"/api/engagements/{eid}/captures/{cid}").json()
            if cap["status"] in ("done", "failed"):
                break
            time.sleep(0.1)
        assert cap["status"] == "done", cap
        assert cap["summary"]["packets"] == 401 and cap["summary"]["findings"]["critical"] >= 2


# ── downloads & permissions ───────────────────────────────────────────────────


def test_download_original_capture(client, tmp_path):
    eid = engagement(client)
    p = small_pcap(tmp_path)
    cid = upload(client, eid, p).json()[0]["capture"]["id"]
    r = client.get(f"/api/engagements/{eid}/captures/{cid}/download")
    assert r.content == p.read_bytes() and "attachment" in r.headers["content-disposition"]


def test_extracted_file_route_validates_hash(client):
    eid = engagement(client)
    assert client.get(f"/api/engagements/{eid}/files/../../etc/passwd").status_code in (404, 422)
    assert client.get(f"/api/engagements/{eid}/files/{'a' * 64}").status_code == 404
    assert client.get(f"/api/engagements/{eid}/files/NOTAHASH").status_code == 422


def test_capture_of_other_engagement_is_404(client, tmp_path):
    a, b = engagement(client, "A"), engagement(client, "B")
    cid = upload(client, a, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    for url in ("", "/result", "/download"):
        assert client.get(f"/api/engagements/{b}/captures/{cid}{url}").status_code == 404


def test_viewer_cannot_upload_or_cancel(make_settings, tmp_path):
    s = make_settings(mode="server", run_jobs_in_app=False, admin_username="admin", admin_password=PW)
    with TestClient(create_app(s)) as admin:
        admin.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        uid = admin.post(
            "/api/users", json={"username": "vic", "password": PW, "role": "viewer"}, headers=H
        ).json()["id"]
        eid = engagement(admin)
        admin.put(f"/api/engagements/{eid}/members/{uid}", json={"role": "viewer"}, headers=H)
        cid = upload(admin, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
        viewer = TestClient(admin.app)
        viewer.post("/api/auth/login", json={"username": "vic", "password": PW}, headers=H)
        assert upload(viewer, eid, small_pcap(tmp_path, "v.pcap")).status_code == 403
        assert viewer.post(f"/api/engagements/{eid}/captures/{cid}/cancel", headers=H).status_code == 403
        assert viewer.get(f"/api/engagements/{eid}/captures").status_code == 200
        assert (
            viewer.post(
                "/api/quicklook", files={"file": ("q.pcap", b"\xd4\xc3\xb2\xa1")}, headers=H
            ).status_code
            == 403
        )


# ── Quick look ────────────────────────────────────────────────────────────────


@needs_tshark
def test_quicklook_flow_and_promotion(app_and_client, tmp_path):
    app, c = app_and_client
    p = small_pcap(tmp_path, "site-walk.pcap")
    r = c.post("/api/quicklook", files={"file": (p.name, p.read_bytes())}, headers=H)
    assert r.status_code == 201
    eng, cap = r.json()["engagement"], r.json()["capture"]
    assert eng["is_quicklook"] and eng["name"] == "site-walk.pcap" and cap["status"] == "queued"
    assert c.get("/api/engagements").json() == []  # not listed with engagements
    assert [x["id"] for x in c.get("/api/engagements?quicklook=true").json()] == [eng["id"]]
    runner(app).run_once()
    assert c.get(f"/api/engagements/{eng['id']}/captures/{cap['id']}").json()["status"] == "done"
    promoted = c.patch(
        f"/api/engagements/{eng['id']}", json={"is_quicklook": False, "name": "Site walk"}, headers=H
    ).json()
    assert not promoted["is_quicklook"]
    assert [x["name"] for x in c.get("/api/engagements").json()] == ["Site walk"]


def test_quicklook_bad_file_leaves_nothing_behind(client):
    r = client.post("/api/quicklook", files={"file": ("x.pcap", b"nope")}, headers=H)
    assert r.status_code == 400
    assert client.get("/api/engagements?quicklook=true").json() == []


def test_quicklooks_are_personal(make_settings, tmp_path):
    s = make_settings(mode="server", run_jobs_in_app=False, admin_username="admin", admin_password=PW)
    with TestClient(create_app(s)) as admin:
        admin.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        admin.post("/api/users", json={"username": "con", "password": PW, "role": "consultant"}, headers=H)
        con = TestClient(admin.app)
        con.post("/api/auth/login", json={"username": "con", "password": PW}, headers=H)
        p = small_pcap(tmp_path)
        ql = con.post("/api/quicklook", files={"file": (p.name, p.read_bytes())}, headers=H).json()[
            "engagement"
        ]
        assert [x["id"] for x in con.get("/api/engagements?quicklook=true").json()] == [ql["id"]]
        assert admin.get("/api/engagements?quicklook=true").json() == []  # not in the admin's own list
        uid = admin.get("/api/directory").json()[0]["id"]
        r = con.put(f"/api/engagements/{ql['id']}/members/{uid}", json={"role": "viewer"}, headers=H)
        assert r.status_code == 400 and "Promote" in r.json()["detail"]
        # The creator leads their own Quick look (rename, delete), even as a consultant…
        assert (
            con.patch(f"/api/engagements/{ql['id']}", json={"name": "renamed"}, headers=H).status_code == 200
        )
        # …but turning it into an engagement needs engagement-creation rights.
        r = con.patch(f"/api/engagements/{ql['id']}", json={"is_quicklook": False}, headers=H)
        assert r.status_code == 403 and "Quick look" in r.json()["detail"]
        # Admins see everything, but a Quick look isn't offered to anyone else as a member.
        assert admin.get(f"/api/engagements/{ql['id']}").status_code == 200


# ── live updates ──────────────────────────────────────────────────────────────


def test_events_stream_reports_revision(client, tmp_path):
    eid = engagement(client)
    with client.stream("GET", f"/api/engagements/{eid}/events") as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        lines = r.iter_lines()
        assert next(lines) == "event: revision"
        first = int(next(lines).split(": ")[1])
        client.post(f"/api/engagements/{eid}/capture-points", json={"name": "TAP"}, headers=H)
        seen = []
        for line in lines:
            if line.startswith("data:"):
                seen.append(int(line.split(": ")[1]))
                break
        assert seen and seen[0] > first


def test_events_404_for_outsiders(client):
    assert client.get("/api/engagements/9999/events").status_code == 404


def test_result_json_is_valid_gzip_on_disk(app_and_client, tmp_path):
    if not shutil.which("tshark"):
        pytest.skip("tshark not installed")
    app, c = app_and_client
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    runner(app).run_once()
    path = app.state.settings.data_dir / "engagements" / str(eid) / "results" / f"{cid}.json.gz"
    data = json.loads(gzip.decompress(path.read_bytes()))
    assert data["capture"]["file_name"] == "small.pcap"
    assert not list(path.parent.glob("*.tmp"))
    with app.state.session_factory() as db:
        assert db.get(Capture, cid).status == CaptureStatus.done
