"""Dashboard, capture diff and packet inspector (M7)."""

import shutil

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from pcapvis.jobs.runner import JobRunner
from tests.test_asset_links import CAM, HMI, PLC, cmd, flow, ingest, res
from tests.test_captures_api import PW, H, engagement, small_pcap, upload

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def ids(c, eid):
    return {a["ips"][0]: a["id"] for a in c.get(f"/api/engagements/{eid}/assets").json()}


def test_diff_between_captures(ac):
    app, c = ac
    eid = engagement(c)
    base = ingest(app, eid, res([flow(1, HMI, PLC)]), "monday.pcap")
    later = ingest(
        app, eid, res([flow(1, HMI, PLC), flow(2, HMI, CAM, protocol="RTSP", port=554)]), "friday.pcap"
    )
    # res() always lists the same hosts, so assets don't change; the new connection does.
    a = ids(c, eid)
    d = c.get(f"/api/engagements/{eid}/diff", params={"base": base, "compare": later}).json()
    assert d["new_assets"] == [] and d["gone_assets"] == []
    assert [(x["src"], x["dst"], x["protocol"]) for x in d["new_links"]] == [(a[HMI], a[CAM], "RTSP")]
    back = c.get(f"/api/engagements/{eid}/diff", params={"base": later, "compare": base}).json()
    assert [x["protocol"] for x in back["gone_links"]] == ["RTSP"]
    assert c.get(f"/api/engagements/{eid}/diff", params={"base": base, "compare": 99999}).status_code == 404


def test_diff_new_assets(ac):
    from tests.test_assets_api import seed
    from tests.test_assets_merge import MAC_A, MAC_B, host

    app, c = ac
    eid = engagement(c)
    b = seed(app, eid, host("10.0.0.5", MAC_A), name="b.pcap")
    n = seed(app, eid, host("10.0.0.5", MAC_A), host("10.0.0.6", MAC_B), name="n.pcap")
    d = c.get(f"/api/engagements/{eid}/diff", params={"base": b, "compare": n}).json()
    assert d["new_assets"] == [ids(c, eid)["10.0.0.6"]]


def test_dashboard(ac):
    app, c = ac
    eid = engagement(c)
    ingest(app, eid, res([flow(1, HMI, PLC, ot_writes=1)], [cmd(HMI, PLC), cmd(HMI, PLC, t=200)]), "a.pcap")
    a = ids(c, eid)
    c.patch(
        f"/api/engagements/{eid}/assets/{a[PLC]}",
        json={"version": 1, "set": {"zone": "Cell", "purdue_level": 1}},
        headers=H,
    )
    c.patch(
        f"/api/engagements/{eid}/assets/{a[HMI]}", json={"version": 1, "set": {"zone": "Control"}}, headers=H
    )
    d = c.get(f"/api/engagements/{eid}/dashboard").json()
    assert d["assets"] == 3 and d["assets_edited"] == 2 and d["assets_by_level"]["1"] == 1
    assert d["ot_connections"] == 1 and d["ot_writes"] == 2 and d["violations"] == 1
    assert d["captures"] == 1 and set(d["findings"]) == {"critical", "high", "medium", "low", "info"}


@needs_tshark
def test_packet_inspector(ac, tmp_path):
    app, c = ac
    eid = engagement(c)
    cid = upload(c, eid, small_pcap(tmp_path)).json()[0]["capture"]["id"]
    JobRunner(app.state.settings, app.state.session_factory).run_once()
    url = f"/api/engagements/{eid}/captures/{cid}/packets"
    r = c.get(url, params={"filter": "http.request"})
    assert r.status_code == 200, r.text
    (p,) = r.json()["packets"]
    assert p["src"] == "10.0.0.5" and p["dst"] == "10.0.0.80" and "GET /tool.exe" in p["info"]
    assert r.json()["truncated"] is False
    allp = c.get(url, params={"limit": 2}).json()
    assert len(allp["packets"]) == 2 and allp["truncated"] is True
    d = c.get(f"{url}/{p['number']}").json()
    assert d["text"].startswith(f"Frame {p['number']}:") and "Hypertext Transfer Protocol" in d["text"]
    bad = c.get(url, params={"filter": "nonsense.field == 1"})
    assert bad.status_code == 400 and "not a valid" in bad.json()["detail"]
    assert c.get(url, params={"filter": "tcp\nudp"}).status_code == 400
    assert c.get(f"{url}/99999").status_code == 404


def test_packet_inspector_needs_the_capture_file(ac):
    app, c = ac
    eid = engagement(c)
    cid = ingest(app, eid, res([]), "imported.pcap")  # no file on disk, as after a results-only import
    r = c.get(f"/api/engagements/{eid}/captures/{cid}/packets")
    assert r.status_code == 404 and "isn't stored" in r.json()["detail"]


def test_packet_inspector_is_for_editors(make_settings):
    app = create_app(make_settings(mode="server", admin_username="admin", admin_password=PW))
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        c.post("/api/users", json={"username": "vic", "password": PW, "role": "viewer"}, headers=H)
        eid = engagement(c)
        vid = next(u["id"] for u in c.get("/api/directory").json() if u["username"] == "vic")
        c.put(f"/api/engagements/{eid}/members/{vid}", json={"role": "viewer"}, headers=H)
        cid = ingest(app, eid, res([]), "x.pcap")
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "vic", "password": PW}, headers=H)
        assert c.get(f"/api/engagements/{eid}/captures/{cid}/packets").status_code == 403
        assert c.get(f"/api/engagements/{eid}/dashboard").status_code == 200
