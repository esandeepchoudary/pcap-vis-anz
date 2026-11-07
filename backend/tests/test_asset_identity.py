"""Manual identity fixes: merging assets the matcher kept apart, splitting one it joined."""

import gzip
import hashlib
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from pcapvis.assets import merge
from pcapvis.db.models import Capture, CaptureStatus
from pcapvis.engagements.storage import Storage
from pcapvis.engine.model import Anomaly
from tests.test_asset_links import cmd, flow
from tests.test_assets_merge import host, result
from tests.test_captures_api import H, engagement

HMI, PLC, PLC2 = "10.0.0.10", "10.0.0.50", "10.0.0.51"
MAC_HMI, MAC_PLC, MAC_PLC2 = "00:0c:29:00:00:10", "00:1b:1b:00:00:50", "00:1b:1b:00:00:51"


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def ingest(app, eid, r, name="a.pcap", cid=None):
    """Store the result (splits rebuild traffic from it) and merge it into the inventory."""
    with app.state.session_factory() as db:
        cap = db.get(Capture, cid) if cid else None
        if cap is None:
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
        with gzip.open(path, "wb") as fh:
            fh.write(r.model_dump_json().encode())
        merge.ingest_capture(db, cap, r)
        db.commit()
        return cap.id


def assets(c, eid):
    return {tuple(a["ips"]): a for a in c.get(f"/api/engagements/{eid}/assets").json()}


def by_ip(c, eid, ip):
    return next(a for a in c.get(f"/api/engagements/{eid}/assets").json() if ip in a["ips"])


def links(c, eid):
    ids = {a["id"]: a["ips"][0] for a in c.get(f"/api/engagements/{eid}/assets").json()}
    return {(ids[x["src"]], ids[x["dst"]]): x for x in c.get(f"/api/engagements/{eid}/links").json()}


def anomaly(src, dst):
    return Anomaly(
        id="a1",
        rule="ot_s7_write",
        category="ot",
        severity="high",
        title="S7 write",
        description="d",
        src=src,
        dst=dst,
        count=1,
        first_seen=1,
        last_seen=2,
    )


# The PLC was seen at two addresses with different NICs: the matcher kept two assets.
def two_nic_result():
    r = result(host(HMI, MAC_HMI), host(PLC, MAC_PLC), host(PLC2, MAC_PLC2))
    r.flows = [flow(1, HMI, PLC, ot_writes=2, packets_c2s=10), flow(2, HMI, PLC2, ot_writes=1, packets_c2s=4)]
    r.ot_commands = [cmd(HMI, PLC), cmd(HMI, PLC2)]
    r.anomalies = [anomaly(HMI, PLC2)]
    return r


def test_merge_folds_traffic_findings_and_history_and_sticks(ac):
    app, c = ac
    eid = engagement(c)
    cid = ingest(app, eid, two_nic_result())
    target, other = by_ip(c, eid, PLC), by_ip(c, eid, PLC2)
    c.patch(
        f"/api/engagements/{eid}/assets/{other['id']}",
        json={"version": other["version"], "set": {"location": "Cabinet 4"}},
        headers=H,
    )
    r = c.post(
        f"/api/engagements/{eid}/assets/{target['id']}/merge",
        json={"version": target["version"], "source_ids": [other["id"]], "reason": "same PLC, two NICs"},
        headers=H,
    )
    assert r.status_code == 200, r.text
    merged = r.json()
    assert merged["ips"] == [PLC, PLC2] and merged["macs"] == [MAC_PLC, MAC_PLC2]
    assert merged["location"] == "Cabinet 4"  # the other's manual value fills an empty field
    assert len(assets(c, eid)) == 2  # HMI + the PLC
    lk = links(c, eid)
    assert lk[(HMI, PLC)]["ot_writes"] == 3 and lk[(HMI, PLC)]["flows"] == 2  # folded
    f = c.get(f"/api/engagements/{eid}/findings").json()
    assert {x["src"] for x in f} == {HMI} and target["id"] in f[0]["asset_ids"]
    hist = c.get(f"/api/engagements/{eid}/assets/{target['id']}/history").json()
    assert hist[0]["kind"] == "merge" and hist[0]["reason"] == "same PLC, two NICs"
    assert any(h["field"] == "location" for h in hist)  # the other asset's history came along
    # Re-analysing the capture (or a later one) keeps them together.
    ingest(app, eid, two_nic_result(), cid=cid)
    assert len(assets(c, eid)) == 2
    assert by_ip(c, eid, PLC2)["id"] == target["id"]


def test_split_moves_addresses_and_traffic_and_beats_the_shared_mac(ac):
    """One MAC answering for two IPs (a NAT gateway in front of two devices): the matcher joined them."""
    app, c = ac
    eid = engagement(c)
    r0 = result(host(HMI, MAC_HMI), host(PLC, MAC_PLC), host(PLC2, MAC_PLC))
    r0.flows = [flow(1, HMI, PLC, ot_writes=2), flow(2, HMI, PLC2, ot_writes=1)]
    r0.ot_commands = [cmd(HMI, PLC), cmd(HMI, PLC2)]
    cid = ingest(app, eid, r0)
    joined = by_ip(c, eid, PLC)
    assert joined["ips"] == [PLC, PLC2]
    assert links(c, eid)[(HMI, PLC)]["ot_writes"] == 3
    r = c.post(
        f"/api/engagements/{eid}/assets/{joined['id']}/split",
        json={"version": joined["version"], "ips": [PLC2], "reason": "different device behind the NAT"},
        headers=H,
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["original"]["ips"] == [PLC] and out["created"]["ips"] == [PLC2]
    lk = links(c, eid)
    assert lk[(HMI, PLC)]["ot_writes"] == 2 and lk[(HMI, PLC2)]["ot_writes"] == 1
    assert c.get(f"/api/engagements/{eid}/assets/{out['created']['id']}/history").json()[0]["kind"] == "split"
    # Re-analysis: the pinned address wins over the shared MAC.
    ingest(app, eid, r0, cid=cid)
    assert by_ip(c, eid, PLC2)["id"] == out["created"]["id"]
    assert by_ip(c, eid, PLC)["id"] == joined["id"]


def test_merge_and_split_guard_rails(ac):
    app, c = ac
    eid = engagement(c)
    ingest(app, eid, two_nic_result())
    plc, other = by_ip(c, eid, PLC), by_ip(c, eid, PLC2)
    base = f"/api/engagements/{eid}/assets/{plc['id']}"
    assert (
        c.post(
            f"{base}/merge", json={"version": plc["version"], "source_ids": [plc["id"]]}, headers=H
        ).status_code
        == 422
    )
    assert (
        c.post(
            f"{base}/merge", json={"version": plc["version"], "source_ids": [99999]}, headers=H
        ).status_code
        == 404
    )
    assert (
        c.post(
            f"{base}/merge", json={"version": plc["version"] + 5, "source_ids": [other["id"]]}, headers=H
        ).status_code
        == 409
    )
    assert (
        c.post(f"{base}/split", json={"version": plc["version"], "ips": [PLC]}, headers=H).status_code == 422
    )  # nothing left
    assert (
        c.post(f"{base}/split", json={"version": plc["version"], "ips": ["10.9.9.9"]}, headers=H).status_code
        == 422
    )
    other_eid = engagement(c, "Elsewhere")
    assert (
        c.post(
            f"/api/engagements/{other_eid}/assets/{plc['id']}/merge",
            json={"version": 1, "source_ids": [other["id"]]},
            headers=H,
        ).status_code
        == 404
    )


def test_pins_survive_a_bundle_round_trip(ac):
    app, c = ac
    eid = engagement(c)
    ingest(app, eid, two_nic_result())
    plc, other = by_ip(c, eid, PLC), by_ip(c, eid, PLC2)
    c.post(
        f"/api/engagements/{eid}/assets/{plc['id']}/merge",
        json={"version": plc["version"], "source_ids": [other["id"]]},
        headers=H,
    )
    data = c.get(f"/api/engagements/{eid}/export").content
    manifest = zipfile.ZipFile(io.BytesIO(data)).read("manifest.json")
    assert PLC2.encode() in manifest and b"pinned_ips" in manifest
    r = c.post("/api/engagements/import", files={"file": ("b.pcapvis", data)}, headers=H)
    assert r.status_code == 201, r.text
    new = r.json()["id"]
    merged = by_ip(c, new, PLC2)
    assert merged["ips"] == [PLC, PLC2]
    hist = c.get(f"/api/engagements/{new}/assets/{merged['id']}/history").json()
    assert any(h["kind"] == "merge" for h in hist)
