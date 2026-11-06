"""Findings workspace and report generation (M8)."""

import io
import json
import xml.etree.ElementTree as ET
import zipfile

import pytest
from docx import Document
from fastapi.testclient import TestClient
from openpyxl import load_workbook

from pcapvis.app import create_app
from pcapvis.engine.model import Anomaly
from tests.test_asset_links import HMI, PLC, cmd, flow, ingest, res
from tests.test_bundles import _assert_rejected, export, import_, make_bundle, manifest
from tests.test_captures_api import PW, H, engagement

EVIL = '=HYPERLINK("http://evil")<script>alert(1)</script>\x07'


def anomaly(key="a1", severity="high", src=HMI, dst=PLC, count=1, t=100.0, evidence=("Block OB1",)):
    return Anomaly(
        id=key,
        rule="ot_s7_code_download",
        category="ot",
        severity=severity,
        title="PLC program download",
        description="Program blocks were downloaded to a PLC",
        src=src,
        dst=dst,
        count=count,
        first_seen=t,
        last_seen=t + 10,
        evidence=list(evidence),
        attack=["T0843"],
    )


def with_anomalies(r, *anoms):
    r.anomalies = list(anoms)
    return r


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def ids(c, eid):
    return {a["ips"][0]: a["id"] for a in c.get(f"/api/engagements/{eid}/assets").json()}


def findings(c, eid):
    return c.get(f"/api/engagements/{eid}/findings").json()


# ── findings ──────────────────────────────────────────────────────────────────


def test_rule_findings_merge_across_captures_and_map_to_assets(ac):
    app, c = ac
    eid = engagement(c)
    c1 = ingest(app, eid, with_anomalies(res([flow(1, HMI, PLC)]), anomaly(count=2, t=100)), "a.pcap")
    c2 = ingest(
        app,
        eid,
        with_anomalies(
            res([flow(1, HMI, PLC)]),
            anomaly(count=3, t=50, evidence=("Block OB35",)),
            anomaly("b2", severity="low"),
        ),
        "b.pcap",
    )
    (f, low) = findings(c, eid)
    a = ids(c, eid)
    assert f["key"] == "a1" and f["count"] == 5 and f["captures"] == [c1, c2]
    assert (f["first_seen"], f["last_seen"]) == (50, 110) and f["evidence"] == ["Block OB1", "Block OB35"]
    assert (
        f["asset_ids"] == sorted([a[HMI], a[PLC]])
        and f["status"] == "open"
        and f["include_in_report"] is True
    )
    assert low["severity"] == "low"


def test_triage_survives_reanalysis_and_drives_report_inclusion(ac):
    app, c = ac
    eid = engagement(c)
    ingest(app, eid, with_anomalies(res([]), anomaly()), "a.pcap")
    url = f"/api/engagements/{eid}/findings/a1"
    r = c.patch(
        url,
        json={
            "status": "confirmed",
            "severity_override": "critical",
            "notes": "Seen on site",
            "recommendation": "Restrict S7 downloads to the EWS",
        },
        headers=H,
    )
    assert r.status_code == 200, r.text
    f = r.json()
    assert (f["severity"], f["detected_severity"], f["status"], f["updated_by"]) == (
        "critical",
        "high",
        "confirmed",
        "local",
    )
    ingest(app, eid, with_anomalies(res([]), anomaly()), "b.pcap")  # another capture with the same finding
    assert findings(c, eid)[0]["status"] == "confirmed"
    c.patch(url, json={"status": "false_positive"}, headers=H)
    assert findings(c, eid)[0]["include_in_report"] is False  # false positives drop out by default
    c.patch(url, json={"include_in_report": True}, headers=H)
    assert findings(c, eid)[0]["include_in_report"] is True  # unless explicitly included
    c.patch(url, json={"clear_severity_override": True}, headers=H)
    assert findings(c, eid)[0]["severity"] == "high"
    assert (
        c.patch(url, json={"title": "renamed"}, headers=H).status_code == 422
    )  # rule text comes from the rule
    assert (
        c.patch(f"/api/engagements/{eid}/findings/nope", json={"status": "resolved"}, headers=H).status_code
        == 404
    )
    assert c.delete(url, headers=H).status_code == 409


def test_manual_findings(ac):
    app, c = ac
    eid = engagement(c)
    ingest(app, eid, res([]), "a.pcap")
    a = ids(c, eid)
    r = c.post(
        f"/api/engagements/{eid}/findings",
        json={
            "title": "Flat network",
            "severity": "medium",
            "description": "IT and OT share VLAN 1",
            "asset_ids": [a[HMI]],
        },
        headers=H,
    )
    assert r.status_code == 201, r.text
    key = r.json()["key"]
    assert r.json()["source"] == "manual" and r.json()["asset_ids"] == [a[HMI]]
    assert (
        c.post(
            f"/api/engagements/{eid}/findings",
            json={"title": "x", "severity": "low", "asset_ids": [99999]},
            headers=H,
        ).status_code
        == 422
    )
    assert (
        c.patch(
            f"/api/engagements/{eid}/findings/{key}", json={"title": "Flat network (VLAN 1)"}, headers=H
        ).json()["title"]
        == "Flat network (VLAN 1)"
    )
    assert c.delete(f"/api/engagements/{eid}/findings/{key}", headers=H).status_code == 204
    assert findings(c, eid) == []


def test_viewers_cannot_triage(make_settings):
    app = create_app(make_settings(mode="server", admin_username="admin", admin_password=PW))
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        c.post("/api/users", json={"username": "vic", "password": PW, "role": "viewer"}, headers=H)
        eid = engagement(c)
        vid = next(u["id"] for u in c.get("/api/directory").json() if u["username"] == "vic")
        c.put(f"/api/engagements/{eid}/members/{vid}", json={"role": "viewer"}, headers=H)
        ingest(app, eid, with_anomalies(res([]), anomaly()), "a.pcap")
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "vic", "password": PW}, headers=H)
        assert len(findings(c, eid)) == 1
        assert (
            c.patch(f"/api/engagements/{eid}/findings/a1", json={"status": "resolved"}, headers=H).status_code
            == 403
        )
        assert c.get(f"/api/engagements/{eid}/reports/report.html").status_code == 200


def test_bundle_round_trip_keeps_triage_and_manual_findings(ac):
    app, c = ac
    eid = engagement(c, "Findings")
    from tests.test_assets_merge import host
    from tests.test_bundles import _seed_with_result

    _seed_with_result(app, eid, host("10.0.0.5", "00:0c:29:00:00:77"))  # a MAC no other fixture uses
    ingest(app, eid, with_anomalies(res([]), anomaly()), "rules.pcap")  # no stored result: triage still exported
    c.patch(
        f"/api/engagements/{eid}/findings/a1",
        json={"status": "accepted_risk", "notes": "Vendor maintenance"},
        headers=H,
    )
    aid = ids(c, eid)["10.0.0.5"]
    c.post(
        f"/api/engagements/{eid}/findings",
        json={"title": "No asset owner", "severity": "low", "asset_ids": [aid]},
        headers=H,
    )
    new = import_(c, export(c, eid, captures=False)).json()["id"]
    got = {f["title"]: f for f in findings(c, new)}
    assert got["No asset owner"]["asset_ids"] == [ids(c, new)["10.0.0.5"]]
    with zipfile.ZipFile(io.BytesIO(export(c, eid, captures=False))) as z:
        m = json.loads(z.read("manifest.json"))
    assert m["format_version"] == 4 and any(f["status"] == "accepted_risk" for f in m["findings"])


@pytest.mark.parametrize(
    ("findings_", "msg"),
    [
        ([{"key": "x", "source": "manual"}], "needs a title"),
        ([{"key": "bad key!", "source": "rule"}], "manifest"),
        ([{"key": "k", "source": "rule"}, {"key": "k", "source": "rule"}], "duplicate findings"),
    ],
)
def test_bundle_rejects_bad_findings(ac, findings_, msg):
    m = manifest(format_version=4, findings=findings_)
    _assert_rejected(ac[1], make_bundle({"manifest.json": json.dumps(m).encode()}), msg)


# ── reports ───────────────────────────────────────────────────────────────────


def hostile_engagement(app, c):
    eid = engagement(c, "ACME / Plant <3>")
    ingest(
        app,
        eid,
        with_anomalies(res([flow(1, HMI, PLC, ot_writes=1)], [cmd(HMI, PLC, detail=EVIL)]), anomaly()),
        "a.pcap",
    )
    a = ids(c, eid)
    c.patch(
        f"/api/engagements/{eid}/assets/{a[PLC]}",
        json={"version": 1, "set": {"name": "=cmd|' /C calc'!A0", "zone": "Cell <1>", "notes": "line"}},
        headers=H,
    )
    c.patch(
        f"/api/engagements/{eid}/findings/a1", json={"recommendation": EVIL.replace("\x07", "")}, headers=H
    )
    return eid


def get(c, eid, name):
    r = c.get(f"/api/engagements/{eid}/reports/{name}")
    assert r.status_code == 200, r.text
    assert (
        "attachment" in r.headers["content-disposition"] and r.headers["x-content-type-options"] == "nosniff"
    )
    return r


def test_xlsx_register_never_writes_formulas(ac):
    app, c = ac
    eid = hostile_engagement(app, c)
    r = get(c, eid, "assets.xlsx")
    assert "ACME_Plant_3-asset-register.xlsx" in r.headers["content-disposition"]
    wb = load_workbook(io.BytesIO(r.content))
    assert wb.sheetnames == ["Assets", "Zones", "Conduits", "Zone violations", "Findings", "OT commands"]
    cells = [cell for ws in wb for row in ws.iter_rows() for cell in row]
    assert not any(cell.data_type == "f" for cell in cells)
    names = [row[1].value for row in wb["Assets"].iter_rows(min_row=2)]
    assert "=cmd|' /C calc'!A0" in names  # kept as text
    assert any("Block" not in str(c_.value) and str(c_.value).startswith("=HYPERLINK") for c_ in cells)


def test_drawio_and_svg_are_well_formed_and_escape_labels(ac):
    app, c = ac
    eid = hostile_engagement(app, c)
    d = get(c, eid, "purdue.drawio").text
    root = ET.fromstring(d)  # well-formed XML despite <, &, quotes in names
    values = [cell.get("value") for cell in root.iter("mxCell")]
    assert "Cell <1>" in values and any(v and v.startswith("=cmd") for v in values)
    assert "html=1" not in d  # labels are plain text in draw.io
    s = get(c, eid, "purdue.svg").text
    ET.fromstring(s)
    assert "<script" not in s


def test_html_report_escapes_and_has_no_scripts(ac):
    app, c = ac
    eid = hostile_engagement(app, c)
    h = get(c, eid, "report.html").text
    assert "<script" not in h and "&lt;script&gt;" in h
    for heading in ("Executive summary", "Scope", "Findings", "Segmentation", "Asset inventory"):
        assert f"<h1>{heading}</h1>" in h
    assert "PLC program download" in h and "T0843" in h


def test_docx_report(ac):
    app, c = ac
    eid = hostile_engagement(app, c)
    doc = Document(io.BytesIO(get(c, eid, "report.docx").content))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "OT network assessment – ACME / Plant <3>" in text and "PLC program download" in text
    assert "Recommendation: " in text and "\x07" not in text
    assert len(doc.tables) >= 3


def test_empty_engagement_reports(ac):
    _app, c = ac
    eid = engagement(c, "Empty")
    for name in ("assets.xlsx", "purdue.drawio", "purdue.svg", "report.docx", "report.html"):
        get(c, eid, name)
    assert "No findings are included" in get(c, eid, "report.html").text


def test_report_downloads_are_audited(ac):
    _app, c = ac
    eid = engagement(c)
    get(c, eid, "report.docx")
    assert any(e["action"] == "report.download" for e in c.get(f"/api/engagements/{eid}/audit").json())
