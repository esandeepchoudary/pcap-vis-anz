"""Importing asset edits from a filled-in register (CSV or XLSX)."""

import csv
import io
import zipfile

import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook, load_workbook

from pcapvis.app import create_app
from tests.test_asset_links import HMI, PLC, cmd, flow, ingest, res
from tests.test_captures_api import H, engagement


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        eid = engagement(c)
        ingest(app, eid, res([flow(1, HMI, PLC)], [cmd(HMI, PLC)]), "a.pcap")
        yield app, c, eid


def upload(c, eid, name, data, apply=False, reason=""):
    return c.post(
        f"/api/engagements/{eid}/assets/import",
        files={"file": (name, data)},
        data={"apply": "true" if apply else "false", "reason": reason},
        headers=H,
    )


def by_ip(c, eid, ip):
    return next(a for a in c.get(f"/api/engagements/{eid}/assets").json() if ip in a["ips"])


def exported_csv(c, eid) -> list[dict]:
    text = c.get(f"/api/engagements/{eid}/assets/export").content.decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(text)))


def to_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()


def test_csv_round_trip_previews_then_applies(ac):
    _app, c, eid = ac
    rows = exported_csv(c, eid)
    plc = next(r for r in rows if PLC in r["ip_addresses"])
    plc.update(
        {
            "name": "PLC-Line2",
            "zone": "Cell 2",
            "tags": "line2; critical",
            "criticality": "High",
        }
    )
    hmi = next(r for r in rows if HMI in r["ip_addresses"])
    hmi.update({"location": "", "owner": "Ops team"})  # blank stays as is
    data = to_csv(rows)

    r = upload(c, eid, "register.csv", data)
    assert r.status_code == 200, r.text
    p = r.json()
    assert not p["applied"] and p["matched"] == 3 and not p["errors"] and not p["unmatched"]
    got = {(ch["asset_id"], ch["field"]): ch["new"] for ch in p["changes"]}
    pid, hid = by_ip(c, eid, PLC)["id"], by_ip(c, eid, HMI)["id"]
    assert got == {
        (pid, "name"): "PLC-Line2",
        (pid, "zone"): "Cell 2",
        (pid, "tags"): ["line2", "critical"],
        (pid, "criticality"): "high",
        (hid, "owner"): "Ops team",
    }  # unchanged cells (e.g. the exported Purdue level) are not changes
    assert by_ip(c, eid, PLC)["name"] is None  # preview changed nothing

    r = upload(c, eid, "register.csv", data, apply=True, reason="Client walkdown 7 Nov")
    assert r.json()["applied"] and r.json()["assets_changed"] == 2
    a = by_ip(c, eid, PLC)
    assert a["name"] == "PLC-Line2" and a["zone"] == "Cell 2" and "zone" in a["overridden"]
    hist = c.get(f"/api/engagements/{eid}/assets/{pid}/history").json()
    assert any(h["field"] == "zone" and h["reason"] == "Client walkdown 7 Nov" for h in hist)
    assert upload(c, eid, "register.csv", data).json()["changes"] == []  # idempotent


def test_xlsx_register_by_labels_and_ip_fallback(ac):
    _app, c, eid = ac
    wb = load_workbook(io.BytesIO(c.get(f"/api/engagements/{eid}/reports/assets.xlsx").content))
    ws = wb["Assets"]
    header = [cell.value for cell in ws[1]]
    for row in ws.iter_rows(min_row=2):
        if PLC in str(row[header.index("IP addresses")].value):
            row[header.index("Purdue level")].value = "L2"
            row[header.index("Asset ID")].value = None  # matched by IP instead
    buf = io.BytesIO()
    wb.save(buf)
    p = upload(c, eid, "register.xlsx", buf.getvalue()).json()
    assert [(ch["field"], ch["new"]) for ch in p["changes"]] == [("purdue_level", 2.0)]


def test_unmatched_rows_and_bad_values_are_reported(ac):
    _app, c, eid = ac
    rows = [
        {"asset_id": "9999", "name": "ghost", "purdue_level": ""},
        {"asset_id": str(by_ip(c, eid, PLC)["id"]), "name": "", "purdue_level": "seven"},
        {"asset_id": str(by_ip(c, eid, PLC)["id"]), "name": "dup", "purdue_level": ""},
    ]
    p = upload(c, eid, "r.csv", to_csv(rows)).json()
    assert p["unmatched"][0] == "row 2: no asset with ID 9999"
    assert "appears twice" in p["unmatched"][1]
    assert p["errors"] == ["row 3, Purdue level: Purdue level must be a number such as 1 or 3.5."]
    assert p["changes"] == []


@pytest.mark.parametrize(
    "name,data,msg",
    [
        ("x.csv", b"foo,bar\n1,2\n", "No 'asset_id'"),
        ("x.csv", b"asset_id,protocols\n1,TCP\n", "No editable columns"),
        ("x.csv", b"", "empty"),
        ("x.xlsx", b"PK\x03\x04 not really", "Not a readable"),
    ],
)
def test_unreadable_files(ac, name, data, msg):
    _app, c, eid = ac
    r = upload(c, eid, name, data)
    assert r.status_code == 400 and msg in r.json()["detail"]


def test_xlsx_with_entities_is_refused(ac):
    """XXE / billion laughs: openpyxl parses through defusedxml."""
    _app, c, eid = ac
    wb = Workbook()
    wb.active.append(["asset_id", "name"])
    buf = io.BytesIO()
    wb.save(buf)
    src = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "xl/worksheets/sheet1.xml":
                data = b'<?xml version="1.0"?><!DOCTYPE worksheet [<!ENTITY e SYSTEM "file:///etc/passwd">]>' + data
            z.writestr(item, data)
    r = upload(c, eid, "evil.xlsx", out.getvalue())
    assert r.status_code == 400 and "Not a readable" in r.json()["detail"] and "root:" not in r.text


def test_viewers_cannot_import(make_settings):
    from tests.test_captures_api import PW

    app = create_app(
        make_settings(mode="server", admin_username="admin", admin_password=PW, run_jobs_in_app=False)
    )
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        eid = engagement(c)
        c.post("/api/users", json={"username": "vic", "password": PW, "role": "viewer"}, headers=H)
        uid = next(u["id"] for u in c.get("/api/users").json() if u["username"] == "vic")
        c.put(f"/api/engagements/{eid}/members/{uid}", json={"role": "viewer"}, headers=H)
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "vic", "password": PW}, headers=H)
        assert upload(c, eid, "r.csv", b"asset_id,name\n1,x\n").status_code == 403
