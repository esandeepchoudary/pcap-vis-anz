"""Zones, conduits, violations and inferred networks (M6)."""

import json

import pytest
from fastapi.testclient import TestClient

from pcapvis.app import create_app
from tests.test_asset_links import CAM, HMI, PLC, cmd, flow, ingest, res
from tests.test_bundles import _assert_rejected, export, import_, make_bundle, manifest
from tests.test_captures_api import PW, H, engagement


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def ids(c, eid):
    return {a["ips"][0]: a["id"] for a in c.get(f"/api/engagements/{eid}/assets").json()}


def set_zone(c, eid, aid, zone):
    v = c.get(f"/api/engagements/{eid}/assets/{aid}").json()["version"]
    r = c.patch(f"/api/engagements/{eid}/assets/{aid}", json={"version": v, "set": {"zone": zone}}, headers=H)
    assert r.status_code == 200, r.text


def zone(c, eid, name, **kw):
    r = c.post(f"/api/engagements/{eid}/zones", json={"name": name, **kw}, headers=H)
    assert r.status_code == 201, r.text
    return r.json()


def setup_plant(app, c):
    eid = engagement(c)
    ingest(
        app,
        eid,
        res([flow(1, HMI, PLC, ot_writes=2), flow(2, HMI, CAM, protocol="RTSP", port=554)], [cmd(HMI, PLC)]),
        "a.pcap",
    )
    a = ids(c, eid)
    set_zone(c, eid, a[HMI], "Control")
    set_zone(c, eid, a[PLC], "Cell 1")
    set_zone(c, eid, a[CAM], "Security")
    return eid, a


def test_undefined_zones_come_from_assets_and_can_be_defined(ac):
    app, c = ac
    eid, a = setup_plant(app, c)
    zs = {z["name"]: z for z in c.get(f"/api/engagements/{eid}/zones").json()}
    assert set(zs) == {"Control", "Cell 1", "Security"} and not any(z["defined"] for z in zs.values())
    z = zone(c, eid, "Cell 1", purdue_level=1, security_level=3, description="Filler line")
    assert z["defined"] and z["asset_ids"] == [a[PLC]] and z["security_level"] == 3
    assert c.post(f"/api/engagements/{eid}/zones", json={"name": "Cell 1"}, headers=H).status_code == 409
    assert (
        c.post(f"/api/engagements/{eid}/zones", json={"name": "x", "purdue_level": 9}, headers=H).status_code
        == 422
    )
    assert c.post(f"/api/engagements/{eid}/zones", json={"name": "a\nb"}, headers=H).status_code == 422
    assert (
        c.post(
            f"/api/engagements/{eid}/zones", json={"name": "x", "security_level": 5}, headers=H
        ).status_code
        == 422
    )


def test_rename_moves_assets_with_history(ac):
    app, c = ac
    eid, a = setup_plant(app, c)
    z = zone(c, eid, "Cell 1")
    r = c.patch(f"/api/engagements/{eid}/zones/{z['id']}", json={"name": "Filler cell"}, headers=H)
    assert r.status_code == 200 and r.json()["asset_ids"] == [a[PLC]]
    assert c.get(f"/api/engagements/{eid}/assets/{a[PLC]}").json()["zone"] == "Filler cell"
    hist = c.get(f"/api/engagements/{eid}/assets/{a[PLC]}/history").json()
    assert hist[0]["reason"] == "Zone renamed from Cell 1"
    other = zone(c, eid, "Other")
    assert (
        c.patch(
            f"/api/engagements/{eid}/zones/{other['id']}", json={"name": "Filler cell"}, headers=H
        ).status_code
        == 409
    )


def test_positions_saved(ac):
    app, c = ac
    eid, _a = setup_plant(app, c)
    z = zone(c, eid, "Control")
    r = c.patch(f"/api/engagements/{eid}/zones/{z['id']}", json={"x": 120.5, "y": 40}, headers=H)
    assert (r.json()["x"], r.json()["y"]) == (120.5, 40)
    for bad in ('{"x": 1e308, "y": 0}', '{"x": NaN, "y": 0}', '{"x": 0, "y": -Infinity}'):
        r = c.patch(
            f"/api/engagements/{eid}/zones/{z['id']}",
            content=bad,
            headers={**H, "content-type": "application/json"},
        )
        assert r.status_code == 422, bad


def test_violations_without_and_with_conduits(ac):
    app, c = ac
    eid, a = setup_plant(app, c)
    v = c.get(f"/api/engagements/{eid}/violations").json()
    assert {(x["src_zone"], x["dst_zone"], x["kind"]) for x in v} == {
        ("Control", "Cell 1", "no_conduit"),
        ("Control", "Security", "no_conduit"),
    }
    assert v[0]["dst_zone"] == "Cell 1" and v[0]["ot_writes"] == 2  # writes first
    ctl, cell, sec = zone(c, eid, "Control"), zone(c, eid, "Cell 1"), zone(c, eid, "Security")
    r = c.post(
        f"/api/engagements/{eid}/conduits",
        json={"zone_a_id": cell["id"], "zone_b_id": ctl["id"], "allowed": ["Modbus", " modbus "]},
        headers=H,
    )
    assert r.status_code == 201 and r.json()["allowed"] == ["Modbus"]
    c.post(
        f"/api/engagements/{eid}/conduits",
        json={"zone_a_id": ctl["id"], "zone_b_id": sec["id"], "allowed": ["HTTPS"]},
        headers=H,
    )
    v = c.get(f"/api/engagements/{eid}/violations").json()
    assert [(x["dst_zone"], x["kind"], x["protocols"]) for x in v] == [
        ("Security", "protocol_not_allowed", ["RTSP"])
    ]
    cid = v[0]["conduit_id"]
    c.patch(f"/api/engagements/{eid}/conduits/{cid}", json={"allowed": []}, headers=H)  # empty = anything
    assert c.get(f"/api/engagements/{eid}/violations").json() == []


def test_conduit_rules(ac):
    app, c = ac
    eid, _a = setup_plant(app, c)
    z1, z2 = zone(c, eid, "Control"), zone(c, eid, "Cell 1")
    url = f"/api/engagements/{eid}/conduits"
    assert c.post(url, json={"zone_a_id": z1["id"], "zone_b_id": z1["id"]}, headers=H).status_code == 422
    assert c.post(url, json={"zone_a_id": z1["id"], "zone_b_id": 99999}, headers=H).status_code == 404
    assert c.post(url, json={"zone_a_id": z1["id"], "zone_b_id": z2["id"]}, headers=H).status_code == 201
    assert c.post(url, json={"zone_a_id": z2["id"], "zone_b_id": z1["id"]}, headers=H).status_code == 409
    assert c.post(
        url, json={"zone_a_id": z1["id"], "zone_b_id": z2["id"], "allowed": ["a\nb"]}, headers=H
    ).status_code in (409, 422)
    # Deleting a zone removes its conduits; assets keep the name as an undefined zone.
    assert c.delete(f"/api/engagements/{eid}/zones/{z1['id']}", headers=H).status_code == 204
    assert c.get(url).json() == []
    assert any(
        z["name"] == "Control" and not z["defined"] for z in c.get(f"/api/engagements/{eid}/zones").json()
    )


def test_cannot_reach_other_engagements_zones(ac):
    app, c = ac
    eid, _a = setup_plant(app, c)
    other = engagement(c, "Other")
    z = zone(c, eid, "Control")
    assert (
        c.patch(f"/api/engagements/{other}/zones/{z['id']}", json={"description": "x"}, headers=H).status_code
        == 404
    )
    z2 = zone(c, other, "Mine")
    assert (
        c.post(
            f"/api/engagements/{other}/conduits",
            json={"zone_a_id": z2["id"], "zone_b_id": z["id"]},
            headers=H,
        ).status_code
        == 404
    )


def test_networks_inferred(ac):
    app, c = ac
    eid, a = setup_plant(app, c)
    c.post(
        f"/api/engagements/{eid}/assets",
        json={"ips": ["10.0.0.254"], "values": {"asset_type": "Firewall"}},
        headers=H,
    )
    (net,) = c.get(f"/api/engagements/{eid}/networks").json()
    assert net["cidr"] == "10.0.0.0/24" and len(net["asset_ids"]) == 4 and len(net["gateways"]) == 1
    assert net["zones"] == ["Cell 1", "Control", "Security"]


def test_viewer_cannot_edit_zones(make_settings):
    app = create_app(make_settings(mode="server", admin_username="admin", admin_password=PW))
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        c.post("/api/users", json={"username": "vic", "password": PW, "role": "viewer"}, headers=H)
        eid = engagement(c)
        vid = next(u["id"] for u in c.get("/api/directory").json() if u["username"] == "vic")
        c.put(f"/api/engagements/{eid}/members/{vid}", json={"role": "viewer"}, headers=H)
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "vic", "password": PW}, headers=H)
        assert c.get(f"/api/engagements/{eid}/zones").status_code == 200
        assert c.post(f"/api/engagements/{eid}/zones", json={"name": "x"}, headers=H).status_code == 403


def test_bundle_round_trip_keeps_zones_and_conduits(ac):
    app, c = ac
    eid, _a = setup_plant(app, c)
    z1 = zone(c, eid, "Control", purdue_level=3, security_level=2)
    z2 = zone(c, eid, "Cell 1", purdue_level=1)
    c.patch(f"/api/engagements/{eid}/zones/{z1['id']}", json={"x": 10, "y": 20}, headers=H)
    c.post(
        f"/api/engagements/{eid}/conduits",
        json={"zone_a_id": z1["id"], "zone_b_id": z2["id"], "allowed": ["Modbus"], "name": "FW-1"},
        headers=H,
    )
    new = import_(c, export(c, eid, captures=False)).json()["id"]
    zs = {z["name"]: z for z in c.get(f"/api/engagements/{new}/zones").json()}
    assert zs["Control"]["defined"] and (zs["Control"]["x"], zs["Control"]["security_level"]) == (10, 2)
    (con,) = c.get(f"/api/engagements/{new}/conduits").json()
    assert con["name"] == "FW-1" and con["allowed"] == ["Modbus"]
    assert {con["zone_a_id"], con["zone_b_id"]} == {zs["Control"]["id"], zs["Cell 1"]["id"]}


@pytest.mark.parametrize(
    ("over", "msg"),
    [
        ({"zones": [{"key": 1, "name": "A"}, {"key": 2, "name": "A"}]}, "duplicate zones"),
        ({"zones": [{"key": 1, "name": "A", "purdue_level": 9}]}, "Invalid zone"),
        (
            {"zones": [{"key": 1, "name": "A"}], "conduits": [{"zone_a_key": 1, "zone_b_key": 7}]},
            "unknown zone",
        ),
    ],
)
def test_bundle_rejects_bad_zones(ac, over, msg):
    m = manifest(format_version=3, **over)
    _assert_rejected(ac[1], make_bundle({"manifest.json": json.dumps(m).encode()}), msg)


def test_v2_bundle_still_imports(ac):
    m = manifest(format_version=2, assets=[])
    r = import_(ac[1], make_bundle({"manifest.json": json.dumps(m).encode()}))
    assert r.status_code == 201


def test_rule_syntax():
    from pcapvis.zones import clean_protocols, parse_rule

    assert parse_rule("Modbus tcp/502 a->b").text() == "Modbus tcp/502 A→B"
    assert parse_rule("* TCP/443 B→A").text() == "* tcp/443 B→A"
    assert parse_rule("EtherNet/IP").text() == "EtherNet/IP"  # a slash in a protocol name isn't a port
    assert parse_rule("tcp/102 both").text() == "* tcp/102"
    assert clean_protocols(["modbus", "Modbus", " S7comm  tcp/102 ", ""]) == ["modbus", "S7comm tcp/102"]
    for bad in ("tcp/70000", "A→B"):
        with pytest.raises(Exception, match="out of range|needs a protocol"):
            parse_rule(bad)


def test_conduit_rules_by_port_and_direction(ac):
    """Control (HMI) polls Cell 1 (PLC) over Modbus tcp/502: conduit A = Cell 1, B = Control, so the traffic is B→A."""
    app, c = ac
    eid, _a = setup_plant(app, c)
    ctl, cell, sec = zone(c, eid, "Control"), zone(c, eid, "Cell 1"), zone(c, eid, "Security")
    c.post(
        f"/api/engagements/{eid}/conduits", json={"zone_a_id": ctl["id"], "zone_b_id": sec["id"]}, headers=H
    )

    def check(allowed):
        r = c.post(
            f"/api/engagements/{eid}/conduits",
            json={"zone_a_id": cell["id"], "zone_b_id": ctl["id"], "allowed": allowed},
            headers=H,
        )
        assert r.status_code == 201, r.text
        v = [x["protocols"] for x in c.get(f"/api/engagements/{eid}/violations").json()]
        c.delete(f"/api/engagements/{eid}/conduits/{r.json()['id']}", headers=H)
        return v

    assert check(["Modbus tcp/502 B→A"]) == []  # exactly what happens
    assert check(["* tcp/502"]) == []  # any protocol on that port, either way
    assert check(["Modbus A→B"]) == [["Modbus (B→A)"]]  # only the other way round is allowed
    assert check(["Modbus tcp/503"]) == [["Modbus"]]  # wrong port
    assert check(["S7comm"]) == [["Modbus"]]
    r = c.post(
        f"/api/engagements/{eid}/conduits",
        json={"zone_a_id": cell["id"], "zone_b_id": ctl["id"], "allowed": ["Modbus tcp/99999"]},
        headers=H,
    )
    assert r.status_code == 422 and "out of range" in r.text


def test_architecture_diagram_exports(ac):
    import xml.etree.ElementTree as ET

    app, c = ac
    eid, a = setup_plant(app, c)
    set_zone(c, eid, a[CAM], "<Security & CCTV>")
    ctl, cell = zone(c, eid, "Control", purdue_level=2), zone(c, eid, "Cell 1", purdue_level=1)
    c.post(
        f"/api/engagements/{eid}/conduits",
        json={"zone_a_id": cell["id"], "zone_b_id": ctl["id"], "allowed": ["Modbus tcp/502 B→A"]},
        headers=H,
    )
    d = c.get(f"/api/engagements/{eid}/reports/architecture.drawio")
    assert d.status_code == 200 and "architecture.drawio" in d.headers["content-disposition"]
    root = ET.fromstring(d.text)
    values = [cell.get("value") or "" for cell in root.iter("mxCell")]
    assert any(v.startswith("Control\n") and "Level 2" in v for v in values)
    assert "Modbus tcp/502 B→A" in values  # the approved conduit
    assert "Unapproved: RTSP" in values  # Control → <Security & CCTV> has no conduit
    assert any(v.startswith("<Security & CCTV>") and "not defined" in v for v in values)
    s = c.get(f"/api/engagements/{eid}/reports/architecture.svg").text
    ET.fromstring(s)
    assert "&lt;Security &amp; CCTV&gt;" in s and "<script" not in s
    empty = engagement(c, "Empty")
    assert "No zones defined yet" in c.get(f"/api/engagements/{empty}/reports/architecture.svg").text
    ET.fromstring(c.get(f"/api/engagements/{empty}/reports/architecture.drawio").text)
