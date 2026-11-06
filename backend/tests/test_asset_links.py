"""Asset-to-asset links and OT operations merged across captures (Purdue map data, M4)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text

from pcapvis.app import create_app
from pcapvis.assets import merge
from pcapvis.db.models import Asset, AssetLink, AssetOtOp
from pcapvis.engine.model import Flow, OtCommand
from tests.test_assets_api import seed
from tests.test_assets_merge import MAC_A, MAC_B, capture, host, result
from tests.test_captures_api import PW, H, engagement

HMI, PLC, CAM = "10.0.0.10", "10.0.0.50", "10.0.0.60"


def flow(i, client, server, protocol="Modbus", port=502, **kw) -> Flow:
    kw.setdefault("packets_c2s", 5)
    kw.setdefault("packets_s2c", 5)
    kw.setdefault("bytes_c2s", 300)
    kw.setdefault("bytes_s2c", 200)
    return Flow(
        id=i,
        transport="tcp",
        client=client,
        client_port=40000 + i,
        server=server,
        server_port=port,
        protocol=protocol,
        direction_basis="handshake",
        first_seen=kw.pop("first", 100.0),
        last_seen=kw.pop("last", 200.0),
        **kw,
    )


def cmd(
    src, dst, function="Write Single Register", kind="write", is_request=True, t=150.0, detail=""
) -> OtCommand:
    return OtCommand(
        time=t,
        flow_id=1,
        src=src,
        dst=dst,
        protocol="Modbus",
        function_code=6,
        function=function,
        kind=kind,
        is_request=is_request,
        detail=detail,
    )


def hosts():
    return [
        host(HMI, MAC_A),
        host(PLC, MAC_B),
        host(CAM, "00:0c:29:00:00:60"),
        host("224.0.0.251", is_multicast=True),
    ]


def res(flows, commands=()):
    r = result(*hosts())
    r.flows = flows
    r.ot_commands = list(commands)
    return r


@pytest.fixture
def ac(make_settings):
    app = create_app(make_settings(mode="laptop", run_jobs_in_app=False))
    with TestClient(app) as c:
        yield app, c


def ingest(app, eid, r, name):
    with app.state.session_factory() as db:
        import hashlib

        from pcapvis.db.models import Capture, CaptureStatus

        cap = Capture(
            engagement_id=eid,
            file_name=name,
            size=1,
            sha256=hashlib.sha256(name.encode()).hexdigest(),
            status=CaptureStatus.done,
        )
        db.add(cap)
        db.flush()
        merge.ingest_capture(db, cap, r)
        db.commit()
        return cap.id


def ids(c, eid) -> dict[str, int]:
    return {a["ips"][0]: a["id"] for a in c.get(f"/api/engagements/{eid}/assets").json()}


def test_links_merge_across_captures(ac):
    app, c = ac
    eid = engagement(c)
    c1 = ingest(
        app,
        eid,
        res(
            [
                flow(1, HMI, PLC, ot_reads=3, ot_writes=1, first=100, last=110),
                flow(2, HMI, PLC, protocol="HTTP", port=80),
                flow(3, HMI, "224.0.0.251", protocol="mDNS", port=5353),  # not an asset
                flow(4, HMI, HMI, protocol="HTTP", port=8080),
            ]
        ),
        "a.pcap",
    )  # to itself
    c2 = ingest(
        app,
        eid,
        res([flow(1, HMI, PLC, ot_writes=2, first=50, last=300, packets_c2s=1, packets_s2c=1)]),
        "b.pcap",
    )
    a = ids(c, eid)
    (link,) = c.get(f"/api/engagements/{eid}/links").json()
    assert (link["src"], link["dst"]) == (a[HMI], a[PLC])
    assert link["is_ot"] is True and link["flows"] == 3 and link["ot_writes"] == 3 and link["ot_reads"] == 3
    assert (link["first_seen"], link["last_seen"]) == (50, 300) and link["captures"] == [c1, c2]
    modbus, http = link["protocols"]
    assert (modbus["protocol"], modbus["packets"], modbus["ports"]) == ("Modbus", 12, ["tcp/502"])
    assert (http["protocol"], http["ports"]) == ("HTTP", ["tcp/80"])


def test_it_only_link_is_not_ot(ac):
    app, c = ac
    eid = engagement(c)
    ingest(app, eid, res([flow(1, HMI, CAM, protocol="RTSP", port=554)]), "a.pcap")
    assert c.get(f"/api/engagements/{eid}/links").json()[0]["is_ot"] is False


def test_ot_operations_grouped_oriented_and_writes_first(ac):
    app, c = ac
    eid = engagement(c)
    cmds = [
        cmd(HMI, PLC, "Read Holding Registers", "read", t=10),
        cmd(HMI, PLC, "Read Holding Registers", "read", t=20),
        cmd(
            PLC, HMI, "Read Holding Registers", "read", is_request=False, t=21
        ),  # plain response: not counted
        cmd(HMI, PLC, t=30, detail="register 40001"),
        cmd(
            PLC, HMI, "Illegal Data Address", "error", is_request=False, t=31
        ),  # error comes back from the PLC
    ]
    c1 = ingest(app, eid, res([flow(1, HMI, PLC)], cmds), "a.pcap")
    c2 = ingest(app, eid, res([flow(1, HMI, PLC)], [cmd(HMI, PLC, t=500)]), "b.pcap")
    a = ids(c, eid)
    ops = c.get(f"/api/engagements/{eid}/ot-operations").json()
    assert [(o["kind"], o["function"], o["count"]) for o in ops] == [
        ("write", "Write Single Register", 2),
        ("error", "Illegal Data Address", 1),
        ("read", "Read Holding Registers", 2),
    ]
    w = ops[0]
    assert (w["src"], w["dst"]) == (a[HMI], a[PLC])
    assert (w["first_seen"], w["last_seen"], w["sample"], w["captures"]) == (
        30,
        500,
        "register 40001",
        [c1, c2],
    )
    assert (ops[1]["src"], ops[1]["dst"]) == (a[HMI], a[PLC])  # master → device


def test_remerge_is_idempotent_and_removal_drops_links(db, eng):
    cap = capture(db, eng)
    r = res([flow(1, HMI, PLC)], [cmd(HMI, PLC)])
    merge.ingest_capture(db, cap, r)
    merge.ingest_capture(db, cap, r)
    db.commit()
    assert len(db.scalars(select(AssetLink)).all()) == 1 and len(db.scalars(select(AssetOtOp)).all()) == 1
    merge.remove_capture(db, cap)
    db.delete(cap)
    db.commit()
    assert db.scalars(select(AssetLink)).all() == [] and db.scalars(select(AssetOtOp)).all() == []
    assert db.scalars(select(Asset)).all() == []


def test_links_follow_bundle_round_trip(ac):
    from tests.test_bundles import _seed_with_result, export, import_

    app, c = ac
    eid = engagement(c, "Linked")
    _seed_with_result(app, eid, *hosts())
    # _seed_with_result has no flows; add a capture with traffic through the normal path.
    import gzip

    from pcapvis.engagements.storage import Storage

    r = res([flow(1, HMI, PLC, ot_writes=1)], [cmd(HMI, PLC)])
    cid = ingest(app, eid, r, "traffic.pcap")
    path = Storage(app.state.settings.data_dir).result_path(eid, cid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(r.model_dump_json().encode()))
    new = import_(c, export(c, eid, captures=False)).json()["id"]
    a = ids(c, new)
    (link,) = c.get(f"/api/engagements/{new}/links").json()
    assert (link["src"], link["dst"], link["ot_writes"]) == (a[HMI], a[PLC], 1)
    assert c.get(f"/api/engagements/{new}/ot-operations").json()[0]["function"] == "Write Single Register"


def test_outsiders_cannot_see_links(make_settings):
    app = create_app(make_settings(mode="server", admin_username="admin", admin_password=PW))
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": PW}, headers=H)
        c.post("/api/users", json={"username": "olly", "password": PW, "role": "consultant"}, headers=H)
        eid = engagement(c)
        seed(app, eid, host(HMI, MAC_A))
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "olly", "password": PW}, headers=H)
        assert c.get(f"/api/engagements/{eid}/links").status_code == 404
        assert c.get(f"/api/engagements/{eid}/ot-operations").status_code == 404


def test_migration_0004_queues_existing_captures_for_remerge(tmp_path):
    from alembic import command

    from pcapvis.db.migrate import alembic_config

    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = alembic_config(url)
    command.upgrade(cfg, "0003")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO engagements (id, name, client, site, description, status, is_quicklook, "
                "created_at, updated_at, revision) VALUES (1, 'E', '', '', '', 'active', 0, "
                "'2026-01-01', '2026-01-01', 0)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO captures (id, engagement_id, file_name, size, sha256, status, progress, "
                "cancel_requested, uploaded_at, assets_merged_at) VALUES (1, 1, 'a', 1, 'x', 'done', 1, 0, "
                "'2026-01-01', '2026-01-01')"
            )
        )
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT assets_merged_at FROM captures")).scalar() is None
    engine.dispose()
