"""Asset identity and merging across captures, auto values, provenance, history, and edits."""

import gzip
import hashlib

import pytest
from sqlalchemy import select

from pcapvis.assets import fields as F
from pcapvis.assets import merge, service
from pcapvis.db.models import (
    Asset,
    AssetChange,
    AssetOrigin,
    AssetSighting,
    Capture,
    CaptureStatus,
    Engagement,
    User,
)
from pcapvis.engagements.storage import Storage
from pcapvis.engine.model import AnalysisResult, CaptureSummary, Evidence, Host, HostName

MAC_A, MAC_B, ROUTER = "00:0c:29:00:00:0a", "00:0c:29:00:00:0b", "00:00:5e:00:01:01"


def host(ip, mac=None, **kw) -> Host:
    kw.setdefault("ip_version", 6 if ":" in ip else 4)
    kw.setdefault("is_private", ip.startswith(("10.", "192.168.", "fe80")))
    kw.setdefault("first_seen", 1000.0)
    kw.setdefault("last_seen", 2000.0)
    return Host(ip=ip, mac=mac, macs=[mac] if mac else [], **kw)


def result(*hosts) -> AnalysisResult:
    return AnalysisResult(
        capture=CaptureSummary(
            file_name="x.pcap", file_size=1, packets=1, bytes=1, first_seen=0, last_seen=1
        ),
        hosts=list(hosts),
        flows=[],
    )


@pytest.fixture
def eng(db):
    e = Engagement(name="Plant")
    db.add(e)
    db.commit()
    return e


@pytest.fixture
def user(db):
    u = User(username="alice", role="consultant")
    db.add(u)
    db.commit()
    return u


def capture(db, eng, name="a.pcap") -> Capture:
    c = Capture(
        engagement_id=eng.id,
        file_name=name,
        size=1,
        sha256=hashlib.sha256(name.encode()).hexdigest(),
        status=CaptureStatus.done,
    )
    db.add(c)
    db.commit()
    return c


def ingest(db, eng, *hosts, name="a.pcap", cap=None) -> Capture:
    cap = cap or capture(db, eng, name)
    merge.ingest_capture(db, cap, result(*hosts))
    db.commit()
    return cap


def assets(db, eng) -> list[Asset]:
    db.expire_all()
    return list(db.scalars(select(Asset).where(Asset.engagement_id == eng.id).order_by(Asset.id)))


def changes(db, a: Asset, kind=None) -> list[AssetChange]:
    q = select(AssetChange).where(AssetChange.asset_id == a.id).order_by(AssetChange.id)
    return [c for c in db.scalars(q) if kind is None or c.kind == kind]


# ── identity ─────────────────────────────────────────────────────────────────


def test_same_mac_across_captures_is_one_asset_even_when_ip_changes(db, eng):
    ingest(db, eng, host("10.0.0.5", MAC_A), name="a.pcap")
    ingest(db, eng, host("10.0.0.99", MAC_A), name="b.pcap")
    (a,) = assets(db, eng)
    assert a.macs == [MAC_A] and a.ips == ["10.0.0.5", "10.0.0.99"]
    assert a.observed["captures"] == 2


def test_multihomed_host_ipv4_and_ipv6_with_one_mac_is_one_asset(db, eng):
    ingest(db, eng, host("10.0.0.5", MAC_A), host("fe80::20c:29ff:fe00:a", MAC_A))
    (a,) = assets(db, eng)
    assert a.ips == ["10.0.0.5", "fe80::20c:29ff:fe00:a"]


def test_hosts_behind_a_router_are_keyed_by_ip(db, eng):
    ingest(
        db,
        eng,
        host("172.16.0.1", ROUTER, mac_is_gateway=True),
        host("172.16.0.2", ROUTER, mac_is_gateway=True),
    )
    a1, a2 = assets(db, eng)
    assert a1.macs == [] and a2.macs == [] and {a1.ips[0], a2.ips[0]} == {"172.16.0.1", "172.16.0.2"}


def test_unflagged_mac_with_many_ips_is_not_merged_into_one_asset(db, eng):
    ingest(db, eng, *[host(f"10.1.0.{i}", ROUTER) for i in range(1, 30)])
    found = assets(db, eng)
    assert len(found) == 29 and all(a.macs == [] for a in found)


def test_ip_only_asset_adopts_mac_when_seen_directly(db, eng):
    ingest(db, eng, host("10.0.0.5", ROUTER, mac_is_gateway=True), name="routed.pcap")
    ingest(db, eng, host("10.0.0.5", MAC_A), name="direct.pcap")
    (a,) = assets(db, eng)
    assert a.macs == [MAC_A]


def test_ip_reused_by_another_device_is_a_different_asset(db, eng):
    ingest(db, eng, host("10.0.0.5", MAC_A), name="a.pcap")
    ingest(db, eng, host("10.0.0.5", MAC_B), name="b.pcap")
    a1, a2 = assets(db, eng)
    assert a1.macs == [MAC_A] and a2.macs == [MAC_B]


def test_routed_sighting_of_known_ip_joins_the_mac_asset(db, eng):
    ingest(db, eng, host("10.0.0.5", MAC_A), name="a.pcap")
    ingest(db, eng, host("10.0.0.5", ROUTER, mac_is_gateway=True), name="b.pcap")
    (a,) = assets(db, eng)
    assert a.observed["captures"] == 2


@pytest.mark.parametrize(
    "h",
    [
        host("224.0.0.251", is_multicast=True),
        host("255.255.255.255", is_broadcast=True),
        host("0.0.0.0"),
        host("127.0.0.1"),
        host("ff02::1"),
        host("not-an-ip"),
    ],
)
def test_non_device_addresses_are_not_assets(db, eng, h):
    ingest(db, eng, h)
    assert assets(db, eng) == []


# ── automatic values ─────────────────────────────────────────────────────────


def test_auto_values_prefer_confident_types_and_fingerprints(db, eng):
    ingest(
        db,
        eng,
        host(
            "10.0.0.5",
            MAC_A,
            host_type="PLC",
            host_type_confidence="high",
            purdue_level=1,
            mac_vendor="Rockwell Automation",
            identity={
                "enip_vendor": "Rockwell Automation/Allen-Bradley",
                "enip_product_name": "1756-L71",
                "enip_revision": "20.11",
                "enip_serial": "0x00c0ffee",
            },
            hostname="plc-01",
            hostnames=[HostName(name="plc-01", source="dhcp")],
            host_type_evidence=[Evidence(kind="serves", detail="Serves EtherNet/IP")],
            last_seen=100,
        ),
        name="a.pcap",
    )
    ingest(
        db,
        eng,
        host(
            "10.0.0.5", MAC_A, host_type="Unknown Host", purdue_level=-1, hostname="plc-01-new", last_seen=200
        ),
        name="b.pcap",
    )
    (a,) = assets(db, eng)
    assert a.auto == {
        "name": "plc-01-new",  # most recent name wins
        "asset_type": "PLC",  # a confident type beats a later unknown
        "purdue_level": 1,
        "vendor": "Rockwell Automation/Allen-Bradley",  # fingerprint beats MAC vendor
        "model": "1756-L71",
        "firmware": "20.11",
        "serial": "0x00c0ffee",
    }
    assert a.observed["type_evidence"][0]["detail"] == "Serves EtherNet/IP"
    assert a.observed["mac_vendor"] == "Rockwell Automation"


def test_mac_vendor_is_the_fallback_vendor(db, eng):
    ingest(db, eng, host("10.0.0.5", MAC_A, mac_vendor="Siemens AG"))
    assert assets(db, eng)[0].auto["vendor"] == "Siemens AG"


def test_observed_facts_are_merged(db, eng):
    ingest(
        db,
        eng,
        host(
            "10.0.0.5",
            MAC_A,
            protocols=["Modbus"],
            vlans=[10],
            packets_sent=5,
            ot_role="outstation",
            first_seen=50,
            last_seen=60,
        ),
        name="a.pcap",
    )
    ingest(
        db,
        eng,
        host(
            "10.0.0.5",
            MAC_A,
            protocols=["HTTP"],
            vlans=[20],
            packets_recv=7,
            ot_role="master",
            first_seen=10,
            last_seen=90,
        ),
        name="b.pcap",
    )
    o = assets(db, eng)[0].observed
    assert o["protocols"] == ["HTTP", "Modbus"] and o["vlans"] == [10, 20]
    assert o["packets"] == 12 and o["ot_role"] == "both"
    assert (o["first_seen"], o["last_seen"]) == (10, 90)


# ── edits survive merges ─────────────────────────────────────────────────────


def test_manual_overrides_survive_new_captures_and_history_records_auto_changes(db, eng, user):
    ingest(db, eng, host("10.0.0.5", MAC_A, host_type="HMI", purdue_level=2, last_seen=100), name="a.pcap")
    (a,) = assets(db, eng)
    assert [c.kind for c in changes(db, a)] == ["created"]  # creation doesn't log every auto value
    service.edit(
        db,
        a,
        user,
        set_={"purdue_level": 3, "zone": "Cell 2"},
        reset=[],
        reason="Per site drawing",
        expected_version=a.version,
    )
    db.commit()
    ingest(
        db,
        eng,
        host("10.0.0.5", MAC_A, host_type="PLC", host_type_confidence="high", purdue_level=1, last_seen=200),
        name="b.pcap",
    )
    (a,) = assets(db, eng)
    eff = F.effective_all(a.auto, a.overrides)
    assert eff["purdue_level"] == 3 and eff["zone"] == "Cell 2"  # manual values kept
    assert eff["asset_type"] == "PLC"  # auto value updated
    auto = {(c.field, c.old, c.new) for c in changes(db, a, "auto")}
    assert ("asset_type", "HMI", "PLC") in auto and ("purdue_level", 2, 1) in auto
    assert all(c.actor == "capture b.pcap" for c in changes(db, a, "auto"))


def test_reanalysing_a_capture_is_idempotent(db, eng):
    cap = ingest(db, eng, host("10.0.0.5", MAC_A, host_type="HMI"), host("10.0.0.6", MAC_B))
    before = [(a.id, a.ips, a.auto) for a in assets(db, eng)]
    merge.ingest_capture(db, cap, result(host("10.0.0.5", MAC_A, host_type="HMI"), host("10.0.0.6", MAC_B)))
    db.commit()
    assert [(a.id, a.ips, a.auto) for a in assets(db, eng)] == before
    assert db.scalar(select(AssetSighting.id).where(AssetSighting.capture_id == cap.id).offset(2)) is None
    assert all(not changes(db, a, "auto") for a in assets(db, eng))


def test_reanalysis_that_no_longer_sees_a_host_drops_its_unedited_asset(db, eng):
    cap = ingest(db, eng, host("10.0.0.5", MAC_A), host("10.0.0.6", MAC_B))
    merge.ingest_capture(db, cap, result(host("10.0.0.5", MAC_A)))
    db.commit()
    assert [a.macs for a in assets(db, eng)] == [[MAC_A]]


def test_removing_a_capture_prunes_unedited_assets_but_keeps_edited_ones(db, eng, user):
    keep = ingest(db, eng, host("10.0.0.1", "00:0c:29:00:00:01"), name="keep.pcap")
    cap = ingest(db, eng, host("10.0.0.5", MAC_A, host_type="PLC"), host("10.0.0.6", MAC_B), name="gone.pcap")
    edited = next(a for a in assets(db, eng) if a.macs == [MAC_A])
    service.edit(db, edited, user, set_={"name": "Filler PLC"}, reset=[], reason="", expected_version=None)
    db.commit()
    merge.remove_capture(db, cap)
    db.delete(cap)
    db.commit()
    left = assets(db, eng)
    assert sorted(a.macs[0] for a in left) == ["00:0c:29:00:00:01", MAC_A]
    kept = next(a for a in left if a.macs == [MAC_A])
    assert kept.observed["captures"] == 0 and kept.ips == ["10.0.0.5"]  # identity kept for re-matching
    assert kept.auto["asset_type"] == "PLC"  # last known values kept
    # A later capture of the same device lands on the edited asset.
    ingest(db, eng, host("10.0.0.50", MAC_A), name="later.pcap")
    again = next(a for a in assets(db, eng) if a.macs == [MAC_A])
    assert again.id == kept.id and F.effective(again.auto, again.overrides, "name") == "Filler PLC"
    assert keep.id


def test_manual_asset_is_matched_by_a_later_capture(db, eng, user):
    m = service.create_manual(
        db,
        eng.id,
        user,
        ips=["10.0.0.254"],
        macs=[],
        values={"name": "FW-1", "asset_type": "Firewall"},
        reason="From network diagram",
    )
    db.commit()
    ingest(db, eng, host("10.0.0.254", "00:0c:29:00:00:fe", host_type="Router"))
    (a,) = assets(db, eng)
    assert a.id == m.id and a.origin == AssetOrigin.manual
    assert a.macs == ["00:0c:29:00:00:fe"] and a.observed["captures"] == 1
    assert F.effective(a.auto, a.overrides, "asset_type") == "Firewall"
    # Its declared identity survives losing the capture.
    cap = db.scalar(select(Capture))
    merge.remove_capture(db, cap)
    db.commit()
    assert assets(db, eng)[0].ips == ["10.0.0.254"]


def test_merge_pending_backfills_captures_from_before_m3(db, eng, settings):
    cap = capture(db, eng)
    store = Storage(settings.data_dir)
    path = store.result_path(eng.id, cap.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as fh:
        fh.write(result(host("10.0.0.5", MAC_A)).model_dump_json().encode())
    missing = capture(db, eng, "missing.pcap")  # no result file: marked, not retried forever
    assert merge.merge_pending(db, store) == 1
    db.expire_all()
    assert len(assets(db, eng)) == 1 and cap.assets_merged_at is not None
    assert missing.assets_merged_at is not None
    assert merge.merge_pending(db, store) == 0


# ── edits ────────────────────────────────────────────────────────────────────


def test_edit_validates_records_history_and_bumps_version(db, eng, user):
    ingest(db, eng, host("10.0.0.5", MAC_A, host_type="HMI", purdue_level=2))
    (a,) = assets(db, eng)
    n = service.edit(
        db,
        a,
        user,
        set_={"purdue_level": 3.5, "tags": ["dmz", " dmz ", "jump"]},
        reset=[],
        reason="Jump host",
        expected_version=1,
    )
    db.commit()
    assert n == 2 and a.version == 2
    assert a.overrides["tags"]["value"] == ["dmz", "jump"]
    assert a.overrides["purdue_level"] == {
        **a.overrides["purdue_level"],
        "value": 3.5,
        "by": "alice",
        "reason": "Jump host",
    }
    # Same value again: no change, no new version.
    assert service.edit(db, a, user, set_={"purdue_level": 3.5}, reset=[], reason="", expected_version=2) == 0
    # Reset goes back to the automatic value.
    service.edit(db, a, user, set_={}, reset=["purdue_level"], reason="Wrong", expected_version=2)
    db.commit()
    assert "purdue_level" not in a.overrides and F.effective(a.auto, a.overrides, "purdue_level") == 2
    hist = [(c.kind, c.field, c.old, c.new) for c in changes(db, a)][1:]
    assert hist == [
        ("override", "purdue_level", 2, 3.5),
        ("override", "tags", [], ["dmz", "jump"]),
        ("reset", "purdue_level", 3.5, 2),
    ]


def test_stale_version_is_a_conflict(db, eng, user):
    ingest(db, eng, host("10.0.0.5", MAC_A))
    (a,) = assets(db, eng)
    service.edit(db, a, user, set_={"zone": "A"}, reset=[], reason="", expected_version=1)
    db.commit()
    with pytest.raises(service.EditConflict):
        service.edit(db, a, user, set_={"zone": "B"}, reset=[], reason="", expected_version=1)


def test_merge_does_not_bump_the_edit_version(db, eng, user):
    ingest(db, eng, host("10.0.0.5", MAC_A), name="a.pcap")
    ingest(db, eng, host("10.0.0.5", MAC_A, host_type="PLC"), name="b.pcap")
    assert assets(db, eng)[0].version == 1


@pytest.mark.parametrize(
    ("field", "value", "msg"),
    [
        ("purdue_level", 7, "Purdue level must be one of"),
        ("purdue_level", "1", "must be a number"),
        ("purdue_level", True, "must be a number"),
        ("criticality", "extreme", "Criticality must be one of"),
        ("name", "a\nb", "single line"),
        ("name", "x" * 201, "longer than 200"),
        ("name", 5, "must be text"),
        ("tags", "a,b", "list of text"),
        ("tags", ["a,b"], "no commas"),
        ("tags", [f"t{i}" for i in range(21)], "At most 20"),
        ("bogus", "x", "Unknown asset field"),
    ],
)
def test_field_validation(field, value, msg):
    with pytest.raises(F.FieldError, match=msg):
        F.validate(field, value)


def test_field_normalisation():
    assert F.validate("name", "  PLC 1 ") == "PLC 1"
    assert F.validate("name", "   ") is None
    assert F.validate("purdue_level", 3.0) == 3 and isinstance(F.validate("purdue_level", 3.0), int)
    assert F.validate("notes", "line 1\nline 2\n") == "line 1\nline 2"
    assert F.validate("criticality", None) is None


def test_manual_asset_identifiers_are_validated(db, eng, user):
    with pytest.raises(F.FieldError, match="Not an IP"):
        service.create_manual(db, eng.id, user, ips=["10.0.0.300"], macs=[], values={}, reason="")
    with pytest.raises(F.FieldError, match="Not a MAC"):
        service.create_manual(db, eng.id, user, ips=[], macs=["zz:zz"], values={}, reason="")
    a = service.create_manual(
        db, eng.id, user, ips=[" 10.0.0.1 "], macs=["00-0C-29-00-00-0A"], values={}, reason=""
    )
    db.commit()
    assert a.ips == ["10.0.0.1"] and a.macs == [MAC_A]
    with pytest.raises(F.FieldError, match="already has MAC"):
        service.create_manual(db, eng.id, user, ips=[], macs=[MAC_A], values={}, reason="")


def test_concurrent_edits_one_wins(db, eng, user, settings):
    """Two sessions load version 1; the second save must fail, not silently overwrite the first."""
    from pcapvis.db.session import make_engine, make_session_factory

    ingest(db, eng, host("10.0.0.5", MAC_A))
    engine = make_engine(settings.resolved_database_url)
    other = make_session_factory(engine)()
    try:
        mine = assets(db, eng)[0]
        theirs = other.get(Asset, mine.id)
        service.edit(other, theirs, None, set_={"zone": "Theirs"}, reset=[], reason="", expected_version=1)
        other.commit()
        with pytest.raises(service.EditConflict):
            service.edit(db, mine, user, set_={"zone": "Mine"}, reset=[], reason="", expected_version=1)
        db.rollback()
        assert assets(db, eng)[0].overrides["zone"]["value"] == "Theirs"
    finally:
        other.close()
        engine.dispose()
