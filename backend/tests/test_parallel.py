"""Splitter and parallel analysis: results must be identical to single-process analysis."""

import gzip
import io
import shutil
import subprocess
from pathlib import Path

import pytest

from pcapvis.engine.analyze import analyze_capture, choose_plan
from pcapvis.engine.runner import CaptureError
from pcapvis.engine.split import SplitUnsupported, _ip_pair_key, capture_format, partition_of, split
from tests import pcapgen as g
from tests.pcapgen import Cap

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")
REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "fixtures" / "network-capture-demo.pcap"


def rich_capture() -> Cap:
    """Many host pairs and every scenario the engine handles, so partitions really differ."""
    cap = Cap()
    plc = ("00:a0:87:00:00:02", "10.0.0.50")
    for i in range(12):
        c = (f"00:0c:29:00:01:{i:02x}", f"10.0.1.{i + 10}")
        cap.tcp_session(
            c,
            plc,
            50000 + i,
            502,
            [
                ("c", g.modbus(i, i % 6 + 1, b"\x06\x00\x01\x00\x01")),
                ("s", g.modbus(i, i % 6 + 1, b"\x06\x00\x01\x00\x01")),
            ],
            vlan=10,
        )
        cap.dns(c, ("00:0c:29:00:00:53", "10.0.0.53"), f"host{i}.plant.local", answers=[f"10.0.2.{i}"])
    ws = ("00:0c:29:00:00:05", "10.0.0.5")
    cap.tcp_session(
        ws,
        ("00:1f:b9:00:00:51", "10.0.0.51"),
        50100,
        102,
        [("c", g.s7(1, g.S7_SETUP)), ("c", g.s7(1, g.S7_REQUEST_DOWNLOAD)), ("c", g.s7(1, g.S7_PLC_STOP))],
    )
    cap.tcp_session(
        ws,
        ("00:0c:29:00:00:80", "10.0.0.80"),
        50101,
        21,
        [("c", b"USER op\r\n"), ("s", b"331\r\n"), ("c", b"PASS admin\r\n")],
    )
    cap.lldp("00:01:2f:00:00:aa", "core-sw").arp_reply("00:01:2f:00:00:aa", "10.0.0.2")
    cap.arp_reply("00:00:5e:00:01:01", "10.0.0.1")
    for i in range(4):
        cap.tcp_session(
            ws,
            ("00:00:5e:00:01:01", f"93.184.216.{i + 1}"),
            50200 + i,
            443,
            [("c", g.tls_client_hello(f"site{i}.example.com"))],
        )
    cap.udp(("00:0c:29:00:00:07", "10.0.0.7"), ("00:0c:29:00:00:50", "10.0.0.50"), 50000, 161, qinq=(100, 10))
    cap.ping(ws, ("00:a0:87:00:00:02", "10.0.0.50"))
    return cap


# ── splitter ──────────────────────────────────────────────────────────────────


def test_capture_format_detection(tmp_path):
    assert capture_format(b"\xd4\xc3\xb2\xa1") == "pcap"
    assert capture_format(b"\x0a\x0d\x0d\x0a") == "pcapng"
    assert capture_format(b"\x1f\x8b\x08\x00") == "gzip"
    assert capture_format(b"junk") == "unknown"


def test_pair_key_is_direction_independent():
    from scapy.all import IP, TCP, Dot1Q, Ether

    a = bytes(Ether() / Dot1Q(vlan=5) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
    b = bytes(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP())
    assert _ip_pair_key(1, a) == _ip_pair_key(1, b) is not None
    assert _ip_pair_key(1, bytes(Ether(type=0x0806) / (b"\x00" * 28))) is None  # ARP → partition 0
    assert partition_of(None, 4) == 0


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_split_routes_pairs_together_and_keeps_order(tmp_path, fmt):
    from scapy.utils import PcapNgWriter, rdpcap

    cap = rich_capture()
    src = tmp_path / f"in.{fmt}"
    if fmt == "pcap":
        cap.write(src)
    else:
        with PcapNgWriter(str(src)) as w:
            for f in cap.frames:
                w.write(f)
    bufs = [io.BytesIO() for _ in range(3)]
    with open(src, "rb") as fh:
        frames = split(fh, [b.write for b in bufs])
    assert sorted(n for part in frames for n in part) == list(range(1, len(cap.frames) + 1))
    for part in frames:
        assert part == sorted(part)  # file order preserved within each partition
    pair_home = {}
    for i, b in enumerate(bufs):
        path = tmp_path / f"p{i}.{fmt}"
        path.write_bytes(b.getvalue())
        for pkt in rdpcap(str(path)):  # every partition is a valid capture file
            if pkt.haslayer("IP"):
                pair = frozenset((pkt["IP"].src, pkt["IP"].dst))
                assert pair_home.setdefault(pair, i) == i  # a host pair never spans partitions


def test_split_rejects_gzip():
    with pytest.raises(SplitUnsupported):
        split(io.BytesIO(gzip.compress(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)), [lambda d: None])


def test_split_on_packet_callback_order(tmp_path):
    cap = rich_capture()
    path = cap.write(Path(tmp_path) / "cb.pcap")
    buf = io.BytesIO(path.read_bytes())
    seen = []
    split(buf, [lambda d: None] * 3, on_packet=seen.append)
    assert len(seen) == len(cap.frames) and set(seen) <= {0, 1, 2}


# ── equivalence ───────────────────────────────────────────────────────────────


def _same(a, b):
    da, db = a.model_dump(exclude={"capture"}), b.model_dump(exclude={"capture"})
    for key in da:
        assert da[key] == db[key], f"{key} differs"
    assert a.capture.packets == b.capture.packets and a.capture.bytes == b.capture.bytes
    assert a.capture.first_seen == b.capture.first_seen and a.capture.last_seen == b.capture.last_seen


@needs_tshark
@pytest.mark.parametrize("workers", [2, 3, 5])
def test_parallel_equals_serial_rich(tmp_path, workers):
    path = rich_capture().write(tmp_path / "rich.pcap")
    serial = analyze_capture(path, workers=1)
    assert serial.ot_commands and serial.credentials and serial.anomalies  # the scenario is meaningful
    _same(serial, analyze_capture(path, workers=workers))


@needs_tshark
def test_parallel_equals_serial_pcapng(tmp_path):
    from scapy.utils import PcapNgWriter

    path = tmp_path / "rich.pcapng"
    with PcapNgWriter(str(path)) as w:
        for f in rich_capture().frames:
            w.write(f)
    _same(analyze_capture(path, workers=1), analyze_capture(path, workers=4))


@needs_tshark
def test_parallel_equals_serial_demo():
    _same(analyze_capture(DEMO, workers=1), analyze_capture(DEMO, workers=4))


@needs_tshark
def test_more_partitions_than_workers(tmp_path, monkeypatch):
    import pcapvis.engine.analyze as A

    path = rich_capture().write(tmp_path / "rich.pcap")
    monkeypatch.setattr(A, "PARTITION_TARGET_BYTES", 2000)  # force many small partitions
    workers, parts = A.choose_plan(path, 2)
    assert workers == 2 and parts > 2
    _same(analyze_capture(path, workers=1), analyze_capture(path, workers=2))


# ── limits, cancel, errors ────────────────────────────────────────────────────


@needs_tshark
def test_parallel_max_packets_matches_serial(tmp_path):
    path = rich_capture().write(tmp_path / "rich.pcap")
    a, b = analyze_capture(path, workers=1, max_packets=40), analyze_capture(path, workers=3, max_packets=40)
    assert a.capture.packets == b.capture.packets == 40 and a.capture.truncated and b.capture.truncated
    _same(a, b)


@needs_tshark
def test_parallel_cancel(tmp_path):
    cap = Cap()
    for i in range(6000):
        cap.udp(("00:0c:29:00:00:01", f"10.0.{i % 200}.1"), ("00:0c:29:00:00:02", "10.0.0.2"), 50000, 161)
    path = cap.write(tmp_path / "many.pcap")
    r = analyze_capture(path, workers=2, should_cancel=lambda: True)
    assert r.capture.truncated and r.capture.packets < 6000


@needs_tshark
def test_parallel_progress_reaches_total(tmp_path):
    path = rich_capture().write(tmp_path / "rich.pcap")
    calls = []
    analyze_capture(path, workers=3, progress=lambda fed, total, n: calls.append((fed, total, n)))
    assert calls and calls[-1][0] == calls[-1][1] and calls[-1][2] > 0


@needs_tshark
def test_gzip_capture_falls_back_to_single_process(tmp_path):
    path = rich_capture().write(tmp_path / "rich.pcap")
    gz = tmp_path / "rich.pcap.gz"
    gz.write_bytes(gzip.compress(path.read_bytes()))
    assert choose_plan(gz, 4) == (1, 1)
    _same(analyze_capture(path, workers=1), analyze_capture(gz, workers=4))


@needs_tshark
def test_parallel_garbage_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"\xff" * 5000)  # valid header, garbage records
    with pytest.raises(CaptureError):
        analyze_capture(bad, workers=3)


def test_plan_small_file_stays_single(tmp_path):
    p = rich_capture().write(tmp_path / "s.pcap")
    assert choose_plan(p, None) == (1, 1)


def test_worker_module_runs_standalone(tmp_path):
    """The worker is launched as `python -m`; make sure it imports cleanly in a fresh interpreter."""
    import sys

    r = subprocess.run([sys.executable, "-c", "import pcapvis.engine.worker"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
