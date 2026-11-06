"""Parity with the legacy (v1) engine: every difference must be explained.

Runs only when PCAPVIS_LEGACY_PYTHON points to a Python with legacy/requirements.txt installed
(CI's parity job sets it). Locally:  PCAPVIS_LEGACY_PYTHON=/path/to/python uv run pytest tests/test_legacy_parity.py
"""

import os
import shutil
from pathlib import Path

import pytest

from pcapvis.devtools.legacy_parity import compare, legacy_summary
from pcapvis.engine.analyze import analyze_capture
from tests import pcapgen as g
from tests.pcapgen import Cap
from tests.test_parallel import rich_capture

LEGACY_PYTHON = os.environ.get("PCAPVIS_LEGACY_PYTHON")
pytestmark = pytest.mark.skipif(
    not LEGACY_PYTHON or not shutil.which("tshark"), reason="needs PCAPVIS_LEGACY_PYTHON and tshark"
)
DEMO = Path(__file__).resolve().parents[2] / "fixtures" / "network-capture-demo.pcap"


def ot_capture() -> Cap:
    C = ("00:0c:29:00:00:01", "10.0.0.5")
    S = ("00:a0:87:00:00:02", "10.0.0.50")
    R = ("00:1d:9c:00:00:03", "10.0.0.60")
    cap = Cap()
    cap.tcp_session(
        C,
        S,
        50000,
        20000,
        [
            ("c", g.dnp3(1, 10, b"\xc0\x0d")),
            ("s", g.dnp3(10, 1, b"\xc0\x81\x00\x00", from_master=False)),
            ("c", g.dnp3(1, 10, b"\xc1\x01\x3c\x01\x06")),
        ],
    )
    cap.tcp_session(
        C,
        R,
        50003,
        44818,
        [
            ("c", g.enip_cip(0x4D, g.cip_symbol_path("Pump1_Speed"), b"\xc4\x00\x01\x00\x0a\x00\x00\x00")),
            ("s", g.enip_cip(0x4D, b"", response=True)),
            ("c", g.enip_cip(0x4E, b"\x20\x06\x24\x01", b"\x0a\x0e" + b"\x00" * 10)),
        ],
    )
    cap.udp(R, C, 44818, 50002, g.enip_list_identity_response())
    cap.tcp_session(
        C,
        ("00:0c:29:00:00:70", "10.0.0.70"),
        50004,
        2404,
        [("c", g.iec104_i(45, 6)), ("c", g.iec104_i(100, 6, element=b"\x14"))],
    )
    bms_peer = ("00:0c:29:00:00:80", "10.0.0.80")
    cap.udp(C, bms_peer, 47808, 47808, g.bacnet_confirmed(15)).udp(
        C, bms_peer, 47808, 47808, g.bacnet_confirmed(12)
    )
    cap.tcp_session(
        C, ("00:0c:29:00:00:90", "10.0.0.90"), 50005, 1883, [("c", g.mqtt_connect("gw", "op", "pw12345"))]
    )
    cap.tcp_session(
        C,
        ("00:0c:29:00:00:91", "10.0.0.91"),
        50006,
        23,
        [("s", b"login: "), ("c", b"root\r\n"), ("s", b"Password: "), ("c", b"toor\r\n")],
    )
    return cap


@pytest.mark.parametrize("name", ["demo", "rich", "ot"])
def test_no_unexplained_differences(tmp_path, name):
    path = {
        "demo": lambda: DEMO,
        "rich": lambda: rich_capture().write(tmp_path / "rich.pcap"),
        "ot": lambda: ot_capture().write(tmp_path / "ot.pcap"),
    }[name]()
    report = compare(path, legacy_summary(path, LEGACY_PYTHON), analyze_capture(path))
    assert report.matches["hosts present in both"] > 0
    assert report.unexplained == [], report.markdown()
