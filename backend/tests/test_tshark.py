import os
import shutil
import stat

import pytest

from pcapvis import tshark


def _fake_tshark(tmp_path, output: str, exit_code: int = 0):
    path = tmp_path / "tshark"
    path.write_text(f"#!/bin/sh\ncat <<'OUT'\n{output}\nOUT\nexit {exit_code}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("TShark (Wireshark) 4.6.4.\n\nCopyright 1998-2025", (4, 6, 4)),
        ("TShark (Wireshark) 3.6.2 (Git v3.6.2 packaged as 3.6.2-2)", (3, 6, 2)),
        ("TShark (Wireshark) 10.0.0.", (10, 0, 0)),
        ("Wireshark 4.2.0", None),
        ("", None),
    ],
)
def test_parse_version(text, expected):
    assert tshark.parse_version(text) == expected


def test_missing_binary(tmp_path):
    st = tshark.check_tshark(str(tmp_path / "nope"))
    assert not st.ok and st.path is None and "not found" in st.message


def test_recent_version_ok(tmp_path):
    st = tshark.check_tshark(_fake_tshark(tmp_path, "TShark (Wireshark) 4.2.7."), "4.0.0")
    assert st.ok and st.version == "4.2.7"


def test_exact_minimum_version_ok(tmp_path):
    assert tshark.check_tshark(_fake_tshark(tmp_path, "TShark (Wireshark) 4.0.0."), "4.0.0").ok


def test_old_version_rejected(tmp_path):
    st = tshark.check_tshark(_fake_tshark(tmp_path, "TShark (Wireshark) 3.6.2."), "4.0.0")
    assert not st.ok and st.version == "3.6.2" and "too old" in st.message


def test_numeric_not_string_comparison(tmp_path):
    # "10.0.0" < "4.0.0" as strings, but must pass as versions.
    assert tshark.check_tshark(_fake_tshark(tmp_path, "TShark (Wireshark) 10.0.0."), "4.0.0").ok


def test_unparseable_output(tmp_path):
    st = tshark.check_tshark(_fake_tshark(tmp_path, "garbage"), "4.0.0")
    assert not st.ok and "Could not read" in st.message


def test_install_hint_mentions_container():
    assert "docker run" in tshark.install_hint()


@pytest.mark.skipif(
    not shutil.which("tshark") or os.environ.get("PCAPVIS_SKIP_REAL_TSHARK"),
    reason="real tshark not installed",
)
def test_real_tshark_detected():
    st = tshark.check_tshark("tshark", "4.0.0")
    assert st.ok, st.message
