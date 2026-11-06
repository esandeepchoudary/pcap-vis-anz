"""Unit tests for helper functions in app.py."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import purdue_level_py, allowed_file


# ── purdue_level_py ───────────────────────────────────────────────────────────

def test_purdue_level_field_devices():
    assert purdue_level_py("Field Device") == 0
    assert purdue_level_py("IoT Sensor") == 0
    assert purdue_level_py("Smart Meter") == 0

def test_purdue_level_plc_rtu():
    assert purdue_level_py("PLC") == 1
    assert purdue_level_py("RTU") == 1
    assert purdue_level_py("IED") == 1
    assert purdue_level_py("Building Controller") == 1

def test_purdue_level_control():
    assert purdue_level_py("HMI") == 2
    assert purdue_level_py("DCS") == 2

def test_purdue_level_supervisory():
    assert purdue_level_py("SCADA Server") == 3
    assert purdue_level_py("Historian") == 3
    assert purdue_level_py("Engineering Workstation") == 3

def test_purdue_level_dmz():
    assert purdue_level_py("VPN Gateway") == 3.5
    assert purdue_level_py("Security Tool") == 3.5
    assert purdue_level_py("Remote Desktop") == 3.5

def test_purdue_level_enterprise():
    assert purdue_level_py("Windows Host") == 4
    assert purdue_level_py("Web Server") == 4
    assert purdue_level_py("Mail Server") == 4
    assert purdue_level_py("Directory Server") == 4
    assert purdue_level_py("Database Server") == 4

def test_purdue_level_external_host_via_country():
    # External hosts (with country code) map to L5 regardless of type
    assert purdue_level_py("Windows Host", country="US") == 5
    assert purdue_level_py("Unknown", country="DE") == 5
    assert purdue_level_py("PLC", country="CN") == 5  # country overrides type

def test_purdue_level_unclassified():
    assert purdue_level_py("Unknown Type") == -1
    assert purdue_level_py("") == -1

def test_purdue_level_it_infrastructure():
    assert purdue_level_py("Router") == 4
    assert purdue_level_py("IoT Gateway") == 4
    assert purdue_level_py("DNS Server") == 4
    assert purdue_level_py("Container Host") == 4
    assert purdue_level_py("Discovery") == 4


# ── allowed_file ──────────────────────────────────────────────────────────────

def test_allowed_file_dot_only():
    """Filename '.' has an empty extension after rsplit — must return False."""
    assert allowed_file(".") is False

def test_allowed_file_no_extension():
    assert allowed_file("nodotfile") is False

def test_allowed_file_valid_extensions():
    assert allowed_file("capture.pcap") is True
    assert allowed_file("capture.pcapng") is True
    assert allowed_file("capture.cap") is True

def test_allowed_file_invalid_extension():
    assert allowed_file("capture.txt") is False
    assert allowed_file("capture.exe") is False

def test_allowed_file_double_extension():
    """Only the last extension matters."""
    assert allowed_file("archive.tar.pcap") is True
    assert allowed_file("capture.pcap.txt") is False

def test_purdue_level_no_country_is_not_l5():
    assert purdue_level_py("Windows Host") == 4  # no country → L4, not L5
    assert purdue_level_py("Windows Host", country=None) == 4

def test_purdue_level_ot_evidence_demotes_l4_to_l3():
    # L4 hosts with OT protocol evidence are demoted to L3 (supervisory)
    assert purdue_level_py("Windows Host", ot_role="master") == 3
    assert purdue_level_py("Windows Host", modbus_unit_ids=[1, 2]) == 3
    assert purdue_level_py("Windows Host", dnp3_addresses=[10]) == 3
    assert purdue_level_py("Web Server", ot_role="outstation") == 3
    # No OT evidence → stays L4
    assert purdue_level_py("Windows Host", ot_role="unknown") == 4
    assert purdue_level_py("Windows Host", modbus_unit_ids=[]) == 4
    assert purdue_level_py("Windows Host", dnp3_addresses=[]) == 4
    # Non-L4 types are not affected by OT evidence
    assert purdue_level_py("PLC", ot_role="master") == 1
    assert purdue_level_py("HMI", modbus_unit_ids=[1]) == 2

def test_purdue_level_public_ip_is_internet():
    # Any non-private IP → level 6 regardless of host type
    assert purdue_level_py("Windows Host", is_private=False) == 6
    assert purdue_level_py("Web Server",   is_private=False) == 6
    assert purdue_level_py("Unknown",      is_private=False) == 6
    # Private IPs stay at their host-type level
    assert purdue_level_py("Windows Host", is_private=True) == 4
    assert purdue_level_py("PLC",          is_private=True) == 1
    # country + is_private=False → still L6 (is_private wins)
    assert purdue_level_py("Windows Host", country="US", is_private=False) == 6
