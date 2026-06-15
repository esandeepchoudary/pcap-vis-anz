"""Unit tests for utility functions: allowed_file, mac_vendor, os_from_ttl, is_private."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import allowed_file, mac_vendor, os_from_ttl, is_private


# ── allowed_file ──────────────────────────────────────────────────────────────

def test_allowed_file_pcap():
    assert allowed_file("capture.pcap") is True

def test_allowed_file_pcapng():
    assert allowed_file("traffic.pcapng") is True

def test_allowed_file_cap():
    assert allowed_file("dump.cap") is True

def test_allowed_file_uppercase_extension():
    assert allowed_file("capture.PCAP") is True
    assert allowed_file("traffic.PCAPNG") is True

def test_allowed_file_disallowed():
    assert allowed_file("malware.exe") is False
    assert allowed_file("data.csv") is False
    assert allowed_file("archive.zip") is False

def test_allowed_file_no_extension():
    assert allowed_file("nodotfile") is False

def test_allowed_file_dot_only():
    assert allowed_file(".pcap") is True  # has a dot; rsplit gives ["", "pcap"]

def test_allowed_file_multiple_dots():
    assert allowed_file("my.capture.2024.pcap") is True
    assert allowed_file("my.file.exe") is False


# ── mac_vendor ────────────────────────────────────────────────────────────────

def test_mac_vendor_vmware():
    assert mac_vendor("00:0c:29:aa:bb:cc") == "VMware"

def test_mac_vendor_cisco():
    assert mac_vendor("00:15:17:aa:bb:cc") == "Cisco"

def test_mac_vendor_raspberry_pi():
    assert mac_vendor("b8:27:eb:11:22:33") == "Raspberry Pi"

def test_mac_vendor_dashes():
    # Dashes instead of colons should still work
    assert mac_vendor("00-0C-29-AA-BB-CC") == "VMware"

def test_mac_vendor_no_separators():
    assert mac_vendor("000C29AABBCC") == "VMware"

def test_mac_vendor_unknown():
    assert mac_vendor("ff:ff:ff:aa:bb:cc") is None

def test_mac_vendor_none_input():
    assert mac_vendor(None) is None

def test_mac_vendor_empty_string():
    assert mac_vendor("") is None

def test_mac_vendor_siemens():
    assert mac_vendor("00:0b:00:11:22:33") == "Siemens"


# ── os_from_ttl ───────────────────────────────────────────────────────────────

def test_os_ttl_linux_low():
    assert os_from_ttl(64) == "Linux/Unix/macOS"

def test_os_ttl_linux_very_low():
    assert os_from_ttl(1) == "Linux/Unix/macOS"

def test_os_ttl_windows():
    assert os_from_ttl(128) == "Windows"

def test_os_ttl_windows_mid():
    assert os_from_ttl(65) == "Windows"

def test_os_ttl_network_device():
    assert os_from_ttl(129) == "Network Device"
    assert os_from_ttl(255) == "Network Device"


# ── is_private ────────────────────────────────────────────────────────────────

def test_is_private_class_a():
    assert is_private("10.0.0.1") is True
    assert is_private("10.255.255.255") is True

def test_is_private_class_b():
    assert is_private("172.16.0.1") is True
    assert is_private("172.31.255.255") is True

def test_is_private_class_b_boundary_low():
    assert is_private("172.15.0.1") is False

def test_is_private_class_b_boundary_high():
    assert is_private("172.32.0.1") is False

def test_is_private_class_c():
    assert is_private("192.168.0.1") is True
    assert is_private("192.168.255.255") is True

def test_is_private_class_c_non_private():
    assert is_private("192.169.0.1") is False

def test_is_private_loopback():
    assert is_private("127.0.0.1") is True
    assert is_private("127.255.255.255") is True

def test_is_private_link_local():
    assert is_private("169.254.0.1") is True
    assert is_private("169.254.255.255") is True

def test_is_private_public():
    assert is_private("8.8.8.8") is False
    assert is_private("1.1.1.1") is False
    assert is_private("203.0.113.1") is False

def test_is_private_ipv6_loopback():
    assert is_private("::1") is True

def test_is_private_ipv6_link_local():
    assert is_private("fe80::1") is True
    assert is_private("FE80::abcd") is True
    assert is_private("fe90::1") is True
    assert is_private("fea0::1") is True
    assert is_private("febf::1") is True
    assert is_private("fec0::1") is False

def test_is_private_ipv6_ula_fc():
    assert is_private("fc00::1") is True

def test_is_private_ipv6_ula_fd():
    assert is_private("fd00::1") is True

def test_is_private_ipv6_public():
    assert is_private("2001:db8::1") is False

def test_is_private_invalid_input():
    assert is_private("not-an-ip") is False
    assert is_private("999.999.999.999") is False
    assert is_private("") is False
