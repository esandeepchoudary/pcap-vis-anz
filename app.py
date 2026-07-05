import base64
import hashlib
import ipaddress
import logging
import math
import os
import re
import socket
import tempfile
import threading
import statistics
from collections import defaultdict, Counter, OrderedDict
from urllib.parse import parse_qs
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError as FutureTimeoutError
from functools import lru_cache
from flask import Flask, request, jsonify, render_template, make_response
from flask_compress import Compress
from werkzeug.utils import secure_filename

# GPU acceleration: use CuPy when a CUDA GPU is available, fall back to NumPy
try:
    import cupy as _xp
    _xp.cuda.runtime.getDeviceCount()  # raises if no GPU
    GPU_AVAILABLE = True
except Exception:
    import numpy as _xp
    GPU_AVAILABLE = False

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB
MAX_UPLOAD_FILES = 100  # max files per /upload request (checked in handler + frontend)
app.secret_key = os.environ.get("PCAPVIS_SECRET_KEY", os.urandom(32))
Compress(app)

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}

# Max concurrent PCAP analysis workers and per-task timeout (seconds)
_UPLOAD_MAX_WORKERS = 4
_UPLOAD_TASK_TIMEOUT = 120
_executor_lock = threading.Lock()
_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None or _executor._shutdown:
            _executor = ThreadPoolExecutor(max_workers=_UPLOAD_MAX_WORKERS)
        return _executor

# Captured file bodies keyed by SHA-256; populated during analyze_pcap.
# Implemented as a size-bounded LRU (OrderedDict) so download links from prior
# uploads remain valid until genuine memory pressure evicts them. The cache is
# never wiped wholesale on a new upload — entries are evicted only when the 256 MB
# cap is exceeded (oldest-first).
_file_body_cache: OrderedDict = OrderedDict()
_file_body_cache_lock = threading.Lock()
_file_body_cache_bytes: int = 0   # running total; guarded by _file_body_cache_lock
_FILE_CACHE_MAX_BYTES = 256 * 1024 * 1024  # 256 MB hard cap on cached file bodies

# ── MAC OUI vendor table (common prefixes) ────────────────────────────────────
MAC_VENDORS = {
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox",
    "525400": "QEMU/KVM",
    "001A11": "Google", "3C5AB4": "Google", "A4C361": "Google",
    "00155D": "Microsoft Hyper-V", "001DD8": "Microsoft",
    "28D244": "Raspberry Pi", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "ACDE48": "Apple", "000A27": "Apple", "001124": "Apple",
    "001C42": "Parallels",
    "001517": "Cisco", "00012F": "Cisco", "000142": "Cisco",
    "D4AD71": "Cisco", "F866F2": "Cisco",
    "001E58": "D-Link", "001CF0": "D-Link",
    "B4752E": "ASUSTek",
    "001018": "Broadcom",
    # OT/ICS vendors
    "001D9C": "Rockwell Automation",
    "00E0B1": "Rockwell Automation",
    "000B00": "Siemens",
    "001FB9": "Siemens",
    "0021CA": "Siemens",
    "00A087": "Schneider Electric",
    "0020F4": "Schneider Electric",
    "002569": "Yokogawa",
    "00A0F1": "ABB",
    "D89D67": "ABB",
    "0008A1": "Emerson",
    "001E67": "GE Digital",
    "000049": "Honeywell",
    "001177": "Honeywell",
    "000D69": "WAGO",
    "0006ED": "Phoenix Contact",
    "00A0D1": "Mitsubishi Electric",
    "00E0E3": "Omron",
    "001094": "Beckhoff",
    "0030D8": "Moxa",
    # IoT device vendors
    "F4F26D": "Amazon Echo",
    "44650D": "Amazon Echo",
    "A4C138": "Amazon Echo",
    "F0272D": "Google Home",
    "4854F7": "Google Nest",
    "1C1AC0": "Google Nest",
    "00178A": "Philips Hue",
    "ECB5FA": "Philips Hue",
    "001788": "Philips Hue",
    "286C07": "Samsung SmartThings",
    "D052A8": "Samsung SmartThings",
    "18B430": "Ring",
    "B0090C": "Ring",
    "DCEF09": "Wyze",
    "2CAA8E": "Wyze",
    "50C7BF": "TP-Link Kasa",
    "B09575": "TP-Link Kasa",
    "34298F": "Tuya Smart",
    "84E342": "Tuya Smart",
    "E8DB84": "Shelly",
    "C45BBE": "Shelly",
    "AC233F": "Particle IoT",
    "0017F2": "Nest Labs",
    "18B7CE": "Nest Labs",
    "6C5697": "Fitbit",
    "3C71BF": "August Smart Lock",
    "D8EBD3": "LIFX Smart Bulb",
}

# ── Port → (protocol label, host-type hint) ───────────────────────────────────
PORT_MAP = {
    20: ("FTP-Data",        "FTP Server"),
    21: ("FTP",             "FTP Server"),
    22: ("SSH",             "SSH Server"),
    23: ("Telnet",          "Telnet Server"),
    25: ("SMTP",            "Mail Server"),
    53: ("DNS",             "DNS Server"),
    67: ("DHCP",            "DHCP Server"),
    68: ("DHCP",            "DHCP Client"),
    80: ("HTTP",            "Web Server"),
    110: ("POP3",           "Mail Server"),
    119: ("NNTP",           "News Server"),
    123: ("NTP",            "NTP Server"),
    137: ("NetBIOS-NS",     "Windows Host"),
    138: ("NetBIOS-DGM",    "Windows Host"),
    139: ("NetBIOS-SSN",    "Windows Host"),
    143: ("IMAP",           "Mail Server"),
    161: ("SNMP",           "Network Device"),
    162: ("SNMP-Trap",      "Network Device"),
    179: ("BGP",            "Router"),
    389: ("LDAP",           "Directory Server"),
    443: ("HTTPS",          "Web Server"),
    445: ("SMB",            "Windows Host"),
    465: ("SMTPS",          "Mail Server"),
    514: ("Syslog",         "Log Server"),
    587: ("SMTP",           "Mail Server"),
    631: ("IPP",            "Print Server"),
    636: ("LDAPS",          "Directory Server"),
    993: ("IMAPS",          "Mail Server"),
    995: ("POP3S",          "Mail Server"),
    1433: ("MSSQL",         "Database Server"),
    1521: ("Oracle-DB",     "Database Server"),
    2375: ("Docker",        "Container Host"),
    2376: ("Docker-TLS",    "Container Host"),
    3306: ("MySQL",         "Database Server"),
    3389: ("RDP",           "Windows Host"),
    4444: ("Metasploit",    "Security Tool"),
    5432: ("PostgreSQL",    "Database Server"),
    5900: ("VNC",           "Remote Desktop"),
    5985: ("WinRM",         "Windows Host"),
    5986: ("WinRM-S",       "Windows Host"),
    6379: ("Redis",         "Cache Server"),
    6443: ("K8s-API",       "Container Host"),
    8080: ("HTTP",          "Web Server"),
    8443: ("HTTPS",         "Web Server"),
    8888: ("HTTP",          "Web Server"),
    9200: ("Elasticsearch", "Search Server"),
    27017: ("MongoDB",      "Database Server"),
    500: ("IKE/IPsec",      "VPN Gateway"),
    1194: ("OpenVPN",       "VPN Gateway"),
    1723: ("PPTP",          "VPN Gateway"),
    4500: ("IPsec-NAT",     "VPN Gateway"),
    5353: ("mDNS",          "Discovery"),
    1900: ("SSDP",          "Discovery"),
    5355: ("LLMNR",         "Windows Host"),
    # OT/ICS protocols
    502:   ("Modbus",       "PLC"),
    2222:  ("EtherNet/IP",  "PLC"),
    44818: ("EtherNet/IP",  "PLC"),
    102:   ("S7comm",       "PLC"),
    20000: ("DNP3",         "RTU"),
    2404:  ("IEC-104",      "IED"),
    47808: ("BACnet",       "Building Controller"),
    4840:  ("OPC-UA",       "SCADA Server"),
    1883:  ("MQTT",         "IoT Gateway"),
    8883:  ("MQTT-TLS",     "IoT Gateway"),
    34964: ("PROFINET",     "PLC"),
    5094:  ("HART-IP",      "Field Device"),
    18245: ("GE-SRTP",      "PLC"),
    18246: ("GE-SRTP",      "PLC"),
    9600:  ("OMRON-FINS",   "PLC"),
    4000:  ("Emerson-DeltaV","DCS"),
    1541:  ("Foxboro",      "DCS"),
    # IoT protocols
    5683:  ("CoAP",          "IoT Sensor"),
    5684:  ("CoAP-DTLS",     "IoT Sensor"),
    5672:  ("AMQP",          "IoT Gateway"),
    5671:  ("AMQPS",         "IoT Gateway"),
    5222:  ("XMPP",          "Smart Home Hub"),
    5223:  ("XMPP-TLS",      "Smart Home Hub"),
    554:   ("RTSP",          "IP Camera"),
    8554:  ("RTSP",          "IP Camera"),
    8000:  ("Hikvision",     "IP Camera"),
    37777: ("Dahua",         "IP Camera"),
    5540:  ("Matter",        "Smart Home Hub"),
    3702:  ("WS-Discovery",  "IoT Gateway"),
    7547:  ("TR-069",        "CPE Device"),
    6668:  ("Tuya-IoT",      "Smart Home Hub"),
    9119:  ("XIMSS",         "Smart Home Hub"),
    1026:  ("CAP",           "Smart Meter"),
    4059:  ("DLMS",          "Smart Meter"),
}

# Pre-built reverse lookup: port -> (proto, svc). O(1) per-packet lookup.
PORT_LOOKUP = dict(PORT_MAP)

HOST_TYPE_PRIORITY = [
    "PLC", "RTU", "IED", "HMI", "SCADA Server", "DCS",
    "Historian", "Engineering Workstation", "Building Controller",
    "IoT Gateway", "Field Device",
    "IP Camera", "Smart Home Hub", "Smart Meter", "IoT Sensor",
    "Smart Speaker", "CPE Device",
    "Router", "VPN Gateway", "Network Device", "DNS Server",
    "DHCP Server", "Web Server", "Mail Server", "Database Server",
    "SSH Server", "FTP Server", "Telnet Server", "Windows Host", "Directory Server",
    "Container Host", "Cache Server", "Search Server", "Log Server",
    "NTP Server", "Print Server", "Security Tool", "Remote Desktop",
]

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 6668}

# Maximum number of half-open credential state entries per protocol (Telnet, FTP, etc.)
# Kept as a module-level constant so tests can monkeypatch it to exercise the cap guard.
MAX_CRED_STATE_ENTRIES = 5_000

# Pre-compiled regex patterns used inside the hot per-packet credential/file extraction
# block.  Compiling once at import time removes the per-call cache-lookup overhead.
_RE_MIME_VALID = re.compile(r'^[a-z0-9][a-z0-9!#$&\-^_.+/]*$')
_RE_CONTENT_DISP_FNAME = re.compile(r'filename\*?=["\']?([^"\';\r\n]+)', re.IGNORECASE)
_RE_HTTP_BASIC_AUTH = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
_RE_SMTP_AUTH_PLAIN = re.compile(r"AUTH PLAIN ([A-Za-z0-9+/=]+)", re.IGNORECASE)
_RE_SMTP_AUTH_LOGIN = re.compile(r"AUTH LOGIN", re.IGNORECASE)
_RE_IMAP_LOGIN = re.compile(
    r'[A-Za-z0-9]+ LOGIN ("(?:[^"\\]|\\.)*"|[^\s"]+)\s+("(?:[^"\\]|\\.)*"|[^\s"]+)',
    re.IGNORECASE,
)
_FILE_MIME_PREFIXES = (
    "application/", "image/", "audio/", "video/",
    "text/csv", "text/xml", "text/plain",
)
_FILE_MIME_SKIP = {
    "text/html", "text/css", "text/javascript",
    "application/json", "application/javascript",
    "application/x-www-form-urlencoded",
}
_FILE_EXT_BY_MIME = {
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/gzip": ".gz",
    "application/x-tar": ".tar",
    "application/x-msdownload": ".exe",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "text/csv": ".csv",
    "text/xml": ".xml",
}
_IPV6_PRIVATE_NETWORKS = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)


def _extract_http_file_transfer(payload: bytes, *, pkt_time=None, rel_time=None,
                                src="", dst=""):
    """Return (metadata, body_bytes) for an interesting HTTP response body."""
    if not payload or not payload.startswith(b"HTTP/"):
        return None
    sep = payload.find(b"\r\n\r\n")
    if sep == -1:
        return None

    hdr_raw = payload[:sep].decode("utf-8", errors="replace")
    body = payload[sep + 4:]
    mime = ""
    filename = ""
    content_len = None

    for header_line in hdr_raw.split("\r\n")[1:]:
        if ":" not in header_line:
            continue
        header_key, header_val = header_line.split(":", 1)
        header_key_l = header_key.strip().lower()
        header_val_s = header_val.strip()
        if header_key_l == "content-type":
            mime = header_val_s.split(";")[0].strip().lower()
            if not _RE_MIME_VALID.match(mime):
                mime = "application/octet-stream"
        elif header_key_l == "content-disposition":
            fname_match = _RE_CONTENT_DISP_FNAME.search(header_val_s)
            if fname_match:
                filename = fname_match.group(1).strip().strip("\"'")[:200]
        elif header_key_l == "content-length":
            try:
                content_len = int(header_val_s)
            except ValueError:
                pass

    interesting = (
        filename or
        (mime and any(mime.startswith(prefix) for prefix in _FILE_MIME_PREFIXES)
         and mime not in _FILE_MIME_SKIP)
    )
    if not interesting or not body:
        return None

    body_bytes = bytes(body)
    sha = hashlib.sha256(body_bytes).hexdigest()
    size = content_len if content_len is not None else len(body_bytes)
    if not filename:
        filename = f"transfer_{sha[:8]}{_FILE_EXT_BY_MIME.get(mime, '')}"

    meta = {
        "filename": filename,
        "mime_type": mime,
        "size": size,
        "sha256": sha,
    }
    if pkt_time is not None:
        meta["time"] = round(pkt_time, 3)
    if rel_time is not None:
        meta["rel_time"] = round(rel_time, 3)
    if src:
        meta["src"] = src
    if dst:
        meta["dst"] = dst
    return meta, body_bytes

# Purdue model level mapping (mirrors JS purdueLevel())
_PURDUE_L5_TYPES: set[str] = set()  # external hosts determined by country field
_PURDUE_L4_TYPES = {
    "Windows Host", "Web Server", "Mail Server", "Directory Server", "Database Server",
    "Router", "Network Device", "DNS Server", "DHCP Server", "DHCP Client", "NTP Server",
    "SSH Server", "FTP Server", "Telnet Server", "Container Host",
    "Log Server", "Print Server", "Cache Server", "Search Server",
    "IoT Gateway", "Smart Home Hub", "Smart Speaker", "CPE Device", "Discovery",
}
_PURDUE_L35_TYPES = {"VPN Gateway", "Security Tool", "Remote Desktop"}
_PURDUE_L3_TYPES = {"SCADA Server", "Historian", "Engineering Workstation"}
_PURDUE_L2_TYPES = {"HMI", "DCS"}
_PURDUE_L1_TYPES = {"PLC", "RTU", "IED", "Building Controller", "IP Camera"}
_PURDUE_L0_TYPES = {"Field Device", "IoT Sensor", "Smart Meter"}

def purdue_level_py(
    host_type: str,
    country: str | None = None,
    ot_role: str = "unknown",
    modbus_unit_ids=None,
    dnp3_addresses=None,
    is_private: bool = True,
) -> float:
    """Return the Purdue Model level for a host (6, 5, 4, 3.5, 3, 2, 1, 0, or -1).

    Level 6 — Public Internet: any non-private (internet-routable) IP, detected
    via the is_private flag regardless of whether GeoIP data is available.

    OT protocol evidence (ot_role, modbus_unit_ids, dnp3_addresses) demotes
    a host from L4 (IT/business) to L3 (supervisory) — e.g. a Windows Host
    running Modbus belongs on the OT side of the DMZ.
    """
    if not is_private:
        return 6
    if country:
        return 5
    if host_type in _PURDUE_L4_TYPES:
        has_ot_evidence = (
            ot_role not in ("unknown", "")
            or bool(modbus_unit_ids)
            or bool(dnp3_addresses)
        )
        return 3 if has_ot_evidence else 4
    if host_type in _PURDUE_L35_TYPES:
        return 3.5
    if host_type in _PURDUE_L3_TYPES:
        return 3
    if host_type in _PURDUE_L2_TYPES:
        return 2
    if host_type in _PURDUE_L1_TYPES:
        return 1
    if host_type in _PURDUE_L0_TYPES:
        return 0
    return -1


_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian
    b"\xa1\xb2\x3c\x4d",  # pcap ns big-endian
    b"\x4d\x3c\xb2\xa1",  # pcap ns little-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


def allowed_file(filename, file_stream=None):
    if "." not in filename:
        return False
    parts = filename.rsplit(".", 1)
    if len(parts) < 2 or not parts[1]:   # catches bare "." with empty extension
        return False
    if parts[1].lower() not in ALLOWED_EXTENSIONS:
        return False
    if file_stream is not None:
        header = file_stream.read(4)
        file_stream.seek(0)
        return header in _PCAP_MAGIC
    return True


def mac_vendor(mac):
    if not mac:
        return None
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return MAC_VENDORS.get(prefix)


def os_from_ttl(ttl):
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    return "Network Device"


def is_private(ip):
    try:
        if ":" in ip:
            # IPv6: loopback (::1), link-local (fe80::/10), ULA (fc00::/7)
            addr = ipaddress.ip_address(ip)
            if addr.version != 6:
                return False
            return any(addr in net for net in _IPV6_PRIVATE_NETWORKS)
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or (a == 169 and b == 254)
        )
    except Exception:
        return False


_geoip_reader = None
_geoip_is_city = False          # True when the opened DB supports city-level lookups
_geoip_lock = threading.Lock()

# Candidate paths tried in order when opening the GeoIP database.
# 1. GEOIP_DB_PATH env var (gunicorn-safe override, any .mmdb format)
# 2. System MaxMind/DB-IP City database (provides city names + coords)
# 3. Bundled DB-IP Country Lite (CC BY 4.0, ships with the repo)
_GEOIP_BUNDLED = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "data", "dbip-country-lite.mmdb")
_GEOIP_CANDIDATES = [
    os.environ.get("GEOIP_DB_PATH", ""),
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    _GEOIP_BUNDLED,
]


def _get_geoip_reader():
    global _geoip_reader, _geoip_is_city
    if _geoip_reader is not None:
        return _geoip_reader
    with _geoip_lock:
        if _geoip_reader is None:
            try:
                import geoip2.database
                for path in _GEOIP_CANDIDATES:
                    if path and os.path.isfile(path):
                        try:
                            reader = geoip2.database.Reader(path)
                            _geoip_reader = reader
                            db_type = reader.metadata().database_type
                            _geoip_is_city = "City" in db_type
                            break
                        except Exception:
                            continue
            except Exception:
                pass
    return _geoip_reader


@lru_cache(maxsize=4096)
def geo_lookup(ip):
    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        if _geoip_is_city:
            r = reader.city(ip)
            return {
                "country": r.country.name,
                "country_code": r.country.iso_code,
                "city": r.city.name,
                "lat": float(r.location.latitude) if r.location.latitude is not None else None,
                "lon": float(r.location.longitude) if r.location.longitude is not None else None,
            }
        else:
            r = reader.country(ip)
            return {
                "country": r.country.name,
                "country_code": r.country.iso_code,
                "city": None,
                "lat": None,
                "lon": None,
            }
    except Exception:
        return None


def _ber_len(data, off):
    """Parse a BER length field. Returns (length, new_offset)."""
    if off >= len(data):
        return 0, off
    b = data[off]
    if b < 0x80:
        return b, off + 1
    elif b == 0x81:
        if off + 1 >= len(data):
            return 0, off
        return data[off + 1], off + 2
    elif b == 0x82:
        if off + 2 >= len(data):
            return 0, off
        return (data[off + 1] << 8) | data[off + 2], off + 3
    return 0, off + 1


def parse_http(payload_bytes, protocol):
    """Try to parse HTTP request or response from payload bytes."""
    if not payload_bytes:
        return None
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        try:
            text = payload_bytes.decode("latin-1", errors="replace")
        except Exception:
            return None

    lines = text.split("\r\n")
    if not lines:
        return None
    first = lines[0]

    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")
    if any(first.startswith(m) for m in http_methods):
        # Request
        parts = first.split(" ", 2)
        if len(parts) < 2:
            return None
        method = parts[0]
        url = parts[1] if len(parts) > 1 else ""
        version = parts[2] if len(parts) > 2 else ""
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body_preview = "\r\n".join(lines[body_start:body_start + 5]) if body_start else ""
        return {"type": "request", "method": method, "url": url, "version": version,
                "headers": headers, "body_preview": body_preview[:500]}
    elif first.startswith("HTTP/"):
        # Response
        parts = first.split(" ", 2)
        version = parts[0] if len(parts) > 0 else ""
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body_preview = "\r\n".join(lines[body_start:body_start + 5]) if body_start else ""
        return {"type": "response", "version": version, "status_code": status_code,
                "reason": reason, "headers": headers, "body_preview": body_preview[:500]}
    return None


def parse_modbus(payload_bytes):
    """Parse Modbus TCP payload. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 6:
        return None
    try:
        import struct
        transaction_id = struct.unpack(">H", payload_bytes[0:2])[0]
        protocol_id    = struct.unpack(">H", payload_bytes[2:4])[0]
        length         = struct.unpack(">H", payload_bytes[4:6])[0]
        if protocol_id != 0 or len(payload_bytes) < 7:
            return None
        unit_id  = payload_bytes[6]
        if len(payload_bytes) <= 7:
            return None  # no function code byte — not a parseable Modbus PDU
        func_code = payload_bytes[7]
        FC_NAMES = {
            1: "Read Coils", 2: "Read Discrete Inputs",
            3: "Read Holding Registers", 4: "Read Input Registers",
            5: "Write Single Coil", 6: "Write Single Register",
            8: "Diagnostics", 15: "Write Multiple Coils",
            16: "Write Multiple Registers", 22: "Mask Write Register",
            23: "Read/Write Multiple Registers", 43: "Read Device Identification",
            90: "Modbus Encapsulated (suspicious)",
        }
        is_error = func_code > 0x80
        real_fc = (func_code & 0x7F) if is_error else func_code
        result = {
            "transaction_id": transaction_id,
            "unit_id": unit_id,
            "unit_id_zero": unit_id == 0,
            "function_code": real_fc,
            "function_name": FC_NAMES.get(real_fc, f"Unknown FC {real_fc}"),
            "is_write": real_fc in (5, 6, 15, 16, 22, 23),
            "is_error": is_error,
            # is_response is set by analyze_pcap based on sport==502 (directional)
            "details": {},
        }
        data = payload_bytes[8:] if len(payload_bytes) > 8 else b""
        if is_error and len(data) >= 1:
            EXCEPTION_CODES = {1: "Illegal Function", 2: "Illegal Data Address",
                               3: "Illegal Data Value", 4: "Slave Device Failure",
                               5: "Acknowledge", 6: "Slave Device Busy",
                               8: "Memory Parity Error", 11: "Gateway Path Unavailable"}
            exc = data[0]
            result["exception_code"] = exc
            result["exception_name"] = EXCEPTION_CODES.get(exc, f"Exception {exc}")
        elif real_fc in (1, 2, 3, 4) and len(data) >= 4:
            result["details"]["start_address"] = struct.unpack(">H", data[0:2])[0]
            result["details"]["quantity"]       = struct.unpack(">H", data[2:4])[0]
            result["register_address"]          = struct.unpack(">H", data[0:2])[0]
            result["quantity"]                  = struct.unpack(">H", data[2:4])[0]
        elif real_fc in (5, 6) and len(data) >= 4:
            result["details"]["output_address"] = struct.unpack(">H", data[0:2])[0]
            result["details"]["output_value"]   = struct.unpack(">H", data[2:4])[0]
            result["register_address"]          = struct.unpack(">H", data[0:2])[0]
        elif real_fc in (15, 16) and len(data) >= 4:
            result["details"]["start_address"]  = struct.unpack(">H", data[0:2])[0]
            result["details"]["quantity"]       = struct.unpack(">H", data[2:4])[0]
            result["register_address"]          = struct.unpack(">H", data[0:2])[0]
            result["quantity"]                  = struct.unpack(">H", data[2:4])[0]
        return result
    except Exception:
        return None


def parse_mqtt(payload_bytes):
    """Parse MQTT packet. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 2:
        return None
    try:
        msg_type_byte = payload_bytes[0]
        msg_type = (msg_type_byte >> 4) & 0x0F
        MQTT_TYPES = {
            1: "CONNECT", 2: "CONNACK", 3: "PUBLISH",
            4: "PUBACK",  5: "PUBREC",  6: "PUBREL",
            7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
            10: "UNSUBSCRIBE", 11: "UNSUBACK",
            12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
        }
        type_name = MQTT_TYPES.get(msg_type, f"Unknown({msg_type})")
        result = {
            "type": msg_type,
            "type_name": type_name,
            "qos": (msg_type_byte >> 1) & 0x03,
            "retain": bool(msg_type_byte & 0x01),
            "details": {},
        }
        # Decode remaining length (variable-length encoding, max 4 bytes per MQTT spec)
        idx = 1
        multiplier = 1
        remaining = 0
        while idx < len(payload_bytes):
            if idx > 4:
                return None
            byte = payload_bytes[idx]
            remaining += (byte & 0x7F) * multiplier
            multiplier *= 128
            idx += 1
            if not (byte & 0x80):
                break
        payload = payload_bytes[idx:]

        if msg_type == 1 and len(payload) >= 10:  # CONNECT
            proto_name_len = (payload[0] << 8) | payload[1]
            if len(payload) >= 2 + proto_name_len + 4:
                proto_name = payload[2:2+proto_name_len].decode("utf-8", errors="replace")
                connect_flags = payload[2 + proto_name_len + 1]
                has_username = bool(connect_flags & 0x80)
                has_password = bool(connect_flags & 0x40)
                clean_session = bool(connect_flags & 0x02)
                result["details"]["protocol"] = proto_name
                result["details"]["clean_session"] = clean_session
                result["details"]["has_credentials"] = has_username or has_password
                # Client ID
                ci_offset = 2 + proto_name_len + 4
                if len(payload) >= ci_offset + 2:
                    ci_len = (payload[ci_offset] << 8) | payload[ci_offset + 1]
                    if len(payload) >= ci_offset + 2 + ci_len:
                        client_id = payload[ci_offset+2:ci_offset+2+ci_len].decode("utf-8", errors="replace")
                        result["details"]["client_id"] = client_id

        elif msg_type == 3 and len(payload) >= 2:  # PUBLISH
            topic_len = (payload[0] << 8) | payload[1]
            if len(payload) >= 2 + topic_len:
                topic = payload[2:2+topic_len].decode("utf-8", errors="replace")
                result["details"]["topic"] = topic
                msg_payload = payload[2+topic_len:]
                try:
                    result["details"]["payload_preview"] = msg_payload[:100].decode("utf-8", errors="replace")
                except Exception:
                    result["details"]["payload_preview"] = msg_payload[:100].hex()

        elif msg_type == 8 and len(payload) >= 4:  # SUBSCRIBE
            topics = []
            p_idx = 2  # skip message ID
            while p_idx + 2 <= len(payload):
                t_len = (payload[p_idx] << 8) | payload[p_idx+1]
                p_idx += 2
                if p_idx + t_len <= len(payload):
                    topics.append(payload[p_idx:p_idx+t_len].decode("utf-8", errors="replace"))
                    p_idx += t_len + 1  # +1 for QoS byte
            if topics:
                result["details"]["topics"] = ", ".join(topics[:5])

        elif msg_type == 2:  # CONNACK
            if len(payload) >= 2:
                RETURN_CODES = {
                    0: "Connection Accepted",
                    1: "Refused: Bad Protocol",
                    2: "Refused: Client ID Rejected",
                    3: "Refused: Server Unavailable",
                    4: "Refused: Bad Credentials",
                    5: "Refused: Not Authorized",
                }
                rc = payload[1] if len(payload) > 1 else 0
                result["details"]["return_code"] = RETURN_CODES.get(rc, f"Unknown ({rc})")
                result["details"]["session_present"] = bool(payload[0] & 0x01)

        return result
    except Exception:
        return None


def parse_coap(payload_bytes):
    """Parse CoAP packet. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 4:
        return None
    try:
        version = (payload_bytes[0] >> 6) & 0x03
        if version != 1:
            return None
        msg_type = (payload_bytes[0] >> 4) & 0x03
        token_len = payload_bytes[0] & 0x0F
        code_byte = payload_bytes[1]
        msg_id = (payload_bytes[2] << 8) | payload_bytes[3]

        code_class = (code_byte >> 5) & 0x07
        code_detail = code_byte & 0x1F
        code_str = f"{code_class}.{code_detail:02d}"

        TYPE_NAMES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
        METHOD_CODES = {
            "0.01": "GET", "0.02": "POST", "0.03": "PUT", "0.04": "DELETE",
        }
        RESPONSE_CODES = {
            "2.01": "Created", "2.02": "Deleted", "2.03": "Valid",
            "2.04": "Changed", "2.05": "Content",
            "4.00": "Bad Request", "4.01": "Unauthorized",
            "4.03": "Forbidden", "4.04": "Not Found",
            "4.05": "Method Not Allowed", "5.00": "Internal Server Error",
        }
        code_name = METHOD_CODES.get(code_str) or RESPONSE_CODES.get(code_str, code_str)

        result = {
            "type": TYPE_NAMES.get(msg_type, str(msg_type)),
            "code": code_str,
            "code_name": code_name,
            "message_id": msg_id,
            "is_request": code_class == 0,
            "details": {},
        }

        # Parse options to find Uri-Path
        idx = 4 + token_len
        uri_parts = []
        prev_opt = 0
        while idx < len(payload_bytes):
            if payload_bytes[idx] == 0xFF:  # payload marker
                rest = payload_bytes[idx+1:]
                try:
                    result["details"]["payload_preview"] = rest[:80].decode("utf-8", errors="replace")
                except Exception:
                    pass
                break
            opt_delta = (payload_bytes[idx] >> 4) & 0x0F
            opt_len   = payload_bytes[idx] & 0x0F
            idx += 1
            if opt_delta == 13:
                if idx >= len(payload_bytes): break
                opt_delta = payload_bytes[idx] + 13; idx += 1
            elif opt_delta == 14:
                if idx + 1 >= len(payload_bytes): break
                opt_delta = ((payload_bytes[idx] << 8) | payload_bytes[idx+1]) + 269; idx += 2
            if opt_len == 13:
                if idx >= len(payload_bytes): break
                opt_len = payload_bytes[idx] + 13; idx += 1
            elif opt_len == 14:
                if idx + 1 >= len(payload_bytes): break
                opt_len = ((payload_bytes[idx] << 8) | payload_bytes[idx+1]) + 269; idx += 2
            opt_num = prev_opt + opt_delta
            prev_opt = opt_num
            if idx + opt_len > len(payload_bytes):
                break  # truncated packet — stop option parsing safely
            opt_val = payload_bytes[idx:idx+opt_len]
            idx += opt_len
            if opt_num == 11:  # Uri-Path
                uri_parts.append(opt_val.decode("utf-8", errors="replace"))
            elif opt_num == 12:  # Content-Format
                result["details"]["content_format"] = int.from_bytes(opt_val, "big") if opt_val else 0
        if uri_parts:
            result["details"]["uri"] = "/" + "/".join(uri_parts)
        return result
    except Exception:
        return None


def parse_dnp3(payload_bytes):
    """Parse DNP3 link-layer + application-layer. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 10:
        return None
    try:
        if payload_bytes[0] != 0x05 or payload_bytes[1] != 0x64:
            return None
        ctrl = payload_bytes[3]
        direction = "master→RTU" if (ctrl & 0x80) else "RTU→master"
        dst_addr = int.from_bytes(payload_bytes[4:6], "little")
        src_addr = int.from_bytes(payload_bytes[6:8], "little")

        func_code = None
        func_name = "N/A"
        is_write = False
        is_error = False

        if len(payload_bytes) >= 12:
            # Application layer starts at byte 10 (after 8-byte link header + 2-byte CRC)
            app_fc = payload_bytes[11]
            func_code = app_fc
            FC_NAMES = {
                0: "Confirm", 1: "Read", 2: "Write", 3: "Select",
                4: "Operate", 5: "Direct Operate", 6: "Direct Operate No ACK",
                7: "Freeze", 8: "Freeze No ACK", 9: "Freeze Clear",
                13: "Cold Restart", 14: "Warm Restart",
                129: "Response", 130: "Unsolicited Response",
            }
            func_name = FC_NAMES.get(func_code, f"Unknown FC {func_code}")
            is_write = func_code in (2, 3, 4, 5, 6, 13, 14)
            # is_error: IIN2 carries true error/exception bits (0x80=event overflow,
            # 0x20=param error, 0x10=already executing, etc.).
            # IIN1 (payload_bytes[12]) bit 0x80 is "Device Restart", not an error.
            is_error = func_code == 129 and len(payload_bytes) >= 14 and bool(payload_bytes[13] & 0x30)

        role = "master" if (ctrl & 0x80) else "outstation"
        data_object_group = None
        DNP3_GROUPS = {
            1: "Binary Input", 2: "Binary Input Change",
            3: "Double-bit Binary Input", 10: "Binary Output",
            12: "Binary Output Control (CROB)",
            20: "Counter", 21: "Frozen Counter",
            30: "Analog Input", 32: "Analog Input Change",
            40: "Analog Output Status", 41: "Analog Output Block",
            50: "Time and Date", 60: "Class Objects",
        }
        if len(payload_bytes) >= 14:
            grp = payload_bytes[12]
            data_object_group = DNP3_GROUPS.get(grp, f"Group {grp}")
        return {
            "src_address": src_addr,
            "dst_address": dst_addr,
            "role": role,
            "function_code": func_code,
            "function_name": func_name,
            "data_object_group": data_object_group,
            "is_write": is_write,
            "is_error": is_error,
            "details": {"direction": direction},
        }
    except Exception:
        return None


def parse_s7comm(payload_bytes):
    """Parse S7comm over TPKT+COTP. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 10:
        return None
    try:
        # TPKT header: version must be 0x03
        if payload_bytes[0] != 0x03:
            return None
        cotp_len = payload_bytes[4]  # COTP length indicator (bytes after it in COTP header)
        s7_offset = 4 + cotp_len + 1
        if len(payload_bytes) < s7_offset + 10:
            return None

        s7 = payload_bytes[s7_offset:]
        if s7[0] != 0x32:
            return None

        ROSCTR_NAMES = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}
        rosctr = s7[1]
        rosctr_name = ROSCTR_NAMES.get(rosctr, f"Unknown({rosctr})")
        pdu_ref = int.from_bytes(s7[4:6], "big")
        param_len = int.from_bytes(s7[6:8], "big")
        data_len = int.from_bytes(s7[8:10], "big")

        is_error = rosctr == 2 and len(s7) >= 12 and s7[10] != 0

        func_code = None
        func_name = "N/A"
        is_write = False
        # ROSCTR 1/7 (Job/Userdata) have a 10-byte header; params start at offset 10.
        # ROSCTR 2/3 (Ack/Ack-Data) have a 12-byte header (error_class[10] + error_code[11]);
        # params (and therefore func_code) start at offset 12.
        param_hdr = 12 if rosctr in (2, 3) else 10
        if rosctr in (1, 3) and param_len > 0 and len(s7) >= param_hdr + 1:
            func_code = s7[param_hdr]
            FUNC_NAMES = {
                0xF0: "Setup Communication",
                0x04: "Read Variable", 0x05: "Write Variable",
                0x1A: "Request Download", 0x1B: "Download Block", 0x1C: "Download Ended",
                0x1D: "Start Upload", 0x1E: "Upload", 0x1F: "End Upload",
                0x28: "PI Service (Start/Stop)", 0x29: "PLC Stop",
            }
            func_name = FUNC_NAMES.get(func_code, f"Unknown FC {hex(func_code)}")
            is_write = func_code in (0x05, 0x1A, 0x1B, 0x28, 0x29)

        result = {
            "rosctr": rosctr,
            "rosctr_name": rosctr_name,
            "pdu_ref": pdu_ref,
            "function_code": func_code,
            "function_name": func_name,
            "is_write": is_write,
            "is_error": is_error,
            "details": {"param_len": param_len, "data_len": data_len},
        }
        # Extract block type and number from Download operations
        if func_code in (0x1A, 0x1B, 0x1C) and len(s7) >= 18:
            try:
                fname_len = s7[13] if len(s7) > 13 else 0
                if 6 <= fname_len <= 14 and len(s7) >= 14 + fname_len:
                    fname_str = bytes(s7[14:14 + fname_len]).decode("ascii", errors="replace")
                    for bt in ("SFB", "SFC", "OB", "DB", "FC", "FB"):
                        idx = fname_str.find(bt)
                        if idx >= 0:
                            result["block_type"] = bt
                            digits = "".join(c for c in fname_str[idx + len(bt):] if c.isdigit())
                            if digits:
                                result["block_number"] = int(digits)
                            break
            except Exception:
                pass
        return result
    except Exception:
        return None


def parse_enip(payload_bytes):
    """Parse EtherNet/IP encapsulation header + CIP service. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 24:
        return None
    try:
        import struct
        command = struct.unpack_from("<H", payload_bytes, 0)[0]
        length = struct.unpack_from("<H", payload_bytes, 2)[0]
        session_handle = struct.unpack_from("<I", payload_bytes, 4)[0]
        status = struct.unpack_from("<I", payload_bytes, 8)[0]

        COMMAND_NAMES = {
            0x0001: "List Services", 0x0004: "List Identity",
            0x0065: "Register Session", 0x0066: "Unregister Session",
            0x006F: "Send RR Data", 0x0070: "Send Unit Data",
            0x0072: "Indicate Status", 0x0073: "Cancel",
        }
        command_name = COMMAND_NAMES.get(command, f"Unknown({hex(command)})")

        cip_service = None
        cip_service_name = None
        is_response = False
        is_write = False

        # Parse CIP for Send RR Data (0x006F)
        if command == 0x006F and len(payload_bytes) >= 30:
            data = payload_bytes[24:]
            # CPF: interface_handle(4) + timeout(2) + item_count(2) + items
            # Null Address Item (type 0x0000, len 0) + Unconnected Data Item (type 0x00B2)
            # CIP payload starts after CPF header (~10 bytes into data)
            cip_offset = 10
            if len(data) > cip_offset:
                svc_byte = data[cip_offset]
                is_response = bool(svc_byte & 0x80)
                cip_service = svc_byte & 0x7F
                CIP_SERVICES = {
                    0x01: "Get_Attribute_All", 0x02: "Set_Attribute_All",
                    0x0E: "Get_Attribute_Single", 0x10: "Set_Attribute_Single",
                    0x4C: "Read Tag", 0x4D: "Write Tag",
                    0x4E: "Read Tag Fragmented", 0x4F: "Write Tag Fragmented",
                    0x0A: "Multiple_Service_Packet",
                }
                cip_service_name = CIP_SERVICES.get(cip_service, f"Service {hex(cip_service)}")
                is_write = (not is_response) and cip_service in (0x10, 0x4D, 0x4F)

        return {
            "command": command,
            "command_name": command_name,
            "session_handle": session_handle,
            "status": status,
            "cip_service": cip_service,
            "cip_service_name": cip_service_name,
            "is_response": is_response,
            "is_write": is_write,
            "is_error": status != 0,
            "details": {"length": length},
        }
    except Exception:
        return None


def parse_iec104(payload_bytes):
    """Parse IEC 60870-5-104 APDU. Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 6:
        return None
    try:
        if payload_bytes[0] != 0x68:
            return None
        apdu_len = payload_bytes[1]
        if len(payload_bytes) < 2 + apdu_len:
            return None
        cf1 = payload_bytes[2]

        if (cf1 & 0x01) == 0:
            frame_type = "I"
        elif (cf1 & 0x03) == 0x01:
            frame_type = "S"
        else:
            frame_type = "U"

        U_TYPES = {
            0x07: "STARTDT act", 0x0B: "STARTDT con",
            0x13: "STOPDT act",  0x23: "STOPDT con",
            0x43: "TESTFR act",  0x83: "TESTFR con",
        }
        u_type = U_TYPES.get(cf1) if frame_type == "U" else None

        type_id = None
        type_name = None
        cot_val = None
        cot_name = None
        common_address = None
        is_write = False
        is_error = False
        vsq = None
        is_test = False

        if frame_type == "I" and len(payload_bytes) >= 13:
            type_id = payload_bytes[6]
            vsq = payload_bytes[7]
            cot_raw = int.from_bytes(payload_bytes[8:10], "little")
            cot_val = cot_raw & 0x3F
            is_test = bool(cot_raw & 0x40)
            is_error = bool(cot_raw & 0x80)
            # ASDU layout (IEC-104 I-frame): type_id[6], VSQ[7], COT[8:10], CA[10:12]
            common_address = int.from_bytes(payload_bytes[10:12], "little")

            TYPE_NAMES = {
                1: "M_SP_NA_1 (Single Point)", 3: "M_DP_NA_1 (Double Point)",
                13: "M_ME_NC_1 (Float Measurement)",
                45: "C_SC_NA_1 (Single Command)", 46: "C_DC_NA_1 (Double Command)",
                47: "C_RC_NA_1 (Regulating Step Command)",
                48: "C_SE_NA_1 (Setpoint Normalized)", 49: "C_SE_NB_1 (Setpoint Scaled)",
                50: "C_SE_NC_1 (Setpoint Float)",
                100: "C_IC_NA_1 (General Interrogation)",
                101: "C_CI_NA_1 (Counter Interrogation)",
                103: "C_CS_NA_1 (Clock Sync)",
            }
            type_name = TYPE_NAMES.get(type_id, f"Type {type_id}")

            COT_NAMES = {
                3: "Spontaneous", 5: "Requested", 6: "Activation",
                7: "Activation Confirmation", 8: "Deactivation",
                9: "Deactivation Confirmation", 10: "Activation Termination",
                44: "Unknown Type ID",
            }
            cot_name = COT_NAMES.get(cot_val, f"COT {cot_val}")
            is_write = type_id in (45, 46, 47, 48, 49, 50) and cot_val == 6

        return {
            "frame_type": frame_type,
            "u_type": u_type,
            "type_id": type_id,
            "type_name": type_name,
            "cot": cot_val,
            "cot_name": cot_name,
            "common_address": common_address,
            "is_write": is_write,
            "is_error": is_error,
            "details": {"vsq": vsq, "test": is_test},
        }
    except Exception:
        return None


def parse_bacnet(payload_bytes):
    """Parse BACnet/IP (BVLC + NPDU + APDU). Returns dict or None."""
    if not payload_bytes or len(payload_bytes) < 6:
        return None
    try:
        if payload_bytes[0] != 0x81:
            return None
        bvlc_func = payload_bytes[1]
        bvlc_len = int.from_bytes(payload_bytes[2:4], "big")

        BVLC_FUNCS = {
            0x00: "BVLC-Result", 0x01: "Write-Broadcast-Distribution-Table",
            0x04: "Register-Foreign-Device", 0x05: "Read-Foreign-Device-Table",
            0x0A: "Original-Unicast-NPDU", 0x0B: "Original-Broadcast-NPDU",
            0x0C: "Distribute-Broadcast-To-Network",
        }
        bvlc_func_name = BVLC_FUNCS.get(bvlc_func, f"BVLC Func {hex(bvlc_func)}")

        # NPDU starts at byte 4
        if len(payload_bytes) < 8:
            return None
        npdu_ctrl = payload_bytes[5]
        # Skip NPDU routing fields: DNET(2)+DLEN(1)+DADR(DLEN)+hop_count(1) / SNET(2)+SLEN(1)+SADR(SLEN)
        apdu_offset = 6
        if npdu_ctrl & 0x04:  # Destination specifier present
            if apdu_offset + 3 > len(payload_bytes):
                return None
            dlen = payload_bytes[apdu_offset + 2]   # DLEN is after the 2-byte DNET field
            apdu_offset += 2 + 1 + dlen + 1         # DNET + DLEN + DADR + hop_count
            if apdu_offset > len(payload_bytes):
                return None
        if npdu_ctrl & 0x08:  # Source specifier present
            if apdu_offset + 3 > len(payload_bytes):
                return None
            slen = payload_bytes[apdu_offset + 2]   # SLEN is after the 2-byte SNET field
            apdu_offset += 2 + 1 + slen              # SNET + SLEN + SADR
            if apdu_offset > len(payload_bytes):
                return None

        if apdu_offset >= len(payload_bytes):
            return {
                "bvlc_function": bvlc_func, "bvlc_function_name": bvlc_func_name,
                "pdu_type": None, "pdu_type_name": "NPDU only",
                "service_choice": None, "service_name": None,
                "invoke_id": None, "is_write": False, "is_error": False,
                "details": {"bvlc_length": bvlc_len},
            }

        apdu = payload_bytes[apdu_offset:]
        pdu_type = (apdu[0] >> 4) & 0x0F
        PDU_TYPES = {
            0x0: "Confirmed-Request", 0x1: "Unconfirmed-Request",
            0x2: "Simple-ACK", 0x3: "Complex-ACK",
            0x5: "Error", 0x6: "Reject", 0x7: "Abort",
        }
        pdu_type_name = PDU_TYPES.get(pdu_type, f"PDU {hex(pdu_type)}")

        CONFIRMED_SERVICES = {
            8: "atomicReadFile", 9: "atomicWriteFile",
            12: "createObject", 13: "deleteObject",
            14: "readProperty", 15: "readPropertyConditional",
            16: "readPropertyMultiple", 17: "writeProperty",
            18: "writePropertyMultiple", 28: "deviceCommunicationControl",
            30: "reinitializeDevice",
        }
        UNCONFIRMED_SERVICES = {
            0: "i-Am", 1: "i-Have", 2: "unconfirmedCOVNotification",
            3: "unconfirmedEventNotification", 7: "timeSynchronization",
            8: "who-Has", 9: "who-Is", 13: "utcTimeSynchronization",
        }

        service_choice = None
        service_name = None
        invoke_id = None
        is_write = False

        if pdu_type == 0x0 and len(apdu) >= 4:  # Confirmed-Request
            invoke_id = apdu[2]
            service_choice = apdu[3]
            service_name = CONFIRMED_SERVICES.get(service_choice, f"Service {service_choice}")
            is_write = service_choice in (9, 12, 13, 17, 18, 28, 30)
        elif pdu_type == 0x1 and len(apdu) >= 2:  # Unconfirmed-Request
            service_choice = apdu[1]
            service_name = UNCONFIRMED_SERVICES.get(service_choice, f"Service {service_choice}")

        return {
            "bvlc_function": bvlc_func,
            "bvlc_function_name": bvlc_func_name,
            "pdu_type": pdu_type,
            "pdu_type_name": pdu_type_name,
            "service_choice": service_choice,
            "service_name": service_name,
            "invoke_id": invoke_id,
            "is_write": is_write,
            "is_error": pdu_type == 0x5,
            "details": {"bvlc_length": bvlc_len},
        }
    except Exception:
        return None


def _is_grease(val):
    """TLS GREASE values (RFC 8701): 0x?A?A pattern where both bytes are equal."""
    lo = val & 0xFF
    return lo == (val >> 8) and (lo & 0x0F) == 0x0A


# Known-malicious JA3 fingerprints (curated from public threat intelligence)
_KNOWN_BAD_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit Meterpreter",
    "6734f37431670b3ab4292b8f60f29984": "Cobalt Strike",
    "b386946a5a44d1ddcc843bc75336dfce": "Dridex",
    "a0e9f5d64349fb13191bc781f81f42e1": "AgentTesla",
    "c12f54a3f91dc7bafd92cb59fe009a35": "Cobalt Strike Beacon",
    "ada79f3a9e63d0f1f4c6cb3ba9e99fa0": "Emotet",
    "72a589da586844d7f0818ce684948eea": "TLS Anomaly (ABUSE.CH)",
    "de350869b8c85de67a350c8d186f11e6": "Trickbot",
    "51c64c77e60f3980eea90869b68c58a8": "AsyncRAT",
    "fd4bc6cea4bef9aea6295ac5b3fd65a9": "CobaltStrike (alt)",
    "6bca5a6d9bf5b08f9cd95feefc1c2c7e": "QakBot",
    "a106ce68aee22e2f5d82ee41fb5fb22a": "IcedID",
}


def parse_tls_client_hello(payload):
    """Parse TLS ClientHello from TCP payload bytes.

    Returns dict with sni, ja3, ja3_str, tls_version or None on failure.
    """
    try:
        if len(payload) < 43:
            return None
        # TLS record header: content_type=0x16 (Handshake), version=0x03xx
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
        record_len = (payload[3] << 8) | payload[4]
        if len(payload) < 5 + record_len:
            return None

        # Handshake header: msg_type (1 byte) + length (3 bytes)
        hs = payload[5:]
        if not hs or hs[0] != 0x01:  # 0x01 = ClientHello
            return None
        hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
        if len(hs) < 4 + hs_len:
            return None

        ch = hs[4:]  # ClientHello body
        if len(ch) < 34:
            return None

        # client_version (2 bytes) + random (32 bytes)
        client_version = (ch[0] << 8) | ch[1]
        pos = 34  # skip version(2) + random(32)

        # session_id
        if pos >= len(ch):
            return None
        sid_len = ch[pos]
        pos += 1 + sid_len

        # cipher_suites
        if pos + 2 > len(ch):
            return None
        cs_len = (ch[pos] << 8) | ch[pos + 1]
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 > len(ch):
                break
            c = (ch[pos + i] << 8) | ch[pos + i + 1]
            if not _is_grease(c):
                ciphers.append(str(c))
        pos += cs_len

        # compression_methods
        if pos >= len(ch):
            return None
        cm_len = ch[pos]
        pos += 1 + cm_len

        # extensions
        sni = None
        ext_types = []
        curves = []
        point_formats = []

        if pos + 2 <= len(ch):
            ext_total = (ch[pos] << 8) | ch[pos + 1]
            pos += 2
            ext_end = min(pos + ext_total, len(ch))
            while pos + 4 <= ext_end:
                ext_type = (ch[pos] << 8) | ch[pos + 1]
                ext_len  = (ch[pos + 2] << 8) | ch[pos + 3]
                pos += 4
                if pos + ext_len > len(ch):
                    break
                ext_data = ch[pos:pos + ext_len]
                pos += ext_len

                if not _is_grease(ext_type):
                    ext_types.append(str(ext_type))

                # SNI (type 0x0000)
                if ext_type == 0x0000 and len(ext_data) >= 5 and ext_data[2] == 0:
                    sni_name_len = (ext_data[3] << 8) | ext_data[4]
                    if len(ext_data) >= 5 + sni_name_len:
                        sni = ext_data[5:5 + sni_name_len].decode("utf-8", errors="replace")

                # Supported Groups / EllipticCurves (type 0x000A)
                elif ext_type == 0x000A and len(ext_data) >= 2:
                    grp_len = (ext_data[0] << 8) | ext_data[1]
                    for i in range(0, grp_len, 2):
                        if 2 + i + 2 > len(ext_data):
                            break
                        g = (ext_data[2 + i] << 8) | ext_data[2 + i + 1]
                        if not _is_grease(g):
                            curves.append(str(g))

                # EC Point Formats (type 0x000B)
                elif ext_type == 0x000B and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    for i in range(pf_len):
                        if 1 + i < len(ext_data):
                            point_formats.append(str(ext_data[1 + i]))

        ja3_str = ",".join([
            str(client_version),
            "-".join(ciphers),
            "-".join(ext_types),
            "-".join(curves),
            "-".join(point_formats),
        ])
        ja3 = hashlib.md5(ja3_str.encode()).hexdigest()

        return {
            "sni": sni,
            "ja3": ja3,
            "ja3_str": ja3_str,
            "tls_version": client_version,
        }
    except Exception:
        return None


def analyze_anomalies(hosts, connections, packet_store, credentials=None,
                      vlan_pkt_total=None, vlan_pkt_bcast=None):
    """Detect network anomalies and return a list of anomaly dicts."""
    anomalies = []

    # ── Port scan: single source contacting >5 unique dst IPs with >15 unique dst ports ──
    src_dst_ips = defaultdict(set)
    src_dst_ports = defaultdict(set)
    for (a, b), conn in connections.items():
        src_dst_ips[a].add(b)
        src_dst_ips[b].add(a)
        for p in conn["dst_ports"]:
            src_dst_ports[a].add(p)
            src_dst_ports[b].add(p)

    for ip, dst_ips in src_dst_ips.items():
        if len(dst_ips) > 5 and len(src_dst_ports.get(ip, set())) > 15:
            anomalies.append({
                "type": "port_scan",
                "severity": "high",
                "src": ip,
                "dst": None,
                "description": f"{ip} contacted {len(dst_ips)} unique IPs across {len(src_dst_ports[ip])} ports — possible port scan",
            })

    # ── Cleartext credentials: FTP/Telnet connections with payload ──
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            dport = pkt.get("dport")
            sport = pkt.get("sport")
            if dport in (21, 23) or sport in (21, 23):
                if pkt.get("payload_hex"):  # only fire when actual payload exists
                    port = dport if dport in (21, 23) else sport
                    proto_name = "FTP" if port == 21 else "Telnet"
                    anomalies.append({
                        "type": "cleartext_credentials",
                        "severity": "medium",
                        "src": pkt.get("src", a),
                        "dst": pkt.get("dst", b),
                        "description": f"Cleartext {proto_name} traffic detected between {a} and {b} — credentials may be exposed",
                    })
                    break

    # ── TLS: known-bad JA3 fingerprint ───────────────────────────────────────
    for ip, h in hosts.items():
        for ja3 in h.get("tls_ja3", set()):
            if ja3 in _KNOWN_BAD_JA3:
                label = _KNOWN_BAD_JA3[ja3]
                anomalies.append({
                    "type": "unusual_ja3",
                    "severity": "high",
                    "src": ip,
                    "dst": None,
                    "description": f"{ip} used TLS fingerprint matching {label} (JA3={ja3}) — known malware/C2 tool signature",
                })

    # ── Beaconing: regular inter-packet timing (vectorized via CuPy/NumPy) ──
    for conn_key, pkts in packet_store.items():
        if len(pkts) < 20:          # need ≥20 packets (19 intervals) for reliable CV
            continue
        times = _xp.array(sorted(p["time"] for p in pkts), dtype=_xp.float64)
        intervals = _xp.diff(times)
        if len(intervals) < 3:
            continue
        mean_interval = float(_xp.mean(intervals))
        if mean_interval < 1.0:  # ignore sub-second bursts (bulk transfers, ACK storms)
            continue
        std_interval = float(_xp.std(intervals))
        cv = std_interval / mean_interval
        if cv < 0.2:
            a, b = conn_key
            anomalies.append({
                "type": "beaconing",
                "severity": "medium",
                "src": a,
                "dst": b,
                "description": f"Regular beaconing detected between {a} and {b} ({len(pkts)} packets, CV={cv:.2%})",
            })

    # ── Data exfiltration: >10MB transferred on a connection to/from an external IP ──
    TEN_MB = 10 * 1024 * 1024
    _seen_exfil = set()
    for (a, b), conn in connections.items():
        a_priv, b_priv = is_private(a), is_private(b)
        if not (a_priv ^ b_priv):   # skip if both private or both public
            continue
        if conn["bytes"] > TEN_MB:
            internal = a if a_priv else b
            external = b if a_priv else a
            key = (internal, external)
            if key not in _seen_exfil:
                _seen_exfil.add(key)
                anomalies.append({
                    "type": "exfiltration",
                    "severity": "high",
                    "src": internal,
                    "dst": external,
                    "description": (
                        f"{internal} transferred {conn['bytes'] / 1048576:.1f} MB "
                        f"with external IP {external} — possible data exfiltration"
                    ),
                })

    # ── Suspicious ports ──
    for (a, b), conn in connections.items():
        for port in conn["dst_ports"]:
            if port in SUSPICIOUS_PORTS:
                anomalies.append({
                    "type": "suspicious_port",
                    "severity": "high",
                    "src": a,
                    "dst": b,
                    "description": f"Suspicious port {port} used between {a} and {b} — possible malicious activity",
                })
                break

    # ── OT: Modbus write commands from unexpected sources ──────────────────────
    for conn_key, pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") == 502 or pkt.get("sport") == 502:
                hex_str = pkt.get("hex", "")
                if hex_str:
                    try:
                        raw = bytes.fromhex(hex_str)
                        # Modbus TCP starts after Ethernet+IP+TCP headers (~54 bytes)
                        # Try to find Modbus payload in raw bytes
                        for offset in range(40, min(60, len(raw) - 8)):
                            mb = parse_modbus(raw[offset:])
                            if mb and mb.get("is_write"):
                                anomalies.append({
                                    "type": "ot_modbus_write",
                                    "severity": "high",
                                    "src": pkt["src"],
                                    "dst": pkt["dst"],
                                    "description": f"Modbus WRITE command ({mb['function_name']}) from {pkt['src']} to {pkt['dst']} — unauthorized PLC write",
                                })
                                break
                    except Exception:
                        pass
                break

    # ── Connection index: ip -> list of (a, b) keys (avoids O(h*c) scans) ──────
    src_conn_index = defaultdict(list)
    dst_conn_index = defaultdict(list)
    for (a, b) in connections:
        src_conn_index[a].append((a, b))
        dst_conn_index[b].append((a, b))

    def _peers_of(ip):
        """Yield (conn_key, peer_ip) for every connection involving ip."""
        for key in src_conn_index[ip]:
            yield key, key[1]
        for key in dst_conn_index[ip]:
            yield key, key[0]

    # ── OT: IT host communicating directly with OT device ─────────────────────
    ot_types = {"PLC", "RTU", "IED", "DCS", "SCADA Server", "Building Controller", "Field Device"}
    for ip, h in hosts.items():
        if h["host_type"] in ot_types:
            for _, peer in _peers_of(ip):
                if not is_private(peer):
                    anomalies.append({
                        "type": "ot_internet_exposure",
                        "severity": "high",
                        "src": peer,
                        "dst": ip,
                        "description": f"OT device {ip} ({h['host_type']}) communicating with internet host {peer} — critical exposure",
                    })

    # ── OT: Cleartext OT protocols (Modbus, DNP3, S7, BACnet) ─────────────────
    cleartext_ot_ports = {502: "Modbus", 20000: "DNP3", 102: "S7comm", 47808: "BACnet", 4840: "OPC-UA"}
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            port = pkt.get("dport") or pkt.get("sport")
            if port in cleartext_ot_ports:
                anomalies.append({
                    "type": "ot_cleartext",
                    "severity": "medium",
                    "src": a,
                    "dst": b,
                    "description": f"Cleartext {cleartext_ot_ports[port]} traffic between {a} and {b} — OT protocol has no encryption",
                })
                break

    # ── IoT: MQTT without TLS (cleartext broker) ──────────────────────────────
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") == 1883 or pkt.get("sport") == 1883:
                anomalies.append({
                    "type": "iot_mqtt_cleartext",
                    "severity": "medium",
                    "src": a,
                    "dst": b,
                    "description": f"Cleartext MQTT (port 1883) between {a} and {b} — credentials and data sent unencrypted",
                })
                break

    # ── IoT: Telnet access to IoT device (Mirai-style) ────────────────────────
    iot_types = {"IP Camera", "Smart Home Hub", "Smart Meter", "IoT Sensor", "Smart Speaker", "IoT Gateway"}
    for ip, h in hosts.items():
        if h["host_type"] in iot_types:
            for conn_key, peer in _peers_of(ip):
                conn = connections[conn_key]
                if 23 in conn.get("dst_ports", set()):
                    anomalies.append({
                        "type": "iot_telnet",
                        "severity": "high",
                        "src": peer,
                        "dst": ip,
                        "description": f"Telnet access to IoT device {ip} ({h['host_type']}) from {peer} — common botnet/Mirai attack vector",
                    })

    # ── IoT: IP Camera sending data to internet ────────────────────────────────
    for ip, h in hosts.items():
        if h["host_type"] == "IP Camera":
            for _, peer in _peers_of(ip):
                if not is_private(peer):
                    anomalies.append({
                        "type": "iot_camera_exfil",
                        "severity": "high",
                        "src": ip,
                        "dst": peer,
                        "description": f"IP Camera {ip} sending data to external host {peer} — possible unauthorized stream or firmware C2",
                    })
                    break

    # ── IoT: Insecure device using TR-069 (CPE WAN management) ───────────────
    for (a, b), conn in connections.items():
        if 7547 in conn.get("dst_ports", set()):
            anomalies.append({
                "type": "iot_tr069",
                "severity": "medium",
                "src": a,
                "dst": b,
                "description": f"TR-069 (port 7547) detected between {a} and {b} — remote CPE management protocol, often exploited",
            })

    # ── OT: DNP3 control/operate commands ────────────────────────────────────
    for conn_key, pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") == 20000 or pkt.get("sport") == 20000:
                dn = pkt.get("dnp3")
                if dn and dn.get("is_write"):
                    anomalies.append({
                        "type": "ot_dnp3_control",
                        "severity": "high",
                        "src": pkt["src"],
                        "dst": pkt["dst"],
                        "description": f"DNP3 control command ({dn['function_name']}) from {pkt['src']} to {pkt['dst']} — unauthorized RTU operate",
                    })
                    break

    # ── OT: S7comm write / PLC stop ──────────────────────────────────────────
    for conn_key, pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") == 102 or pkt.get("sport") == 102:
                s7 = pkt.get("s7comm")
                if s7 and s7.get("is_write"):
                    fc = s7.get("function_code")
                    if fc in (0x28, 0x29):
                        anomalies.append({
                            "type": "ot_s7_critical",
                            "severity": "high",
                            "src": pkt["src"],
                            "dst": pkt["dst"],
                            "description": f"S7comm {s7['function_name']} from {pkt['src']} to {pkt['dst']} — critical PLC control command",
                        })
                    else:
                        anomalies.append({
                            "type": "ot_s7_write",
                            "severity": "high",
                            "src": pkt["src"],
                            "dst": pkt["dst"],
                            "description": f"S7comm Write Variable from {pkt['src']} to {pkt['dst']} — unauthorized PLC write",
                        })
                    break

    # ── OT: EtherNet/IP CIP write tag ────────────────────────────────────────
    for conn_key, pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") in (2222, 44818) or pkt.get("sport") in (2222, 44818):
                ei = pkt.get("enip")
                if ei and ei.get("is_write"):
                    anomalies.append({
                        "type": "ot_enip_write",
                        "severity": "high",
                        "src": pkt["src"],
                        "dst": pkt["dst"],
                        "description": f"EtherNet/IP CIP {ei['cip_service_name']} from {pkt['src']} to {pkt['dst']} — unauthorized tag write",
                    })
                    break

    # ── OT: IEC 60870-5-104 control command ──────────────────────────────────
    for conn_key, pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") == 2404 or pkt.get("sport") == 2404:
                ic = pkt.get("iec104")
                if ic and ic.get("is_write"):
                    anomalies.append({
                        "type": "ot_iec104_command",
                        "severity": "high",
                        "src": pkt["src"],
                        "dst": pkt["dst"],
                        "description": f"IEC-104 control command ({ic['type_name']}) from {pkt['src']} to {pkt['dst']} — activation of IED control",
                    })
                    break

    # ── OT: BACnet write property ─────────────────────────────────────────────
    for conn_key, pkts in packet_store.items():
        for pkt in pkts:
            if pkt.get("dport") == 47808 or pkt.get("sport") == 47808:
                bn = pkt.get("bacnet")
                if bn and bn.get("is_write"):
                    anomalies.append({
                        "type": "ot_bacnet_write",
                        "severity": "high",
                        "src": pkt["src"],
                        "dst": pkt["dst"],
                        "description": f"BACnet {bn['service_name']} from {pkt['src']} to {pkt['dst']} — unauthorized building controller write",
                    })
                    break

    # ── OT: Modbus bulk register read (reconnaissance pattern) ────────────────
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            mb = pkt.get("modbus")
            if mb and mb.get("quantity", 0) > 100 and mb["function_code"] in (3, 4):
                anomalies.append({
                    "type": "ot_modbus_bulk_read",
                    "severity": "medium",
                    "src": a,
                    "dst": b,
                    "description": f"Modbus bulk read ({mb['quantity']} registers, FC{mb['function_code']}) from {a} to {b} — large register scan may indicate reconnaissance",
                })
                break

    # ── OT: Modbus broadcast (unit_id=0, affects all PLCs on segment) ─────────
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            mb = pkt.get("modbus")
            if mb and mb.get("unit_id_zero"):
                anomalies.append({
                    "type": "ot_modbus_broadcast",
                    "severity": "high",
                    "src": a,
                    "dst": b,
                    "description": f"Modbus broadcast (unit_id=0) from {a} — command targets ALL PLCs on segment, unauthorized broadcast risk",
                })
                break

    # ── OT: Modbus exception response (bad commands or access failures) ────────
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            mb = pkt.get("modbus")
            if mb and mb.get("exception_code") is not None:
                anomalies.append({
                    "type": "ot_modbus_exception",
                    "severity": "medium",
                    "src": a,
                    "dst": b,
                    "description": f"Modbus exception {mb.get('exception_name', mb['exception_code'])} on {b} — may indicate unauthorized access attempt or misconfigured client",
                })
                break

    # ── OT: S7 code download (PLC logic modification) ─────────────────────────
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            s7 = pkt.get("s7comm")
            if s7 and s7.get("function_code") == 0x1A:
                block_desc = ""
                if s7.get("block_type"):
                    block_desc = f" ({s7['block_type']}"
                    if s7.get("block_number") is not None:
                        block_desc += f" #{s7['block_number']}"
                    block_desc += ")"
                anomalies.append({
                    "type": "ot_s7_code_download",
                    "severity": "high",
                    "src": a,
                    "dst": b,
                    "description": f"S7 code download{block_desc} from {a} to {b} — PLC logic is being modified, verify authorization",
                })
                break

    # ── OT: DNP3 unusual function codes (evasion/persistence) ────────────────
    UNUSUAL_DNP3_FCS = {4: "Immediate Freeze Without Reply", 8: "Freeze No ACK", 14: "Warm Restart"}
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            dn = pkt.get("dnp3")
            if dn and dn.get("function_code") in UNUSUAL_DNP3_FCS:
                anomalies.append({
                    "type": "ot_dnp3_unusual_fc",
                    "severity": "medium",
                    "src": a,
                    "dst": b,
                    "description": f"DNP3 {UNUSUAL_DNP3_FCS[dn['function_code']]} (FC{dn['function_code']}) from {a} — covert control or evasion technique",
                })
                break

    # ── OT: Multi-unit Modbus polling (network mapping of slaves) ────────────
    modbus_unit_id_map = defaultdict(set)  # src_ip -> set of unit_ids
    for ip, h in hosts.items():
        if h.get("modbus_unit_ids"):
            modbus_unit_id_map[ip] = h["modbus_unit_ids"]
    for ip, unit_ids in modbus_unit_id_map.items():
        non_zero = {u for u in unit_ids if u != 0}
        if len(non_zero) >= 5:
            anomalies.append({
                "type": "ot_multiunit_poll",
                "severity": "medium",
                "src": ip,
                "dst": ip,
                "description": f"{ip} polling {len(non_zero)} distinct Modbus unit IDs ({sorted(non_zero)[:8]}) — may indicate network mapping of PLC segments",
            })

    # ── DNS tunneling: high-entropy subdomains, excessive length, unique-label flood ──
    for ip, h in hosts.items():
        queries = h.get("dns_queries", set())
        if len(queries) < 3:
            continue

        reason = None

        # Signal 1: any label >24 chars with very high entropy (base64/hex encoded data)
        for q in queries:
            parts = q.split(".")
            for label in parts[:-2]:  # skip TLD + 2LD
                if len(label) > 24 and _shannon_entropy(label) > 4.5:
                    reason = f"high-entropy subdomain '{label[:24]}…' ({len(queries)} queries)"
                    break
            if reason:
                break

        # Signal 2: unusually long average query name
        if not reason:
            avg_len = sum(len(q) for q in queries) / len(queries)
            if avg_len > 60 and len(queries) >= 5:
                reason = f"abnormally long DNS queries (avg {avg_len:.0f} chars, {len(queries)} queries)"

        # Signal 3: many unique 3rd-level labels to same parent domain
        if not reason:
            parent_subs = defaultdict(set)
            for q in queries:
                parts = q.split(".")
                if len(parts) >= 3:
                    parent_subs[".".join(parts[-2:])].add(parts[-3])
            for parent, subs in parent_subs.items():
                if len(subs) > 20:
                    reason = f"{len(subs)} unique subdomain labels under {parent} — likely C2 channel"
                    break

        if reason:
            anomalies.append({
                "type": "dns_tunneling",
                "severity": "high",
                "src": ip,
                "dst": None,
                "description": f"{ip} shows DNS tunneling indicators: {reason}",
            })

    # ── VLAN: host seen on multiple VLANs (potential VLAN hopping) ───────────
    routing_types = {"Router", "Network Device", "VPN Gateway"}
    for ip, h in hosts.items():
        vlan_ids = h.get("vlan_ids", set())
        if len(vlan_ids) > 1 and h.get("host_type") not in routing_types and not h.get("vlan_qinq"):
            anomalies.append({
                "type": "vlan_hopping",
                "severity": "medium",
                "src": ip,
                "dst": None,
                "description": (
                    f"{ip} ({h['host_type']}) seen on multiple VLANs {sorted(vlan_ids)} — "
                    "may indicate VLAN hopping attack or misconfigured trunk port"
                ),
            })

    # ── VLAN: host sending both tagged and untagged frames (native VLAN leakage) ──
    for ip, h in hosts.items():
        if h.get("vlan_untagged") and h.get("vlan_ids"):
            anomalies.append({
                "type": "vlan_native_leak",
                "severity": "low",
                "src": ip,
                "dst": None,
                "description": (
                    f"{ip} sending both untagged and VLAN-tagged ({sorted(h['vlan_ids'])}) frames — "
                    "possible native VLAN leakage or misconfigured access port"
                ),
            })

    # ── VLAN: QinQ (double-tagged) frames detected ────────────────────────────
    for ip, h in hosts.items():
        if h.get("vlan_qinq"):
            anomalies.append({
                "type": "vlan_qinq",
                "severity": "medium",
                "src": ip,
                "dst": None,
                "description": (
                    f"{ip} involved in 802.1ad QinQ double-tagged frames "
                    f"(outer VLANs: {sorted(h.get('vlan_outer_ids', set()))}) — "
                    "legitimate in carrier networks but a classic VLAN-hopping attack vector"
                ),
            })

    # ── VLAN: OT host communicating across VLAN segments ─────────────────────
    for (a, b), conn in connections.items():
        ha = hosts.get(a, {})
        hb = hosts.get(b, {})
        ot_involved = ha.get("ot_role", "unknown") not in (None, "unknown") or \
                      hb.get("ot_role", "unknown") not in (None, "unknown")
        if not ot_involved:
            continue
        va = ha.get("vlan_ids", set())
        vb = hb.get("vlan_ids", set())
        if va and vb and va.isdisjoint(vb):
            ot_ip = a if ha.get("ot_role", "unknown") not in (None, "unknown") else b
            other_ip = b if ot_ip == a else a
            ot_host = hosts.get(ot_ip, {})
            anomalies.append({
                "type": "vlan_cross_segment_ot",
                "severity": "high",
                "src": other_ip,
                "dst": ot_ip,
                "description": (
                    f"OT device {ot_ip} (VLAN {sorted(hosts.get(ot_ip, {}).get('vlan_ids', set()))}) "
                    f"communicating with {other_ip} (VLAN {sorted(hosts.get(other_ip, {}).get('vlan_ids', set()))}) "
                    "across VLAN boundaries — potential OT network segmentation violation"
                ),
            })

    # ── PCP priority abuse: end-hosts sending high-priority QoS frames ───────────
    _HIGH_PCP_HOSTS = {
        "Windows Host", "Linux Host", "Unknown Host",
        "IP Camera", "IoT Sensor", "Smart Meter", "Smart Home Hub",
        "Smart Speaker", "CPE Device", "Field Device",
    }
    for ip, h in hosts.items():
        pcps = h.get("vlan_pcps", set())
        high_pcps = sorted(p for p in pcps if p >= 7)
        if high_pcps and h.get("host_type") in _HIGH_PCP_HOSTS:
            anomalies.append({
                "type": "pcp_abuse",
                "severity": "low",
                "src": ip,
                "dst": None,
                "description": (
                    f"{ip} ({h['host_type']}) sending frames with high QoS priority "
                    f"PCP {high_pcps} — unexpected for this device type"
                ),
            })

    # ── ARP spoofing: multiple MACs claiming the same IP within a VLAN ──────────
    # Build (vlan_id, ip) → set of MACs; flag any IP with 2+ distinct MACs on same VLAN
    vlan_ip_macs: dict = defaultdict(set)
    for ip, h in hosts.items():
        # Use the full set of observed MACs (h["macs"]) so ARP-spoof detection
        # can actually see multiple MACs per IP, not just the first-seen one.
        all_macs = {m for m in h.get("macs", set()) if m and m != "00:00:00:00:00:00"}
        if not all_macs:
            continue
        for vlan_id in h.get("vlan_ids", set()):
            vlan_ip_macs[(vlan_id, ip)].update(all_macs)
        if h.get("vlan_untagged") and not h.get("vlan_ids"):
            vlan_ip_macs[("untagged", ip)].update(all_macs)

    for (vlan_id, ip), macs in vlan_ip_macs.items():
        if len(macs) > 1:
            vlan_label = f"VLAN {vlan_id}" if vlan_id != "untagged" else "untagged VLAN"
            anomalies.append({
                "type": "arp_spoofing",
                "severity": "high",
                "src": ip,
                "dst": None,
                "description": (
                    f"{ip} seen with {len(macs)} different MAC addresses on {vlan_label} "
                    f"({', '.join(sorted(macs))}) — possible ARP spoofing or MAC flapping"
                ),
            })

    # ── Broadcast storm: VLAN with >10% broadcast traffic ────────────────────
    BCAST_THRESHOLD = 0.10
    BCAST_MIN_PKTS  = 50          # avoid false positives on tiny captures
    if vlan_pkt_total and vlan_pkt_bcast:
        for vlan_id, total in vlan_pkt_total.items():
            bcast = vlan_pkt_bcast.get(vlan_id, 0)
            if total >= BCAST_MIN_PKTS and bcast / total > BCAST_THRESHOLD:
                anomalies.append({
                    "type": "broadcast_storm",
                    "severity": "medium",
                    "src": None,
                    "dst": None,
                    # Host-less anomaly — carry the VLAN explicitly so consumers (e.g. the
                    # VLAN flow matrix) can still place it without a src/dst IP to look up.
                    "vlan_id": vlan_id,
                    "description": (
                        f"VLAN {vlan_id}: {bcast} broadcast packets out of {total} total "
                        f"({bcast * 100 // total}%) — possible broadcast storm or misconfiguration"
                    ),
                })

    # ── Password reuse across protocols or destinations ───────────────────────
    if credentials:
        pw_services = defaultdict(set)
        for c in credentials:
            pw = c.get("password", "")
            if pw and len(pw) >= 4:
                pw_services[pw].add((c.get("protocol"), c.get("dst")))
        for pw, services in pw_services.items():
            if len(services) >= 2:
                svc_list = sorted(f"{p}@{d}" for p, d in services)
                anomalies.append({
                    "type": "password_reuse",
                    "severity": "high",
                    "src": None,
                    "dst": None,
                    "description": f"Password reused across {len(services)} services: {', '.join(svc_list[:5])}",
                })

    # Deduplicate — key includes description so distinct findings of the same
    # type between the same pair (e.g. two password_reuse events, two JA3 hits)
    # are all kept; only exact duplicates are collapsed.
    seen = set()
    deduped = []
    for a in anomalies:
        key = (a["type"], a["src"], a["dst"], a.get("description", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    return deduped


# ── Hot-loop helpers for RawPcapReader-based packet parsing ──────────────────

_TCP_FLAG_MAP = [
    (0x01, 'F'), (0x02, 'S'), (0x04, 'R'), (0x08, 'P'),
    (0x10, 'A'), (0x20, 'U'), (0x40, 'E'), (0x80, 'C'),
]


def _tcp_flag_str(flags_byte):
    """Render TCP flags byte as compact string (e.g. 'SA' for SYN+ACK)."""
    return ''.join(c for bit, c in _TCP_FLAG_MAP if flags_byte & bit) or '0'


def _ipv6_str(b):
    """Convert 16 bytes to a compressed IPv6 address string."""
    return str(ipaddress.IPv6Address(bytes(b)))


_ICMP_TYPE_NAMES = {0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "Time Exceeded"}


def _shannon_entropy(s):
    """Shannon entropy in bits/char for string s."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in freq.values())


def _build_packet_detail(raw, rel_t, sip, dip, protocol, plen,
                         sport, dport, payload, is_ipv6,
                         tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_doff_bytes,
                         udp_len, icmp_type, icmp_code,
                         smac, dmac, ttl, l3_off, eth_type):
    """Build the packet-detail dict for the drill-down panel from already-parsed fields."""
    pd = {
        "time": rel_t, "src": sip, "dst": dip,
        "protocol": protocol, "len": plen,
        "sport": sport, "dport": dport,
        "layers": [], "hex": "", "info": "",
        "http": None, "modbus": None, "mqtt": None, "coap": None,
        "dnp3": None, "s7comm": None, "enip": None,
        "iec104": None, "bacnet": None, "tls": None,
    }

    if smac is not None:
        pd["layers"].append({"name": "Ethernet", "start": 0, "end": l3_off, "fields": [
            {"k": "Dst MAC", "v": dmac},
            {"k": "Src MAC", "v": smac},
            {"k": "Type",    "v": hex(eth_type)},
        ]})

    l4_off = l3_off  # default; updated below per-protocol
    if not is_ipv6 and l3_off + 20 <= len(raw):
        ihl = (raw[l3_off] & 0x0f) * 4
        l4_off = l3_off + ihl
        total_len = (raw[l3_off + 2] << 8) | raw[l3_off + 3]
        ip_id = (raw[l3_off + 4] << 8) | raw[l3_off + 5]
        df = bool(raw[l3_off + 6] & 0x40)
        mf = bool(raw[l3_off + 6] & 0x20)
        ip_flags_str = '+'.join(x for x, cond in [('DF', df), ('MF', mf)] if cond) or '0'
        pd["layers"].append({"name": "Internet Protocol", "start": l3_off, "end": l4_off, "fields": [
            {"k": "Version",    "v": 4},
            {"k": "Hdr Length", "v": f"{ihl} bytes"},
            {"k": "Total Len",  "v": total_len},
            {"k": "ID",         "v": hex(ip_id)},
            {"k": "Flags",      "v": ip_flags_str},
            {"k": "TTL",        "v": ttl},
            {"k": "Protocol",   "v": raw[l3_off + 9]},
            {"k": "Src",        "v": sip},
            {"k": "Dst",        "v": dip},
        ]})
    elif is_ipv6 and l3_off + 40 <= len(raw):
        l4_off = l3_off + 40
        tc = ((raw[l3_off] & 0x0f) << 4) | (raw[l3_off + 1] >> 4)
        fl = ((raw[l3_off + 1] & 0x0f) << 16) | (raw[l3_off + 2] << 8) | raw[l3_off + 3]
        ipv6_plen = (raw[l3_off + 4] << 8) | raw[l3_off + 5]
        nh = raw[l3_off + 6]
        pd["layers"].append({"name": "Internet Protocol Version 6", "start": l3_off, "end": l4_off, "fields": [
            {"k": "Version",       "v": 6},
            {"k": "Traffic Class", "v": tc},
            {"k": "Flow Label",    "v": hex(fl)},
            {"k": "Payload Len",   "v": ipv6_plen},
            {"k": "Next Header",   "v": nh},
            {"k": "Hop Limit",     "v": ttl},
            {"k": "Src",           "v": sip},
            {"k": "Dst",           "v": dip},
        ]})

    if tcp_flags is not None:
        flag_str = _tcp_flag_str(tcp_flags)
        tcp_hdr_end = l4_off + (tcp_doff_bytes if tcp_doff_bytes else 20)
        pd["layers"].append({"name": "Transmission Control Protocol", "start": l4_off, "end": tcp_hdr_end, "fields": [
            {"k": "Src Port", "v": sport},
            {"k": "Dst Port", "v": dport},
            {"k": "Seq",      "v": tcp_seq},
            {"k": "Ack",      "v": tcp_ack},
            {"k": "Flags",    "v": flag_str},
            {"k": "Window",   "v": tcp_window},
        ]})
        if payload:
            pd["layers"].append({"name": "Payload", "start": tcp_hdr_end, "end": tcp_hdr_end + len(payload), "fields": []})
        pd["info"] = f"{sport} → {dport} [{flag_str}] Seq={tcp_seq}"
        if payload:
            pd["info"] += f" Len={len(payload)}"
    elif udp_len is not None:
        pd["layers"].append({"name": "User Datagram Protocol", "start": l4_off, "end": l4_off + 8, "fields": [
            {"k": "Src Port", "v": sport},
            {"k": "Dst Port", "v": dport},
            {"k": "Length",   "v": udp_len},
        ]})
        if payload:
            pd["layers"].append({"name": "Payload", "start": l4_off + 8, "end": l4_off + 8 + len(payload), "fields": []})
        pd["info"] = f"{sport} → {dport}"
    elif icmp_type is not None:
        pd["layers"].append({"name": "Internet Control Message Protocol", "start": l4_off, "end": l4_off + 8, "fields": [
            {"k": "Type", "v": f"{icmp_type} ({_ICMP_TYPE_NAMES.get(icmp_type, 'Unknown')})"},
            {"k": "Code", "v": icmp_code},
        ]})
        pd["info"] = _ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")

    if payload:
        pd["payload_hex"] = payload[:256].hex()
    pd["hex"] = raw[:256].hex()
    return pd


def analyze_pcap(filepath):
    try:
        from scapy.layers.dns import DNS as _DNS   # reconstructed only for port 53 traffic
        from scapy.utils import RawPcapReader
    except ImportError as e:
        return {"error": f"scapy not available: {e}"}

    hosts = {}
    vlan_pkt_total: defaultdict = defaultdict(int)   # vlan_id → total packets on that VLAN
    vlan_pkt_bcast: defaultdict = defaultdict(int)   # vlan_id → broadcast packets on that VLAN
    cdp_lldp: dict = {}   # smac → {"hostname": str, "native_vlan": int|None, "protocol": "CDP"|"LLDP"}
    connections = defaultdict(lambda: {
        "protocols": set(),
        "packet_count": 0,
        "bytes": 0,
        "dst_ports": set(),
        "first_seen": None,
        "last_seen": None,
        "abs_first_seen": None,
        "abs_last_seen": None,
        "ot_reads": 0,
        "ot_writes": 0,
        "ot_errors": 0,
        "fc_counts": defaultdict(int),
        "vlan_ids": set(),
    })

    def host(ip, mac=None):
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "mac": mac,
                "mac_vendor": mac_vendor(mac) if mac else None,
                "protocols": set(),
                "dst_ports": set(),
                "services": set(),
                "host_type_hints": Counter(),
                "ttl_values": [],
                "hostname": None,
                "dns_names": set(),
                "dns_queries": set(),
                "os_hint": None,
                "host_type": "Unknown Host",
                "packet_count": 0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "flags": set(),
                "is_private": is_private(ip),
                "modbus_unit_ids": set(),
                "dnp3_addresses": set(),
                "ot_role": "unknown",
                "has_s7_download": False,
                "tls_sni": set(),
                "tls_ja3": set(),
                "vlan_ids": set(),
                "vlan_outer_ids": set(),
                "vlan_pcps": set(),
                "vlan_untagged": False,
                "vlan_qinq": False,
                "macs": set(),  # all observed MACs — used by ARP-spoof detector
            }
        h = hosts[ip]
        if mac:
            h["macs"].add(mac)
            if not h["mac"]:
                h["mac"] = mac
                h["mac_vendor"] = mac_vendor(mac)
        return h

    MAX_PACKETS = 1_000_000
    MAX_HOSTS = 250_000         # raised: parse all hosts; render cap is in the frontend
    MAX_CONNECTIONS = 1_000_000  # raised: parse all connections; render cap is in the frontend
    MAX_CREDS = 500
    MAX_FILES = 200
    MAX_OT_COMMANDS = 5_000
    MAX_TTL_VALUES = 256        # per-host TTL sample cap (enough for Counter.most_common)
    MAX_DNS_ENTRIES = 1_000     # per-host dns_names / dns_queries cap
    # MAX_CRED_STATE_ENTRIES is module-level (above) so tests can monkeypatch it
    processed = 0
    parse_errors = 0
    _hosts_truncated = False       # True if MAX_HOSTS backstop was hit
    _conns_truncated = False       # True if MAX_CONNECTIONS backstop was hit
    packet_store = defaultdict(list)
    MAX_STORED_PER_CONN = 50
    first_pkt_time = None
    last_pkt_time = None
    credentials = []
    _cred_seen  = set()
    files = []
    _cred_ftp   = {}   # conn_key → {"user": str}
    _cred_pop3  = {}   # conn_key → {"user": str}
    _cred_smtp  = {}   # conn_key → {"phase": "user"|"pass", "user": str}
    _cred_telnet = {}  # conn_key → {"phase": str, "buf": str, "user": str}
    _CRED_HTTP_PORTS  = {80, 8080, 8000, 3000, 8008, 8888}
    _CRED_SMTP_PORTS  = {25, 587, 465}
    _CRED_POP3_PORTS  = {110}
    _CRED_IMAP_PORTS  = {143}
    _CRED_LDAP_PORTS  = {389}
    _CRED_SNMP_PORTS  = {161, 162}
    _CRED_TELNET_PORT = 23
    ot_commands = []

    try:
        with RawPcapReader(filepath) as reader:
            for raw, meta in reader:
                if processed >= MAX_PACKETS:
                    break
                processed += 1

                if hasattr(meta, "sec"):          # pcap (PacketMetadata)
                    pkt_time = meta.sec + meta.usec / 1_000_000.0
                else:                             # pcapng (PacketMetadataNg)
                    pkt_time = ((meta.tshigh << 32) | meta.tslow) / meta.tsresol
                if first_pkt_time is None:
                    first_pkt_time = pkt_time
                last_pkt_time = pkt_time

                # ── Ethernet header ───────────────────────────────────────────
                # NOTE: assumes DLT_EN10MB (standard Ethernet). Non-Ethernet
                # link types (DLT_NULL, DLT_LINUX_SLL, etc.) will be skipped.
                if len(raw) < 14:
                    continue

                dmac = raw[0:6].hex(":")   # C-level: ~3× faster than f-string join
                smac = raw[6:12].hex(":")
                ethertype = (raw[12] << 8) | raw[13]
                l2_off = 14

                vlan_outer = vlan_inner = pcp = dei = None
                is_qinq = False

                if ethertype == 0x88A8 and len(raw) >= 18:   # 802.1ad QinQ outer tag
                    tci_outer = (raw[14] << 8) | raw[15]
                    vlan_outer = tci_outer & 0x0FFF
                    inner_ethertype = (raw[16] << 8) | raw[17]
                    if inner_ethertype == 0x8100 and len(raw) >= 22:
                        tci_inner = (raw[18] << 8) | raw[19]
                        vlan_inner = tci_inner & 0x0FFF
                        pcp = (tci_inner >> 13) & 0x07
                        dei = (tci_inner >> 12) & 0x01
                        ethertype = (raw[20] << 8) | raw[21]
                        l2_off = 22
                        is_qinq = True
                    else:
                        ethertype = inner_ethertype
                        l2_off = 18
                elif ethertype == 0x8100 and len(raw) >= 18:   # 802.1Q single tag (or stacked 0x8100/0x8100)
                    tci_outer = (raw[14] << 8) | raw[15]
                    vlan_outer = tci_outer & 0x0FFF
                    inner_ethertype = (raw[16] << 8) | raw[17]
                    if inner_ethertype == 0x8100 and len(raw) >= 22:
                        # Stacked double 0x8100 tags — some switches (older Cisco
                        # dot1q-tunnel/"tag-in-tag") emit QinQ using 0x8100 for both
                        # the outer and inner tag instead of the 802.1ad 0x88A8 outer
                        # TPID. Without this, these frames fell through to `else:
                        # continue` below (no matching L3 ethertype) and were dropped
                        # entirely — no host, no VLAN, no flow recorded for them.
                        tci_inner = (raw[18] << 8) | raw[19]
                        vlan_inner = tci_inner & 0x0FFF
                        pcp = (tci_inner >> 13) & 0x07
                        dei = (tci_inner >> 12) & 0x01
                        ethertype = (raw[20] << 8) | raw[21]
                        l2_off = 22
                        is_qinq = True
                    else:
                        pcp = (tci_outer >> 13) & 0x07
                        dei = (tci_outer >> 12) & 0x01
                        ethertype = inner_ethertype
                        l2_off = 18

                eth_type = ethertype

                # ── CDP (Cisco Discovery Protocol) ────────────────────────────
                # CDP uses 802.3/LLC/SNAP: length field < 0x0600, DSAP/SSAP=0xAA,
                # Cisco OUI=00:00:0c, PID=0x2000
                if (dmac == "01:00:0c:cc:cc:cc" and ethertype < 0x0600
                        and len(raw) >= l2_off + 8
                        and raw[l2_off] == 0xAA and raw[l2_off + 1] == 0xAA
                        and raw[l2_off + 3:l2_off + 6] == b'\x00\x00\x0c'
                        and raw[l2_off + 6:l2_off + 8] == b'\x20\x00'):
                    try:
                        _cdp_off = l2_off + 8 + 4   # skip LLC(3) + SNAP(5) + version(1) + ttl(1) + checksum(2)
                        _cdp_hostname = None
                        _cdp_vlan = None
                        while _cdp_off + 4 <= len(raw):
                            _t = (raw[_cdp_off] << 8) | raw[_cdp_off + 1]
                            _l = (raw[_cdp_off + 2] << 8) | raw[_cdp_off + 3]
                            if _l < 4: break
                            _v = raw[_cdp_off + 4:_cdp_off + _l]
                            if _t == 0x0001 and _v:   # Device ID
                                _cdp_hostname = _v.decode("utf-8", errors="replace").strip()
                            elif _t == 0x000A and len(_v) >= 2:   # Native VLAN
                                _cdp_vlan = (_v[0] << 8) | _v[1]
                            _cdp_off += _l
                        if smac not in cdp_lldp:
                            cdp_lldp[smac] = {"hostname": _cdp_hostname, "native_vlan": _cdp_vlan, "protocol": "CDP"}
                        elif _cdp_hostname:
                            cdp_lldp[smac]["hostname"] = cdp_lldp[smac]["hostname"] or _cdp_hostname
                            if _cdp_vlan is not None:
                                cdp_lldp[smac]["native_vlan"] = _cdp_vlan
                    except Exception:
                        pass
                    continue

                # ── LLDP (IEEE 802.1AB) ───────────────────────────────────────
                if ethertype == 0x88CC:
                    try:
                        _lldp_off = l2_off
                        _lldp_hostname = None
                        _lldp_pvid = None
                        while _lldp_off + 2 <= len(raw):
                            _th = (raw[_lldp_off] << 8) | raw[_lldp_off + 1]
                            _tt = (_th >> 9) & 0x7F   # TLV type
                            _tl = _th & 0x01FF         # TLV length
                            _lldp_off += 2
                            if _tt == 0:               # End TLV
                                break
                            if _tl == 0:               # zero-length non-End TLV → malformed, stop
                                break
                            if _lldp_off + _tl > len(raw): break
                            _tv = raw[_lldp_off:_lldp_off + _tl]
                            if _tt == 5 and _tv:       # System Name
                                _lldp_hostname = _tv.decode("utf-8", errors="replace").strip()
                            elif _tt == 127 and len(_tv) >= 4:   # Org-specific TLV
                                _oui = bytes(_tv[:3])
                                _sub = _tv[3]
                                if _oui == b'\x00\x80\xc2' and _sub == 1 and len(_tv) >= 6:
                                    _lldp_pvid = (_tv[4] << 8) | _tv[5]   # IEEE 802.1 PVID
                            _lldp_off += _tl
                        if smac not in cdp_lldp:
                            cdp_lldp[smac] = {"hostname": _lldp_hostname, "native_vlan": _lldp_pvid, "protocol": "LLDP"}
                        elif _lldp_hostname:
                            cdp_lldp[smac]["hostname"] = cdp_lldp[smac]["hostname"] or _lldp_hostname
                            if _lldp_pvid is not None:
                                cdp_lldp[smac]["native_vlan"] = _lldp_pvid
                    except Exception:
                        pass
                    continue

                # ── ARP ──────────────────────────────────────────────────────
                if ethertype == 0x0806:
                    # Tally per-VLAN packet/broadcast totals for ARP frames too — ARP
                    # (mostly L2-broadcast requests) dominates real broadcast storms, but
                    # was previously excluded since this branch `continue`s before ever
                    # reaching the IP-only tally below, silently under-counting the
                    # broadcast_storm ratio's numerator and denominator alike.
                    _vlan_arp = vlan_inner if vlan_inner is not None else vlan_outer
                    if _vlan_arp is not None:
                        vlan_pkt_total[_vlan_arp] += 1
                        if dmac == "ff:ff:ff:ff:ff:ff":
                            vlan_pkt_bcast[_vlan_arp] += 1
                    if len(raw) >= l2_off + 28:
                        try:
                            spa = socket.inet_ntoa(raw[l2_off + 14:l2_off + 18])
                            sha = raw[l2_off + 8:l2_off + 14].hex(":")
                            if spa and spa not in ("0.0.0.0", "255.255.255.255"):
                                h = host(spa, sha)
                                h["protocols"].add("ARP")
                                if _vlan_arp is not None:
                                    h["vlan_ids"].add(_vlan_arp)
                                    if pcp is not None:
                                        h["vlan_pcps"].add(pcp)
                                    if is_qinq:
                                        h["vlan_outer_ids"].add(vlan_outer)
                                        h["vlan_qinq"] = True
                                else:
                                    h["vlan_untagged"] = True
                        except Exception:
                            pass
                    continue

                # ── IPv4 / IPv6 ──────────────────────────────────────────────
                if ethertype == 0x0800:
                    if len(raw) < l2_off + 20:
                        continue
                    ihl = (raw[l2_off] & 0x0f) * 4
                    if ihl < 20 or len(raw) < l2_off + ihl:
                        continue
                    ttl = raw[l2_off + 8]
                    proto_num = raw[l2_off + 9]
                    sip = socket.inet_ntoa(raw[l2_off + 12:l2_off + 16])
                    dip = socket.inet_ntoa(raw[l2_off + 16:l2_off + 20])
                    l3_off = l2_off
                    l4_off = l3_off + ihl
                    is_ipv6 = False
                elif ethertype == 0x86DD:
                    if len(raw) < l2_off + 40:
                        continue
                    ttl = raw[l2_off + 7]       # hop limit
                    proto_num = raw[l2_off + 6]  # next header
                    sip = _ipv6_str(raw[l2_off + 8:l2_off + 24])
                    dip = _ipv6_str(raw[l2_off + 24:l2_off + 40])
                    l3_off = l2_off
                    # Walk IPv6 extension headers to reach the transport layer.
                    # Known extension-header types and their length encodings:
                    #   Hop-by-Hop (0), Routing (43), Destination Options (60):
                    #     length = (raw[off+1] + 1) * 8
                    #   Fragment (44): fixed 8 bytes
                    #   AH (51): length = (raw[off+1] + 2) * 4
                    # Any unknown next-header type is treated as transport.
                    _EXT_HDR_TYPES = {0, 43, 44, 51, 60}
                    _off = l2_off + 40   # start of first extension header / transport
                    _nh = proto_num
                    _hops = 0
                    while _nh in _EXT_HDR_TYPES and _hops < 8:
                        if _nh == 44:           # Fragment header: fixed 8 bytes
                            _ext_len = 8
                        elif _nh == 51:         # AH: (hdr ext len + 2) * 4
                            if _off + 2 > len(raw):
                                break
                            _ext_len = (raw[_off + 1] + 2) * 4
                        else:                   # Hop-by-hop, Routing, Destination Options
                            if _off + 2 > len(raw):
                                break
                            _ext_len = (raw[_off + 1] + 1) * 8
                        if _off + _ext_len > len(raw):
                            break
                        _nh = raw[_off]         # next header field is always byte 0
                        _off += _ext_len
                        _hops += 1
                    proto_num = _nh
                    l4_off = _off
                    is_ipv6 = True
                else:
                    continue

                # Cap host table to prevent memory exhaustion from crafted PCAPs
                if len(hosts) >= MAX_HOSTS and sip not in hosts and dip not in hosts:
                    _hosts_truncated = True
                    continue

                plen = meta.wirelen if meta.wirelen > 0 else len(raw)
                rel_t = round(pkt_time - first_pkt_time, 6) if first_pkt_time else 0

                sh = host(sip, smac)
                dh = host(dip, dmac)

                if len(sh["ttl_values"]) < MAX_TTL_VALUES:
                    sh["ttl_values"].append(ttl)
                sh["packet_count"] += 1
                sh["bytes_sent"] += plen
                dh["packet_count"] += 1
                dh["bytes_recv"] += plen

                # broadcast / multicast flags — also treat an L2-broadcast destination MAC
                # as broadcast (catches directed broadcasts on subnets wider than /24,
                # which the IP-suffix heuristic alone misses).
                is_bcast = dip.endswith(".255") or dip == "255.255.255.255" or dmac == "ff:ff:ff:ff:ff:ff"
                if is_bcast:
                    dh["flags"].add("broadcast")
                if dip.startswith(("224.", "225.", "239.")) or dip.startswith("ff"):
                    dh["flags"].add("multicast")

                protocol = "IP"
                conn_key = (sip, dip) if sip <= dip else (dip, sip)  # avoids list alloc + sort

                # Cap connection table to prevent N² memory exhaustion on crafted PCAPs
                if conn_key not in connections and len(connections) >= MAX_CONNECTIONS:
                    _conns_truncated = True
                    continue

                # Update connection timing
                conn = connections[conn_key]
                if conn["first_seen"] is None:
                    conn["first_seen"] = rel_t
                conn["last_seen"] = rel_t
                if conn["abs_first_seen"] is None:
                    conn["abs_first_seen"] = pkt_time
                conn["abs_last_seen"] = pkt_time

                # Track VLAN membership on hosts and connection; tally per-VLAN broadcast stats
                _vlan_id = vlan_inner if vlan_inner is not None else vlan_outer
                if _vlan_id is not None:
                    sh["vlan_ids"].add(_vlan_id)
                    dh["vlan_ids"].add(_vlan_id)
                    conn["vlan_ids"].add(_vlan_id)
                    vlan_pkt_total[_vlan_id] += 1
                    if is_bcast:
                        vlan_pkt_bcast[_vlan_id] += 1
                    if pcp is not None:
                        sh["vlan_pcps"].add(pcp)
                        dh["vlan_pcps"].add(pcp)
                    if is_qinq:
                        sh["vlan_outer_ids"].add(vlan_outer)
                        dh["vlan_outer_ids"].add(vlan_outer)
                        sh["vlan_qinq"] = True
                        dh["vlan_qinq"] = True
                else:
                    sh["vlan_untagged"] = True
                    dh["vlan_untagged"] = True

                # Initialize transport-layer fields — always defined for drill-down
                sport = None
                dport = None
                payload = b""
                tcp_flags = None
                tcp_seq = None
                tcp_ack = None
                tcp_window = None
                tcp_doff_bytes = None
                udp_len = None
                icmp_type = None
                icmp_code = None

                # ── TCP ──────────────────────────────────────────────────────
                if proto_num == 6:
                    if len(raw) >= l4_off + 20:
                        sport = (raw[l4_off] << 8) | raw[l4_off + 1]
                        dport = (raw[l4_off + 2] << 8) | raw[l4_off + 3]
                        tcp_seq        = int.from_bytes(raw[l4_off + 4:l4_off + 8], 'big')
                        tcp_ack        = int.from_bytes(raw[l4_off + 8:l4_off + 12], 'big')
                        tcp_doff_bytes = (raw[l4_off + 12] >> 4) * 4
                        tcp_flags      = raw[l4_off + 13]
                        tcp_window     = (raw[l4_off + 14] << 8) | raw[l4_off + 15]
                        p_off = l4_off + max(tcp_doff_bytes, 20)
                        payload = raw[p_off:] if p_off < len(raw) else b""
                        protocol = "TCP"

                        if dport in PORT_LOOKUP:
                            proto_lbl, svc = PORT_LOOKUP[dport]
                            protocol = proto_lbl
                            dh["dst_ports"].add(dport)
                            dh["services"].add(svc)
                            dh["host_type_hints"][svc] += 1
                        elif sport in PORT_LOOKUP:
                            proto_lbl, svc = PORT_LOOKUP[sport]
                            protocol = proto_lbl
                            sh["dst_ports"].add(sport)
                            sh["services"].add(svc)
                            sh["host_type_hints"][svc] += 1
                        else:
                            dh["dst_ports"].add(dport)

                        conn["dst_ports"].add(dport)

                        # HTTP response file detection
                        if payload and len(files) < MAX_FILES and sport in _CRED_HTTP_PORTS and payload[:5] == b"HTTP/":
                            try:
                                _file_result = _extract_http_file_transfer(
                                    payload, pkt_time=pkt_time, rel_time=rel_t,
                                    src=sip, dst=dip,
                                )
                                if _file_result:
                                    _file_meta, _body_bytes = _file_result
                                    files.append(_file_meta)
                                    _entry_size = len(_body_bytes)
                                    _sha = _file_meta["sha256"]
                                    _filename = _file_meta["filename"]
                                    _mime = _file_meta["mime_type"]
                                    with _file_body_cache_lock:
                                        global _file_body_cache_bytes
                                        if _entry_size <= _FILE_CACHE_MAX_BYTES:
                                            # LRU eviction: drop oldest entries until the new one fits
                                            while _file_body_cache_bytes + _entry_size > _FILE_CACHE_MAX_BYTES and _file_body_cache:
                                                _, _evicted = _file_body_cache.popitem(last=False)
                                                _file_body_cache_bytes -= len(_evicted["body"])
                                            if _sha not in _file_body_cache:
                                                _file_body_cache[_sha] = {
                                                    "body": _body_bytes,
                                                    "filename": _filename,
                                                    "mime": _mime or "application/octet-stream",
                                                }
                                                _file_body_cache_bytes += _entry_size
                                            else:
                                                # Already cached; promote to most-recently-used
                                                _file_body_cache.move_to_end(_sha)
                            except Exception:
                                pass

                # ── UDP ──────────────────────────────────────────────────────
                elif proto_num == 17:
                    if len(raw) >= l4_off + 8:
                        sport = (raw[l4_off] << 8) | raw[l4_off + 1]
                        dport = (raw[l4_off + 2] << 8) | raw[l4_off + 3]
                        udp_len = (raw[l4_off + 4] << 8) | raw[l4_off + 5]
                        payload = raw[l4_off + 8:] if l4_off + 8 < len(raw) else b""
                        protocol = "UDP"

                        if dport in PORT_LOOKUP:
                            proto_lbl, svc = PORT_LOOKUP[dport]
                            protocol = proto_lbl
                            dh["dst_ports"].add(dport)
                            dh["services"].add(svc)
                            dh["host_type_hints"][svc] += 1
                        elif sport in PORT_LOOKUP:
                            proto_lbl, svc = PORT_LOOKUP[sport]
                            protocol = proto_lbl
                            sh["dst_ports"].add(sport)
                            sh["services"].add(svc)
                            sh["host_type_hints"][svc] += 1
                        else:
                            dh["dst_ports"].add(dport)

                        # DNS name extraction — reconstruct DNS layer from payload only for port 53
                        if (dport == 53 or sport == 53) and payload:
                            try:
                                dns = _DNS(payload)
                                if dns.qr == 0 and dns.qdcount > 0 and dns.qd:
                                    qname = dns.qd.qname
                                    if isinstance(qname, bytes):
                                        qname = qname.decode("utf-8", errors="replace")
                                    if len(sh["dns_queries"]) < MAX_DNS_ENTRIES:
                                        sh["dns_queries"].add(qname.rstrip("."))
                                elif dns.qr == 1:
                                    an = dns.an
                                    for _ in range(100):
                                        if not (an and hasattr(an, "type")):
                                            break
                                        if an.type == 1:  # A record
                                            rip = an.rdata
                                            rname = an.rrname
                                            if isinstance(rip, bytes):
                                                rip = ".".join(str(b) for b in rip)
                                            if isinstance(rname, bytes):
                                                rname = rname.decode("utf-8", errors="replace")
                                            rname = rname.rstrip(".")
                                            rip_str = str(rip)
                                            if rip_str in hosts:
                                                if not hosts[rip_str]["hostname"]:
                                                    hosts[rip_str]["hostname"] = rname
                                                if len(hosts[rip_str]["dns_names"]) < MAX_DNS_ENTRIES:
                                                    hosts[rip_str]["dns_names"].add(rname)
                                        an = an.payload if hasattr(an, "payload") else None
                            except Exception:
                                pass

                        conn["dst_ports"].add(dport)

                # ── ICMP ─────────────────────────────────────────────────────
                elif proto_num == 1:
                    protocol = "ICMP"
                    if len(raw) >= l4_off + 2:
                        icmp_type = raw[l4_off]
                        icmp_code = raw[l4_off + 1]

                # ── Credential extraction ─────────────────────────────────────
                if payload and sport is not None and dport is not None and len(credentials) < MAX_CREDS:
                    _cred_rec = None
                    try:
                        # HTTP Basic auth & POST form fields
                        if dport in _CRED_HTTP_PORTS and payload[:5] in (b"GET /", b"POST ", b"PUT /", b"PATCH", b"DELET"):
                            _htxt = payload[:4000].decode("utf-8", errors="replace")
                            _am = _RE_HTTP_BASIC_AUTH.search(_htxt)
                            if _am:
                                _dec = base64.b64decode(_am.group(1) + "==").decode("utf-8", errors="replace")
                                if ":" in _dec:
                                    _u, _p = _dec.split(":", 1)
                                    _cred_rec = {"protocol": "HTTP", "type": "Basic Auth",
                                                 "username": _u[:120], "password": _p[:120]}
                            if not _cred_rec and payload[:5] == b"POST ":
                                _sep_idx = _htxt.find("\r\n\r\n")
                                _sep_sz = 4
                                if _sep_idx == -1:
                                    _sep_idx = _htxt.find("\n\n")
                                    _sep_sz = 2
                                if _sep_idx != -1:
                                    _body_str = _htxt[_sep_idx + _sep_sz:]
                                    _form = parse_qs(_body_str, keep_blank_values=True)
                                    _pw_val = next((_form[k][0][:120] for k in ("password", "passwd", "pwd") if k in _form), None)
                                    if _pw_val:
                                        _user_val = next((_form[k][0][:120] for k in ("username", "user", "login", "email", "name") if k in _form), "")
                                        _cred_rec = {"protocol": "HTTP", "type": "Form POST",
                                                     "username": _user_val, "password": _pw_val}
                        # FTP USER / PASS sequence
                        elif dport == 21 or sport == 21:
                            _ftxt = payload.decode("utf-8", errors="replace").strip()
                            _fcmd = _ftxt.upper()
                            if _fcmd.startswith("USER "):
                                if len(_cred_ftp) < MAX_CRED_STATE_ENTRIES:
                                    _cred_ftp[conn_key] = {"user": _ftxt[5:].strip()[:120]}
                            elif _fcmd.startswith("PASS ") and conn_key in _cred_ftp:
                                _cred_rec = {"protocol": "FTP", "type": "USER/PASS",
                                             "username": _cred_ftp.pop(conn_key)["user"],
                                             "password": _ftxt[5:].strip()[:120]}
                        # SMTP AUTH PLAIN / AUTH LOGIN
                        elif dport in _CRED_SMTP_PORTS or sport in _CRED_SMTP_PORTS:
                            _stxt = payload.decode("utf-8", errors="replace").strip()
                            _m = _RE_SMTP_AUTH_PLAIN.match(_stxt)
                            if _m:
                                _dec = base64.b64decode(_m.group(1) + "==").decode("utf-8", errors="replace")
                                _pts = _dec.split("\x00")
                                if len(_pts) >= 3:
                                    _cred_rec = {"protocol": "SMTP", "type": "AUTH PLAIN",
                                                 "username": _pts[1][:120], "password": _pts[2][:120]}
                            elif _RE_SMTP_AUTH_LOGIN.match(_stxt):
                                if len(_cred_smtp) < MAX_CRED_STATE_ENTRIES:
                                    _cred_smtp[conn_key] = {"phase": "user"}
                            elif conn_key in _cred_smtp:
                                _cs = _cred_smtp[conn_key]
                                if _cs.get("phase") == "user":
                                    _cs["user"] = base64.b64decode(_stxt + "==").decode("utf-8", errors="replace")[:120]
                                    _cs["phase"] = "pass"
                                elif _cs.get("phase") == "pass":
                                    _pw = base64.b64decode(_stxt + "==").decode("utf-8", errors="replace")[:120]
                                    _cred_rec = {"protocol": "SMTP", "type": "AUTH LOGIN",
                                                 "username": _cs.get("user", ""), "password": _pw}
                                    del _cred_smtp[conn_key]
                        # POP3 USER / PASS sequence
                        elif dport in _CRED_POP3_PORTS or sport in _CRED_POP3_PORTS:
                            _ptxt = payload.decode("utf-8", errors="replace").strip()
                            if _ptxt.upper().startswith("USER "):
                                if len(_cred_pop3) < MAX_CRED_STATE_ENTRIES:
                                    _cred_pop3[conn_key] = {"user": _ptxt[5:].strip()[:120]}
                            elif _ptxt.upper().startswith("PASS ") and conn_key in _cred_pop3:
                                _cred_rec = {"protocol": "POP3", "type": "USER/PASS",
                                             "username": _cred_pop3.pop(conn_key)["user"],
                                             "password": _ptxt[5:].strip()[:120]}
                        # IMAP LOGIN command (handles quoted credentials)
                        elif dport in _CRED_IMAP_PORTS or sport in _CRED_IMAP_PORTS:
                            _itxt = payload.decode("utf-8", errors="replace").strip()
                            _im = _RE_IMAP_LOGIN.match(_itxt)
                            if _im:
                                _cred_rec = {"protocol": "IMAP", "type": "LOGIN",
                                             "username": _im.group(1).strip('"')[:120],
                                             "password": _im.group(2).strip('"')[:120]}
                        # LDAP Simple Bind
                        elif dport in _CRED_LDAP_PORTS or sport in _CRED_LDAP_PORTS:
                            if len(payload) > 6 and payload[0] == 0x30:
                                _off = 1
                                _, _off = _ber_len(payload, _off)
                                if _off < len(payload) and payload[_off] == 0x02:
                                    _off += 1
                                    _mid_len, _off = _ber_len(payload, _off)
                                    _off += _mid_len
                                if _off < len(payload) and payload[_off] == 0x60:
                                    _off += 1
                                    _, _off = _ber_len(payload, _off)
                                    if _off < len(payload) and payload[_off] == 0x02:
                                        _off += 1
                                        _vlen, _off = _ber_len(payload, _off)
                                        _off += _vlen
                                    _dn = ""
                                    _ldap_pw = ""
                                    if _off < len(payload) and payload[_off] == 0x04:
                                        _off += 1
                                        _dn_len, _off = _ber_len(payload, _off)
                                        _dn = payload[_off:_off + _dn_len].decode("utf-8", errors="replace")
                                        _off += _dn_len
                                    if _off < len(payload) and payload[_off] == 0x80:
                                        _off += 1
                                        _pw_len, _off = _ber_len(payload, _off)
                                        _ldap_pw = payload[_off:_off + _pw_len].decode("utf-8", errors="replace")
                                    if _dn or _ldap_pw:
                                        _cred_rec = {"protocol": "LDAP", "type": "Simple Bind",
                                                     "username": _dn[:120], "password": _ldap_pw[:120]}
                        # SNMP community string (v1/v2c only)
                        elif dport in _CRED_SNMP_PORTS or sport in _CRED_SNMP_PORTS:
                            if len(payload) > 6 and payload[0] == 0x30:
                                _off = 1
                                _, _off = _ber_len(payload, _off)
                                if _off < len(payload) and payload[_off] == 0x02:
                                    _off += 1
                                    _vlen, _off = _ber_len(payload, _off)
                                    _snmp_ver = payload[_off] if (_vlen >= 1 and _off < len(payload)) else 99
                                    _off += _vlen
                                    if _snmp_ver != 3 and _off < len(payload) and payload[_off] == 0x04:
                                        _off += 1
                                        _clen, _off = _ber_len(payload, _off)
                                        if 0 < _clen <= 120:
                                            _community = payload[_off:_off + _clen].decode("utf-8", errors="replace")
                                            _cred_rec = {"protocol": "SNMP", "type": "Community String",
                                                         "username": _community, "password": ""}
                        # Telnet login (prompt/response state machine)
                        elif dport == _CRED_TELNET_PORT or sport == _CRED_TELNET_PORT:
                            _clean = bytearray()
                            _ti = 0
                            _raw_tel = bytes(payload)
                            while _ti < len(_raw_tel):
                                if _raw_tel[_ti] == 0xFF and _ti + 1 < len(_raw_tel):
                                    _ti += 1
                                    _nb = _raw_tel[_ti]
                                    if _nb == 0xFF:
                                        _clean.append(0xFF)
                                        _ti += 1
                                    elif _nb == 0xFA:
                                        _ti += 1
                                        while _ti + 1 < len(_raw_tel) and not (
                                                _raw_tel[_ti] == 0xFF and _raw_tel[_ti + 1] == 0xF0):
                                            _ti += 1
                                        if _ti + 2 <= len(_raw_tel):
                                            _ti += 2
                                    elif 0xFB <= _nb <= 0xFE:
                                        _ti += 2
                                    else:
                                        _ti += 1
                                else:
                                    _clean.append(_raw_tel[_ti])
                                    _ti += 1
                            _tel_txt = _clean.decode("utf-8", errors="replace")
                            # Guard only the credential-state branch; never skip the
                            # whole packet iteration (that would drop packet/byte counts).
                            if conn_key in _cred_telnet or len(_cred_telnet) < MAX_CRED_STATE_ENTRIES:
                                _tstate = _cred_telnet.setdefault(conn_key, {"phase": None, "buf": "", "user": ""})
                                _tel_lower = _tel_txt.lower()
                                if "login:" in _tel_lower or "username:" in _tel_lower:
                                    _tstate["phase"] = "user"
                                    _tstate["buf"] = ""
                                elif "password:" in _tel_lower:
                                    _tstate["phase"] = "pass"
                                    _tstate["buf"] = ""
                                elif _tstate["phase"] in ("user", "pass"):
                                    _tstate["buf"] = (_tstate["buf"] + _tel_txt)[:256]
                                    if "\n" in _tstate["buf"] or "\r" in _tstate["buf"]:
                                        _val = _tstate["buf"].strip()[:120]
                                        if _tstate["phase"] == "user":
                                            _tstate["user"] = _val
                                            _tstate["phase"] = "pass"
                                            _tstate["buf"] = ""
                                        elif _tstate["phase"] == "pass" and _tstate["user"]:
                                            _cred_rec = {"protocol": "Telnet", "type": "Login",
                                                         "username": _tstate["user"], "password": _val}
                                            del _cred_telnet[conn_key]
                    except Exception:
                        pass
                    if _cred_rec:
                        _cred_rec.update({"time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                          "src": sip, "dst": dip, "dport": dport})
                        _cred_key = (_cred_rec["protocol"], _cred_rec["src"], _cred_rec["dst"],
                                     _cred_rec.get("dport"), _cred_rec.get("username"), _cred_rec.get("password"))
                        if _cred_key not in _cred_seen:
                            _cred_seen.add(_cred_key)
                            credentials.append(_cred_rec)

                sh["protocols"].add(protocol)
                dh["protocols"].add(protocol)

                conn["protocols"].add(protocol)
                conn["packet_count"] += 1
                conn["bytes"] += plen

                # ── Per-packet capture for drill-down ────────────────────────
                if len(packet_store[conn_key]) < MAX_STORED_PER_CONN:
                    try:
                        pd = _build_packet_detail(
                            raw, rel_t, sip, dip, protocol, plen,
                            sport, dport, payload, is_ipv6,
                            tcp_flags, tcp_seq, tcp_ack, tcp_window, tcp_doff_bytes,
                            udp_len, icmp_type, icmp_code,
                            smac, dmac, ttl, l3_off, eth_type,
                        )
                        # Tag packet with its VLAN ID for the per-VLAN timeline
                        _vid = vlan_inner if vlan_inner is not None else vlan_outer
                        if _vid is not None:
                            pd["vlan_id"] = _vid

                        # HTTP parsing
                        if protocol == "HTTP" and payload:
                            pd["http"] = parse_http(payload, protocol)

                        # Modbus TCP parsing
                        if payload and (dport == 502 or sport == 502):
                            mb = parse_modbus(payload)
                            if mb:
                                mb["is_response"] = sport == 502
                                pd["modbus"] = mb
                                if mb.get("unit_id") is not None:
                                    sh["modbus_unit_ids"].add(mb["unit_id"])
                                if mb["is_write"]:
                                    conn["ot_writes"] += 1
                                elif not mb["is_error"]:
                                    conn["ot_reads"] += 1
                                if mb["is_error"]:
                                    conn["ot_errors"] += 1
                                if mb.get("function_code") is not None:
                                    fc_label = f"Modbus:FC{mb['function_code']} {mb.get('function_name', '')}".rstrip()
                                    conn["fc_counts"][fc_label] += 1
                                if len(ot_commands) < MAX_OT_COMMANDS:
                                    _dir = "error" if mb["is_error"] else ("write" if mb["is_write"] else "read")
                                    ot_commands.append({
                                        "time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                        "src": sip, "dst": dip,
                                        "protocol": "Modbus",
                                        "function_code": mb.get("function_code"),
                                        "function_name": mb.get("function_name", ""),
                                        "direction": _dir,
                                        "register": mb.get("register_address"),
                                        "quantity": mb.get("quantity"),
                                        "unit_id": mb.get("unit_id"),
                                    })

                        # MQTT parsing
                        if payload and (dport in (1883, 8883) or sport in (1883, 8883)):
                            mq = parse_mqtt(payload)
                            if mq:
                                pd["mqtt"] = mq

                        # CoAP parsing
                        if payload and (dport in (5683, 5684) or sport in (5683, 5684)):
                            cp = parse_coap(payload)
                            if cp:
                                pd["coap"] = cp

                        # DNP3 parsing
                        if payload and (dport == 20000 or sport == 20000):
                            dn = parse_dnp3(payload)
                            if dn:
                                pd["dnp3"] = dn
                                sh["dnp3_addresses"].add(dn["src_address"])
                                dh["dnp3_addresses"].add(dn["dst_address"])
                                if dn.get("role") == "master":
                                    sh["ot_role"] = "master"
                                    dh["ot_role"] = "outstation"
                                elif dn.get("role") == "outstation":
                                    sh["ot_role"] = "outstation"
                                    dh["ot_role"] = "master"
                                if dn["is_write"]:
                                    conn["ot_writes"] += 1
                                elif not dn["is_error"]:
                                    conn["ot_reads"] += 1
                                if dn["is_error"]:
                                    conn["ot_errors"] += 1
                                if dn.get("function_code") is not None:
                                    fn = dn.get("function_name") or f"FC{dn['function_code']}"
                                    conn["fc_counts"][f"DNP3:{fn}"] += 1
                                if len(ot_commands) < MAX_OT_COMMANDS:
                                    _dir = "error" if dn["is_error"] else ("write" if dn["is_write"] else "read")
                                    ot_commands.append({
                                        "time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                        "src": sip, "dst": dip,
                                        "protocol": "DNP3",
                                        "function_code": dn.get("function_code"),
                                        "function_name": dn.get("function_name", ""),
                                        "direction": _dir,
                                        "register": None,
                                        "quantity": None,
                                        "unit_id": None,
                                        "address": dn.get("dst_address"),
                                        "data_object": dn.get("data_object_group"),
                                    })

                        # S7comm parsing
                        if payload and (dport == 102 or sport == 102):
                            s7 = parse_s7comm(payload)
                            if s7:
                                pd["s7comm"] = s7
                                if s7.get("function_code") == 0x1A:
                                    sh["has_s7_download"] = True
                                if s7["is_write"]:
                                    conn["ot_writes"] += 1
                                elif not s7["is_error"]:
                                    conn["ot_reads"] += 1
                                if s7["is_error"]:
                                    conn["ot_errors"] += 1
                                if s7.get("function_code") is not None:
                                    fn = s7.get("function_name") or hex(s7["function_code"])
                                    conn["fc_counts"][f"S7:{fn}"] += 1
                                if len(ot_commands) < MAX_OT_COMMANDS:
                                    _dir = "error" if s7["is_error"] else ("write" if s7["is_write"] else "read")
                                    ot_commands.append({
                                        "time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                        "src": sip, "dst": dip,
                                        "protocol": "S7comm",
                                        "function_code": s7.get("function_code"),
                                        "function_name": s7.get("function_name", ""),
                                        "direction": _dir,
                                        "register": None,
                                        "quantity": None,
                                        "unit_id": None,
                                    })

                        # EtherNet/IP parsing
                        if payload and (dport in (2222, 44818) or sport in (2222, 44818)):
                            ei = parse_enip(payload)
                            if ei:
                                pd["enip"] = ei
                                if ei.get("cip_service_name"):
                                    conn["fc_counts"][f"EtherNet/IP:{ei['cip_service_name']}"] += 1
                                if len(ot_commands) < MAX_OT_COMMANDS:
                                    _dir = "error" if ei.get("is_error") else ("write" if ei.get("is_write") else "read")
                                    ot_commands.append({
                                        "time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                        "src": sip, "dst": dip,
                                        "protocol": "EtherNet/IP",
                                        "function_code": ei.get("command"),
                                        "function_name": ei.get("cip_service_name") or ei.get("command_name", ""),
                                        "direction": _dir,
                                        "register": None, "quantity": None, "unit_id": None,
                                    })

                        # IEC 60870-5-104 parsing
                        if payload and (dport == 2404 or sport == 2404):
                            ic = parse_iec104(payload)
                            if ic:
                                pd["iec104"] = ic
                                if ic.get("type_name"):
                                    conn["fc_counts"][f"IEC-104:{ic['type_name']}"] += 1
                                if len(ot_commands) < MAX_OT_COMMANDS:
                                    _dir = "write" if ic.get("is_write") else ("read" if ic.get("frame_type") == "I" else "diagnostic")
                                    ot_commands.append({
                                        "time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                        "src": sip, "dst": dip,
                                        "protocol": "IEC-104",
                                        "function_code": ic.get("type_id"),
                                        "function_name": ic.get("type_name", ""),
                                        "direction": _dir,
                                        "register": None, "quantity": None, "unit_id": None,
                                    })

                        # BACnet parsing
                        if payload and (dport == 47808 or sport == 47808):
                            bn = parse_bacnet(payload)
                            if bn:
                                pd["bacnet"] = bn
                                if bn.get("service_name"):
                                    conn["fc_counts"][f"BACnet:{bn['service_name']}"] += 1
                                if len(ot_commands) < MAX_OT_COMMANDS:
                                    if bn.get("is_error"):
                                        _dir = "error"
                                    elif bn.get("is_write"):
                                        _dir = "write"
                                    elif bn.get("service_name") in ("i-Am", "i-Have", "who-Is", "who-Has",
                                                                     "timeSynchronization", "utcTimeSynchronization"):
                                        _dir = "diagnostic"
                                    else:
                                        _dir = "read"
                                    ot_commands.append({
                                        "time": round(pkt_time, 3), "rel_time": round(rel_t, 3),
                                        "src": sip, "dst": dip,
                                        "protocol": "BACnet",
                                        "function_code": bn.get("service_choice"),
                                        "function_name": bn.get("service_name", ""),
                                        "direction": _dir,
                                        "register": None, "quantity": None, "unit_id": None,
                                    })

                        # TLS ClientHello — SNI + JA3 fingerprint
                        if (len(payload) >= 43 and
                                payload[0] == 0x16 and payload[1] == 0x03):
                            tls = parse_tls_client_hello(payload)
                            if tls:
                                pd["tls"] = tls
                                if tls.get("sni"):
                                    sh["tls_sni"].add(tls["sni"])
                                if tls.get("ja3"):
                                    sh["tls_ja3"].add(tls["ja3"])

                        packet_store[conn_key].append(pd)
                    except Exception:
                        parse_errors += 1

    except Exception:
        logger.warning("analyze_pcap failed", exc_info=True)
        return {"error": "Failed to parse PCAP file"}

    # ── CDP/LLDP host enrichment ──────────────────────────────────────────────
    # Correlate CDP/LLDP discoveries (keyed by MAC) with hosts (keyed by IP)
    mac_to_ip = {h["mac"]: ip for ip, h in hosts.items() if h.get("mac")}
    for mac, info in cdp_lldp.items():
        ip = mac_to_ip.get(mac)
        if not ip:
            continue
        h = hosts[ip]
        # Set hostname from CDP/LLDP if not already discovered via DNS/ARP
        if not h.get("hostname") and info.get("hostname"):
            h["hostname"] = info["hostname"]
        # Register native VLAN
        if info.get("native_vlan") is not None:
            h["vlan_ids"].add(info["native_vlan"])
        # Boost "Network Device" hint so this host is classified as a switch/AP
        h["host_type_hints"]["Network Device"] += 5
        h["protocols"].add(info["protocol"])

    # ── Host type classification ──────────────────────────────────────────────
    for ip, h in hosts.items():
        # OS from TTL
        if h["ttl_values"]:
            common_ttl = Counter(h["ttl_values"]).most_common(1)[0][0]
            h["os_hint"] = os_from_ttl(common_ttl)

        # Broadcast / multicast shortcuts
        if "broadcast" in h["flags"] or ip.endswith(".255") or ip == "255.255.255.255":
            h["host_type"] = "Broadcast"
            continue
        if "multicast" in h["flags"] or ip.startswith(("224.", "225.", "239.")):
            h["host_type"] = "Multicast"
            continue

        # Pick best host type: first entry in HOST_TYPE_PRIORITY that was observed
        if h["host_type_hints"]:
            for prio in HOST_TYPE_PRIORITY:
                if prio in h["host_type_hints"]:
                    h["host_type"] = prio
                    break
            else:
                h["host_type"] = h["host_type_hints"].most_common(1)[0][0]
        elif h["os_hint"] == "Windows":
            h["host_type"] = "Windows Host"
        elif h["os_hint"] == "Linux/Unix/macOS":
            h["host_type"] = "Linux Host"
        elif h["os_hint"] == "Network Device":
            h["host_type"] = "Network Device"
        elif not h["is_private"]:
            h["host_type"] = "Internet Host"
        else:
            h["host_type"] = "Unknown Host"

    # ── Engineering Workstation auto-detection ────────────────────────────────
    for ip, h in hosts.items():
        if h.get("has_s7_download") and h["host_type"] not in ("PLC", "Engineering Workstation"):
            h["host_type"] = "Engineering Workstation"

    # ── Anomaly detection ─────────────────────────────────────────────────────
    _anomaly_failed = False
    try:
        anomalies = analyze_anomalies(hosts, connections, packet_store, credentials,
                                      vlan_pkt_total=vlan_pkt_total,
                                      vlan_pkt_bcast=vlan_pkt_bcast)
    except Exception:
        logger.warning("analyze_anomalies failed", exc_info=True)
        anomalies = []
        _anomaly_failed = True

    # ── Per-host risk score (0–100) ───────────────────────────────────────────
    _SEV_WEIGHT = {"high": 30, "medium": 15, "low": 5}
    _OT_WRITE_TYPES = {
        "ot_modbus_write", "ot_dnp3_control", "ot_s7_write", "ot_s7_critical",
        "ot_enip_write", "ot_iec104_command", "ot_bacnet_write", "ot_s7_code_download",
    }
    ip_anomalies = defaultdict(list)
    for a in anomalies:
        if a.get("src"):
            ip_anomalies[a["src"]].append(a)
        if a.get("dst") and a["dst"] != a.get("src"):
            ip_anomalies[a["dst"]].append(a)

    # Build per-IP connection index once — avoids O(hosts × connections) scans below.
    # Each entry: ip → [(peer_ip, conn_dict), ...]
    ip_conns: dict = defaultdict(list)
    for (ca, cb), _cv in connections.items():
        ip_conns[ca].append((cb, _cv))
        ip_conns[cb].append((ca, _cv))

    host_risk = {}
    for ip, h in hosts.items():
        score = 0
        # Anomaly severity contribution (capped at 60)
        score += min(sum(_SEV_WEIGHT.get(a.get("severity", "low"), 5)
                         for a in ip_anomalies[ip]), 60)
        # Cross-zone egress to non-private IP (+15)
        for peer, _ in ip_conns[ip]:
            if not is_private(peer):
                score += 15
                break
        # Suspicious port usage (capped at 20)
        sp_count = sum(
            1 for _, _conn in ip_conns[ip]
            for p in _conn["dst_ports"] if p in SUSPICIOUS_PORTS
        )
        score += min(sp_count * 5, 20)
        # OT device targeted by write command (+10)
        if any(a["type"] in _OT_WRITE_TYPES for a in ip_anomalies[ip]):
            score += 10
        host_risk[ip] = min(score, 100)

    # Attach absolute timestamps to anomalies for the timeline strip
    for a in anomalies:
        src, dst = a.get("src"), a.get("dst")
        key = (src, dst) if src and dst and src != dst and src <= dst else \
              (dst, src) if src and dst and src != dst else None
        conn = connections.get(key) if key else None
        if conn is None and src:
            # src-only anomalies (port_scan, multiunit_poll): use index instead of full scan
            _peers = ip_conns.get(src)
            conn = _peers[0][1] if _peers else None
        a["first_seen"] = conn["abs_first_seen"] if conn else None
        a["last_seen"] = conn["abs_last_seen"] if conn else None

    # ── Serialise ─────────────────────────────────────────────────────────────
    nodes = []
    for ip, h in hosts.items():
        geo = None
        if not h["is_private"]:
            geo = geo_lookup(ip)
        nodes.append({
            "id": ip,
            "ip": ip,
            "mac": h["mac"],
            "mac_vendor": h["mac_vendor"],
            "hostname": h["hostname"],
            "dns_names": sorted(h["dns_names"]),
            "protocols": sorted(h["protocols"]),
            "services": sorted(h["services"]),
            "open_ports": sorted(h["dst_ports"]),
            "os_hint": h["os_hint"],
            "host_type": h["host_type"],
            "packet_count": h["packet_count"],
            "bytes_sent": h["bytes_sent"],
            "bytes_recv": h["bytes_recv"],
            "dns_queries": sorted(h["dns_queries"]),
            "is_private": h["is_private"],
            "flags": list(h["flags"]),
            "geo": geo,
            "ot_role": h.get("ot_role", "unknown"),
            "modbus_unit_ids": sorted(h.get("modbus_unit_ids", set())),
            "dnp3_addresses": sorted(h.get("dnp3_addresses", set())),
            "tls_sni": sorted(h.get("tls_sni", set())),
            "tls_ja3": sorted(h.get("tls_ja3", set())),
            "vlans": sorted(h.get("vlan_ids", set())),
            "vlan_outer": sorted(h.get("vlan_outer_ids", set())),
            "vlan_pcps": sorted(h.get("vlan_pcps", set())),
            "vlan_untagged": bool(h.get("vlan_untagged")),
            "vlan_qinq": bool(h.get("vlan_qinq")),
            "purdue_level": purdue_level_py(
                h["host_type"],
                geo.get("country_code") if geo else None,
                ot_role=h.get("ot_role", "unknown"),
                modbus_unit_ids=h.get("modbus_unit_ids"),
                dnp3_addresses=h.get("dnp3_addresses"),
                is_private=h.get("is_private", True),
            ),
            "risk_score": host_risk.get(ip, 0),
            "ip_version": 6 if ":" in ip else 4,
            "host_type_hints": dict(h["host_type_hints"]),
            "has_s7_download": bool(h.get("has_s7_download", False)),
        })

    edges = []
    for (src, dst), c in connections.items():
        edges.append({
            "source": src,
            "target": dst,
            "protocols": sorted(c["protocols"]),
            "packet_count": c["packet_count"],
            "bytes": c["bytes"],
            "ports": sorted(c["dst_ports"]),
            "first_seen": c["first_seen"],
            "last_seen": c["last_seen"],
            "ot_reads": c.get("ot_reads", 0),
            "ot_writes": c.get("ot_writes", 0),
            "ot_errors": c.get("ot_errors", 0),
            "fc_counts": dict(c.get("fc_counts", {})),
            "vlans": sorted(c.get("vlan_ids", set())),
        })

    all_protocols = sorted({p for n in nodes for p in n["protocols"]})
    all_host_types = sorted({n["host_type"] for n in nodes})
    all_vlans = sorted({v for n in nodes for v in n["vlans"]})

    # ── Build packets output (top 40 connections) ──────────────────────────
    top_conn_keys = sorted(
        connections.keys(),
        key=lambda k: connections[k]["packet_count"],
        reverse=True,
    )[:40]
    packets_out = {}
    for k in top_conn_keys:
        if packet_store[k]:
            packets_out[f"{k[0]}|{k[1]}"] = packet_store[k]

    return {
        "nodes": nodes,
        "edges": edges,
        "packets": packets_out,
        "anomalies": anomalies,
        "anomaly_error": _anomaly_failed,
        "credentials": credentials,
        "files": files,
        "ot_commands": ot_commands,
        "stats": {
            "total_packets": processed,
            "total_hosts": len(nodes),
            "total_connections": len(edges),
            "protocols": all_protocols,
            "host_types": all_host_types,
            "vlans": all_vlans,
            "vlans_detected": len(all_vlans),
            "ip_versions": sorted({n["ip_version"] for n in nodes}),
            "has_untagged": any(n["vlan_untagged"] for n in nodes),
            "ipv4_count": sum(1 for n in nodes if n["ip_version"] == 4),
            "ipv6_count": sum(1 for n in nodes if n["ip_version"] == 6),
            "cdp_lldp_discovered": len(cdp_lldp),
            "truncated": processed >= MAX_PACKETS,
            "hosts_truncated": _hosts_truncated,
            "connections_truncated": _conns_truncated,
            "capture_start": first_pkt_time,
            "capture_end": last_pkt_time,
            "parse_errors": parse_errors,
            "geoip_available": _get_geoip_reader() is not None,
        },
    }


def merge_results(results):
    """Merge multiple analyze_pcap result dicts into one."""
    merged_nodes = {}
    merged_edges = {}
    merged_packets = {}
    merged_anomalies = []
    merged_credentials = []
    merged_files = []
    merged_ot_commands = []
    anomaly_keys = set()
    seen_hashes = set()
    total_packets = 0
    truncated = False
    capture_start = None
    capture_end = None

    for result in results:
        if "error" in result:
            continue
        total_packets += result["stats"]["total_packets"]
        if result["stats"]["truncated"]:
            truncated = True
        cs = result["stats"].get("capture_start")
        ce = result["stats"].get("capture_end")
        if cs is not None:
            capture_start = cs if capture_start is None else min(capture_start, cs)
        if ce is not None:
            capture_end = ce if capture_end is None else max(capture_end, ce)

        # Merge nodes
        for n in result["nodes"]:
            ip = n["ip"]
            if ip not in merged_nodes:
                merged_nodes[ip] = dict(n)
                merged_nodes[ip]["protocols"] = set(n["protocols"])
                merged_nodes[ip]["services"] = set(n["services"])
                merged_nodes[ip]["open_ports"] = set(n["open_ports"])
                merged_nodes[ip]["dns_names"] = set(n["dns_names"])
                merged_nodes[ip]["dns_queries"] = set(n["dns_queries"])
                merged_nodes[ip]["modbus_unit_ids"] = set(n.get("modbus_unit_ids", []))
                merged_nodes[ip]["dnp3_addresses"] = set(n.get("dnp3_addresses", []))
                merged_nodes[ip]["tls_sni"] = set(n.get("tls_sni", []))
                merged_nodes[ip]["tls_ja3"] = set(n.get("tls_ja3", []))
                merged_nodes[ip]["vlans"] = set(n.get("vlans", []))
                merged_nodes[ip]["vlan_outer"] = set(n.get("vlan_outer", []))
                merged_nodes[ip]["vlan_pcps"] = set(n.get("vlan_pcps", []))
                merged_nodes[ip]["vlan_untagged"] = bool(n.get("vlan_untagged"))
                merged_nodes[ip]["vlan_qinq"] = bool(n.get("vlan_qinq"))
                merged_nodes[ip]["host_type_hints"] = Counter(n.get("host_type_hints", {}))
                merged_nodes[ip]["has_s7_download"] = bool(n.get("has_s7_download", False))
                merged_nodes[ip]["flags"] = set(n.get("flags", []))
            else:
                mn = merged_nodes[ip]
                mn["packet_count"] += n["packet_count"]
                mn["bytes_sent"] += n["bytes_sent"]
                mn["bytes_recv"] += n["bytes_recv"]
                mn["protocols"].update(n["protocols"])
                mn["services"].update(n["services"])
                mn["open_ports"].update(n["open_ports"])
                mn["dns_names"].update(n["dns_names"])
                mn["dns_queries"].update(n["dns_queries"])
                mn["modbus_unit_ids"].update(n.get("modbus_unit_ids", []))
                mn["dnp3_addresses"].update(n.get("dnp3_addresses", []))
                mn["tls_sni"].update(n.get("tls_sni", []))
                mn["tls_ja3"].update(n.get("tls_ja3", []))
                mn["vlans"].update(n.get("vlans", []))
                mn["vlan_outer"].update(n.get("vlan_outer", []))
                mn["vlan_pcps"].update(n.get("vlan_pcps", []))
                mn["vlan_untagged"] = mn["vlan_untagged"] or bool(n.get("vlan_untagged"))
                mn["vlan_qinq"] = mn["vlan_qinq"] or bool(n.get("vlan_qinq"))
                mn["host_type_hints"].update(n.get("host_type_hints", {}))
                mn["has_s7_download"] = mn["has_s7_download"] or bool(n.get("has_s7_download", False))
                mn["flags"].update(n.get("flags", []))
                if not mn["hostname"] and n["hostname"]:
                    mn["hostname"] = n["hostname"]
                if not mn["geo"] and n.get("geo"):
                    mn["geo"] = n["geo"]
                if mn.get("ot_role", "unknown") == "unknown" and n.get("ot_role", "unknown") != "unknown":
                    mn["ot_role"] = n["ot_role"]
                mn["risk_score"] = max(mn.get("risk_score", 0), n.get("risk_score", 0))

        # Merge edges
        for e in result["edges"]:
            key = tuple(sorted([e["source"], e["target"]]))
            if key not in merged_edges:
                merged_edges[key] = {
                    "source": key[0],
                    "target": key[1],
                    "protocols": set(e["protocols"]),
                    "packet_count": e["packet_count"],
                    "bytes": e["bytes"],
                    "ports": set(e["ports"]),
                    "first_seen": e.get("first_seen"),
                    "last_seen": e.get("last_seen"),
                    "ot_reads": e.get("ot_reads", 0),
                    "ot_writes": e.get("ot_writes", 0),
                    "ot_errors": e.get("ot_errors", 0),
                    "fc_counts": dict(e.get("fc_counts", {})),
                    "vlans": set(e.get("vlans", [])),
                }
            else:
                me = merged_edges[key]
                me["packet_count"] += e["packet_count"]
                me["bytes"] += e["bytes"]
                me["protocols"].update(e["protocols"])
                me["ports"].update(e["ports"])
                me["ot_reads"] += e.get("ot_reads", 0)
                me["ot_writes"] += e.get("ot_writes", 0)
                me["ot_errors"] += e.get("ot_errors", 0)
                for k, v in e.get("fc_counts", {}).items():
                    me["fc_counts"][k] = me["fc_counts"].get(k, 0) + v
                me.setdefault("vlans", set()).update(e.get("vlans", []))
                if e.get("first_seen") is not None:
                    if me["first_seen"] is None or e["first_seen"] < me["first_seen"]:
                        me["first_seen"] = e["first_seen"]
                if e.get("last_seen") is not None:
                    if me["last_seen"] is None or e["last_seen"] > me["last_seen"]:
                        me["last_seen"] = e["last_seen"]

        # Merge packets
        for conn_key, pkts in result["packets"].items():
            if conn_key not in merged_packets:
                merged_packets[conn_key] = pkts[:50]
            else:
                existing = merged_packets[conn_key]
                remaining = 50 - len(existing)
                if remaining > 0:
                    merged_packets[conn_key] = existing + pkts[:remaining]

        # Merge anomalies (deduplicate by type+src+dst+description)
        for a in result.get("anomalies", []):
            akey = (a["type"], a["src"], a["dst"], a.get("description", ""))
            if akey not in anomaly_keys:
                anomaly_keys.add(akey)
                merged_anomalies.append(a)

        # Merge credentials (cap at 2000 total)
        remaining_creds = 2000 - len(merged_credentials)
        if remaining_creds > 0:
            merged_credentials.extend(result.get("credentials", [])[:remaining_creds])

        # Merge files (cap at 500 total, deduplicate by sha256)
        for _f in result.get("files", []):
            if len(merged_files) >= 500:
                break
            if _f["sha256"] not in seen_hashes:
                merged_files.append(_f)
                seen_hashes.add(_f["sha256"])

        # Merge OT commands (cap at 10000)
        remaining_ot = 10_000 - len(merged_ot_commands)
        if remaining_ot > 0:
            merged_ot_commands.extend(result.get("ot_commands", [])[:remaining_ot])

    # Serialize merged nodes
    nodes_out = []
    # Re-classify host types using merged hints (priority list wins over frequency)
    for ip, mn in merged_nodes.items():
        hints = mn.get("host_type_hints")
        if hints:
            for prio in HOST_TYPE_PRIORITY:
                if prio in hints:
                    mn["host_type"] = prio
                    break
            else:
                mn["host_type"] = hints.most_common(1)[0][0]
        if mn.get("has_s7_download") and mn["host_type"] not in ("PLC", "Engineering Workstation"):
            mn["host_type"] = "Engineering Workstation"

    for ip, mn in merged_nodes.items():
        nodes_out.append({
            "id": ip,
            "ip": ip,
            "mac": mn["mac"],
            "mac_vendor": mn["mac_vendor"],
            "hostname": mn["hostname"],
            "dns_names": sorted(mn["dns_names"]),
            "protocols": sorted(mn["protocols"]),
            "services": sorted(mn["services"]),
            "open_ports": sorted(mn["open_ports"]),
            "os_hint": mn["os_hint"],
            "host_type": mn["host_type"],
            "packet_count": mn["packet_count"],
            "bytes_sent": mn["bytes_sent"],
            "bytes_recv": mn["bytes_recv"],
            "dns_queries": sorted(mn["dns_queries"]),
            "is_private": mn["is_private"],
            "flags": list(mn.get("flags", [])),
            "geo": mn.get("geo"),
            "ot_role": mn.get("ot_role", "unknown"),
            "modbus_unit_ids": sorted(mn.get("modbus_unit_ids", set())),
            "dnp3_addresses": sorted(mn.get("dnp3_addresses", set())),
            "tls_sni": sorted(mn.get("tls_sni", set())),
            "tls_ja3": sorted(mn.get("tls_ja3", set())),
            "vlans": sorted(mn.get("vlans", set())),
            "vlan_outer": sorted(mn.get("vlan_outer", set())),
            "vlan_pcps": sorted(mn.get("vlan_pcps", set())),
            "vlan_untagged": bool(mn.get("vlan_untagged")),
            "vlan_qinq": bool(mn.get("vlan_qinq")),
            "purdue_level": purdue_level_py(
                mn["host_type"],
                mn.get("geo", {}).get("country_code") if mn.get("geo") else None,
                ot_role=mn.get("ot_role", "unknown"),
                modbus_unit_ids=mn.get("modbus_unit_ids"),
                dnp3_addresses=mn.get("dnp3_addresses"),
                is_private=mn.get("is_private", True),
            ),
            "risk_score": mn.get("risk_score", 0),
            "ip_version": 6 if ":" in ip else 4,
            "host_type_hints": dict(mn.get("host_type_hints", {})),
            "has_s7_download": bool(mn.get("has_s7_download", False)),
        })

    edges_out = []
    for key, me in merged_edges.items():
        edges_out.append({
            "source": me["source"],
            "target": me["target"],
            "protocols": sorted(me["protocols"]),
            "packet_count": me["packet_count"],
            "bytes": me["bytes"],
            "ports": sorted(me["ports"]),
            "first_seen": me.get("first_seen"),
            "last_seen": me.get("last_seen"),
            "ot_reads": me.get("ot_reads", 0),
            "ot_writes": me.get("ot_writes", 0),
            "ot_errors": me.get("ot_errors", 0),
            "fc_counts": me.get("fc_counts", {}),
            "vlans": sorted(me.get("vlans", set())),
        })

    all_protocols = sorted({p for n in nodes_out for p in n["protocols"]})
    all_host_types = sorted({n["host_type"] for n in nodes_out})
    all_vlans = sorted({v for n in nodes_out for v in n["vlans"]})

    return {
        "nodes": nodes_out,
        "edges": edges_out,
        "packets": merged_packets,
        "anomalies": merged_anomalies,
        "anomaly_error": any(r.get("anomaly_error") for r in results if "error" not in r),
        "credentials": merged_credentials,
        "files": merged_files,
        "ot_commands": merged_ot_commands,
        "stats": {
            "total_packets": total_packets,
            "total_hosts": len(nodes_out),
            "total_connections": len(edges_out),
            "protocols": all_protocols,
            "host_types": all_host_types,
            "vlans": all_vlans,
            "vlans_detected": len(all_vlans),
            "ip_versions": sorted({n["ip_version"] for n in nodes_out}),
            "has_untagged": any(n.get("vlan_untagged") for n in nodes_out),
            "ipv4_count": sum(1 for n in nodes_out if n["ip_version"] == 4),
            "ipv6_count": sum(1 for n in nodes_out if n["ip_version"] == 6),
            "truncated": truncated,
            "hosts_truncated": any(r.get("stats", {}).get("hosts_truncated") for r in results if "error" not in r),
            "connections_truncated": any(r.get("stats", {}).get("connections_truncated") for r in results if "error" not in r),
            "parse_errors": sum(r.get("stats", {}).get("parse_errors", 0) for r in results if "error" not in r),
            "geoip_available": _get_geoip_reader() is not None,
            "cdp_lldp_discovered": sum(r.get("stats", {}).get("cdp_lldp_discovered", 0) for r in results if "error" not in r),
            "gpu": GPU_AVAILABLE,
            "capture_start": capture_start,
            "capture_end": capture_end,
        },
    }


# ── Security headers ──────────────────────────────────────────────────────────

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"error": "Upload too large. Maximum total size is 1 GB."}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found."}), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.exception("Unhandled 500 error")
    return jsonify({"error": "Internal server error."}), 500


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    files = request.files.getlist("file")
    if not files:
        single = request.files.get("file")
        files = [single] if single else []
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No file provided"}), 400

    files = [f for f in files if f.filename]
    if len(files) > MAX_UPLOAD_FILES:
        return jsonify({"error": f"Too many files. Upload at most {MAX_UPLOAD_FILES} at a time."}), 400

    results = []
    tmp_paths = []
    file_names = []
    try:
        for f in files:
            if not allowed_file(f.filename, f.stream):
                return jsonify({"error": f"Unsupported file type: {f.filename}. Upload .pcap, .pcapng, or .cap files."}), 400
            parts = f.filename.rsplit(".", 1)
            ext = parts[-1].lower() if len(parts) == 2 else ""
            if ext not in ALLOWED_EXTENSIONS:
                ext = "pcap"
            tmp = tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False)
            tmp.close()
            tmp_paths.append(tmp.name)  # register before save so cleanup always runs
            file_names.append(f.filename)
            f.save(tmp.name)

        ex = _get_executor()
        futures = [ex.submit(analyze_pcap, p) for p in tmp_paths]
        results = []
        for i, fut in enumerate(futures):
            try:
                results.append(fut.result(timeout=_UPLOAD_TASK_TIMEOUT))
            except FutureTimeoutError:
                # The thread cannot be force-killed (Python limitation); process
                # isolation (ProcessPoolExecutor) would be needed for hard
                # cancellation. Cancel any queued futures that haven't started yet
                # to avoid starving the shared worker pool.
                logger.warning(
                    "analyze_pcap task exceeded %ds timeout; cancelling remaining queued tasks",
                    _UPLOAD_TASK_TIMEOUT,
                )
                for remaining in futures[i + 1:]:
                    remaining.cancel()
                results.append({"error": "Failed to parse PCAP file (parse timed out)"})
            except Exception:
                logger.warning("analyze_pcap task failed", exc_info=True)
                results.append({"error": "Failed to parse PCAP file"})

        if not results:
            return jsonify({"error": "No valid files processed"}), 400

        # Check for errors — if all files failed return an error; if some failed, merge the rest with warnings
        file_warnings = [
            f"Could not parse '{n}': {r['error']}"
            for n, r in zip(file_names, results)
            if "error" in r
        ]
        valid_results = [r for r in results if "error" not in r]
        if not valid_results:
            return jsonify({"error": file_warnings[0] if file_warnings else "No valid files processed"}), 400

        result = merge_results(valid_results)
        result["warnings"] = file_warnings
        return jsonify(result)
    finally:
        for path in tmp_paths:
            try:
                os.unlink(path)
            except OSError:
                pass


@app.route("/download/<sha256>")
def download_file(sha256):
    """Serve a captured file body from the in-memory cache by its SHA-256 hash."""
    if not re.match(r'^[0-9a-f]{64}$', sha256):
        return jsonify({"error": "Invalid hash"}), 400
    with _file_body_cache_lock:
        entry = _file_body_cache.get(sha256)
        if entry is not None:
            _file_body_cache.move_to_end(sha256)  # promote to most-recently-used
    if entry is None:
        return jsonify({"error": "File not in cache. Re-upload the PCAP to download."}), 404
    safe_fn = secure_filename(entry["filename"]) or f"transfer_{sha256[:8]}"
    resp = make_response(entry["body"])
    resp.headers["Content-Type"] = entry["mime"]
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_fn}"'
    resp.headers["Content-Length"] = str(len(entry["body"]))
    return resp


@app.route("/gpu-status")
def gpu_status():
    info = {"gpu": GPU_AVAILABLE}
    if GPU_AVAILABLE:
        try:
            dev = _xp.cuda.Device(0)
            info["device"] = dev.attributes.get("DeviceName", "CUDA GPU")
            info["memory_mb"] = dev.mem_info[1] // (1024 * 1024)
        except Exception:
            pass
    return jsonify(info)


@app.route("/session-schema")
def session_schema():
    return jsonify({"status": "ok", "note": "Sessions are handled client-side only."})


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PCAP Network Visualizer")
    parser.add_argument(
        "--public",
        action="store_true",
        help="Bind to 0.0.0.0 so the app is reachable from other devices on the network. "
             "Default is 127.0.0.1 (localhost only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="HTTP port to listen on (default: 5000).",
    )
    args = parser.parse_args()
    host = "0.0.0.0" if args.public else "127.0.0.1"
    if args.public:
        print(
            "\n"
            "  WARNING: --public binds the Werkzeug development server to 0.0.0.0.\n"
            "  This server is NOT hardened for production use. Anyone on your network\n"
            "  can upload arbitrary files to this process.\n"
            "  For production/LAN use, run behind gunicorn:\n"
            "    gunicorn -w 2 -b 0.0.0.0:5000 'app:app'\n",
            flush=True,
        )
    app.run(debug=False, host=host, port=args.port)
