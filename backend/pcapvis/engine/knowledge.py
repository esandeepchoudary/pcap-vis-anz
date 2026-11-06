"""Domain knowledge: ports, protocol labels, host types, Purdue levels, OS hints.

Ported from the legacy app (v1) and extended. Keep tables here, logic elsewhere.
"""

import ipaddress
from functools import lru_cache

# Port → (protocol label, host type suggested for the host *serving* that port)
PORT_MAP: dict[int, tuple[str, str]] = {
    20: ("FTP-Data", "FTP Server"),
    21: ("FTP", "FTP Server"),
    22: ("SSH", "SSH Server"),
    23: ("Telnet", "Telnet Server"),
    25: ("SMTP", "Mail Server"),
    53: ("DNS", "DNS Server"),
    67: ("DHCP", "DHCP Server"),
    68: ("DHCP", "DHCP Client"),
    80: ("HTTP", "Web Server"),
    110: ("POP3", "Mail Server"),
    119: ("NNTP", "News Server"),
    123: ("NTP", "NTP Server"),
    137: ("NetBIOS-NS", "Windows Host"),
    138: ("NetBIOS-DGM", "Windows Host"),
    139: ("NetBIOS-SSN", "Windows Host"),
    143: ("IMAP", "Mail Server"),
    161: ("SNMP", "Network Device"),
    162: ("SNMP-Trap", "Network Device"),
    179: ("BGP", "Router"),
    389: ("LDAP", "Directory Server"),
    443: ("HTTPS", "Web Server"),
    445: ("SMB", "Windows Host"),
    465: ("SMTPS", "Mail Server"),
    514: ("Syslog", "Log Server"),
    587: ("SMTP", "Mail Server"),
    631: ("IPP", "Print Server"),
    636: ("LDAPS", "Directory Server"),
    993: ("IMAPS", "Mail Server"),
    995: ("POP3S", "Mail Server"),
    1433: ("MSSQL", "Database Server"),
    1521: ("Oracle-DB", "Database Server"),
    2375: ("Docker", "Container Host"),
    2376: ("Docker-TLS", "Container Host"),
    3306: ("MySQL", "Database Server"),
    3389: ("RDP", "Windows Host"),
    4444: ("Metasploit", "Security Tool"),
    5432: ("PostgreSQL", "Database Server"),
    5900: ("VNC", "Remote Desktop"),
    5985: ("WinRM", "Windows Host"),
    5986: ("WinRM-S", "Windows Host"),
    6379: ("Redis", "Cache Server"),
    6443: ("K8s-API", "Container Host"),
    8080: ("HTTP", "Web Server"),
    8443: ("HTTPS", "Web Server"),
    8888: ("HTTP", "Web Server"),
    9200: ("Elasticsearch", "Search Server"),
    27017: ("MongoDB", "Database Server"),
    500: ("IKE/IPsec", "VPN Gateway"),
    1194: ("OpenVPN", "VPN Gateway"),
    1723: ("PPTP", "VPN Gateway"),
    4500: ("IPsec-NAT", "VPN Gateway"),
    5353: ("mDNS", "Discovery"),
    1900: ("SSDP", "Discovery"),
    5355: ("LLMNR", "Windows Host"),
    # OT/ICS
    502: ("Modbus", "PLC"),
    2222: ("EtherNet/IP", "PLC"),
    44818: ("EtherNet/IP", "PLC"),
    102: ("S7comm", "PLC"),
    20000: ("DNP3", "RTU"),
    2404: ("IEC-104", "IED"),
    47808: ("BACnet", "Building Controller"),
    4840: ("OPC-UA", "SCADA Server"),
    1883: ("MQTT", "IoT Gateway"),
    8883: ("MQTT-TLS", "IoT Gateway"),
    34964: ("PROFINET", "PLC"),
    5094: ("HART-IP", "Field Device"),
    18245: ("GE-SRTP", "PLC"),
    18246: ("GE-SRTP", "PLC"),
    9600: ("OMRON-FINS", "PLC"),
    4000: ("Emerson-DeltaV", "DCS"),
    1541: ("Foxboro", "DCS"),
    # IoT
    5683: ("CoAP", "IoT Sensor"),
    5684: ("CoAP-DTLS", "IoT Sensor"),
    5672: ("AMQP", "IoT Gateway"),
    5671: ("AMQPS", "IoT Gateway"),
    5222: ("XMPP", "Smart Home Hub"),
    5223: ("XMPP-TLS", "Smart Home Hub"),
    554: ("RTSP", "IP Camera"),
    8554: ("RTSP", "IP Camera"),
    8000: ("Hikvision", "IP Camera"),
    37777: ("Dahua", "IP Camera"),
    5540: ("Matter", "Smart Home Hub"),
    3702: ("WS-Discovery", "IoT Gateway"),
    7547: ("TR-069", "CPE Device"),
    6668: ("Tuya-IoT", "Smart Home Hub"),
    9119: ("XIMSS", "Smart Home Hub"),
    1026: ("CAP", "Smart Meter"),
    4059: ("DLMS", "Smart Meter"),
}

# tshark protocol name (from frame.protocols) → (our label, host type for the server side).
# When tshark positively identifies one of these, it wins over the port table:
# that's how Modbus on port 5020 or HTTP on 9000 get labelled correctly.
TSHARK_PROTOCOLS: dict[str, tuple[str, str | None]] = {
    "modbus": ("Modbus", "PLC"),
    "mbtcp": ("Modbus", "PLC"),
    "dnp3": ("DNP3", "RTU"),
    "s7comm": ("S7comm", "PLC"),
    "s7comm_plus": ("S7comm-Plus", "PLC"),
    "enip": ("EtherNet/IP", "PLC"),
    "cip": ("EtherNet/IP", "PLC"),
    "cipcm": ("EtherNet/IP", "PLC"),
    "iec60870_104": ("IEC-104", "IED"),
    "iec60870_asdu": ("IEC-104", "IED"),
    "bvlc": ("BACnet", "Building Controller"),
    "bacnet": ("BACnet", "Building Controller"),
    "bacapp": ("BACnet", "Building Controller"),
    "opcua": ("OPC-UA", "SCADA Server"),
    "pn_io": ("PROFINET", "PLC"),
    "pn_dcp": ("PROFINET", "PLC"),
    "hartip": ("HART-IP", "Field Device"),
    "omron": ("OMRON-FINS", "PLC"),
    "gesrtp": ("GE-SRTP", "PLC"),
    "mms": ("IEC-61850-MMS", "IED"),
    "goose": ("IEC-61850-GOOSE", "IED"),
    "mqtt": ("MQTT", "IoT Gateway"),
    "coap": ("CoAP", "IoT Sensor"),
    "amqp": ("AMQP", "IoT Gateway"),
    "rtsp": ("RTSP", "IP Camera"),
    "http": ("HTTP", "Web Server"),
    "tls": ("TLS", None),
    "ssh": ("SSH", "SSH Server"),
    "dns": ("DNS", "DNS Server"),
    "mdns": ("mDNS", "Discovery"),
    "llmnr": ("LLMNR", "Windows Host"),
    "ftp": ("FTP", "FTP Server"),
    "ftp-data": ("FTP-Data", "FTP Server"),
    "telnet": ("Telnet", "Telnet Server"),
    "smtp": ("SMTP", "Mail Server"),
    "pop": ("POP3", "Mail Server"),
    "imap": ("IMAP", "Mail Server"),
    "rdp": ("RDP", "Windows Host"),
    "smb": ("SMB", "Windows Host"),
    "smb2": ("SMB", "Windows Host"),
    "nbns": ("NetBIOS-NS", "Windows Host"),
    "nbss": ("NetBIOS-SSN", "Windows Host"),
    "ldap": ("LDAP", "Directory Server"),
    "kerberos": ("Kerberos", "Directory Server"),
    "snmp": ("SNMP", "Network Device"),
    "ntp": ("NTP", "NTP Server"),
    "dhcp": ("DHCP", "DHCP Server"),
    "syslog": ("Syslog", "Log Server"),
    "bgp": ("BGP", "Router"),
    "ssdp": ("SSDP", "Discovery"),
    "vnc": ("VNC", "Remote Desktop"),
    "mysql": ("MySQL", "Database Server"),
    "pgsql": ("PostgreSQL", "Database Server"),
    "tds": ("MSSQL", "Database Server"),
    "sip": ("SIP", None),
    "quic": ("QUIC", None),
}
# Our protocol label → host type for the side serving it (first definition wins).
SERVER_TYPE_BY_LABEL: dict[str, str] = {}
for _label, _stype in TSHARK_PROTOCOLS.values():
    if _stype:
        SERVER_TYPE_BY_LABEL.setdefault(_label, _stype)

# TLS label depends on the port: HTTPS on web ports, otherwise the port's TLS label or "TLS".
TLS_WEB_PORTS = {443, 8443}

# Order of preference when several host types are suggested (first match wins).
HOST_TYPE_PRIORITY = [
    "PLC",
    "RTU",
    "IED",
    "HMI",
    "SCADA Server",
    "DCS",
    "Historian",
    "Engineering Workstation",
    "Building Controller",
    "IoT Gateway",
    "Field Device",
    "IP Camera",
    "Smart Home Hub",
    "Smart Meter",
    "IoT Sensor",
    "Smart Speaker",
    "CPE Device",
    "Router",
    "VPN Gateway",
    "Network Device",
    "DNS Server",
    "DHCP Server",
    "Web Server",
    "Mail Server",
    "Database Server",
    "SSH Server",
    "FTP Server",
    "Telnet Server",
    "Windows Host",
    "Directory Server",
    "Container Host",
    "Cache Server",
    "Search Server",
    "Log Server",
    "NTP Server",
    "Print Server",
    "Security Tool",
    "Remote Desktop",
]
_PRIORITY_RANK = {t: i for i, t in enumerate(HOST_TYPE_PRIORITY)}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 6668}

# Device protocols whose peers both use the well-known UDP port, so *both* ends are devices speaking it
# (a BACnet controller talking to another, a CoAP sensor posting to a gateway). Generic OS chatter such as
# NetBIOS (137↔137) is deliberately excluded: it says little about what the device is.
SYMMETRIC_PEER_PROTOCOLS = {"BACnet", "CoAP", "DNP3"}

OT_PROTOCOLS = {
    "Modbus",
    "DNP3",
    "S7comm",
    "S7comm-Plus",
    "EtherNet/IP",
    "IEC-104",
    "BACnet",
    "OPC-UA",
    "PROFINET",
    "HART-IP",
    "OMRON-FINS",
    "GE-SRTP",
    "IEC-61850-MMS",
    "IEC-61850-GOOSE",
    "Emerson-DeltaV",
    "Foxboro",
}

PURDUE_LEVELS: dict[str, float] = {}
for _t in (
    "Windows Host",
    "Web Server",
    "Mail Server",
    "Directory Server",
    "Database Server",
    "Router",
    "Network Device",
    "DNS Server",
    "DHCP Server",
    "DHCP Client",
    "NTP Server",
    "SSH Server",
    "FTP Server",
    "Telnet Server",
    "Container Host",
    "Log Server",
    "Print Server",
    "Cache Server",
    "Search Server",
    "IoT Gateway",
    "Smart Home Hub",
    "Smart Speaker",
    "CPE Device",
    "Discovery",
):
    PURDUE_LEVELS[_t] = 4
for _t in ("VPN Gateway", "Security Tool", "Remote Desktop"):
    PURDUE_LEVELS[_t] = 3.5
for _t in ("SCADA Server", "Historian", "Engineering Workstation"):
    PURDUE_LEVELS[_t] = 3
for _t in ("HMI", "DCS"):
    PURDUE_LEVELS[_t] = 2
for _t in ("PLC", "RTU", "IED", "Building Controller", "IP Camera"):
    PURDUE_LEVELS[_t] = 1
for _t in ("Field Device", "IoT Sensor", "Smart Meter"):
    PURDUE_LEVELS[_t] = 0


def priority_rank(host_type: str) -> int:
    return _PRIORITY_RANK.get(host_type, len(HOST_TYPE_PRIORITY))


def os_from_ttl(ttl: int) -> str:
    """Initial-TTL heuristic: 64 Linux/Unix/macOS, 128 Windows, 255 network gear."""
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    return "Network Device"


# Address space treated as "inside the site". Everything else is internet (Purdue L6).
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",  # RFC 1918
        "100.64.0.0/10",  # carrier-grade NAT, common on OT WANs
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",  # loopback, link-local, "this network"
        "::1/128",
        "fe80::/10",
        "fc00::/7",
        "::/128",  # IPv6 loopback, link-local, ULA, unspecified
    )
)


@lru_cache(maxsize=65536)
def ip_info(ip: str) -> tuple[int, bool, bool]:
    """(version, is_private, is_multicast). Multicast and broadcast count as private (local scope)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (6 if ":" in ip else 4, True, False)
    if addr.is_multicast or ip == "255.255.255.255":
        return (addr.version, True, addr.is_multicast)
    return (addr.version, any(addr in net for net in PRIVATE_NETWORKS), False)


def is_ephemeral(port: int) -> bool:
    return port >= 49152 or (32768 <= port < 49152 and port not in PORT_MAP)
