"""The tshark fields the engine extracts, grouped by purpose.

Fields are requested with ``-T ek -e <field>``; EK output names replace '.' with '_'.
Fields unknown to the installed tshark are dropped at startup (see tshark_env.py), so
older Wireshark versions degrade gracefully instead of failing.
"""

CORE = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "eth.src.oui_resolved",
    "sll.src.eth",
    "vlan.id",
    "vlan.priority",
    "vlan.dei",
    "ieee8021ad.id",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.proto",
    "ip.flags.mf",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.hlim",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.len",
    "tcp.seq_raw",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "icmp.type",
    "icmpv6.type",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "_ws.malformed",
]

NAMES = [
    "dns.flags.response",
    "dns.qry.name",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "dhcp.option.hostname",
    "dhcp.option.vendor_class_id",
    "dhcp.hw.mac_addr",
    "nbns.name",
    "lldp.tlv.system.name",
    "lldp.tlv.system.desc",
    "lldp.port.id",
    "cdp.deviceid",
    "cdp.platform",
    "cdp.software_version",
    "cdp.native_vlan",
]

TLS = ["tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja3", "tls.handshake.ja4"]

HTTP = [
    "http.request.method",
    "http.request.uri",
    "http.host",
    "http.user_agent",
    "http.server",
    "http.response.code",
    "http.content_type",
    "http.authorization",
    "http.request.full_uri",
]

OT = [
    # Modbus/TCP
    "mbtcp.unit_id",
    "mbtcp.trans_id",
    "modbus.func_code",
    "modbus.reference_num",
    "modbus.word_cnt",
    "modbus.bit_cnt",
    "modbus.exception_code",
    "modbus.request_frame",
    # DNP3
    "dnp3.src",
    "dnp3.dst",
    "dnp3.al.func",
    "dnp3.ctl.dir",
    "dnp3.ctl.prm",
    # S7comm
    "s7comm.header.rosctr",
    "s7comm.param.func",
    "s7comm.param.userdata.funcgroup",
    "s7comm.param.userdata.subfunc",
    "s7comm.data.userdata.szl_id",
    "s7comm.param.blockcontrol.filename",
    "s7comm.header.errcls",
    "s7comm.header.errcod",
    # EtherNet/IP + CIP
    "enip.command",
    "enip.lir.vendor",
    "enip.lir.devtype",
    "enip.lir.prodcode",
    "enip.lir.serial",
    "enip.lir.name",
    "enip.lir.revision",
    "cip.sc",
    "cip.class",
    "cip.symbol",
    "cip.genstat",
    "cip.rr",
    # IEC 60870-5-104
    "iec60870_104.type",
    "iec60870_asdu.typeid",
    "iec60870_asdu.causetx",
    "iec60870_asdu.addr",
    # BACnet
    "bvlc.function",
    "bacapp.type",
    "bacapp.confirmed_service",
    "bacapp.unconfirmed_service",
    "bacapp.vendor_identifier",
    "bacapp.instance_number",
]

IOT = [
    "mqtt.msgtype",
    "mqtt.topic",
    "mqtt.clientid",
    "mqtt.username",
    "mqtt.passwd",
    "mqtt.qos",
    "coap.type",
    "coap.code",
    "coap.opt.uri_path",
]

CREDENTIALS = [
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "telnet.data",
    "pop.request.command",
    "pop.request.parameter",
    "smtp.req.command",
    "smtp.auth.username",
    "smtp.auth.password",
]

# Detail fields for OT errors/identity, credentials, and file-name linking.
DETAIL = [
    "s7comm.data.blockcontrol.block_type",
    "dnp3.al.iin",
    "iec60870_asdu.nega",
    "bacapp.objectType",
    "http.authbasic",
    "http.request_in",
    "http.content_length",
    "urlencoded-form.key",
    "urlencoded-form.value",
    "snmp.community",
    "imap.request.command",
    "imap.request.username",
    "imap.request.password",
]

ALL_FIELDS: list[str] = list(dict.fromkeys(CORE + NAMES + TLS + HTTP + OT + IOT + CREDENTIALS + DETAIL))


def ek_name(field: str) -> str:
    return field.replace(".", "_")
