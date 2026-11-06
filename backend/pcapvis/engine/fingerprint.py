"""Passive device fingerprinting: identity a device reveals about itself in protocol responses (M5).

Each extractor reads tshark fields from one packet and returns identity attributes for the *sender*
(the device answering), namespaced by source (``s7_``, ``modbus_``, ``pn_``, ``snmp_``…). Device-type
hints are derived afterwards from a host's complete identity (``type_hints``), so the result doesn't depend
on packet order or partitioning. Values come from untrusted traffic: they are cleaned and length-capped.
Vendor and device-type names come from Wireshark's own tables (``env.name``), never hand-written lists.
"""

import re
from dataclasses import dataclass, field

from pcapvis.engine.model import Evidence
from pcapvis.engine.packet import Packet

MAX_VALUE = 200
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

# tshark dissector names (frame.protocols) that may carry identity.
FINGERPRINT_DISSECTORS = {"modbus", "s7comm", "pn_dcp", "cip", "enip", "snmp", "bacapp"}

MODBUS_OBJECTS = {
    0: "modbus_vendor",
    1: "modbus_product_code",
    2: "modbus_revision",
    3: "modbus_vendor_url",
    4: "modbus_product",
    5: "modbus_model",
    6: "modbus_app_name",
}
S7_SZL_1C = {
    "s7comm_szl_001c_0001_name": "s7_plc_name",
    "s7comm_szl_001c_0002_name": "s7_module_name",
    "s7comm_szl_001c_0003_tag": "s7_plant_tag",
    "s7comm_szl_001c_0005_serialn": "s7_serial",
    "s7comm_szl_001c_0007_cputypname": "s7_module_type",
}
SNMP_SYSTEM = {  # MIB-2 system group, string-typed objects
    "1.3.6.1.2.1.1.1.0": "snmp_sys_descr",
    "1.3.6.1.2.1.1.4.0": "snmp_sys_contact",
    "1.3.6.1.2.1.1.5.0": "snmp_sys_name",
    "1.3.6.1.2.1.1.6.0": "snmp_sys_location",
}
# CIP device profiles (names from Wireshark) → asset type.
CIP_TYPE_HINTS = (
    ("logic controller", "PLC"),
    ("human-machine", "HMI"),
    ("drive", "Field Device"),
    ("motor", "Field Device"),
    ("valve", "Field Device"),
    ("sensor", "Field Device"),
    ("encoder", "Field Device"),
    ("contactor", "Field Device"),
)
PN_ROLE_CONTROLLER, PN_ROLE_DEVICE = 0x02, 0x01


@dataclass
class Fingerprint:
    identity: dict[str, str] = field(default_factory=dict)
    ip: str | None = None  # an address the device announced for itself (PROFINET DCP)


def clean(v: str | None) -> str | None:
    if v is None:
        return None
    v = _CONTROL.sub(" ", v).strip()
    return v[:MAX_VALUE] or None


def _all(L: dict, key: str) -> list[str]:
    return L.get(key) or []


def _one(L: dict, key: str) -> str | None:
    v = L.get(key)
    return clean(v[0]) if v else None


def _int(s: str | None) -> int | None:
    if s is None:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def cip_type_hint(device_type: str | None) -> str | None:
    t = (device_type or "").lower()
    return next((hint for needle, hint in CIP_TYPE_HINTS if needle in t), None)


def _modbus(L: dict) -> Fingerprint | None:
    ids, values = _all(L, "modbus_object_id"), _all(L, "modbus_object_str_value")
    if not ids or len(ids) != len(values):
        return None
    ident = {}
    for oid, val in zip(ids, values, strict=True):
        key = MODBUS_OBJECTS.get(_int(oid) or -1)
        if key and (v := clean(val)):
            ident[key] = v
    return Fingerprint(ident) if ident else None


def _s7(L: dict) -> Fingerprint | None:
    ident: dict[str, str] = {}
    for idx, mlfb, ausbg, ausbe in zip(
        _all(L, "s7comm_szl_xy11_0001_index"),
        _all(L, "s7comm_szl_xy11_0001_anz") + [""] * 16,
        _all(L, "s7comm_szl_xy11_0001_ausbg") + ["0"] * 16,
        _all(L, "s7comm_szl_xy11_0001_ausbe") + ["0"] * 16,
        strict=False,
    ):
        i = _int(idx)
        if i == 1 and (v := clean(mlfb)):
            ident["s7_order_number"] = v
        elif i == 7:  # firmware: 'V' then major, minor, patch
            g, e = _int(ausbg) or 0, _int(ausbe) or 0
            if g >> 8 == ord("V"):
                ident["s7_firmware"] = f"V{g & 0xFF}.{e >> 8}.{e & 0xFF}"
    for f, key in S7_SZL_1C.items():
        if v := _one(L, f):
            ident[key] = v
    return Fingerprint(ident) if ident else None


def _cip(L: dict, env) -> Fingerprint | None:
    name = _one(L, "cip_id_product_name")
    if name is None:
        return None
    vendor_id, devtype = _int(_one(L, "cip_id_vendor_id")), _int(_one(L, "cip_id_device_type"))
    vendor = env.name("cip.id.vendor_id", vendor_id) if env and vendor_id is not None else None
    dtype = env.name("cip.id.device_type", devtype) if env and devtype is not None else None
    major, minor = _one(L, "cip_id_major_rev"), _one(L, "cip_id_minor_rev")
    ident = {
        "enip_product_name": name,
        "enip_vendor": clean(vendor) or (str(vendor_id) if vendor_id is not None else None),
        "enip_device_type": clean(dtype) or (str(devtype) if devtype is not None else None),
        "enip_product_code": _one(L, "cip_id_product_code"),
        "enip_serial": _one(L, "cip_id_serial_number"),
        "enip_revision": f"{_int(major)}.{_int(minor)}" if major and minor else None,
    }
    return Fingerprint({k: v for k, v in ident.items() if v})  # type hint: see enip_type_hint()


def _pn_dcp(L: dict) -> Fingerprint | None:
    ident = {
        "pn_name_of_station": _one(L, "pn_dcp_suboption_device_nameofstation"),
        "pn_type_of_station": _one(L, "pn_dcp_suboption_device_devicevendorvalue"),
        "pn_vendor_id": _one(L, "pn_dcp_suboption_vendor_id"),
        "pn_device_id": _one(L, "pn_dcp_suboption_device_id"),
    }
    role = _int(_one(L, "pn_dcp_suboption_device_role"))
    if role is not None and role & PN_ROLE_CONTROLLER:
        ident["pn_role"] = "IO controller"
    elif role is not None and role & PN_ROLE_DEVICE:
        ident["pn_role"] = "IO device"
    ident = {k: v for k, v in ident.items() if v}
    if not ident:
        return None
    return Fingerprint(ident, ip=_one(L, "pn_dcp_suboption_ip_ip"))


def _snmp(L: dict, p: Packet) -> Fingerprint | None:
    if p.sport != 161:  # responses come from the agent
        return None
    names, octets = _all(L, "snmp_name"), _all(L, "snmp_value_octets")
    strings = [n for n in names if n in SNMP_SYSTEM]
    # tshark lists values for string-typed varbinds only. The system objects we read are always strings,
    # so pair them only when the counts match: any other string varbind would shift the pairing.
    if not strings or len(strings) != len(octets):
        return None
    ident = {}
    for name, hexval in zip(strings, octets, strict=True):
        try:
            text = bytes.fromhex(hexval.replace(":", "")).decode("utf-8", "replace")
        except ValueError:
            continue
        if v := clean(text):
            ident[SNMP_SYSTEM[name]] = v
    return Fingerprint(ident) if ident else None


def _bacnet(L: dict) -> Fingerprint | None:
    # object-name (77) of a device object, in a readProperty ACK
    if "77" in _all(L, "bacapp_property_identifier") and (name := _one(L, "bacapp_object_name")):
        return Fingerprint({"bacnet_device_name": name})
    return None


def extract(p: Packet, env, protos: set[str]) -> Fingerprint | None:
    L = p.layers
    if "modbus" in protos and "modbus_object_str_value" in L:
        return _modbus(L)
    if "s7comm" in protos and ("s7comm_szl_xy11_0001_index" in L or any(k in L for k in S7_SZL_1C)):
        return _s7(L)
    if "cip_id_product_name" in L:
        return _cip(L, env)
    if "pn_dcp" in protos:
        return _pn_dcp(L)
    if "snmp" in protos and "snmp_value_octets" in L:
        return _snmp(L, p)
    if "bacapp" in protos and "bacapp_object_name" in L:
        return _bacnet(L)
    return None


def type_hints(identity: dict[str, str]) -> list[tuple[str, Evidence]]:
    """Device-type hints from what a device says about itself. Strong evidence: it's the device's own word."""
    hints: list[tuple[str, Evidence]] = []
    if any(k.startswith("s7_") for k in identity):
        module = (
            identity.get("s7_module_type")
            or identity.get("s7_module_name")
            or identity.get("s7_order_number")
        )
        detail = "Identifies itself over S7comm" + (f" as {module}" if module else "")
        if identity.get("s7_order_number") and identity["s7_order_number"] != module:
            detail += f" ({identity['s7_order_number']})"
        hints.append(("PLC", Evidence(kind="fingerprint", detail=detail, weight=20)))
    if t := cip_type_hint(identity.get("enip_device_type")):
        what = " ".join(v for v in (identity.get("enip_vendor"), identity.get("enip_product_name")) if v)
        detail = f"EtherNet/IP identity: {identity['enip_device_type']}" + (f" ({what})" if what else "")
        hints.append((t, Evidence(kind="fingerprint", detail=detail, weight=20)))
    role = identity.get("pn_role")
    station = identity.get("pn_type_of_station")
    suffix = f" ({station})" if station else ""
    if role == "IO controller":
        hints.append(
            (
                "PLC",
                Evidence(
                    kind="fingerprint",
                    detail=f"PROFINET: announces itself as an IO controller{suffix}",
                    weight=20,
                ),
            )
        )
    elif role == "IO device":
        hints.append(
            (
                "Field Device",
                Evidence(
                    kind="fingerprint",
                    detail=f"PROFINET: announces itself as an IO device{suffix}",
                    weight=10,
                ),
            )
        )
    return hints


DHCP_OS = (
    ("msft", "Windows"),
    ("android", "Android"),
    ("dhcpcd", "Linux/Unix/macOS"),
    ("udhcp", "Linux/Unix/macOS"),
)


def os_from_dhcp(vendor_class: str | None) -> str | None:
    vc = (vendor_class or "").lower()
    return next((os for needle, os in DHCP_OS if vc.startswith(needle)), None)
