"""OT/ICS command extraction from tshark fields.

One OtCommand per *request* (responses only add errors), so counts reflect what operators did.
Function names come from Wireshark's own tables (TsharkEnv.name), never hand-maintained lists.
"""

from dataclasses import dataclass

from pcapvis.engine.packet import Packet
from pcapvis.engine.tshark_env import TsharkEnv

# What counts as a write/control action, per protocol specification.
MODBUS_WRITES = {5, 6, 15, 16, 21, 22, 23}  # coils, registers, file record, mask write, read/write
MODBUS_DIAG = {8, 17, 43}  # diagnostics, report server ID, encapsulated interface (device ID)
DNP3_WRITES = {2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18, 24, 25, 26, 27, 30, 31}
# write, select, operate, direct operate (+no ack), cold/warm restart, init data, app start/stop,
# save config, record current time, open/delete/write file, activate config, authenticate-req
DNP3_RESTARTS = {13, 14}
DNP3_RESPONSES = {129, 130, 131}
S7_WRITES = {0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29}  # write var, download x3, PI service, PLC stop
S7_DOWNLOAD = {0x1A, 0x1B}
# CIP common services (same meaning on every object class).
CIP_COMMON_WRITES = {0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x15, 0x16}
# set attrs all/list, reset, start, stop, create, delete, set attr single, restore, save
CIP_COMMON_READS = {0x01, 0x03, 0x0E}  # get attrs all/list/single
# Object-specific services (0x4B+) depend on the target: Logix symbolic tags vs the Connection Manager.
CIP_TAG_SERVICES = {
    0x4C: ("Read Tag", "read"),
    0x4D: ("Write Tag", "write"),
    0x4E: ("Read Modify Write Tag", "write"),
    0x52: ("Read Tag Fragmented", "read"),
    0x53: ("Write Tag Fragmented", "write"),
}
CIP_CONNECTION_MANAGER = 0x06
CIP_CM_SERVICES = {
    0x4E: "Forward Close",
    0x52: "Unconnected Send",
    0x54: "Forward Open",
    0x5B: "Large Forward Open",
    0x56: "Get Connection Data",
}
IEC104_CONTROL = set(range(45, 52)) | set(range(58, 65)) | {105, 107}  # commands, reset process, test w/ time
IEC104_ACTIVATION = 6
IEC104_ERROR_COT = {44, 45, 46, 47}  # unknown type / cause / common address / object address
BACNET_WRITES = {7, 8, 9, 10, 11, 15, 16, 17, 20, 27}
# atomicWriteFile, add/removeListElement, create/deleteObject, writeProperty(+Multiple),
# deviceCommunicationControl, reinitializeDevice, lifeSafetyOperation
BACNET_ERROR_TYPES = {5, 6, 7}  # Error, Reject, Abort


@dataclass(slots=True)
class OtEvent:
    protocol: str
    function_code: int | None
    function: str
    kind: str  # "read" | "write" | "error" | "other"
    is_request: bool
    unit: int | None = None  # Modbus unit id, DNP3 destination address
    address: int | None = None  # register / point address
    quantity: int | None = None
    detail: str = ""
    master_addr: int | None = None  # DNP3 link address of the sender, when it's the master
    outstation_addr: int | None = None
    s7_download: bool = False
    identity: dict | None = None  # device identity learned from a response (ListIdentity, I-Am)


def _i(layers: dict, key: str, idx: int = 0) -> int | None:
    v = layers.get(key)
    if not v or len(v) <= idx:
        return None
    try:
        return int(v[idx], 0)
    except ValueError:
        return None


def _b(layers: dict, key: str) -> bool:
    v = layers.get(key)
    return bool(v) and v[0] in ("True", "1")


def _s(layers: dict, key: str) -> str | None:
    v = layers.get(key)
    return v[0] if v else None


def extract(p: Packet, env: TsharkEnv, c2s: bool) -> list[OtEvent]:
    """Return OT events found in this packet (usually 0 or 1)."""
    L = p.layers
    out: list[OtEvent] = []
    if "modbus_func_code" in L:
        out.append(_modbus(L, env))
    if "dnp3_al_func" in L:
        out.append(_dnp3(L, env))
    if "s7comm_header_rosctr" in L:
        ev = _s7(L, env)
        if ev:
            out.append(ev)
    if "enip_command" in L:
        ev = _enip(L, env, c2s)
        if ev:
            out.append(ev)
    if "iec60870_asdu_typeid" in L:
        out.append(_iec104(L, env))
    if "bacapp_type" in L:
        ev = _bacnet(L, env)
        if ev:
            out.append(ev)
    return out


def _modbus(L, env) -> OtEvent:
    fc = _i(L, "modbus_func_code")
    is_response = "modbus_request_frame" in L
    exc = _i(L, "modbus_exception_code")
    name = env.name("modbus.func_code", fc) or f"Function {fc}"
    if exc is not None:
        exc_name = env.name("modbus.exception_code", exc) or f"exception {exc}"
        return OtEvent(
            "Modbus", fc, name, "error", False, unit=_i(L, "mbtcp_unit_id"), detail=f"Exception: {exc_name}"
        )
    kind = "write" if fc in MODBUS_WRITES else "other" if fc in MODBUS_DIAG else "read"
    qty = _i(L, "modbus_word_cnt")
    if qty is None:
        qty = _i(L, "modbus_bit_cnt")
    return OtEvent(
        "Modbus",
        fc,
        name,
        kind,
        not is_response,
        unit=_i(L, "mbtcp_unit_id"),
        address=_i(L, "modbus_reference_num"),
        quantity=qty,
    )


def _dnp3(L, env) -> OtEvent:
    fc = _i(L, "dnp3_al_func")
    name = env.name("dnp3.al.func", fc) or f"Function {fc}"
    from_master = _b(L, "dnp3_ctl_dir")
    src, dst = _i(L, "dnp3_src"), _i(L, "dnp3_dst")
    is_request = fc not in DNP3_RESPONSES
    kind = "write" if fc in DNP3_WRITES else "read" if fc == 1 else "other"
    iin = _i(L, "dnp3_al_iin")
    detail = ""
    if not is_request and iin and iin & 0x0700:  # IIN2: no func support / object unknown / param error
        kind, detail = "error", f"IIN 0x{iin:04x}"
    return OtEvent(
        "DNP3",
        fc,
        name,
        kind,
        is_request,
        unit=dst,
        detail=detail,
        master_addr=src if from_master else dst,
        outstation_addr=dst if from_master else src,
    )


def _s7(L, env) -> OtEvent | None:
    rosctr = _i(L, "s7comm_header_rosctr")
    errcls = _i(L, "s7comm_header_errcls")
    if rosctr == 7:  # Userdata: SZL reads, cyclic data, block info…
        grp = _i(L, "s7comm_param_userdata_funcgroup")
        grp_name = env.name("s7comm.param.userdata.funcgroup", grp) or f"group {grp}"
        szl = _i(L, "s7comm_data_userdata_szl_id")
        detail = f"SZL 0x{szl:04x}" if szl is not None else ""
        return OtEvent("S7comm", grp, f"Userdata: {grp_name}", "read", True, detail=detail)
    fc = _i(L, "s7comm_param_func")
    if fc is None:
        return None
    name = env.name("s7comm.param.func", fc) or f"Function 0x{fc:02x}"
    if rosctr in (2, 3) and errcls:
        return OtEvent("S7comm", fc, name, "error", False, detail=f"Error class 0x{errcls:02x}")
    if fc == 0xF0:  # setup communication
        return OtEvent("S7comm", fc, name, "other", rosctr == 1)
    kind = "write" if fc in S7_WRITES else "read" if fc == 0x04 else "other"
    block = _s(L, "s7comm_param_blockcontrol_filename") or ""
    return OtEvent(
        "S7comm",
        fc,
        name,
        kind,
        rosctr == 1,
        detail=f"Block {block}" if block else "",
        s7_download=fc in S7_DOWNLOAD and rosctr == 1,
    )


def _enip(L, env, c2s: bool) -> OtEvent | None:
    cmd = _i(L, "enip_command")
    if cmd == 0x63 and "enip_lir_vendor" in L:  # List Identity response: device fingerprint
        vendor = _i(L, "enip_lir_vendor")
        devtype = _i(L, "enip_lir_devtype")
        rev = L.get("enip_lir_revision", [""])[0]
        ident = {
            "enip_vendor": env.name("enip.lir.vendor", vendor) or str(vendor),
            "enip_device_type": env.name("enip.lir.devtype", devtype) or str(devtype),
            "enip_product_name": _s(L, "enip_lir_name") or "",
            "enip_product_code": _s(L, "enip_lir_prodcode") or "",
            "enip_serial": _s(L, "enip_lir_serial") or "",
            "enip_revision": rev,
        }
        return OtEvent(
            "EtherNet/IP",
            cmd,
            "List Identity",
            "read",
            False,
            detail=ident["enip_product_name"],
            identity={k: v for k, v in ident.items() if v},
        )
    if "cip_sc" not in L:
        if cmd is None:
            return None
        name = env.name("enip.command", cmd) or f"Command 0x{cmd:02x}"
        return OtEvent("EtherNet/IP", cmd, name, "other", c2s)
    sc = _i(L, "cip_sc")
    is_response = _i(L, "cip_rr") == 1
    symbol = _s(L, "cip_symbol") or ""
    cls = _i(L, "cip_class")
    name, kind = _cip_service(env, sc, symbol, cls)
    status = _i(L, "cip_genstat")
    if is_response:
        if status:
            return OtEvent(
                "EtherNet/IP",
                sc,
                name,
                "error",
                False,
                detail=env.name("cip.genstat", status) or f"status 0x{status:02x}",
            )
        return OtEvent("EtherNet/IP", sc, name, "other", False)
    return OtEvent("EtherNet/IP", sc, name, kind, True, detail=symbol)


def _cip_service(env, sc: int | None, symbol: str, cls: int | None) -> tuple[str, str]:
    if sc is None:
        return "Unknown service", "other"
    if sc < 0x4B:
        name = env.name("cip.sc", sc) or f"Service 0x{sc:02x}"
        return name, "write" if sc in CIP_COMMON_WRITES else "read" if sc in CIP_COMMON_READS else "other"
    if cls == CIP_CONNECTION_MANAGER and sc in CIP_CM_SERVICES:
        return CIP_CM_SERVICES[sc], "other"
    if symbol and sc in CIP_TAG_SERVICES:
        return CIP_TAG_SERVICES[sc]
    # Object-specific service on an object we can't identify: don't guess read vs write.
    return f"Service 0x{sc:02x}", "other"


def _iec104(L, env) -> OtEvent:
    tid = _i(L, "iec60870_asdu_typeid")
    cot = _i(L, "iec60870_asdu_causetx")
    name = env.name("iec60870_asdu.typeid", tid) or f"Type {tid}"
    cot_name = env.name("iec60870_asdu.causetx", cot) or f"COT {cot}"
    negative = _b(L, "iec60870_asdu_nega")
    if cot in IEC104_ERROR_COT or negative:
        return OtEvent(
            "IEC-104", tid, name, "error", False, unit=_i(L, "iec60870_asdu_addr"), detail=cot_name
        )
    is_request = cot == IEC104_ACTIVATION
    if tid in IEC104_CONTROL and is_request:
        kind = "write"
    elif tid in (100, 101, 102):  # interrogation, counter interrogation, read
        kind = "read"
    else:
        kind = "other"  # monitoring data, confirmations
    return OtEvent("IEC-104", tid, name, kind, is_request, unit=_i(L, "iec60870_asdu_addr"), detail=cot_name)


def _bacnet(L, env) -> OtEvent | None:
    ptype = _i(L, "bacapp_type")
    if ptype in BACNET_ERROR_TYPES:
        return OtEvent("BACnet", ptype, env.name("bacapp.type", ptype) or "Error", "error", False)
    if ptype == 0:  # Confirmed-Request
        svc = _i(L, "bacapp_confirmed_service")
        name = env.name("bacapp.confirmed_service", svc) or f"Service {svc}"
        kind = "write" if svc in BACNET_WRITES else "read" if svc in (6, 12, 14, 26) else "other"
        return OtEvent("BACnet", svc, name, kind, True)
    if ptype == 1:  # Unconfirmed-Request
        svc = _i(L, "bacapp_unconfirmed_service")
        name = env.name("bacapp.unconfirmed_service", svc) or f"Service {svc}"
        ident = None
        if svc == 0 and "bacapp_vendor_identifier" in L:  # I-Am
            vid = _i(L, "bacapp_vendor_identifier")
            ident = {"bacnet_vendor": env.name("bacapp.vendor_identifier", vid) or str(vid)}
            inst = _s(L, "bacapp_instance_number")
            if inst:
                ident["bacnet_device_instance"] = inst
        kind = "write" if svc == 10 else "other"  # writeGroup
        return OtEvent("BACnet", svc, name, kind, svc != 0, identity=ident)
    return None
