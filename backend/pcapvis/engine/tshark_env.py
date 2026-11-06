"""What the installed tshark supports: field list and value-name tables. Cached per version."""

import subprocess  # noqa: S404 - runs the configured tshark binary with fixed arguments
import threading
from dataclasses import dataclass, field
from functools import lru_cache

from pcapvis.engine.fields import ALL_FIELDS

# Fields whose numeric values we show by name. Names come from Wireshark itself, so they
# always match the dissector (no hand-maintained tables to drift).
NAMED_FIELDS = {
    "modbus.func_code",
    "modbus.exception_code",
    "dnp3.al.func",
    "s7comm.header.rosctr",
    "s7comm.param.func",
    "s7comm.param.userdata.funcgroup",
    "s7comm.data.userdata.szl_id",
    "enip.command",
    "cip.sc",
    "cip.genstat",
    "enip.lir.vendor",
    "enip.lir.devtype",
    "cip.id.vendor_id",
    "cip.id.device_type",
    "iec60870_104.type",
    "iec60870_asdu.typeid",
    "iec60870_asdu.causetx",
    "bvlc.function",
    "bacapp.type",
    "bacapp.confirmed_service",
    "bacapp.unconfirmed_service",
    "bacapp.vendor_identifier",
    "bacapp.objectType",
    "dnp3.ctl.prifunc",
    "mqtt.msgtype",
    "coap.type",
    "coap.code",
    "icmp.type",
    "icmpv6.type",
}


@dataclass
class TsharkEnv:
    tshark_path: str
    fields: list[str]
    missing_fields: list[str]
    value_names: dict[str, dict[int, str]] = field(default_factory=dict)

    def name(self, field_name: str, value: int | None) -> str | None:
        if value is None:
            return None
        return self.value_names.get(field_name, {}).get(value)


def _run(tshark: str, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        [tshark, *args], capture_output=True, text=True, check=True, timeout=180
    ).stdout


def _parse_int(text: str) -> int | None:
    try:
        return int(text, 0)
    except ValueError:
        return None


def parse_value_names(dump: str, wanted: set[str]) -> dict[str, dict[int, str]]:
    """Parse ``tshark -G values`` output ("V<TAB>field<TAB>value<TAB>name" lines)."""
    out: dict[str, dict[int, str]] = {}
    for line in dump.splitlines():
        if not line.startswith("V\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 4 or parts[1] not in wanted:
            continue
        value = _parse_int(parts[2])
        if value is not None:
            out.setdefault(parts[1], {}).setdefault(value, parts[3])
    return out


def parse_field_list(dump: str) -> set[str]:
    """Parse ``tshark -G fields`` output; field abbreviations are the 3rd column of F lines."""
    names = set()
    for line in dump.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in ("F", "P"):
            names.add(parts[2])
    return names


_lock = threading.Lock()


@lru_cache(maxsize=4)
def _load(tshark_path: str) -> TsharkEnv:
    available = parse_field_list(_run(tshark_path, "-G", "fields"))
    usable = [f for f in ALL_FIELDS if f in available]
    missing = [f for f in ALL_FIELDS if f not in available]
    names = parse_value_names(_run(tshark_path, "-G", "values"), NAMED_FIELDS)
    return TsharkEnv(tshark_path, usable, missing, names)


def load_env(tshark_path: str = "tshark") -> TsharkEnv:
    """Introspect tshark once per process (takes a few seconds; cached)."""
    with _lock:
        return _load(tshark_path)
