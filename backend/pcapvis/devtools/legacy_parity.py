"""Compare the v2 engine with the legacy (v1) engine on the same captures.

Every difference is either *explained* (an intended v2 behaviour, with the reason) or *unexplained*
(a candidate regression). CI fails on unexplained differences.

    uv run python -m pcapvis.devtools.legacy_parity --legacy-python /path/to/python capture.pcap [...]

The legacy side runs in its own interpreter (it needs legacy/requirements.txt) via scripts/legacy_dump.py.
"""

import argparse
import json
import re
import subprocess  # noqa: S404
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pcapvis.engine.analyze import analyze_capture
from pcapvis.engine.model import AnalysisResult

REPO = Path(__file__).resolve().parents[3]
DUMP = REPO / "scripts" / "legacy_dump.py"

# Legacy rule types → v2 rule ids (same meaning).
RULE_MAP = {"ot_s7_write": "ot_s7_write"}
# v2 rules that legacy doesn't have, or legacy never fired for the same evidence.
NEW_V2_RULES = {
    "default_credentials": "new in v2: vendor-default / trivial passwords",
    "ot_s7_critical": "legacy only scanned the first 50 packets per connection and missed PLC Stop / PI service",
}
# Rules whose *count* legitimately differs because v2 groups hits per (rule, src, dst) or per server.
GROUPED_RULES = {
    "ot_cleartext": "v2 reports one finding per server and protocol (legacy: per host pair, per packet)",
    "cleartext_credentials": "v2 reports every cleartext credential (legacy: only FTP/Telnet traffic)",
    "vlan_native_leak": "v2 skips routers and hosts only seen through a router's MAC (their tags belong to the router)",
    "vlan_hopping": "v2 skips hosts only seen through a router's MAC",
    "ot_multiunit_poll": "legacy emitted duplicates (once per host and once per unit-ID map)",
    "iot_camera_exfil": "v2 needs an outbound connection or >1 MB; answering an inbound session is exposure",
    "ot_modbus_write": "v2 groups writes per (source, PLC) with a count",
}
# Legacy's hand-written parsers mis-decode standard frames of these protocols (verified against
# Wireshark): DNP3 reads the transport byte as the function code ("Unknown FC 192"), EtherNet/IP doesn't
# walk the CIP item list ("Service 0x0"), BACnet reads the service from the wrong byte ("Service 1").
LEGACY_GARBAGE = {
    "DNP3": re.compile(r"^Unknown FC (19[2-9]|2\d\d)$"),
    "EtherNet/IP": re.compile(r"^Service 0x0$"),
    "BACnet": re.compile(r"^Service \d+$"),
}
OT_RULE_PROTOCOL = {
    "ot_dnp3_control": "DNP3",
    "ot_dnp3_unusual_fc": "DNP3",
    "ot_enip_write": "EtherNet/IP",
    "ot_bacnet_write": "BACnet",
    "ot_modbus_write": "Modbus",
    "ot_s7_write": "S7comm",
}
LEGACY_OT_TYPES = {"PLC", "RTU", "IED", "DCS", "SCADA Server", "Building Controller", "Field Device"}

TYPE_UPGRADES = {
    # legacy type → v2 types that are a deliberate refinement
    (
        "Linux Host",
        "Engineering Workstation",
    ): "v2 detects S7 program downloads in all packets (legacy only the first 50)",
    ("Unknown Host", "Linux Host"): "v2 falls back to the TTL OS hint",
    ("Unknown Host", "Windows Host"): "v2 falls back to the TTL OS hint",
}


@dataclass
class Diff:
    area: str
    item: str
    legacy: object
    v2: object
    reason: str | None = None  # None = unexplained

    @property
    def explained(self) -> bool:
        return self.reason is not None


@dataclass
class Report:
    capture: str
    diffs: list[Diff] = field(default_factory=list)
    matches: Counter = field(default_factory=Counter)

    @property
    def unexplained(self) -> list[Diff]:
        return [d for d in self.diffs if not d.explained]

    def add(self, area, item, legacy, v2, reason=None):
        self.diffs.append(Diff(area, item, legacy, v2, reason))

    def markdown(self) -> str:
        lines = [f"### {self.capture}", ""]
        lines.append("Matches: " + ", ".join(f"{k} {v}" for k, v in sorted(self.matches.items())))
        lines.append(f"Differences: {len(self.diffs)} ({len(self.unexplained)} unexplained)")
        lines.append("")
        if self.diffs:
            lines.append("| Area | Item | Legacy | v2 | Explanation |")
            lines.append("|---|---|---|---|---|")
            for d in sorted(self.diffs, key=lambda d: (d.explained, d.area, str(d.item))):
                why = d.reason or "**UNEXPLAINED**"
                lines.append(f"| {d.area} | {d.item} | {_short(d.legacy)} | {_short(d.v2)} | {why} |")
        return "\n".join(lines) + "\n"


def _short(v) -> str:
    s = json.dumps(v, default=str) if not isinstance(v, str) else v
    return (s[:80] + "…") if len(s) > 80 else s


def legacy_summary(capture: Path, legacy_python: str) -> dict:
    out = subprocess.run(  # noqa: S603
        [legacy_python, str(DUMP), str(capture)], capture_output=True, text=True, check=True, timeout=1800
    ).stdout
    return json.loads(out.strip().splitlines()[-1])


def compare(capture: Path, legacy: dict, v2: AnalysisResult) -> Report:
    rep = Report(capture.name)
    hosts = {h.ip: h for h in v2.hosts}

    # ── packets ───────────────────────────────────────────────────────────
    if legacy["packets"] == v2.capture.packets:
        rep.matches["packet count"] += 1
    else:
        rep.add("capture", "packets", legacy["packets"], v2.capture.packets)

    # ── hosts ─────────────────────────────────────────────────────────────
    for ip in sorted(set(legacy["hosts"]) | set(hosts)):
        lh, vh = legacy["hosts"].get(ip), hosts.get(ip)
        if lh is None:
            why = None
            if vh.packets_sent == 0 and vh.packets_recv == 0:
                why = "v2 also lists hosts seen only in ARP"
            elif vh.is_multicast or vh.is_broadcast:
                why = "v2 keeps multicast/broadcast destinations as hosts"
            rep.add("hosts", ip, None, vh.host_type, why)
            continue
        if vh is None:
            rep.add("hosts", ip, lh["host_type"], None)
            continue
        rep.matches["hosts present in both"] += 1
        _compare_host(rep, ip, lh, vh)

    # ── conversations (unordered host pairs) ──────────────────────────────
    v2_pairs = Counter()
    for f in v2.flows:
        v2_pairs["|".join(sorted((f.client, f.server)))] += f.packets
    for pair in sorted(set(legacy["pairs"]) | set(v2_pairs)):
        lp, vp = legacy["pairs"].get(pair), v2_pairs.get(pair)
        if lp == vp:
            rep.matches["host pairs with equal packet counts"] += 1
        else:
            rep.add("pairs", pair, lp, vp)

    # ── anomalies (by rule type) ──────────────────────────────────────────
    garbled = _legacy_garbled(legacy)
    lt = Counter(RULE_MAP.get(a[0], a[0]) for a in legacy["anomalies"])
    vt = Counter(a.rule for a in v2.anomalies)
    for rule in sorted(set(lt) | set(vt)):
        if lt[rule] == vt[rule]:
            rep.matches["anomaly types with equal counts"] += 1
            continue
        why = NEW_V2_RULES.get(rule) if lt[rule] == 0 else None
        why = why or GROUPED_RULES.get(rule)
        proto = OT_RULE_PROTOCOL.get(rule)
        if why is None and proto in garbled and vt[rule] > lt[rule]:
            why = f"legacy's {proto} parser mis-decodes standard frames ({garbled[proto]})"
        if why is None and rule == "ot_internet_exposure":
            extra = [
                a for a in v2.anomalies if a.rule == rule and hosts[a.src].host_type not in LEGACY_OT_TYPES
            ]
            if vt[rule] - len(extra) == lt[rule]:
                why = "v2 also treats engineering workstations, HMIs and historians as OT assets"
        if why is None and rule == "ot_s7_write" and lt[rule] > vt[rule] and vt["ot_s7_code_download"]:
            why = "legacy reported a program download twice (download + write); v2 reports it once"
        if why is None and rule == "arp_spoofing" and lt[rule] > vt[rule]:
            if all(len(c.macs) == 1 for c in v2.arp_claims):
                why = "legacy counted destination MACs; v2 uses ARP claims, and none conflict"
        rep.add("anomalies", rule, lt[rule], vt[rule], why)

    # ── credentials ───────────────────────────────────────────────────────
    lc = {tuple(c) for c in legacy["credentials"]}
    vc = {(c.protocol, c.username, c.secret) for c in v2.credentials}
    for c in sorted(lc - vc, key=str):
        rep.add("credentials", "/".join(map(str, c)), "found", "missing")
    for c in sorted(vc - lc, key=str):
        why = (
            "v2 extracts this protocol (legacy did not)"
            if c[0] in ("MQTT", "SNMP", "IMAP", "POP3", "SMTP")
            else None
        )
        rep.add("credentials", "/".join(map(str, c)), "missing", "found", why)
    rep.matches["credentials in both"] += len(lc & vc)

    # ── OT operations (requests by protocol and kind) ─────────────────────
    lo = {(p, k): n for p, k, n in legacy["ot"]}
    vo = Counter((c.protocol, c.kind) for c in v2.ot_commands if c.is_request or c.kind == "error")
    for key in sorted(set(lo) | set(vo)):
        if lo.get(key, 0) == vo.get(key, 0):
            rep.matches["OT operation counts"] += 1
        else:
            why = None
            if key[1] in ("read", "write") and vo.get(key, 0) <= lo.get(key, 0):
                why = "legacy counted requests and responses; v2 counts each request once"
            elif key[1] == "other":
                why = "v2 records session/setup functions as 'other' (legacy dropped or mislabelled them)"
            elif lo.get(key, 0) == 0 and key[0] == "S7comm":
                why = "legacy only scanned the first 50 packets per connection"
            elif key[0] in garbled:
                why = f"legacy's {key[0]} parser mis-decodes standard frames ({garbled[key[0]]})"
            rep.add("ot", f"{key[0]} {key[1]}", lo.get(key, 0), vo.get(key, 0), why)
    return rep


def _legacy_garbled(legacy: dict) -> dict[str, str]:
    """Protocols whose legacy decode produced garbage function names → an example of the garbage."""
    out = {}
    for entry in legacy.get("ot_functions", []):
        proto, _, name = entry.partition("|")
        pat = LEGACY_GARBAGE.get(proto)
        if pat and pat.match(name):
            out.setdefault(proto, f"e.g. '{name}'")
    return out


def _compare_host(rep: Report, ip: str, lh: dict, vh) -> None:
    if lh["mac"] == vh.mac:
        rep.matches["MACs"] += 1
    else:
        why = None
        if vh.mac is None and vh.mac_is_gateway:
            why = "v2 doesn't give hosts behind a router the router's MAC"
        elif vh.mac is None and lh["mac"] is None:
            why = None
        rep.add("mac", ip, lh["mac"], vh.mac, why)
    if (lh["vendor"] or None) != (vh.mac_vendor or None):
        rep.add(
            "vendor",
            ip,
            lh["vendor"],
            vh.mac_vendor,
            "v2 uses Wireshark's full OUI database (legacy: a 70-entry table with errors)",
        )
    else:
        rep.matches["vendors"] += 1
    if lh["host_type"] == vh.host_type:
        rep.matches["host types"] += 1
    else:
        why = TYPE_UPGRADES.get((lh["host_type"], vh.host_type))
        if why is None and any(
            e.kind in ("lldp", "cdp", "gateway_mac", "s7_download") for e in vh.host_type_evidence
        ):
            why = f"v2 evidence: {vh.host_type_evidence[0].detail}"
        rep.add("host_type", ip, lh["host_type"], vh.host_type, why)
    if float(lh["purdue"]) == float(vh.purdue_level):
        rep.matches["Purdue levels"] += 1
    else:
        why = "follows the host-type difference" if lh["host_type"] != vh.host_type else None
        if why is None and any(e.kind == "ot_master" for e in vh.purdue_evidence):
            why = "v2 places hosts that command OT devices at Level 3 (legacy left them unclassified)"
        rep.add("purdue", ip, lh["purdue"], vh.purdue_level, why)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+", type=Path)
    ap.add_argument("--legacy-python", required=True, help="Python with legacy/requirements.txt installed")
    ap.add_argument("--report", type=Path, help="Write a markdown report here")
    args = ap.parse_args(argv)
    reports = []
    for cap in args.captures:
        reports.append(compare(cap, legacy_summary(cap, args.legacy_python), analyze_capture(cap)))
    text = "\n".join(r.markdown() for r in reports)
    if args.report:
        args.report.write_text("# Legacy parity report\n\n" + text)
    print(text)
    bad = sum(len(r.unexplained) for r in reports)
    print(f"{bad} unexplained difference(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
