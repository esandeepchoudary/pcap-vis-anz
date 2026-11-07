#!/usr/bin/env python3
"""Load the synthetic plant into a running PCAP Visualizer and check what it reports against truth.json.

Creates an engagement, uploads the captures with their capture points, waits for analysis, then checks:
inventory (every device once, right MAC, VLANs, captures seen in, no phantom assets), Purdue levels,
fingerprints (vendor/model/firmware), conversations and their direction, OT write counts, planted findings,
credentials, findings that must not appear, the DMZ-bypass paths and the capture diff.

    cd backend && uv run python ../fixtures/plant/check_soundness.py --dir /tmp/plant \\
        --url http://127.0.0.1:8000 --user admin --password ...

Exit code 1 when any hard check fails. Soft checks (classification quality) are reported, not failed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import httpx

H = {"x-pcapvis-client": "1"}
PROTO_ALIASES = {"cip": {"cip", "enip", "ethernet/ip"}, "iec 60870-5-104": {"iec 60870-5-104", "iec-104", "iec104"},
                 "tls": {"tls", "https", "ssl"}, "dns": {"dns"}, "opc ua": {"opc ua", "opcua", "opc-ua"}}


class Report:
    def __init__(self):
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, area: str, ok: bool | None, what: str, detail: str = ""):
        self.rows.append((area, "PASS" if ok else "SOFT" if ok is None else "FAIL", what, detail))

    def print(self):
        width = max(len(r[2]) for r in self.rows)
        for area, st, what, detail in self.rows:
            mark = {"PASS": "✓", "FAIL": "✗", "SOFT": "~"}[st]
            print(f"{mark} {area:<12} {what:<{width}}  {detail}")
        fails = sum(r[1] == "FAIL" for r in self.rows)
        soft = sum(r[1] == "SOFT" for r in self.rows)
        print(f"\n{len(self.rows) - fails - soft} passed, {fails} failed, {soft} soft (classification quality)")
        return fails


def proto_match(expected: str, actual: str) -> bool:
    e, a = expected.lower(), actual.lower()
    return a in PROTO_ALIASES.get(e, {e})


def load(c: httpx.Client, d: Path, truth: dict, name: str) -> int:
    eng = c.post("/api/engagements", json={"name": name, "client": "Riverside Water (synthetic)",
                                           "site": "Riverside WTP", "description": "Synthetic plant from fixtures/plant/build_plant.py"}, headers=H)
    eng.raise_for_status()
    eid = eng.json()["id"]
    points: dict[str, int] = {}
    for key in sorted(truth["captures"]):
        meta = truth["captures"][key]
        p = meta["capture_point"]
        if p not in points:
            r = c.post(f"/api/engagements/{eid}/capture-points", json={"name": p}, headers=H)
            r.raise_for_status()
            points[p] = r.json()["id"]
        with open(d / meta["file"], "rb") as fh:
            r = c.post(f"/api/engagements/{eid}/captures", files={"files": (meta["file"], fh, "application/vnd.tcpdump.pcap")},
                       data={"capture_point_id": str(points[p])}, headers=H, timeout=600)
        r.raise_for_status()
        print(f"uploaded {meta['file']}", flush=True)
    deadline = time.time() + 1800
    while time.time() < deadline:
        caps = c.get(f"/api/engagements/{eid}/captures").json()
        states = [x["status"] for x in caps]
        if all(s in ("done", "failed", "cancelled") for s in states):
            bad = [x["file_name"] for x in caps if x["status"] != "done"]
            if bad:
                sys.exit(f"analysis failed for {bad}")
            return eid
        print("analysing: " + ", ".join(f"{x['file_name']} {x['status']} {round(100 * (x.get('progress') or 0))}%" for x in caps), flush=True)
        time.sleep(10)
    sys.exit("timed out waiting for analysis")


def check(c: httpx.Client, eid: int, truth: dict) -> int:
    rep = Report()
    caps = {x["file_name"]: x for x in c.get(f"/api/engagements/{eid}/captures").json()}
    cap_id = {k: caps[m["file"]]["id"] for k, m in truth["captures"].items()}
    key_of = {v: k for k, v in cap_id.items()}
    assets = c.get(f"/api/engagements/{eid}/assets").json()
    links = c.get(f"/api/engagements/{eid}/links").json()
    findings = c.get(f"/api/engagements/{eid}/findings").json()
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for a in assets:
        for ip in a["ips"]:
            by_ip[ip].append(a)
    ip_of = {a["id"]: (a["ips"][0] if a["ips"] else f"#{a['id']}") for a in assets}

    # Packet totals: what the app counted equals what was written.
    for k, m in truth["captures"].items():
        got = (caps[m["file"]].get("summary") or {}).get("packets")
        rep.add("capture", got == m["packets"], f"{m['file']} packet count", f"wrote {m['packets']:,}, app counted {got}")

    # Inventory.
    devices = {d["ip"]: d for d in truth["devices"]}
    for ip, d in devices.items():
        found = by_ip.get(ip, [])
        if len(found) != 1:
            rep.add("inventory", False, f"{d['name']} {ip} is one asset", f"found {len(found)}")
            continue
        a = found[0]
        rep.add("inventory", d["mac"] in a["macs"], f"{d['name']} MAC", f"expected {d['mac']}, got {a['macs']}")
        expected_vlans = [d["vlan"]] if d["vlan"] not in (None,) and any(k != "c2" for k in d["seen_in"]) else []
        if d["vlan"] == 1:
            expected_vlans = [1]
        rep.add("vlan", sorted(a["vlans"]) == expected_vlans, f"{d['name']} VLANs", f"expected {expected_vlans}, got {a['vlans']}")
        if len(a["ips"]) > 1:
            rep.add("inventory", False, f"{d['name']} has only its own IP", f"got {a['ips']}")
        rep.add("inventory", a["capture_count"] == len(d["seen_in"]), f"{d['name']} seen in captures",
                f"expected {len(d['seen_in'])}, got {a['capture_count']}")
        if d["family"] != "control":  # e.g. a port scan must not turn its targets into PLCs
            rep.add("inventory", a["asset_type"] not in {"PLC", "RTU"}, f"{d['name']} isn't typed as a controller",
                    f"typed {a['asset_type']}")
        lv_ok = abs(float(a["purdue_level"]) - d["level"]) < 0.01
        rep.add("purdue", lv_ok or None, f"{d['name']} Purdue level", f"expected {d['level']:g}, got {a['purdue_level']:g} ({a['asset_type']})")
        for f in ("vendor", "model", "firmware"):
            if d.get(f) and d["family"] == "control" and d.get("model"):
                rep.add("fingerprint", (a.get(f) or "") == d[f], f"{d['name']} {f}", f"expected {d[f]!r}, got {a.get(f)!r}")
    internet = {x for v in truth["internet"].values() for x in (v if isinstance(v, list) else [v])}
    known = set(devices) | internet
    phantom = [ip for ip in by_ip if ip not in known and not ip.startswith(("224.", "239.", "255.", "0.", "ff", "fe80"))
               and ip not in truth["router"]["ips"].values()]
    rep.add("inventory", not phantom, "no phantom assets", ", ".join(sorted(phantom)[:10]) or "none")
    router = [a for a in assets if truth["router"]["mac"] in a["macs"]]
    rep.add("inventory", not router, "router MAC not merged into one asset", f"{len(router)} assets carry it")

    # Conversations and direction.
    lk = {(ip_of[x["src"]], ip_of[x["dst"]]): x for x in links}
    seen_pairs = set()
    for t in truth["links"]:
        pair = (t["client"], t["server"])
        if (pair, t["protocol"]) in seen_pairs:
            continue
        seen_pairs.add((pair, t["protocol"]))
        x = lk.get(pair)
        if x is None:
            rev = lk.get((t["server"], t["client"]))
            rep.add("links", False, f"{t['client']} → {t['server']} {t['protocol']}", "reversed" if rev else "missing")
            continue
        ok = any(proto_match(t["protocol"], p["protocol"]) for p in x["protocols"])
        rep.add("links", ok, f"{t['client']} → {t['server']} {t['protocol']}", "protocols " + ", ".join(p["protocol"] for p in x["protocols"]))
    for w in truth["ot_writes"]:
        x = lk.get((w["client"], w["server"]))
        got = x["ot_writes"] if x else None
        rep.add("ot writes", got == w["count"], f"{w['client']} → {w['server']} writes", f"expected {w['count']}, got {got}")
    expected_writers = {(w["client"], w["server"]) for w in truth["ot_writes"]}
    extra = [f"{a}→{b} ({lk[(a, b)]['ot_writes']})" for (a, b) in lk if lk[(a, b)]["ot_writes"] and (a, b) not in expected_writers]
    rep.add("ot writes", not extra, "no unexpected writers", ", ".join(extra) or "none")

    # Findings.
    by_rule = defaultdict(list)
    for f in findings:
        by_rule[f["rule"]].append(f)
    for t in truth["findings"]:
        hits = [f for f in by_rule.get(t["rule"], []) if (t["src"] is None or f["src"] == t["src"]) and (t["dst"] is None or f["dst"] == t["dst"])]
        rep.add("findings", bool(hits), f"{t['rule']} {t['src'] or '*'} → {t['dst'] or '*'}",
                f"{len(by_rule.get(t['rule'], []))} {t['rule']} findings in total")
    for t in truth["must_not_find"]:
        bad = [f for f in by_rule.get(t["rule"], []) if f["src"] in devices and f["dst"] in devices]
        rep.add("findings", not bad, f"no {t['rule']} between internal devices",
                f"{len(bad)} false positives, e.g. " + "; ".join(f"{f['src']}→{f['dst']}" for f in bad[:4]) if bad else t["why"])
    # Each finding should name the assets it is about.
    unlinked = [f["key"] for f in findings if f["source"] == "rule" and (f["src"] or f["dst"]) and not f["asset_ids"]]
    rep.add("findings", not unlinked, "every rule finding is linked to its assets", f"{len(unlinked)} unlinked")

    # Credentials, from the per-capture results.
    creds = []
    for cid in cap_id.values():
        r = c.get(f"/api/engagements/{eid}/captures/{cid}/result", timeout=120)
        creds += r.json().get("credentials", [])
    for t in truth["credentials"]:
        hit = [x for x in creds if x["protocol"].lower() == t["protocol"].lower() and x["client"] == t["client"] and x["server"] == t["server"]
               and (t["username"] is None or x["username"] == t["username"])]
        rep.add("credentials", bool(hit), f"{t['protocol']} {t['client']} → {t['server']}", f"user {t['username']}")

    # DMZ bypass: business (L4+) talking straight to control (L1-) or the reverse.
    level = {ip: float(by_ip[ip][0]["purdue_level"]) for ip in by_ip if len(by_ip[ip]) == 1}
    for t in truth["dmz_bypass"]:
        a, b = level.get(t["client"]), level.get(t["server"])
        flagged = a is not None and b is not None and ((a >= 4 and b <= 3) or (b >= 4 and a <= 3)) and (t["client"], t["server"]) in lk
        rep.add("purdue", flagged, f"DMZ bypass {t['client']} → {t['server']}", f"levels {a} → {b}")

    # Diff: the rogue laptop is new in the last capture.
    for k, ips in truth["new_in"].items():
        prev = sorted(cap_id)[sorted(cap_id).index(k) - 1]
        d = c.get(f"/api/engagements/{eid}/diff", params={"base": cap_id[prev], "compare": cap_id[k]}).json()
        new_ips = {ip_of.get(i) for i in d["new_assets"]}
        for ip in ips:
            rep.add("diff", ip in new_ips, f"{ip} new in {k} vs {prev}", f"{len(new_ips)} new assets: {sorted(x for x in new_ips if x)[:6]}")

    # Timeline: links span the captures they were seen in.
    spans = [(m["start"], m["end"]) for m in truth["captures"].values()]
    lo, hi = min(s for s, _ in spans), max(e for _, e in spans)
    out = [x for x in links if x["first_seen"] is not None and not (lo - 1 <= x["first_seen"] <= x["last_seen"] <= hi + 1)]
    rep.add("timeline", not out, "link first/last seen within the capture spans", f"{len(out)} outside")
    _ = key_of
    return rep.print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, required=True)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--engagement", type=int, help="check an engagement that's already loaded")
    ap.add_argument("--name", default="Riverside Water Treatment (synthetic)")
    a = ap.parse_args()
    truth = json.loads((a.dir / "truth.json").read_text())
    with httpx.Client(base_url=a.url, timeout=60) as c:
        if a.user:
            c.post("/api/auth/login", json={"username": a.user, "password": a.password}, headers=H).raise_for_status()
        eid = a.engagement or load(c, a.dir, truth, a.name)
        print(f"engagement {eid}\n")
        sys.exit(1 if check(c, eid, truth) else 0)


if __name__ == "__main__":
    main()
