#!/usr/bin/env python3
"""Run the legacy (v1) engine on a capture and print a normalised JSON summary.

Used by the v2 parity harness (backend/pcapvis/devtools/legacy_parity.py). Run it with a Python that
has legacy/requirements.txt installed:  python scripts/legacy_dump.py capture.pcap
"""
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "legacy"))

import app  # noqa: E402  (legacy Flask app module)


def main(path: str) -> None:
    r = app.analyze_pcap(path)
    if "error" in r:
        print(json.dumps({"error": r["error"]}))
        return
    hosts = {
        n["ip"]: {
            "mac": n["mac"], "vendor": n["mac_vendor"], "host_type": n["host_type"],
            "purdue": n["purdue_level"], "protocols": sorted(n["protocols"]), "hostname": n["hostname"],
        }
        for n in r["nodes"]
    }
    pairs = {"|".join(sorted((e["source"], e["target"]))): e["packet_count"] for e in r["edges"]}
    out = {
        "packets": r["stats"]["total_packets"],
        "hosts": hosts,
        "pairs": pairs,
        "anomalies": sorted([a["type"], a.get("src"), a.get("dst")] for a in r["anomalies"]),
        "credentials": sorted(
            [c.get("protocol"), c.get("username"), c.get("password")] for c in r.get("credentials", [])
        ),
        "ot": sorted(
            [k[0], k[1], v] for k, v in Counter((c["protocol"], c["direction"]) for c in r["ot_commands"]).items()
        ),
        "ot_functions": sorted({f"{c['protocol']}|{c.get('function_name', '')}" for c in r["ot_commands"]}),
    }
    print(json.dumps(out, sort_keys=True, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
