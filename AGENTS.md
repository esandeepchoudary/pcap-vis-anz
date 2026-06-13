# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Branching

Before making major changes (new features, protocol additions, refactors touching multiple files, changes to core data flow), create and check out a feature branch:

```bash
git checkout -b feature/<short-description>
```

Major changes include:
- Adding a new protocol parser or anomaly rule
- Modifying `analyze_pcap()`, `merge_results()`, or `analyze_anomalies()`
- Restructuring the frontend rendering pipeline or global state
- Changing the JSON schema returned by `/upload`

Minor changes (typo fixes, constant tweaks, CSS-only edits) can go directly on `main`.

Once a feature is fully implemented and tests pass, ask the user to review and merge the branch into `main`:

> "Feature is complete and tests pass. Please review and merge `feature/<name>` into `main` when ready."

## Workflow

After completing any change:
1. Update `README.md` to reflect the change (new protocols, updated limits, new features, etc.)
2. Update `backlog.md` -- mark completed items `[x]`, add newly discovered bugs or ideas.
3. Run any relevant unit tests: `python -m pytest tests/ -q` (create tests in `tests/` if they don't exist yet).
4. Start the app and verify it runs without errors: `python app.py` -- check the terminal for startup errors before reporting the task complete.
5. Commit and push to GitHub:

```bash
git add <changed files>
git commit -m "your message"
git push
```

## Testing

Write unit tests in `tests/` using `pytest`. Tests cover:
- Protocol parsers (`parse_modbus`, `parse_dnp3`, `parse_s7comm`, etc.) in `tests/test_parsers.py`
- Anomaly detection rules in `tests/test_anomalies.py`
- Helper functions (`is_private`, `mac_vendor`, `geo_lookup`) in `tests/test_helpers.py`

Run tests before committing:
```bash
python -m pytest tests/ -q
```

## Running the app

```bash
pip install -r requirements.txt          # first time; add --break-system-packages on Kali/Debian
python app.py                            # serves on http://localhost:5000
python app.py --public                   # bind to 0.0.0.0 (LAN-reachable)
python app.py --port 8080                # use a different port
```

No build step, no test suite, no linter config. Changes to Python or JS/CSS take effect on the next request (Flask debug mode is on).

## Architecture

A single-page Flask app with three files of substance:

- **`app.py`** -- entire Python backend (~1,340 lines)
- **`static/js/app.js`** -- entire frontend (~1,810 lines, vanilla JS + D3.js v7)
- **`static/css/style.css`** -- dark GitHub-style theme (~1,130 lines)
- **`templates/index.html`** -- static HTML shell, no Jinja logic

D3.js v7 is bundled locally at `static/js/d3.v7.min.js` for air-gapped use; don't CDN-ify it.

### Backend (`app.py`)

**Data flow:** `POST /upload` -> save to `tempfile` -> `analyze_pcap()` per file -> `merge_results()` -> JSON response -> `GET /` renders the shell.

Key functions in call order:

| Function | Purpose |
|---|---|
| `analyze_pcap(filepath)` | Streams PCAP via scapy `RawPcapReader` with manual byte parsing (Eth/IP/IPv6/TCP/UDP/ICMP/ARP); builds `hosts` dict and `connections` defaultdict; calls protocol parsers on matching ports; caps at 1,000,000 packets and 50 stored packets per connection. DNS layer reconstructed from payload bytes only for port 53 traffic. ~30x faster than the old `PcapReader` approach. |
| `merge_results(results)` | Merges multiple `analyze_pcap` results for multi-file uploads; deduplicates anomalies |
| `analyze_anomalies(hosts, connections, packet_store)` | Detects port scans, cleartext credentials, beaconing (CV < 0.2), exfiltration (>10 MB to external), suspicious ports, OT/IoT-specific issues |
| `parse_http / parse_modbus / parse_mqtt / parse_coap` | Deep-inspection parsers called per packet when the port matches |

**Constants to know when adding protocols:**
- `PORT_MAP` -- maps port number -> `(protocol_label, host_type_hint)` for both TCP and UDP
- `MAC_VENDORS` -- OUI prefix -> vendor name (6 hex chars, no separators)
- `HOST_TYPE_PRIORITY` -- ordered list; first match wins during host classification
- `SUSPICIOUS_PORTS` -- set of ports that trigger `suspicious_port` anomaly

**Host classification** runs after the packet loop: TTL -> OS hint, then `host_type_hints` counter resolved against `HOST_TYPE_PRIORITY`.

**GeoIP** (`geo_lookup`) is optional; silently returns `None` if `geoip2` can't open `/usr/share/GeoIP/GeoLite2-City.mmdb`.

### Frontend (`static/js/app.js`)

**Global state:**
- `graphData` -- the parsed JSON from `/upload` (`nodes`, `edges`, `packets`, `anomalies`, `stats`)
- `packetData` -- packet drill-down data, keyed `"srcIP|dstIP"`
- `simulation` -- D3 force simulation instance
- `activeProtos` / `activeTypes` -- Sets driving sidebar filter visibility
- `currentView` -- `"graph"` | `"table"` | `"dns"` | `"ot"`
- `currentLayout` -- `"force"` | `"radial"` | `"cluster"`

**Rendering pipeline:** upload -> `renderGraph(data)` -> builds SVG nodes/edges -> `buildSidebar()` populates filter checkboxes -> `applyFilters()` shows/hides elements. Switching layouts calls `applyLayout()`.

**Node detail panel** (right sidebar): clicking a node populates `#detail-panel` with host metadata and a packet table for that connection. Protocol deep-inspection results (HTTP, Modbus, MQTT, CoAP) are rendered here.

**Color maps** (`HOST_COLORS`, `PROTO_COLORS`) at the top of `app.js` must stay in sync with any new host types or protocols added to `PORT_MAP`.

## Key limits (change in `app.py`)

| Limit | Default | Location |
|---|---|---|
| Max upload size | 1 GB | `app.config["MAX_CONTENT_LENGTH"]` |
| Max packets parsed | 1,000,000 | `MAX_PACKETS` in `analyze_pcap()` |
| Stored packets per connection | 50 | `MAX_STORED_PER_CONN` |
| Packet connections in output | top 40 by count | `top_conn_keys` slice |
| Ports per node in output | 30 | `sorted(...)[:30]` in serialisation |
