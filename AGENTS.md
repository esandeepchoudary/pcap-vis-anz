# AGENTS.md

This file provides guidance to coding agents when working with code in this repository. It's the canonical, detailed agent-facing doc — `CLAUDE.md` just points here (Claude Code looks for that filename by convention).

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

Minor changes (typo fixes, constant tweaks, CSS-only edits) can go directly on `master`.

Once a feature is fully implemented and tests pass, ask the user to review and merge the branch into `master`:

> "Feature is complete and tests pass. Please review and merge `feature/<name>` into `master` when ready."

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

Write unit tests in `tests/` (18 files, including `conftest.py`) using `pytest`. Tests cover:
- Protocol parsers (`parse_modbus`, `parse_dnp3`, `parse_s7comm`, HTTP/MQTT/CoAP, etc.) in `tests/test_parsers.py`, `tests/test_http_mqtt_coap.py`
- Anomaly detection rules (general + OT-specific) in `tests/test_anomalies.py`, `tests/test_anomalies_ot.py`
- Helper functions (`is_private`, `mac_vendor`, `geo_lookup`) in `tests/test_helpers.py`
- Credential extraction, file-transfer caching/extraction, VLAN handling, pcapng parsing, IPv6 extension headers, multi-file merge, output serialization, and `/upload` route behavior in the remaining `test_*.py` files

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

No build step for the Flask app itself. Changes to Python or JS/CSS take effect on the next request (Flask debug mode is on). `ruff` is listed in `requirements-dev.txt` as an available linter, though no `ruff.toml`/lint config exists yet — running it is optional, not enforced by any CI check.

## Architecture

A single-page Flask app with three files of substance:

- **`app.py`** -- entire Python backend (~3,785 lines)
- **`static/js/app.js`** -- entire frontend (~9,466 lines, vanilla JS + D3.js v7)
- **`static/css/style.css`** -- dark GitHub-style theme (~3,207 lines)
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

**Other routes** beyond `/` and `/upload`: `GET /download/<sha256>` serves a cached file transfer by hash; `GET /gpu-status` reports whether CUDA/cupy acceleration is available; `GET /session-schema` returns a real JSON Schema describing the `/upload` response shape (nodes/edges/anomalies/stats/etc.) -- fetch it directly rather than reverse-engineering the shape from `app.py` if you're integrating against the API.

### Frontend (`static/js/app.js`)

**Global state:**
- `graphData` -- the parsed JSON from `/upload` (`nodes`, `edges`, `packets`, `anomalies`, `stats`, `credentials`, `files`, `ot_commands`)
- `packetData` -- packet drill-down data, keyed `"srcIP|dstIP"`
- `simulation` -- D3 force simulation instance
- `activeProtos` / `activeTypes` -- Sets driving sidebar filter visibility
- `currentView` -- `"graph"` | `"table"` | `"dns"` | `"ot"` | `"otlog"` | `"vlangraph"` | `"diff"` | `"dashboard"` | `"findings"` (nine views total; see `setView()`)
- `currentLayout` -- `"force"` | `"radial"` | `"cluster"`

**Rendering pipeline:** upload -> `renderGraph(data)` -> builds SVG nodes/edges -> `buildSidebar()` populates filter checkboxes -> `applyFilters()` shows/hides elements. Switching layouts calls `applyLayout()`. Switching views calls `setView()`, which toggles both the active nav-tab class and the corresponding view container's visibility together (keep these coupled if you touch view-switching logic -- see the `.vt-btn.active` class toggle inside `setView()`).

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

## Beyond the core app

The repo also carries a documentation toolchain, generated by the [DocSolace](https://github.com/) Claude Code plugin -- not something you need to touch for a typical app change, but worth knowing about if a task involves docs:

- **`docs/`** -- generated Markdown: a product overview/getting-started/concepts/configuration/troubleshooting/changelog, plus one tutorial page per app feature (Graph, Table, DNS Map, OT Map, OT Log, VLAN, Diff, Dashboard, Findings, plus the upload flow itself), each with real screenshots under `docs/images/`. Never hand-edit these files outside a `<!-- docsolace:keep -->` region -- they're regenerated by `/document`. `docs/_sidebar.docsolace.json` drives the site's sidebar structure.
- **`site/`** -- a Docusaurus v3 site that serves `docs/` directly (no content duplication), deployed to GitHub Pages at https://esandeepchoudary.github.io/pcap-vis-anz/ via `.github/workflows/deploy-docs.yml` on every push to `master` that touches `docs/` or `site/`. `cd site && npm start` for a local live-reload preview.
- **`tours/`** -- YAML tour specs (one per feature) that drive the docs generation: which UI steps to capture, what to screenshot, etc.
- **`fixtures/network-capture-demo.pcap`** (+ `build_demo_pcap.py`) -- a synthetic demo capture (29 hosts, 31 anomalies across OT/IoT/VLAN/credential scenarios) used to drive the app for documentation screenshots, since almost nothing in the UI is visible without an uploaded capture.
- **`docsolace.config.yaml`** -- config for the doc-generation tooling itself (base URL, viewports, etc.) -- not app configuration.

If you're an agent invoked via the `docsolace:document` Claude Code plugin skill, see that skill's own instructions rather than this file for the doc-generation workflow.

## Other docs in this repo

- **`README.md`** -- the user-facing product README (features, installation, usage). Keep it current; see "Workflow" above.
- **`backlog.md`** -- a running log of completed work and open ideas, organized roughly chronologically by feature/date. Mostly a historical record at this point (235+ completed items vs. a handful open) -- check it for "is this already done" before assuming a feature doesn't exist.
- **`REVIEW.md`**, **`review-by-claude.md`** -- point-in-time security/logic audit reports (dated 2026-05-17 and 2026-06-15 respectively). Their file:line references drift as the code changes and are already stale relative to the current file sizes above -- useful for the *categories* of issues found, not as a current line-accurate map.
