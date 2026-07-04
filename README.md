# PCAP Network Visualizer

An interactive web-based tool for visualizing network packet captures. Upload a `.pcap`, `.pcapng`, or `.cap` file and explore your network as a live force-directed graph — with host classification, protocol detection, OS fingerprinting, and DNS resolution.

![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![Flask](https://img.shields.io/badge/flask-2.3%2B-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Interactive graph** — D3.js v7 force simulation with Force, Radial, and Cluster layout modes; drag, zoom, and pan
- **Host classification** — 38 host types: Router, PLC, IP Camera, Web Server, DNS Server, Windows Host, and more
- **Protocol detection** — 80+ protocols identified by port (HTTP, SSH, DNS, RDP, MySQL, Modbus, MQTT, CoAP, …)
- **IPv4 and IPv6 support** — both address families tracked; private ranges correctly classified (including IPv6 loopback, ULA, and the full `fe80::/10` link-local range); IPv6 nodes shown with a dashed-stroke ring; header adoption stat (`IPv6: X% (N/total)`) appears when both families are present; sidebar **IP Version** filter (shown only in mixed captures); IPv6 extension headers (hop-by-hop, routing, destination options, fragment, AH) are traversed so TCP/UDP ports are correctly identified even with extension headers present
- **OS fingerprinting** — TTL / hop-limit heuristic (Linux/Unix, Windows, Network Device)
- **MAC vendor lookup** — OUI lookup covering IT, OT, and IoT vendors (VMware, Cisco, Siemens, Amazon Echo, …)
- **DNS name resolution** — Extracts hostnames and query logs from captured DNS traffic
- **TLS inspection** — Parses TLS ClientHello to extract SNI (server name) and compute JA3 fingerprints; matches against a curated known-bad JA3 list to flag malware/C2 TLS sessions
- **Credentials extraction** — Captures cleartext credentials from HTTP Basic Auth, HTML form POSTs, FTP, Telnet, MQTT CONNECT, and CoAP; shown in sidebar with reveal-password toggle and exportable to CSV
- **Per-host risk score** — 0–100 composite score based on anomaly severity, OT write/error counts, internet exposure, and TLS anomalies; shown in node detail panel and ranked in the audit report
- **Filtering** — Filter graph by protocol or host type via sidebar checkboxes; selections saved to localStorage and restored on next load
- **Search** — Find nodes by IP address or hostname (300ms debounce); `/` keyboard shortcut focuses the search box
- **Detail panel** — Click any node to see host details (ports, services, traffic stats, DNS queries, TLS SNI names, anomalies, OT analysis, conversations, and captured credentials); safe copy buttons (⧉) next to IP, hostname, JA3 fingerprints, and SHA-256 hashes
- **Nine views** — Graph (network map), Table (sortable connection list), DNS Map (query explorer), OT Map (Purdue Model zone layout), OT Log (chronological OT command history), VLAN Graph (VLAN segment topology), Diff (baseline comparison), **Dashboard** (summary cards, risk-score bar chart, protocol distribution, clickable Top Anomalies list; key `8`), and **Findings** (analyst triage workspace; key `9`)
- **Findings workspace** — Automatically derives reviewable findings from anomalies, captured credentials, file transfers, OT write/error command groups, and high-risk hosts; supports status, severity override, analyst notes, report include/exclude, evidence-copy bundles, graph/packet navigation, and false-positive suppression.
- **Light/dark mode** — ☀/☾ toggle in header; full CSS variable override for both themes; persisted in localStorage with FOUC prevention
- **Collapsible sidebar** — `‹`/`›` toggle button collapses the sidebar to a 32 px icon rail; state persisted in localStorage
- **Packet inspector search** — live-filter input above the packet table; matches any column text; shows `N / M` count badge; clears when switching connections
- **Filter presets** — save the current protocol + host-type filter selection as a named preset; chip list in sidebar with one-click load and delete; stored in localStorage across sessions
- **Colour-blind safe palette** — ◑ button in graph controls switches all node and edge colours to a deuteranopia-safe palette (greens → teal, reds → orange); persisted in localStorage
- **Stats sparkline** — 48×12 px inline SVG bar chart next to the Packets stat shows packet-density distribution across the capture duration
- **Expanded right-click menu** — "Highlight Anomalies" fades all non-anomaly nodes for immediate triage focus; "Open in Table" switches to the connection table pre-filtered to that node's IP
- **VLAN identification** — Full 802.1Q single-tag and 802.1ad QinQ double-tag parsing: extracts VLAN ID, PCP priority bits, DEI bit, and outer/inner VIDs for QinQ; tracked per host, per connection, and aggregated in stats.
  - **VLAN Graph view** — dedicated tab showing VLANs as super-nodes with convex-hull cluster polygons; hosts clustered inside; multi-VLAN (hopping) hosts physically placed between segments; cross-VLAN traffic shown as red edges; inter-VLAN gateway nodes marked with a GW badge; **host nodes now show the same host-type emoji icons as the main Graph view** (🌐 web server, ⚙️ PLC, 📷 IP camera, …)
  - **VLAN security analysis** — segmentation score (0–100 with Good/Fair/Poor/Critical rating), ARP spoofing detection per-VLAN, broadcast storm detection (>10% broadcast threshold), PCP priority abuse detection; 4 VLAN anomaly rules (hopping, native leak, QinQ, cross-segment OT)
  - **VLAN data enrichment** — VLAN-to-subnet mapping, CDP/LLDP frame parsing (extracts device hostname and native VLAN from Cisco Discovery Protocol and IEEE 802.1AB switch frames), per-VLAN aggregate risk score, VLAN sprawl metrics (singleton/isolated VLANs)
  - **VLAN exports** — VLAN Inventory CSV (14 columns per host per VLAN), VLAN Traffic CSV (with source/dest VLAN and cross-VLAN flag), VLAN Diagram SVG, VLAN Matrix PNG (active view or all 4 views sequentially, each with title/legend bands), VLAN sections in Markdown audit report, VLAN name CSV import
  - **VLAN UX** — color-by-VLAN toggle in main graph, VLAN search in VLAN tab toolbar, user-assigned VLAN labels (double-click to rename, persisted in localStorage), VLAN health summary card in sidebar, ⊞ Matrix view (VLAN×VLAN flow adjacency grid), VLAN spotlight (one-click filter main graph to single VLAN), VLAN change detection column in ⊕ Diff view, per-VLAN bandwidth stacked timeline minimap
  - **VLAN flow matrix — 4 views** — the ⊞ Matrix toggle now offers a segmented switcher with four modes: **Traffic** (cell brightness = log-scaled flow volume, with a Bytes | Packets sub-toggle and in-cell totals), **OT/ICS** (orange heat on VLAN pairs carrying OT/ICS protocol traffic, orange cell border when OT writes cross the boundary, gray for traffic-but-no-OT pairs), **Anomalies** (cell color = worst severity across all anomaly types — not just cross-segment OT — with in-cell anomaly count; single-host anomalies like port scans land on the diagonal), and **Protocol** (dominant protocol per pair, with a legend listing every protocol color shown plus the cross-VLAN OT-anomaly swatch). Each mode has its own hover tooltip and legend. Cell attribution now uses each host's **full VLAN membership** (not just its first VLAN), matching the totals shown in the VLAN graph view's cross-link tooltips — multi-VLAN hosts contribute to every membership pair. Cell size scales to fill the available pane width (up to 110px per cell for ≤20 VLANs), and small (few-VLAN) matrices are centered rather than stuck in the top-left corner. Every view can be exported as a self-describing, high-resolution PNG (title header + legend footer band, minimum 2x pixel density regardless of display) via the toolbar's **⤓ PNG** button (Shift-click, or the global Export menu's "…(all views)" item, exports all four views sequentially)
  - **File transfer downloads** — HTTP files captured in PCAPs are available for download directly from the File Transfers sidebar panel (size-bounded LRU in-memory cache, 256 MB cap, download links survive subsequent uploads)
- **OT Map** — Full Purdue Model swimlane view (L0 Field → L6 Public Internet) with automatic Public Internet zone for non-RFC1918 IPs (no GeoIP required), D3 zoom/pan (Ctrl+scroll, toolbar buttons), traffic-weighted edges, anomaly callouts (! badge on affected nodes, lane tint for high-severity), cross-zone vs. cross-level edge counting, zone legend, Purdue level tooltips, activeTypes filter integration with sidebar bypass toggle ("Respect filters" button), OT protocol evidence-based Purdue level assignment, and editable mode: drag-to-reclassify, add/remove devices (IP format + Purdue level validation with inline error), risk annotation (Critical → Info, panel positioned near clicked node), and PNG/JSON export
- **OT Communication Matrix** — Toggle within the OT Map view (⊞ Matrix button) to switch to a device×device adjacency matrix: each cell is coloured by dominant OT protocol, orange for cross-zone traffic, and red-bordered when an anomaly is present; hover for packet count, byte total, OT read/write counts, and cross-zone/anomaly warnings
- **Timeline** — Two-handle brush for selecting an arbitrary time window (drag either end to resize, drag the blue selection to move); auto-play slides the window forward; speed selector (0.5×, 1×, 2×, 5×); abs/rel toggle switches between `HH:MM:SS–HH:MM:SS` and `+Ns–+Ns`; Space to play/pause, ←/→ shift the window
- **Graph power features** — Node pinning (select node → press P; dashed yellow ring; drag to reposition; right-click → Unpin All); isolate mode (double-click a node to show only it + direct neighbours; double-click again to restore); minimap (150×100 overview, bottom-right, drag to pan); edge packet-count labels on hover; keyboard shortcuts overlay (press ?); **cluster collapse** (⊕ button enters cluster mode — click any host-type label in sidebar to collapse that type into a centroid chip, click chip to re-expand)
- **Keyboard shortcuts** — Press `?` to open the overlay: `1`–`9` switch views, `F` fits graph, `/` focuses search, `Space`/`←`/`→` control timeline brush, `P` pins selected node, `Esc` closes panels
- **Inline anomaly explanations** — Every anomaly badge has an `ℹ` button; clicking it expands a "What / Why / Steps" panel covering all 30+ anomaly types with remediation guidance
- **Packet inspector** — Click any edge or node to open a Wireshark-style panel with three tabs: **Packets** (per-packet protocol tree and protocol-coloured hex dump — each layer highlighted in a distinct colour), **Cmd Log** (OT command history for OT connections), and **Stream** (ASCII/hex payload reassembly for TCP sessions); **⧉ float button** detaches the inspector into a resizable draggable overlay; **⊡** re-docks it; live packet search with `N / M` count badge across the full packet list (not just the first page)
- **OT Analysis panel** — Per-node read/write/error ratio bar, master/outstation role badge, Modbus unit IDs, DNP3 link addresses
- **Exports** — PNG graph screenshot, **Connections CSV** (every connection with source/dest country), **Hosts Inventory CSV** (one row per IP with country in "Name (CC)" format), **Anomalies CSV** (with source/dest country), **Credentials CSV** (with source/dest country), Markdown audit report (curated findings, capture summary, geographic distribution of external endpoints, risk ranking, anomalies by severity, OT inventory, VLAN device inventory, VLAN traffic by VLAN, TLS/SNI observations, captured credentials, file transfers, OT write log), **VLAN Inventory CSV** (with country), **VLAN Traffic CSV** (with source/dest country), VLAN Diagram SVG; all CSV exports always contain the complete dataset even when the graph only renders a top-N subset
- **File transfer detection** — Detects HTTP file downloads (Content-Disposition: attachment + interesting Content-Type); sidebar "File Transfers" panel with filename, MIME, size, SHA-256 hash, safe copy/download controls, and production-tested extraction helper; 200 files/capture, 500/merge (deduped by hash)
- **PCAP baseline diff** — "Set Baseline" button in header; upload a second PCAP and open the "⊕ Diff" tab to compare: new/disappeared hosts (with specific change labels: type change, risk delta >20, new protocols, new ports), new connections with protocols, traffic-volume changes (>2× or <0.5× packet ratio), and new anomalies vs baseline; four-column diff view, no server round-trip
- **Session save / load** — Export full analysis, findings, and analyst triage edits to JSON and reload without re-uploading the capture file; older or partial session JSON is normalized on load so missing optional fields do not break the UI
- **Node annotations** — Right-click any node to attach a persistent note using the in-app note modal (stored in browser localStorage)
- **Anomaly detection** — 32 detection rules across general network, OT/ICS, IoT, and VLAN threat categories
- **Large capture support** — Streams up to 1,000,000 packets without loading into memory (up to 100 files · 1 GB total per upload); multi-file uploads processed in parallel
- **Performance-optimised parsing** — C-level MAC/IPv4 formatting (`bytes.hex`, `socket.inet_ntoa`), branch-compare `conn_key`, hoisted broadcast flag, module-level compiled regexes, and O(C) risk-scoring via a per-IP connection index (replaces prior O(H×C) double-scan); frontend canvas tick uses a cached visible-node set and precomputed per-edge colour/width, minimap throttled to every 5th tick, `applyFilters` folded to a single DOM pass

## Anomaly Detection

32 detection rules fire automatically after analysis:

**General network**
- Port scan — single source contacting >5 IPs across >15 unique ports
- Cleartext credentials — FTP or Telnet traffic with payload
- **Password reuse** — same password observed across 2+ protocols or destination hosts
- Beaconing — connection with highly regular inter-packet timing (coefficient of variation < 0.2)
- Data exfiltration — host sending >10 MB to a non-private IP
- Suspicious ports — known C2/hack-tool ports (4444, 1337, 31337, 6666, 6667)
- **Known-bad TLS fingerprint** — JA3 hash matches a curated list of malware/C2 tool signatures (Cobalt Strike, Metasploit, AsyncRAT, and others)

**OT / ICS**
- Modbus write commands (FC 5/6/15/16) — unauthorized PLC writes
- **Modbus bulk register read** (FC 3/4 with quantity >100) — large scan indicates reconnaissance
- **Modbus broadcast** (unit_id=0) — command targets every PLC on the segment
- **Modbus exception response** — illegal function/address errors indicate bad commands or failed access attempts
- DNP3 control/operate commands (Direct Operate, Select-Before-Operate, Cold/Warm Restart)
- **DNP3 unusual function codes** (FC 4 Immediate Freeze Without Reply, FC 14 Warm Restart) — evasion/persistence patterns
- S7comm Write Variable and PLC Stop / PI Service commands
- **S7 code download** (Request Download FC) — PLC logic is being modified; block type and number extracted
- EtherNet/IP CIP Write Tag / Set Attribute operations
- IEC 60870-5-104 command activation (Type IDs 45–50 with COT=Activation)
- BACnet writeProperty / reinitializeDevice / deviceCommunicationControl
- OT device communicating with an internet host
- Cleartext OT protocols (Modbus, DNP3, S7, BACnet have no encryption)
- **Multi-unit Modbus polling** (≥5 distinct unit IDs from one host) — network mapping of PLC segments

**IoT**
- Cleartext MQTT (port 1883) — credentials and sensor data unencrypted
- Telnet access to an IoT device — classic Mirai botnet vector
- IP Camera sending data to an external IP — unauthorized stream or C2
- TR-069 (port 7547) — remote management protocol frequently exploited

**VLAN**
- Host seen on multiple VLANs — non-routing host tagged with 2+ VLAN IDs; possible VLAN hopping attack
- Untagged + tagged frame mix — same host sending both untagged and tagged frames; possible native VLAN leakage
- QinQ (double-tagged) frames — 802.1ad outer tag detected; legitimate in carrier networks but a classic VLAN-hopping vector
- Cross-VLAN OT traffic — OT/ICS device communicating with a host on a different VLAN; segmentation violation
- **ARP spoofing within VLAN** — same IP seen with 2+ different MACs on the same VLAN; possible ARP poisoning or MAC flapping
- **Broadcast storm** — VLAN with >10% broadcast traffic (and >50 broadcast packets); misconfiguration or loop
- **PCP priority abuse** — end-host (Windows PC, IP camera, IoT sensor) sending frames tagged with PCP ≥ 6 (network-control priority); unexpected QoS manipulation

All anomalies are shown in the sidebar and on the node detail panel; affected nodes pulse with a coloured ring (red = high, yellow = medium).

## OT/ICS Protocol Support

The visualizer detects and classifies industrial control system devices and protocols:

**Supported protocols:** Modbus TCP, EtherNet/IP, Siemens S7comm, DNP3, IEC 60870-5-104, BACnet, OPC-UA, MQTT, PROFINET, HART-IP, GE SRTP, OMRON FINS, Emerson DeltaV

**OT device types:** PLC, RTU, IED, HMI, SCADA Server, DCS, Historian, Engineering Workstation, Building Controller, IoT Gateway, Field Device

**OT vendor fingerprinting:** Rockwell Automation, Siemens, Schneider Electric, ABB, Emerson, GE Digital, Honeywell, Yokogawa, WAGO, Phoenix Contact, Mitsubishi Electric, Omron, Beckhoff, Moxa

**OT-specific anomaly detection:**
- Modbus write commands (FC 5/6/15/16) — unauthorized PLC writes
- DNP3 control/operate commands (Direct Operate, Select-Before-Operate, Cold/Warm Restart)
- S7comm Write Variable, PLC Stop, and PI Service (Start/Stop) commands
- EtherNet/IP CIP Write Tag / Set Attribute operations
- IEC 60870-5-104 command activation (Type IDs 45–50 with COT=Activation)
- BACnet writeProperty / reinitializeDevice / deviceCommunicationControl
- OT device exposed to internet traffic
- Cleartext OT protocols (Modbus, DNP3, S7, BACnet have no encryption)

**OT Topology:**
- **OT Map view** — Full Purdue Reference Model swimlane layout (L0 Field → L6 Public Internet) with:
  - Zone grouping brackets: **Public Internet** (L6, non-private IPs), **IT Zone** (L4–L5), **Industrial DMZ** (L3.5), **OT Zone** (L0–L3)
  - **Public Internet zone** — all non-RFC1918 IP addresses are automatically placed here, no GeoIP database required; zone is suppressed when only private IPs are present
  - IT/OT demarcation line between L3.5 and L4
  - Level subtitles describing what each Purdue level represents
  - Device counts per lane
  - **Unclassified lane** for devices that don't map to a known Purdue level
  - **Bridge-node detection**: devices spanning OT↔IT/Internet zones highlighted with orange pulsing rings
  - Cross-zone edge highlighting (orange dashed lines); OT→Internet edges flagged as critical cross-zone
  - Hover tooltips showing IP, type, Purdue level, protocols, and connection count
  - `purdue_level` field on every node in the `/upload` JSON response
  - **Editable mode** (✎ Edit button) — drag nodes between Purdue lanes to reclassify, add/remove devices manually, annotate nodes with Critical/High/Medium/Low/Info risk labels (colour ring + badge), then export the annotated map as a **PNG** or structured **JSON**
- **Purdue level badge** — shown in the node detail panel for every device
- **Cross-zone edge highlighting** — dashed orange edges in the graph view for any connection spanning Purdue levels
- **Engineering Workstation auto-detection** — hosts that initiate S7 Download sessions are automatically reclassified from unknown to Engineering Workstation

**OT Analysis (per-node detail panel):**
- Role badge — master / outstation / unknown derived from DNP3 direction bits and Modbus traffic patterns
- Read/Write/Error ratio bar — aggregate OT operation counts across all connected edges
- Modbus unit IDs polled — reveals which PLC slaves a host queries
- DNP3 link-layer addresses seen

**Protocol deep inspection (packet detail panel + Command Log tab):**
- **Modbus TCP**: Function codes, unit ID, register/coil address, quantity, exception code and name; write commands flagged in red
- **DNP3**: Link-layer src/dst addresses, application function code, explicit master/outstation role, data object group (12 groups: Binary Output Control, Analog Input, Class Objects, …)
- **S7comm**: ROSCTR message type, PDU reference, function code; block type (OB/DB/FC/FB/SFB/SFC) and block number extracted on Download operations
- **EtherNet/IP**: Encapsulation command, session handle, CIP service code and name
- **IEC 60870-5-104**: Frame type (I/S/U), ASDU type ID, Cause of Transmission (COT), common address
- **BACnet/IP**: BVLC function, APDU PDU type, confirmed/unconfirmed service name

**OT Command Log** — dedicated tab in the packet inspector (visible on OT connections only) showing a compact chronological table: time, protocol, direction arrow, function name, address/block detail, and OK/ERR result

## IoT Device Support

**Supported protocols:** MQTT, MQTT-TLS, CoAP, CoAP-DTLS, AMQP, AMQPS, XMPP, RTSP, Matter, WS-Discovery, TR-069, Tuya-IoT, Hikvision, Dahua, DLMS (smart meters)

**IoT device types:** IP Camera, Smart Home Hub, Smart Meter, IoT Sensor, Smart Speaker, IoT Gateway, CPE Device

**IoT vendor fingerprinting (MAC OUI):** Amazon Echo, Google Home/Nest, Philips Hue, Samsung SmartThings, Ring, Wyze, TP-Link Kasa, Tuya Smart, Shelly, Particle, Fitbit, LIFX, August Smart Lock

**IoT-specific anomaly detection:**
- Cleartext MQTT (port 1883) — credentials and sensor data unencrypted
- Telnet access to IoT devices — classic Mirai botnet attack vector
- IP Camera sending data to external IPs — unauthorized streams or C2
- TR-069 (port 7547) — remote management protocol frequently exploited

**Protocol deep inspection:**
- **MQTT**: Decodes message type (CONNECT/PUBLISH/SUBSCRIBE), client ID, topic names, payload preview, QoS level, credential presence
- **CoAP**: Decodes message type (CON/NON/ACK), method/response code, URI path, payload preview

## Requirements

- Python 3.8+
- pip

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/esandeepchoudary/pcap-vis-anz.git
cd pcap-vis-anz
```

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note for Kali / Debian systems** — if pip complains about externally managed environments, add `--break-system-packages`:
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

## Usage

```bash
python app.py                # localhost only (default, safe)
python app.py --public       # expose to your local network — see warning below
python app.py --port 8080    # use a different port
```

Then open your browser and go to `http://localhost:5000` (or your machine's LAN IP if `--public` was used).

> **Security note — `--public` flag:** This flag binds the Werkzeug **development** server to `0.0.0.0`, making it reachable from other devices on your network. The development server is **not hardened** for production use. Anyone on the same network can upload arbitrary files to this process. Use `--public` only on fully trusted, isolated networks (e.g. a dedicated analysis VLAN). For long-running or multi-user deployments, run behind gunicorn instead:
> ```bash
> pip install gunicorn
> gunicorn -w 2 -b 0.0.0.0:5000 'app:app'
> ```

Upload a capture file (`.pcap`, `.pcapng`, or `.cap`, up to 1 GB) and the graph will render automatically.

## Capturing your own traffic

If you don't have a capture file handy, you can create one with `tcpdump` or Wireshark:

```bash
# Capture 60 seconds of traffic on any interface
sudo tcpdump -i any -w capture.pcap -G 60 -W 1

# Or capture on a specific interface
sudo tcpdump -i eth0 -w capture.pcap
```

Sample `.pcap` files are also available at [https://www.malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) and the [Wireshark sample captures page](https://wiki.wireshark.org/SampleCaptures).

## Project Structure

```
pcap-vis-anz/
├── app.py                  # Flask backend + PCAP parser (scapy)
├── requirements.txt        # Python dependencies
├── data/
│   ├── dbip-country-lite.mmdb  # Bundled DB-IP Country Lite GeoIP DB (CC BY 4.0)
│   └── DB-IP-LICENSE.txt       # Attribution and refresh instructions
├── templates/
│   └── index.html          # Single-page app shell
├── static/
│   ├── css/style.css       # Dark GitHub-style theme
│   └── js/app.js           # D3.js force graph + UI logic
└── tests/
    ├── conftest.py            # Shared pytest fixtures and packet builders
    ├── test_parsers.py         # Protocol parser unit tests (Modbus, DNP3, S7, CoAP, …)
    ├── test_anomalies.py       # Anomaly detection rule tests
    ├── test_anomalies_ot.py    # OT/IoT anomaly rule tests (Modbus writes, DNP3 control, S7, EtherNet/IP, IEC-104, BACnet, IoT)
    ├── test_credentials.py     # Credential extraction tests
    ├── test_file_cache.py      # Captured file download-cache tests
    ├── test_file_extraction.py # HTTP file transfer detection tests
    ├── test_frontend_findings_static.py # Static frontend regression tests
    ├── test_geoip.py           # GeoIP bundled-DB and geo_lookup() tests
    ├── test_helpers.py         # Helper function tests (is_private, mac_vendor, geo_lookup)
    ├── test_http_mqtt_coap.py  # HTTP / MQTT / CoAP parser tests
    ├── test_ipv6_ext_headers.py # IPv6 extension-header parsing tests
    ├── test_merge.py           # Multi-file merge tests
    ├── test_pcapng.py          # pcapng parse and parity tests
    ├── test_routes.py          # /upload endpoint HTTP tests (happy path, errors, file count cap)
    ├── test_serialization.py   # Output schema and truncation-flag tests
    ├── test_vlan.py            # VLAN parsing, merge, stats, and anomaly tests
    └── test_utils.py           # Utility function tests
```

## Testing

```bash
pip install pytest            # or: pip install -r requirements-dev.txt
pytest tests/ -q
```

The suite contains 354 tests across 18 files covering protocol parsers, anomaly detection (including all 16 OT/IoT rules), credential extraction, file transfer detection, multi-file merging, full-fidelity serialization (no port/DNS truncation), GeoIP bundling, frontend regression guards, and the `/upload` HTTP endpoint.

## Configuration

| Setting | Default | Description |
|---|---|---|
| `MAX_UPLOAD_FILES` | 100 | Maximum files per upload request |
| `MAX_CONTENT_LENGTH` | 1 GB | Maximum total upload size |
| `MAX_PACKETS` | 1,000,000 | Packets processed per file |
| `MAX_HOSTS` | 250,000 | Backstop — max unique hosts per file (parse-time safety guard; rarely hit) |
| `MAX_CONNECTIONS` | 1,000,000 | Backstop — max unique IP-pairs per file (parse-time safety guard; rarely hit) |
| `MAX_STORED_PER_CONN` | 50 | Packets stored per connection for the inspector |
| `_FILE_CACHE_MAX_BYTES` | 256 MB | Memory budget for captured file bodies |
| `RENDER_NODE_CAP` | 1,500 | Max SVG node groups drawn in the force graph (see below) |
| `RENDER_EDGE_CAP` | 4,000 | Max edges drawn (SVG/canvas) in the force graph |
| `MAX_CRED_STATE_ENTRIES` | 5,000 | Half-open credential state entries per protocol (Telnet, FTP, etc.); module-level so it can be overridden in tests |

### Full-fidelity exports vs. render caps

The backend parses and serializes **all** hosts and connections up to the backstop limits. CSV exports (Connections, Hosts Inventory, VLAN Inventory, VLAN Traffic) always use the full dataset — no connection or IP is omitted from an export due to UI rendering decisions.

When a capture contains more than `RENDER_NODE_CAP` hosts, the graph view renders only the top-N by traffic and shows a blue banner: *"Graph shows top N of M hosts — exports contain the full dataset."* The **Table view** and all CSV exports still reflect every host and connection. The `stats.hosts_truncated` / `stats.connections_truncated` flags in the `/upload` JSON response are `true` only when the parse-time backstop limits (250k hosts / 1M connections) are actually exceeded.
| Connections in inspector | top 40 | Connections with packet detail (by packet count) |
| Ports shown per node | 30 | Open ports listed in the detail panel |
| DNS names per node | 5 | Resolved hostnames shown in the detail panel |
| DNS queries per node | 10 | DNS queries shown in the detail panel |
| Port | 5000 | HTTP port (`--port` flag) |

## Security & self-containment

This tool is designed for **air-gapped / offline use**:

- D3.js v7 is bundled locally — no CDN requests
- **GeoIP database bundled** — [DB-IP Country Lite](https://db-ip.com) (CC BY 4.0) ships as `data/dbip-country-lite.mmdb`; no internet connection or MaxMind account required. Country names, ISO codes, and flag emoji work out of the box. Attribution: *IP Geolocation by DB-IP*.
- CSS uses system fonts only — no Google Fonts
- The only outbound browser request is `POST /upload` to the same origin
- PNG export uses `blob:` URLs — no third-party image host

**Using a richer GeoIP database:** The bundled DB-IP Country Lite resolves country only (city names are absent). If you have a city-level database (`GeoLite2-City.mmdb` or `dbip-city-lite.mmdb`), you can point the app at it:

```bash
# Environment variable (works with both python app.py and gunicorn)
GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb python app.py

# Or place it at the default system path (checked before the bundled DB)
/usr/share/GeoIP/GeoLite2-City.mmdb
```

**Refreshing the bundled database:** DB-IP releases free monthly updates.

```bash
YYYYMM=2026-07  # update to the target month
curl -L -o /tmp/dbip.mmdb.gz \
  "https://download.db-ip.com/free/dbip-country-lite-${YYYYMM}.mmdb.gz"
gunzip -c /tmp/dbip.mmdb.gz > data/dbip-country-lite.mmdb
```

HTTP security headers are set on every response (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`). The app binds to `127.0.0.1` by default so it is not reachable from the network. Pass `--public` to bind to `0.0.0.0` for LAN access — only do this on trusted networks, as the app processes potentially sensitive capture files.

Robustness hardening applied in v0.9: all API endpoints return JSON errors (including 413/404/500), captured file bodies are memory-bounded (256 MB cache), connection/host/DNS/credential-state tables are capped, download filenames are sanitised with `secure_filename`, and the session-import validator rejects non-array shapes before they reach the renderers.

## Troubleshooting

**`scapy` import error** — Make sure you installed dependencies inside the correct Python environment (or virtualenv).

**Permission denied reading pcap** — Some systems require root to read certain capture files. Try `sudo python app.py`.

**Graph is empty after upload** — The file may contain only non-IP traffic (e.g. pure Bluetooth or USB captures). The tool supports IPv4, IPv6, and ARP packets.

**Very large files are slow** — Only the first 1,000,000 packets are processed. For faster results, pre-filter with `tcpdump`:
```bash
tcpdump -r big.pcap -w filtered.pcap 'tcp or udp'
```

## License

MIT
