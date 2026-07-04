# Backlog

## Completed

- [x] Bug sweep: Partial/older session JSON is normalized at `loadGraph()` entry, including safe defaults for stats, nodes, edges, anomalies, packets, credentials, file transfers, OT commands, and warnings
- [x] Bug sweep: Frontend filter, legend, connection-table, and VLAN-export paths no longer directly dereference missing `graphData.stats` fields
- [x] Bug sweep: `/upload` frontend error handling reads the response body once as text, preserves non-JSON server diagnostics, and parses JSON manually to avoid empty single-use response bodies
- [x] OT Map: Fix undefined CSS variables `--bg1` / `--text1` (caused white patch in dark mode)
- [x] OT Map: Add D3 zoom + pan (Ctrl+scroll to zoom, drag to pan, +/−/⊡ toolbar buttons)
- [x] OT Map: ResponsiveObserver — SVG re-renders on container resize and detail-panel close
- [x] OT Map: Replace native SVG `<title>` tooltips with styled `#tooltip` div
- [x] OT Map: Highlight connected edges and dim unconnected on node hover
- [x] OT Map: Traffic-weighted edges — stroke width scales with `packet_count` (log scale)
- [x] OT Map: Anomaly callouts — `!` badge on nodes from `anomalyNodeIps`, lane tint for high-severity
- [x] OT Map: Legend — zone colour swatches, risk-level dots, bridge ring, edge type samples
- [x] OT Map: Risk annotation panel positioned near clicked node (viewport-clamped)
- [x] OT Map: Edit-mode hint bar with instructions; dismiss button; hint bar hidden by default
- [x] OT Map: Distinguish cross-zone (security boundary) vs cross-level (same zone) stats chips
- [x] OT Map: Suppress empty Unclassified zone from rendering
- [x] OT Map: Respect sidebar `activeTypes` filter; "filtered" chip when active
- [x] OT Map: Purdue level tooltips on lane label text elements
- [x] OT Map: `alert()` in Add Device replaced with inline `#ot-am-error` element
- [x] Backend: `purdue_level_py()` uses OT evidence (ot_role, modbus_unit_ids, dnp3_addresses) to demote L4→L3
- [x] Backend: `merge_results()` now outputs `purdue_level` for merged nodes
- [x] Frontend: `purdueLevel()` mirrors OT evidence demotion logic
- [x] OT Map: Public Internet zone (L6) — all non-RFC1918 IPs automatically placed in a top "Public Internet" lane; no GeoIP database required; zone suppressed when only private IPs present; OT→Internet edges flagged as critical cross-zone
- [x] UI: "Clear all filters" button — one click to reset protocols + host types + search back to defaults
- [x] UI: Zero-results feedback — inline message when search/filter combination hides all nodes
- [x] UI: Toast notifications — replaced all `alert()` calls with auto-dismissing toasts (4 s)
- [x] UI: Active filter count badge on Protocols / Host Types section headers
- [x] UI: Fit-to-visible after filtering — auto-zoom to visible node set
- [x] Performance: Progress bar during large PCAP parsing (streaming status instead of blank spinner)
- [x] Performance: Virtual scrolling in connection table and packet inspector (windowed rendering)
- [x] Performance: Anomaly deduplication summary — collapses repeated same-source anomalies into one entry
- [x] Performance: Replace `PcapReader` with `RawPcapReader` + manual byte parsing in `analyze_pcap()` hot loop (~30× speedup; 150K-packet capture: ~44s → ~1.5s)
- [x] VLAN: Full 802.1Q + 802.1ad QinQ parsing (VID, PCP, DEI); per-host and per-edge tracking; VLAN filter in sidebar; VLAN section in host detail panel; VLANs stat in header; 4 new anomaly rules (hopping, native leak, QinQ, cross-segment OT); dedicated VLAN Graph view (VLANs as super-nodes, hosts clustered inside, cross-VLAN traffic highlighted in red)
- [x] VLAN graph overhaul: multi-VLAN host membership (hopping hosts sit between segments); generalized cross-VLAN edge builder (all src×dst VLAN pairs); rich node decorations via shared `appendNodeDecorations` helper (anomaly rings, risk/cred glyphs, host icons, risk badges); shared tooltip helpers; neighbor highlighting + selection state; super-node click → VLAN detail panel (PCP dist, QinQ, cross-VLAN partners, member host list); stats bar (cross-VLAN flows/bytes, untagged/hopping counts); legend entries for cross-VLAN edge and untagged; hash-based `vlanColor` (no palette collisions)
- [x] IPv4/IPv6 filtering: `ip_version` per node + `ip_versions`/`has_untagged`/`ipv4_count`/`ipv6_count` in stats (both `analyze_pcap` and `merge_results`); IP Version sidebar filter (shown only when both present); `applyFilters` and table filter honour it; IPv6 dashed-stroke node distinction; header IPv6 adoption stat
- [x] VLAN exports: two new Export dropdown items (Export VLAN Inventory CSV, Export VLAN Traffic CSV); `exportVlanInventoryCsv()` emits one row per (VLAN, host) pair with 14 columns; `exportVlanTrafficCsv()` emits flat table with Source/Dest VLAN columns and Cross-VLAN flag; audit report gains "VLAN Device Inventory" section (per-VLAN host tables) and "IP-to-IP Traffic by VLAN" section (grouped by VLAN, capped at 100/group), plus VLANs-detected row in Capture Summary

## Navigation & Discoverability

- [x] Collapsible sidebar — toggle arrow (`‹`/`›`) collapses sidebar to 32 px; state persisted in localStorage
- [x] Keyboard shortcuts — F = fit graph, 1–8 = switch views, / = focus search, Esc = close; `?` overlay lists all shortcuts
- [x] Expanded right-click context menu — Highlight Anomalies (fades non-anomaly nodes), Open in Table (switches view and pre-filters to that node's IP)
- [x] Breadcrumb / back button when jumping from anomaly sidebar → node → packet inspector — `showDetailPanel` accepts `navCtx`; breadcrumb bar shows "Anomalies › <type> › <ip>" with back-arrow
- [x] View-specific empty states for DNS Map and OT Map before upload (illustrated placeholder) — `#dns-empty-state` / `#ot-empty-state` divs shown via `setView()` when no data loaded

## Graph View

- [x] Node pinning — select a node and press P to lock position; dashed yellow ring; drag updates pin; Unpin All in right-click menu
- [x] Minimap — 150×100 overview thumbnail (bottom-right) with viewport rectangle; drag to pan; live sync with simulation
- [x] Isolate mode — double-click a node to show only it + direct neighbours; double-click again to restore
- [x] Edge label on hover — inline packet count label at edge midpoint; hidden in canvas mode (>150 nodes)
- [x] Cluster expand / collapse — ⊕ button in graph controls enters cluster mode; click a host-type label in sidebar to collapse that type into a centroid chip overlay; click chip to expand; mode indicator and localStorage-free toggle

## Packet Inspector & Detail Panel

- [x] Protocol-coloured hex dump — byte regions highlighted by layer (Ethernet / IP / TCP / payload); backend emits start/end byte offsets per layer; frontend builds per-byte color array and wraps hex bytes in colored spans
- [x] Copy buttons next to IP addresses, hostnames, JA3 fingerprints, and SHA-256 hashes in detail panel and files sidebar
- [x] Floating inspector mode — ⧉ button in packet inspector header detaches to fixed overlay; draggable via resize handle; ⊡ button re-docks; docking restores graph-wrap layout
- [x] Search within packet list — live-filter input above packet table; shows `N / M` count badge; clears on new connection open

## Timeline

- [x] Brush selection on timeline — two-handle range brush replaces single slider; select an arbitrary time window; play advances the window; ←/→ shift the window; blue selection highlight overlay
- [x] Playback speed control — 0.5×, 1×, 2×, 5× selector next to the play button
- [x] Timestamp format toggle — "abs" button switches between UTC HH:MM:SS and relative +Ns format

## Polish & Accessibility

- [x] Persistent filter state — last-used protocol/host-type selections saved to localStorage; restored on next load
- [x] Light / dark mode toggle — ☀/☾ button in header; CSS variable overrides for full dark/light switch; persisted in localStorage; FOUC-prevention inline script
- [x] Stats bar sparklines — 48×12 px inline SVG bar chart (60 bins) next to Packets stat; shows packet density over capture time
- [x] Colour-blind safe palette option — ◑ button; deuteranopia-safe overrides (greens→teal, reds→orange); re-colors all graph nodes + filter swatches; persisted in localStorage

## Bigger Ideas

- [x] PCAP diff / comparison mode — upload two files and highlight added hosts, connections, anomalies
- [x] Saved filter presets — name and save a filter combination for one-click recall; presets stored in localStorage; chip list in sidebar with delete buttons; auto-shown when at least one preset exists
- [x] Inline anomaly explanation panel — ℹ button on every anomaly badge expands a "What / Why / Steps" explanation covering all ~30 anomaly types; toggles closed with a second click
- [x] Dashboard / summary view — 8th view tab (⊛ Dashboard); 5 summary cards (hosts/connections/packets/anomalies/protocols); top-10 risk-score horizontal bar chart; protocol distribution bars; anomaly severity chips (High/Med/Low/Info counts); busiest-connections list; clicking a risk-bar row jumps to graph and highlights the node; key shortcut: 8
- [x] Dashboard Top Anomalies panel — lists up to 6 highest-severity anomaly groups (sorted high→info, then by count); each row shows a severity dot + human-readable summary reusing `_anomalySummary()`; clicking any row calls `_jumpToAnomaly()` to navigate to the graph, select the source node, and open the detail panel; "+N more" footer when findings exceed the display limit; empty state "No anomalies detected"
- [x] Raise multi-file upload cap to 100 — backend `MAX_UPLOAD_FILES = 100` constant replaces hard-coded `10`; frontend pre-validates count in `uploadFiles()` with matching error message; drop-zone hint updated; `test_routes.py` boundary tests updated to 100/101
- [x] Robustness hardening pass (BH1–BH6, FH1–FH5, 12 new tests):
  - **BH1** JSON error handlers for 413/404/500 — API contract preserved under all failure modes
  - **BH2** `secure_filename` on download `Content-Disposition` — removes header-injection/path-traversal risk
  - **BH3** `_file_body_cache` locked writes + 256 MB byte cap — removes data race and memory exhaustion
  - **BH4** `MAX_CONNECTIONS = 200_000` cap — prevents N² connection-table blowup on crafted PCAPs
  - **BH5** Per-host/conn caps: `ttl_values` ≤256, `dns_names`/`dns_queries` ≤1000, cred-state dicts ≤5000
  - **BH6** `allowed_file` rejects bare `"."` and empty-extension filenames
  - **FH1** Session validator requires `Array.isArray(nodes) && Array.isArray(edges)`
  - **FH2** `||0` / `||1` guards on all `packet_count` divisors (node radius, edge width, canvas, collision, note icons)
  - **FH3** `fmtNum`/`fmtBytes` guard non-finite/undefined inputs centrally
  - **FH4** `renderGraph`/`renderOTMap`/`renderVlanGraph` normalise non-array shapes before iterating
  - **FH5** `exportCsv` guards `protocols`/`ports` with `||[]`; three `localStorage.setItem` calls wrapped in try/catch
  - Deferred (out of scope): thread cancellation on `analyze_pcap` timeout; mass `addEventListener` null guards
- [x] Full-fidelity exports — parse all data, cap only for rendering (feature/full-fidelity-exports):
  - **BE1** Raised `MAX_HOSTS` 50k→250k, `MAX_CONNECTIONS` 200k→1M — now parse all hosts/connections; caps are parse-time backstops, not UI limits
  - **BE2** `stats.hosts_truncated` / `stats.connections_truncated` flags — honest signal when (rarely) the backstop is hit; frontend shows a distinct warning toast
  - **BE3** Removed per-field truncation slices from serialization: `dns_names[:5]`, `open_ports[:30]`, `dns_queries[:10]` per node; `ports[:20]` per edge; same in `merge_results` — full sets now reach the frontend and exports
  - **FE1** `RENDER_NODE_CAP=1500` / `RENDER_EDGE_CAP=4000` constants in `app.js` — graph renders only top-N by traffic; cap operates on local copies inside `renderGraph`, never mutating `graphData`
  - **FE2** Persistent `#cap-banner` (blue) shown when graph is capped: *"Graph shows top N of M hosts — exports contain the full dataset"*; one-shot toast mirrors VLAN cap precedent
  - **FE3** `_isRendered(id)` helper + guards in `_jumpToAnomaly` and search handler — when target is outside rendered subset, detail panel still opens with full data; toast directs user to Table view / CSV
  - **FE4** Hard-cap-hit warning toast when `stats.hosts_truncated`/`connections_truncated` are true
  - **FE5** New **Hosts Inventory CSV** (`exportHostsCsv`) — one row per `graphData.nodes` entry (full IP space); columns: IP, Hostname, MAC, MAC Vendor, Host Type, OS Hint, Protocols, Open Ports, Bytes Sent/Recv, VLANs, Purdue Level, Risk Score, Is Private, Geo Country; button in Export menu
  - **FE6** `sliceMore(arr, n)` display helper — `showDetailPanel` now slices `open_ports`→30, `dns_names`/`dns_queries`→20 with "+N more" notice so the panel stays tidy while data/exports remain full
  - Updated `test_merge.py` (ports-cap test renamed to assert full preservation); added `tests/test_serialization.py` (3 new tests: edge ports untruncated, node open_ports untruncated, stats flags present)

## VLAN Follow-ups

- [x] Per-VLAN bandwidth chart / VLAN timeline — timeline minimap now shows stacked per-VLAN byte bars when VLAN data is present; bars are colored by VLAN using the same vlanColor() palette; falls back to plain density bars for non-VLAN captures
- [x] VLAN export — covered by Export VLAN Traffic CSV (includes Source/Dest VLAN columns and Cross-VLAN flag)

## Completed (Enrichments)

- [x] Backend: DNS tunneling detection — `dns_tunneling_suspected` anomaly using three signals: high-entropy subdomain labels (>24 chars, >4.5 bits), abnormally long average query names (>60 chars), or unique-subdomain flood (>20 labels under same parent). 5 unit tests added.
- [x] Backend: Per-host risk score (0–100) — composite of anomaly severity, cross-zone egress (+15), suspicious port usage (capped +20), and OT write targeting (+10); emitted as `risk_score` on every node, propagated through `merge_results` (max of captures).
- [x] Frontend: Risk score badge on graph nodes (colored ring with number: gray <40, yellow 40–69, red ≥70); risk line in node tooltip; risk badge row in detail panel.
- [x] Backend: TLS ClientHello parsing — `parse_tls_client_hello()` extracts SNI (cleartext server name) and computes JA3/MD5 fingerprint from cipher suites + extensions + elliptic curves; stored per host as `tls_sni` / `tls_ja3`; propagated through `merge_results`.
- [x] Backend: `unusual_ja3` anomaly — fires when a host's JA3 matches a bundled known-bad fingerprint list (Metasploit, Cobalt Strike, Dridex, Emotet, Trickbot, AsyncRAT, QakBot, IcedID).
- [x] Frontend: TLS SNI list shown in detail panel and node tooltip; JA3 hashes shown with threat label and red color when matching known-bad; 8 unit tests added.

- [x] UI: Timeline keyboard shortcuts — Space toggles play/pause; ←/→ step the slider by one tick; shortcuts disabled when focus is inside an input/select
- [x] OT Map: Add Device validation — IP format check (reject non-IPv4) and Purdue level bounds check (−1 to 6) with inline error display; refactored duplicate error display into shared `_showErr` helper
- [x] DNS view: DNS tunnel suspect badges — hosts flagged by `dns_tunneling` anomaly now show an amber "DNS Tunnel?" badge in the DNS host list
- [x] Code: Packet inspector tab label parsing refactored — `_pktsForCurrentConn()` helper replaces three identical regex blocks in pkt-tab-pkts / pkt-tab-cmds / pkt-tab-stream click handlers

## Enhancements (2026-06-09)

- [x] Exports: country info ("Name (CC)" format) added to all IP-bearing exports — Connections CSV (source/dest country), Anomalies CSV (source/dest country), Credentials CSV (source/dest country), VLAN Inventory CSV (per-host country), VLAN Traffic CSV (source/dest country); Hosts Inventory CSV geo column upgraded from bare ISO code to "Name (CC)"; Audit Report gains a "Geographic Distribution" section grouping external endpoints by country with flag emoji and host count

## Bug Fixes (2026-06-09, iteration 2)

- [x] **FE-HIGH** — Color-by-VLAN and colour-blind toggles painted the anomaly ring instead of the main fill circle (anomaly ring is appended first in `appendNodeDecorations` so `querySelector("circle")` returned it). Fixed: both `btn-color-vlan` handler and `updateNodeColors()` now filter on `!this.getAttribute("class")` (main circle has no class; anomaly ring has `"anomaly-ring-*"`).
- [x] **FE-MED** — Layout-switch tick was missing edge-label repositioning, minimap sync, and the `on("end")` zoom-fit present in the main `renderGraph` tick. Fixed: layout-switch tick now mirrors the canonical tick body exactly.
- [x] **FE-MED** — Packet search (`applyPktSearch`) only scanned loaded DOM rows; matches beyond the first page (PKT_PAGE_SIZE=20) were silently ignored and the N/M denominator was wrong. Fixed: when a search term is active, the "Load more" row is programmatically clicked to expand the full packet list before searching.
- [x] **FE-MED** — Floating inspector re-dock checked `inspector.classList.contains("open")` but open/closed state is tracked via the `hidden` class, so `graphWrap` never re-reserved space after docking. Fixed: check `!inspector.classList.contains("hidden")` instead.
- [x] **FE-MED** — Docked `#pkt-resize-handle` mousedown handler had no floating guard; both the docked handler and the floating-reposition handler fired while floating, causing the panel to simultaneously move and resize. Fixed: guard the docked handler with `if (pktInspector.classList.contains("pkt-floating")) return;`.
- [x] **FE-MED** — OT-Log filter Sets were re-created all-active on every view visit while buttons were built only once; button visuals and filter state desynchronised after leaving and returning to the view. Fixed: `_otLogActiveProtoF`/`_otLogActiveDirF` hoisted to module scope and built once under the `_otLogRendered` guard so all closures share the same objects.
- [x] **BE-MED** — `parse_iec104` read `common_address` from `payload_bytes[11:13]`; correct ASDU offset is `[10:12]` (one byte too far). Fixed: corrected slice; added test asserting `common_address == 1`.
- [x] **BE-MED** — `parse_s7comm` read `func_code = s7[10]` for ROSCTR=3 (Ack-Data); Ack-Data has a 12-byte header so params start at offset 12, not 10 — every S7 response was mis-decoded. Fixed: compute `param_hdr = 12 if rosctr in (2,3) else 10` and read `s7[param_hdr]`; added ROSCTR=3 test.
- [x] **FE-LOW** — `e.protocols.some/includes/slice` unguarded in three sites (`_buildConnRows`, `dominantProto`, OT matrix tooltip); added `|| []` guards matching the pattern used everywhere else.
- [x] **FE-LOW** — OT-matrix `nodeZone()` read `n.purdue_level` directly with no `purdueLevel(n)` fallback; every other site uses the fallback. Fixed.
- [x] **FE-LOW** — `openPktInspectorForHost` set `#pkt-tab-cmds` visibility but never set `#pkt-tab-stream`; stream tab visibility leaked from the previous connection. Fixed: set stream tab from `hasPayloadHost`.
- [x] **BE-LOW** — DNP3 `is_error` checked `payload_bytes[12] & 0x80` which is the IIN1 "Device Restart" bit, not an error indicator. True errors are in IIN2 (`payload_bytes[13]`). Fixed: re-pointed to `payload_bytes[13] & 0x30` (Parameter Error | Already Executing).
- 2 new tests added: `test_s7_ack_data_rosctr3`, `test_iec104_i_frame_with_asdu` now asserts `common_address == 1`. Total: 333 passing.

## Bug Fixes (2026-06-09)

- [x] FE: `purdueLevel()` called with string `n.host_type` instead of the node object at `app.js:1845` — cross-zone edge highlighting broken in canvas mode (graphs >150 nodes); fix: pass `n`
- [x] FE: Audit report DNS Tunneling section matched wrong anomaly type `dns_tunneling_suspected` (backend emits `dns_tunneling`); section was always empty; fix: corrected filter string
- [x] FE: `exportCredentialsCsv()` defined but never wired — no menu item, no event handler; fix: added `exp-credentials` item to Export dropdown and click handler
- [x] FE: Audit report Capture Summary rows used `s.hosts`/`s.connections` (undefined) instead of `s.total_hosts`/`s.total_connections`; always fell back to `.length` silently; fix: correct stat key names
- [x] FE: Modbus command-table direction arrows used lexicographic IP comparison instead of `modbus.is_response`; fix: `p.modbus.is_response ? "←" : "→"`

## Known Issues

- OT Map: PNG export exports the current zoom/pan view; consider a "fit-to-full" export option
- OT Map: Drag-to-reclassify ghost circle may flicker at extreme zoom levels
- ~~General: GeoIP lookup is optional and silently skipped if MMDB absent; consider a warning banner~~ — resolved: DB-IP Country Lite bundled (see feature/bundled-geoip)
- General: Test coverage for `analyze_pcap` and `merge_results` is thin — add integration tests with sample PCAPs

- [x] Feature #4: TCP Follow Stream — "Stream" tab in packet inspector; sorts packets by time, groups by direction (client=blue, server=green), decodes hex payload to ASCII with non-printables as `.`; tab hidden when no payloads captured
- [x] Feature #5: Credentials extraction view — HTTP Basic auth, HTTP form POST, FTP USER/PASS, SMTP AUTH PLAIN/LOGIN, POP3 USER/PASS, IMAP LOGIN; sidebar panel with protocol filter + click-to-reveal passwords; capped at 500/capture, 2000/merge
- [x] Feature #10: Credentials feature improvements — fixed critical bug (extraction block was inside UDP branch, so TCP protocols were never extracted); added LDAP Simple Bind (BER-parsed), SNMP community strings (v1/v2c BER-parsed), Telnet login (IAC-stripped prompt/response state machine); fixed IMAP quoted-credential regex; fixed HTTP form POST to use parse_qs (handles &-in-password); added deduplication (same proto/src/dst/dport/user/pw kept once); password-reuse anomaly (high severity, fires when same password seen across 2+ protocols/destinations); key-icon on graph nodes with credentials; credentials section in node detail panel; "Export Credentials CSV" in export menu (includes passwords); 23 new unit tests
- [x] Feature #6: Unified OT command log — chronological global table of all Modbus/DNP3/S7comm/EtherNet/IP/IEC-104/BACnet commands; 5th view tab ("OT Log"); filter by protocol + direction; color-coded read/write/error/diagnostic; 5000 cmd cap per capture
- [x] Feature #7: HTTP file transfer detection — detects HTTP server responses with interesting Content-Type (application/*, image/*, audio/*, video/*, text/csv, text/xml) or Content-Disposition: attachment; extracts filename, MIME type, Content-Length, SHA-256 of body bytes; sidebar "File Transfers" panel with hash; capped at 200/capture, 500/merge (deduped by SHA-256); 12 unit tests added
- [x] Feature #8: PCAP baseline diff — "Set Baseline" header button saves current graphData; uploading a second PCAP reveals "⊕ Diff" view tab; three-column diff shows new/disappeared hosts, new connections (with protocols), and new anomalies vs baseline; frontend-only, no server round-trip
- [x] Diff view enhancement — host diff now detects type changes, risk-score delta >20, new protocols, new open ports, each shown as a descriptive badge; connection diff adds a "changed traffic" row when byte/packet count ratio is >2× or <0.5× between captures
- [x] Feature #9: Markdown audit report — "Export Audit Report" in export dropdown; generates a `.md` file client-side with: capture summary table, top-10 hosts by risk score, anomalies grouped by severity, OT inventory by Purdue level, TLS/SNI observations, DNS tunneling suspects, captured credentials table, file transfers table, OT write operations; no server round-trip

## Completed (Bug Fixes)

- [x] Backend: IPv6 packet inspector crash — packet-inspector block unconditionally accessed `pkt[IP]`; now correctly branches `IP in pkt` / `IPv6 in pkt` and emits IPv6 header fields
- [x] Backend: CoAP option parser out-of-bounds — missing `idx >= len` guards before extended delta/length field reads; fixed with bounds checks
- [x] Backend: Port-scan false positives — bidirectional `src_dst_ports` attribution caused servers with many clients to be flagged; now only attributes ports to the connection's smaller-IP key
- [x] Backend: Purdue level returned -1 for Router, IoT Gateway, DNS Server, and 15 other common host types; added them to `_PURDUE_L4_TYPES` / `_PURDUE_L1_TYPES`
- [x] Frontend: `fetch("/upload")` did not check `resp.ok` before calling `.json()` — HTTP errors (4xx/5xx) showed a confusing parse error instead of the server message
- [x] Frontend: 26 protocols in PORT_MAP had no PROTO_COLORS entry and rendered as flat gray (NNTP, NetBIOS-*, LDAP/LDAPS, Docker, K8s-API, VNC, WinRM, IKE/IPsec, OpenVPN, Metasploit, etc.)
- [x] Frontend: DHCP Client, Discovery, and News Server host types had no HOST_COLORS entry and rendered as default gray
- [x] Frontend: OT filter toggle button (`#ot-filter-btn`) was wired in JS but missing from `index.html`; `otFilterAll` state was never togglable — added button to OT toolbar
- [x] Frontend: `d.dns_names[0]` in detail panel had no null guard; now `(d.dns_names && d.dns_names[0])`
- [x] CSS: `#ot-legend` rule incorrectly removed as "dead code" — element is created dynamically by JS; restored with `display: flex; flex-wrap: wrap` so legend items flow horizontally instead of stacking as block rows (~200 px tall)
- [x] OT Map: Matrix view color key — replaced plain-text legend note with inline SVG color swatches for each OT protocol (Modbus/DNP3/S7comm/EtherNet/IP/IEC-104/BACnet/CoAP/MQTT)
- [x] Tests: Added 8 unit tests for `parse_enip` (register session, read/write tag, error status, malformed input)
- [x] OT Matrix: Sticky row/column headers via CSS Grid (3-SVG layout: cols/rows/cells); headers remain visible while scrolling large captures
- [x] OT Matrix: Click trap removed — cell click now navigates to graph view + opens packet inspector for that connection; tooltip shows "Click to inspect packets"
- [x] OT Matrix: Row/column hover highlight — crosshair bands highlight the active row and column; hovered label turns bright white
- [x] OT Matrix: Group nodes by zone (OT → DMZ → IT → Internet) before sorting by connection count; faint separator lines at zone boundaries on both axes
- [x] OT Matrix: Middle-ellipsis label truncation with full-name `<title>` tooltip on hover (previously cut the front of long hostnames)
- [x] OT Matrix: Empty state shows friendly message when no devices match current filters (was silent)
- [x] OT Matrix: Re-renders automatically when sidebar filters change (was stale until manually toggled)
- [x] OT Matrix: PNG export targets the matrix SVGs when in matrix mode (previously always exported the hidden Purdue map)
- [x] OT Matrix: "Showing top 40 of N" hint rendered in legend area when capture has >40 devices
- [x] OT Matrix: Tooltip arrow changed from → to ↔ (edges are undirected)
- [x] OT Matrix: Anomaly border stroke-width increased to 2 on cross-zone+anomaly cells for visibility
- [x] OT Matrix: Diagonal cells rendered as visually inert dark rects (no hover/click)
- [x] Bug fix: pcapng files crashed `analyze_pcap` with `'PacketMetadataNg' object has no attribute 'sec'` — fixed timestamp extraction to use `tshigh`/`tslow`/`tsresol` for pcapng vs `sec`/`usec` for pcap (`app.py:1867`)
- [x] Tests: Added `tests/test_pcapng.py` — 4 integration tests covering pcapng parse, pcap/pcapng parity, and mixed-format merge

## Robustness Review — MED/LOW Deferred Items

Items surfaced in the 2026-05-17 robustness review (`REVIEW.md`) that were not addressed in `feature/robustness-fixes` (all HIGH items are fixed). Sorted roughly by risk.

- [x] **E3** — surface `parse_errors` count in `stats`; shown as info toast on upload
- [x] **E4** — `fetch /upload` wraps `.json()` in try/catch; falls back to `resp.text()` for non-JSON error bodies
- [x] **E5** — `FileReader.onerror` handler added to both file-load usages; shows toast on failure
- [x] **U4** — Tempfile path appended to `tmp_paths` before `f.save()` so cleanup always runs
- [x] **U5** — `secure_filename` on unicode-only names returns empty string; whitelist suffix to `.pcap/.pcapng/.cap`
- [x] **P3** — BACnet NPDU routing-field bounds check tightened; falls through with `return None` on truncation
- [x] **P4** — IEC104 `apdu_len` validated against `len(payload_bytes)` before use
- [x] **X5** — `c.dport` in nodeCreds block escaped via `escHtml()`
- [x] **X6** — `modbus_unit_ids` / `dnp3_addresses` escaped with `.map(escHtml).join(", ")`
- [x] **X7** — OT-edge tooltip source/target values escaped
- [x] **X8** — `resolvedIps.map(escHtml).join(", ")` in DNS view
- [x] **X9** — `open_ports.slice(0,20).map(escHtml).join(", ")`
- [x] **N5** — `(f.sha256 || '').slice(0,16)` guards missing sha256 field
- [x] **N6** — `s7.function_code != null` (loose equality catches both null and undefined)
- [x] **L2** — Simulation tick/end handlers nulled out before `stop()` in `renderGraph` and `buildSimulation`
- [x] **L3** — `_zoomFitTimer` cleared on re-upload; no stale zoomFit after new graph load
- [x] **PF4** — `_getSortedEdges()` cache with fingerprint string avoids re-sorting on every filter toggle
- [x] **S3** — `_geoip_lock` already in place; double-checked and confirmed thread-safe
- [x] **S4** — `app.secret_key = os.environ.get("PCAPVIS_SECRET_KEY", os.urandom(32))`
- [x] **T5** — `tests/conftest.py` created with shared fixtures and packet-builder helpers
- [x] **D1** — `geoip2>=4.0.0,<5` pinned in requirements.txt
- [ ] **PF3** — `openPktInspectorForHost` concatenates all packets and sorts in main thread (150k packets → jank)
- [ ] **S2** — No CSRF protection on `/upload` POST (low risk on localhost; medium when `--public`)
- [x] **H3** — README does not warn that `--public` exposes a Werkzeug dev server
- [x] **General** — No `prompt()` modal replacement (blocks page, disabled by Firefox after 2 dialogs); affects OT risk note input and annotation input

## Bug-Sweep Fixes (2026-06-07)

- [x] **B1** — ARP-spoofing detector was dead code: `host()` only stored first-seen MAC so detector's set was always size ≤1. Fixed by accumulating all observed MACs per IP in `h["macs"]`; detector now reads from that set.
- [x] **B2** — Cleartext-creds false positive: check was `pkt.get("hex")` which is always truthy (set unconditionally for every stored packet). Changed to `pkt.get("payload_hex")` (only present when transport payload exists).
- [x] **B3** — Anomaly dedup silently collapsed distinct findings with same `(type, src, dst)`. Added `description` to dedup key at both `analyze_anomalies` and `merge_results` sites.
- [x] **B4** — `parse_modbus` set `"is_response": is_error`, conflating two unrelated concepts. Removed; `is_response` is set directionally in `analyze_pcap` via `sport == 502`.
- [x] **B5** — `parse_modbus` emitted a junk record (`"Unknown FC None"`) for ≤7-byte payloads with no function code. Now returns `None` early.
- [x] **B6** — Modbus exception code 0 dropped by truthiness. Changed to `is not None`.
- [x] **B7** — CoAP option parser could read beyond buffer on truncated packets. Added bounds check before `opt_val` slice.
- [x] **B8** — `geo_lookup` treated coordinate `0.0` as missing (truthiness). Changed to `is not None`.
- [x] **B9** — SNMP BER index could raise `IndexError` after `_ber_len` on truncated packets. Added `_off < len(payload)` guard.
- [x] **B10** — Beaconing false positives on sub-second ACK/retransmit bursts. Added `mean_interval >= 1.0s` floor.
- [x] **F1** — Session load crash: `updateFilterUI` accessed `stats.protocols.length` / `stats.host_types.length` without `|| []` guard, throwing `TypeError` on partial session JSON.
- [x] **F2** — Table view showed previous capture's rows: `_getSortedEdges` cache fingerprinted by edge count only; same-count uploads reused stale data. Added per-load nonce to fingerprint.
- [x] **F3** — "Duration" column sort was a no-op: edges have no `duration` field. Added special-case in comparator using `last_seen - first_seen`.
- [x] **F4** — Colour-blind toggle corrupted anomaly rings (painted over severity colors) and ignored active VLAN coloring. Fixed `updateNodeColors` to target only the main circle and branch on `colorByVlan`.
- [x] **F5** — Cluster-collapse state (`collapsedTypes`, `_clusterCollapseMode`) not reset on new upload. Added reset in `loadGraph`.
- [x] **F6** — Dead `_crossCount` / `cross-zone-badge` computation (element never in DOM). Removed.

## Deferred (architectural — out of scope for this sweep)

- [ ] **Port-scan misattribution** — undirected connection key `tuple(sorted([sip,dip]))` loses direction; scanner vs server attribution can be wrong. Needs directional byte/port accounting in `analyze_pcap` core data flow.
- [ ] **Exfiltration direction** — same undirected key causes `conn["bytes"]` to include both directions; downloads can be flagged as exfiltration. Same root cause as port-scan misattribution.

## Bug-Sweep Fixes (2026-06-07, feature/bug-sweep)

- [x] **H1** — Dashboard "Top Hosts by Risk" bar click threw `ReferenceError: buildDetailPanel is not defined`; `highlightNode(nd.ip)` also used wrong signature. Fixed to call `showDetailPanel(nd)` + `highlightNode(nd, linkSel, nodeSel)` with `_isRendered` guard; capped-out hosts get an informative toast instead.
- [x] **H2** — Audit report "Packets" and "Bytes" rows were always blank; used `s.packets`/`s.bytes` which don't exist on the backend. Fixed to `s.total_packets` (fmtNum) and edges-summed bytes.
- [x] **H3** — Telnet cred-state cap (`MAX_CRED_STATE_ENTRIES`) used `continue` inside the main packet loop, silently dropping packet/byte/protocol counting for connections after the cap was reached. Fixed to scope the guard to the telnet state-machine branch only. Promoted `MAX_CRED_STATE_ENTRIES` to module level so tests can monkeypatch it.
- [x] **M1** — `merge_results` stats dict was missing `parse_errors`, `geoip_available`, and `cdp_lldp_discovered` that single-file `analyze_pcap` emits. Frontend GeoIP toast and parse-error toast never fired for multi-file uploads. Added all three keys.
- [x] **M2** — Zero-results overlay showed falsely when a searched IP existed in `graphData.nodes` but was capped out of the render. Added a full-dataset check: if a cap-miss match is found, show an informative toast instead of the overlay.
- [x] **M3** — "Fit to visible" timer fired on every filter cycle when render cap was active (visible count always < full graphData.nodes.length). Fixed to compare against the rendered node count (`nodesGroup.selectAll(".node").size()`).
- [x] **M4** — Markdown table injection: hostnames/usernames/filenames with `|` or newlines broke audit report table layout. Added `mdCell()` helper (replaces `|`→`\|`, strips CR/LF) applied to all user-data cells in the report.
- [x] **L1** — MQTT SUBSCRIBE topic loop used `< len(payload)` (strict) causing the final topic to be missed when it ends exactly at the buffer boundary. Changed to `<=`.
- [x] **L2** — `Content-Length` response header set as `int`; changed to `str(len(...))` for correctness.
- [x] **L3** — `merge_results` node output dict omitted `host_type_hints` and `has_s7_download` that single-file `analyze_pcap` includes. Added to the output dict for schema parity.
- [x] **L5** — Dead code: `data._nodeMap = {}` was assigned in `renderGraph` but never read anywhere. Removed.

## Polish (2026-06-07, feature/vlan-node-icons)

- [x] VLAN Graph host nodes now show the same host-type emoji icons as the main Graph view — `hostIcon(d.host_type)` appended as `<text class="node-icon">` after the host circle; reuses the existing `hostIcon()` function and `.node-icon` CSS (emoji font stack); `text-anchor: middle` and `pointer-events: none` set for correct centering and click-through.
- [x] **Bug fix**: VLAN graph host-type icons were invisible — `.node-icon` base rule sets `fill: transparent`; main-graph icons are rescued by the more-specific `.node text { fill: var(--text) }` rule, but VLAN node groups use class `vhost` (not `node`) so that rule never applied. Fixed by adding `.attr("fill", "var(--text)")` inline on the VLAN icon text element.

## Logic Review Fixes (2026-06-15, feature/analyst-workflow-improvements)

Fixes for all five issues identified in `review-by-claude.md` (2026-06-15).

- [x] **Fix 1 (High)** — Purdue cross-zone highlighting was broken: `renderGraph()` called `purdueLevel(n.host_type)` (string) instead of the full node object. Changed to `n.purdue_level ?? purdueLevel(n)` to match all other call sites and prefer the more-accurate backend value.
- [x] **Fix 2 (Medium)** — OT Log stale filter buttons: `renderOtLog()` empty-command early return now clears `#otlog-filter-protos` and `#otlog-filter-dirs` before returning, removing buttons left over from a prior capture.
- [x] **Fix 3 (Medium)** — Concurrent uploads wiped the global file-body download cache: converted `_file_body_cache` from a plain dict (cleared on every `/upload`) to a size-bounded LRU `OrderedDict` (evicts oldest entries at the 256 MB cap). Download links from prior uploads now survive subsequent uploads.
- [x] **Fix 4 (Medium)** — Timed-out parse tasks kept running in the worker pool: `FutureTimeoutError` is now caught separately with a clear log message and remaining not-yet-started futures in the batch are cancelled. Running threads cannot be force-killed in Python (process isolation would be required for hard cancellation — deferred).
- [x] **Fix 5 (Low)** — IPv6 extension headers not parsed: the parser previously assumed a fixed 40-byte base header offset. It now walks hop-by-hop (0), routing (43), destination options (60), fragment (44), and AH (51) extension headers (up to 8 hops, with bounds checks) before dispatching to TCP/UDP/ICMP.
- [x] **Tests** — Added `tests/test_ipv6_ext_headers.py` (7 tests), `tests/test_file_cache.py` (3 tests), and 2 static frontend assertions in `tests/test_frontend_findings_static.py`. Total: 348 tests passing.

## Bug Fixes (2026-06-15, feature/bugfix-audit-findings)

- [x] **BE** — `is_private()` now classifies the full IPv6 link-local range `fe80::/10` as private instead of only `fe80::/16`; prevents `fe90::`/`fea0::`/`febf::` hosts from being treated as Public Internet.
- [x] **BE** — HTTP file-transfer extraction is now a production helper (`_extract_http_file_transfer`) used by `analyze_pcap()` and tests, removing the old duplicated test-only parser.
- [x] **FE** — Removed inline `onclick` handlers from copy/download buttons; file-transfer, IP, hostname, JA3, and SHA-256 actions now use escaped `data-*` attributes plus delegated click handling.
- [x] **Tests** — Added IPv6 link-local boundary assertions, production-helper file extraction coverage, and a static frontend guard preventing inline event handlers from returning.

## Analyst Workflow Improvements (2026-06-13, feature/analyst-workflow-improvements)

- [x] **AGENTS.md** — Added repo-root agent instructions mirroring `CLAUDE.md` workflow, branch, test, run, commit, and push guidance.
- [x] **Findings workspace** — Added a ninth view for analyst triage; derives findings from anomalies, credentials, file transfers, grouped OT write/error commands, and high-risk hosts.
- [x] **Triage state** — Findings support status, severity override, analyst notes, report include/exclude, evidence-copy bundles, and graph/packet navigation.
- [x] **Persistence** — Finding edits persist in `localStorage` per capture fingerprint and are included in session save/load JSON.
- [x] **Report curation** — Markdown audit reports now include a Curated Findings section and suppress anomaly findings marked false positive or excluded from report.
- [x] **Prompt replacement** — Host notes, context-menu notes, VLAN labels, and finding notes now use an in-app text modal instead of blocking `prompt()`.
- [ ] **Search/query mode** — Global query terms such as `risk>70`, `protocol:modbus`, `vlan:10`, `external:true`, `creds:true`, and `status:open`.
- [ ] **Evidence-first details** — "Why" sections for risk score, host type, Purdue level, VLAN classification, JA3/SNI findings, and anomaly rules.
- [ ] **Timeline investigation mode** — Clickable markers for anomalies, credentials, file transfers, OT writes, and first/last seen host activity.
- [ ] **Persistent baseline projects** — Named baselines and comparisons that survive browser reloads.
- [ ] **Packet inspector scalability** — Paginate or workerize host packet aggregation to address `openPktInspectorForHost` main-thread jank.
- [ ] **Classification confidence** — Confidence/evidence fields for host type, OS hint, vendor, and Purdue level.
- [ ] **Custom rule packs** — JSON rules for suspicious ports, approved domains, known-good VLAN flows, asset metadata, and JA3 allow/block lists.
- [ ] **Dashboard v2** — Analyst queues for changed assets, risky paths, external exposure, cleartext secrets, OT writes, and segmentation violations.

## Bundled GeoIP (2026-06-08, feature/bundled-geoip)

- [x] **GeoIP self-contained** — DB-IP IP-to-Country Lite (CC BY 4.0, June 2026 edition, ~8 MB uncompressed) bundled as `data/dbip-country-lite.mmdb`; no MaxMind account or external download required. Attribution per CC BY 4.0: *IP Geolocation by DB-IP* (https://db-ip.com).
- [x] **Path resolution** — `_get_geoip_reader()` tries in order: `GEOIP_DB_PATH` env var → `/usr/share/GeoIP/GeoLite2-City.mmdb` → bundled DB. Env var works under gunicorn.
- [x] **DB-type branching** — `_geoip_is_city` flag set from `metadata().database_type`; Country DB calls `reader.country()` (returns `city/lat/lon=None`); City DB retains existing `reader.city()` path. All consumers already guard with `|| ""`/truthiness so nothing breaks.
- [x] **Toast self-resolves** — `geoip_available` is now `true` with the bundled DB; `app.js:775` toast no longer fires.
- [x] **7 unit tests** added in `tests/test_geoip.py` covering reader availability, `geoip_available` flag, `geo_lookup("8.8.8.8") → US`, Country-DB city/lat/lon=None, dict shape, private IP graceful handling.

## Performance Improvements (2026-06-07, feature/perf-improvements)

**Backend — `app.py`**
- [x] **B1** — MAC formatting: `':'.join(f'{b:02x}' for b in raw[0:6])` → `raw[0:6].hex(":")` (C-level, ~3× faster); same for ARP SHA
- [x] **B2** — IPv4 dotted-quad: `'.'.join(str(b) for b in ...)` → `socket.inet_ntoa(...)` (C-level) for both `sip`/`dip` and ARP SPA; added `import socket`
- [x] **B3** — `conn_key`: `tuple(sorted([sip, dip]))` → `(sip, dip) if sip <= dip else (dip, sip)` (eliminates list alloc + sort)
- [x] **B4** — Reuse `conn` local: removed redundant `conn = connections[conn_key]` at line 2716 and two `connections[conn_key]["dst_ports"].add(...)` re-index calls
- [x] **B5** — Hoist broadcast check: `is_bcast = dip.endswith(".255") or dip == "255.255.255.255"` computed once; reused for both `dh["flags"]` and `vlan_pkt_bcast`
- [x] **B6** — Module-level compiled regexes: `_RE_MIME_VALID`, `_RE_CONTENT_DISP_FNAME`, `_RE_HTTP_BASIC_AUTH`, `_RE_SMTP_AUTH_PLAIN`, `_RE_SMTP_AUTH_LOGIN`, `_RE_IMAP_LOGIN` replace inline patterns in hot credential/file block
- [x] **B7** — Risk-scoring O(H×C) → O(C): build `ip_conns` index once before risk loop; replaces two full `connections` scans per host with per-IP lookup
- [x] **B8** — Anomaly-timestamp fallback: `ip_conns[src][0]` replaces full `connections` scan per src-only anomaly

**Frontend — `static/js/app.js`**
- [x] **F1** — Canvas tick visible-set: removed per-tick `nodesGroup.selectAll(".node").each(...)` DOM scan from `drawCanvasEdges`; cache `_visibleNodeIds` updated only in `applyFilters` and `highlightNode`; precompute static per-edge `_canvasColor`/`_canvasWidth` once at render
- [x] **F2** — Minimap throttle: `updateMinimap()` in tick handler fires only every 5th tick via `_minimapTickCount`
- [x] **F3** — `applyFilters` single-pass: folded `isolated`/`anom-faded` class writes into the existing `.each()` (was 3 separate `selectAll` passes); hoisted `_allVlans`/`_allIpVers` to module scope (computed once per dataset in `loadGraph`)
- [x] **F5** — Packet-search debounce: `applyPktSearch` now debounced 160ms; rows cache lowercased text in `dataset.searchText` at build time to avoid re-materialising `textContent` per keystroke
- [x] **F6** — `_isRendered` O(1): replaced full DOM `.each()` scan with `_renderedNodeIds.has(id)` (Set populated at render time)

## VLAN Matrix Views (2026-07-04, feature/vlan-matrix-views)

- [x] **Multi-view matrix** — `⊞ Matrix` now has a segmented switcher with 4 modes: Traffic (log-scaled heat, Bytes|Packets sub-toggle, in-cell totals), OT/ICS (orange heat on OT-carrying VLAN pairs, orange border when OT writes present, gray for traffic-but-no-OT), Anomalies (severity color + in-cell count across **all** anomaly types, not just `vlan_cross_segment_ot`; single-host anomalies land on the diagonal), Protocol (original dominant-protocol rendering, preserved)
- [x] **Full VLAN membership fix** — replaced `primaryVlan` (`node.vlans[0]` only) with `vlansOf()` (full membership, matching the VLAN graph view); canonical sorted `"a|b"` pair keys prevent double-counting for multi-VLAN hosts. **Behavior change**: matrix cross-VLAN totals now match the VLAN graph's cross-link tooltips for multi-VLAN hosts (previously under-counted)
- [x] **`buildVlanFlowMatrix(data)`** — new pure/DOM-free data-layer function; `VLAN_OT_PROTOCOLS` set cross-checked against `PORT_MAP` (app.py) / `PROTO_COLORS` (app.js) labels the backend actually emits (dropped `PROFIBUS` — declared in `PROTO_COLORS` but never emitted by any `PORT_MAP` entry)
- [x] **Per-mode legends** — `vlanMatrixLegendSpec()` declarative spec drives both the on-screen legend and the PNG export footer (gradient for Traffic/OT, severity swatches for Anomalies, note-only for Protocol)
- [x] **PNG export** — `exportVlanMatrixPng()` (title header + legend footer band, mirrors the `exportOTMatrixPng` composition pattern) and `exportVlanMatrixAllViews()` (sequential export of all 4 views); wired to the toolbar `⤓ PNG` button (Shift-click = all views) and two new global Export-menu items (`Export VLAN Matrix PNG` / `…(all views)`)
- [ ] **Deferred** — light-theme matrix colors (currently hardcoded dark, matching existing OT-matrix precedent); per-cell click-to-drill-down into the connection table (currently hover-only tooltips)

### UI polish pass (2026-07-04, same branch)

- [x] **Column-label overlap fixed** — rotated VLAN headers (`renderVlanMatrix`) changed from a downward `rotate(-60)`/`translate(…,LABEL-4)` (which dove into the first cell row) to a rising `rotate(45)` anchored 8px above the cell band, so labels stay within the header band on screen
- [x] **Matrix now fills the pane** — `CELL` size is computed from `#vlan-matrix-container.clientWidth` (was a fixed 44–60px band regardless of window size), capped at 84px for ≤20 VLANs / 52px above that (tuned down from an initial 110px/60px cap per user feedback); `#vlan-matrix-layout` gets `margin:0 auto` so small (few-VLAN) matrices are centered instead of stranded top-left
- [x] **Bold axis labels** — VLAN row/column headers in `renderVlanMatrix` now render `font-weight:700` for readability (carries through to PNG export since it re-serializes the same SVG text nodes)
- [x] **Protocol-view legend** — `vlanMatrixLegendSpec()`'s protocol branch previously returned `items: []` (note-only); now populates swatches from the dominant protocol of every non-diagonal cell (via new shared `dominantProto()` helper, also used by `protoColor()` so colors can't drift) plus the cross-VLAN-OT-anomaly swatch; PNG footer wraps swatches onto multiple rows when they don't fit one line
- [x] **Export quality** — `exportVlanMatrixPng()` and `exportOTMatrixPng()` both floor resolution at `Math.max(2, devicePixelRatio)` (was `devicePixelRatio || 2`, i.e. 1x on standard displays) and rasterize each layer's SVG at its scaled intrinsic size via `viewBox` (was rasterized at logical size then blurrily upscaled by `drawImage`)
- [x] **Export label clipping fixed** — the VLAN matrix's column-label PNG layer is now serialized with a left-side `viewBox` bleed (`BLEED=24`) matching the new up-left label rise, replacing the old bottom-only `COL_BLEED` that didn't help an upward/leftward overhang
- [ ] **Deferred** — OT matrix's on-screen column labels (`rotate(-55)`, dive-down geometry) share the same overlap risk as the VLAN matrix's old geometry; not reported by users yet, left untouched this pass (only its export got the crispness fix)

### Heat ramp direction fix (2026-07-04)

- [x] **Reversed Traffic + OT heat ramps** — both `makeHeatScale()` gradients in `renderVlanMatrix` (and their matching `vlanMatrixLegendSpec()` legend stops) were previously dark-for-low/light-for-high, which read backwards on a heatmap; stops arrays reversed so **light = less data exchange, dark = more** for both Bytes/Packets (blue) and OT-share (orange) views. In-cell `textFill` contrast ternaries in `vlanCellStyle()` flipped to match (light text now shows on the now-dark high-value cells)
