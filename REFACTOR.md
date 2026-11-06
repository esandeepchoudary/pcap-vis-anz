# Refactor plan -- PCAP Network Visualizer v2

Status: **draft, being finalized interactively** (branch `develop`, started 2026-11-06 from v0.1.0).

This document has three parts:

1. **Feature inventory**: everything the app does today, so nothing is lost in the rebuild.
2. **Gaps and problems**: architecture, UX, and missing features.
3. **Decisions**: the choices we make together, plus the resulting target design.

---

## 1. Feature inventory (v0.1.0)

### 1.1 Ingest and parsing (backend, `app.py`)

| Area | What exists |
|---|---|
| Upload | Up to 100 files / 1 GB per upload; pcap, pcapng, cap; files analyzed in parallel, then merged (`merge_results`) |
| Parser | Streams with scapy `RawPcapReader` plus manual byte parsing: Ethernet, 802.1Q, QinQ (0x88A8 and stacked 0x8100), IPv4, IPv6 with extension headers, TCP, UDP, ICMP, ARP |
| Limits | 1,000,000 packets; 50 stored packets per connection; top 40 connections with packet detail; 30 ports per node in the output |
| Host identity | TTL OS hint; MAC OUI vendor (IT, OT, IoT); DNS names; CDP/LLDP device names and native VLAN; GeoIP country (bundled DB-IP Lite) |
| Classification | 38 host types; 80+ protocols identified by port; Purdue level (`purdue_level_py`); OT master/outstation role; Engineering Workstation auto-detection from S7 Download |
| OT deep inspection | Modbus TCP, DNP3, S7comm, EtherNet/IP CIP, IEC 60870-5-104, BACnet/IP |
| IoT and IT deep inspection | HTTP, MQTT, CoAP, TLS ClientHello (SNI, JA3 plus a known-bad JA3 list) |
| Credentials | HTTP Basic, form POST, FTP, Telnet, MQTT CONNECT, CoAP; password-reuse detection |
| File carving | HTTP downloads with SHA-256; LRU cache (256 MB) served at `/download/<sha256>` |
| Anomalies | 32 rules: network (scan, beaconing, exfiltration, suspicious ports, bad JA3), OT (writes, restarts, code download, broadcast, bulk reads, exceptions, unit polling, internet exposure, cleartext), IoT (MQTT, Telnet, camera egress, TR-069), VLAN (hopping, native leak, QinQ, cross-VLAN OT, ARP spoofing, broadcast storm, PCP abuse) |
| Scoring | Per-host risk score from 0 to 100; VLAN segmentation score |
| API | `/`, `/upload`, `/download/<sha256>`, `/gpu-status`, `/session-schema`, `/version` |

### 1.2 Views (frontend, `static/js/app.js`)

| View | What it does |
|---|---|
| Graph | D3 force, radial, and cluster layouts; pin, isolate, minimap, cluster collapse; colour-blind palette; cross-zone edges; right-click menu; time-window brush with playback |
| Table | Sortable and filterable connection list |
| DNS Map | Per-host DNS queries and query log |
| OT Map | Purdue swimlanes L0 to L6 plus Unclassified; zone tints; bridge detection; cross-zone and cross-level counts; anomaly badges and timeline. **Edit mode:** drag to change level, risk label with note, add or remove device. PNG and JSON export |
| OT Matrix | Device-by-device grid coloured by OT protocol, cross-zone, and anomaly |
| OT Log | Chronological OT command history |
| VLAN | VLAN super-nodes with hulls; gateway badges; 4-mode VLAN matrix (Traffic, OT, Anomalies, Protocol); segmentation health; VLAN labels; CSV, SVG, and PNG exports |
| Diff | Baseline comparison: new or disappeared hosts, connections, volume changes, new anomalies |
| Dashboard | Summary cards, risk bar chart, protocol distribution, top anomalies |
| Findings | Triage workspace: status, severity override, notes, include in report, evidence bundles, false-positive suppression |

### 1.3 Cross-cutting UI

- Detail panel (host metadata, ports, DNS, TLS, OT analysis, conversations, credentials, risk score, Purdue badge)
- Packet inspector: protocol tree, coloured hex dump, OT command log, TCP stream; can float or dock; search
- Sidebar: protocol, host-type, VLAN, and IP-version filters; filter presets; anomaly list by category; credentials; file transfers
- Search (`/`), keyboard shortcuts (`?`, `1`-`9`, `F`, `P`, `Space`, arrow keys), light and dark themes, collapsible sidebar
- Node annotations (stored in localStorage by IP); VLAN labels (localStorage)
- Exports: graph PNG; Connections, Hosts, Anomalies, Credentials, VLAN Inventory, and VLAN Traffic CSVs; Markdown audit report; VLAN SVG; matrix PNGs; OT JSON
- Session save and load (JSON)
- Fully offline: bundled D3 and GeoIP, no CDN

### 1.4 Supporting assets

- 375 pytest tests (backend-heavy; the frontend only has static regex guards)
- Docusaurus docs site plus DocSolace tours and screenshots; synthetic demo pcap (`fixtures/`)
- Versioning: `VERSION`, `CHANGELOG.md`, bump script, CI check and tagging

---

## 2. Gaps and problems

### 2.1 Architecture and code health

| # | Problem | Impact |
|---|---|---|
| A1 | `app.js` is one 9,466-line file with 139 top-level globals, 149 `innerHTML` writes, and 139 inline `style=` strings | Every change risks breaking an unrelated view; hard to test; XSS surface |
| A2 | `app.py` is one 4,000-line file; `analyze_pcap` is about 1,150 lines with nested closures | Parsers, rules, and serialization can't be tested or extended in isolation |
| A3 | Connections are keyed undirected (`sorted([src, dst])`) | Port-scan attribution and exfiltration direction can be wrong (open backlog bugs) |
| A4 | No persistence model: data lives in browser memory; edits are scattered across memory (OT edits), localStorage keyed by IP (notes, VLAN labels, presets, findings), and session JSON (which omits OT edits, notes, and VLAN labels) | A consultant can lose a day's classification work; nothing ties edits to an engagement |
| A5 | Upload is one blocking `fetch` with no progress, job queue, or cancel | Large captures look frozen and can time out |
| A6 | Server-side rendering caps (top 40 connections, 50 packets each) are baked into the analysis output | Drill-down is incomplete for anything outside the top N |
| A7 | No frontend tests and no CI test run (CI only deploys docs and checks the version) | Regressions are found by hand |
| A8 | No CSRF protection or authentication when run with `--public` | Unsafe on a shared client network |

### 2.2 UX and look and feel

| # | Problem |
|---|---|
| U1 | Nine peer tabs, several hidden until data arrives. The app reads as nine tools, not one workflow |
| U2 | Graph-first home. For OT consulting, the main deliverables are the **asset inventory, Purdue map, and architecture diagram**; the force graph is supporting evidence |
| U3 | Four separate annotation systems (node notes, OT risk labels, finding notes, VLAN labels) that don't know about each other |
| U4 | Editing is drag-only and one host at a time; no forms, bulk edits, or undo |
| U5 | The header is crowded (stats, nine tabs, filters, export, session, theme); exports are spread across the header, view toolbars, and sidebars |
| U6 | Emoji icons and hard-coded colours (OT and VLAN matrices are dark-only); inconsistent spacing and typography between views |
| U7 | Mobile and tablet layouts aren't usable; on-site work is often on a laptop, but report review happens elsewhere |

### 2.3 Missing capabilities (OT consulting workflow)

| # | Gap | Notes |
|---|---|---|
| G1 | **Engagement or project model** | Client, site, capture points (switch, SPAN, segment), captures, assessor, dates |
| G2 | **First-class asset inventory** | Editable record per asset: level, zone, type, vendor, model, firmware, serial, location, criticality, owner, notes; tracks auto vs. manual per field with the reason for each override; keyed by MAC and IP so edits survive new captures |
| G3 | **Passive asset fingerprinting** | Read identity from protocol responses the parser currently ignores: EtherNet/IP ListIdentity (vendor, product, serial, revision), Modbus FC43/14 device ID, S7 SZL (module, firmware), BACnet I-Am and device object, PROFINET DCP, LLDP system description, DHCP and NetBIOS names, SNMP sysDescr |
| G4 | **Protocol coverage** | PROFINET, OPC UA, IEC 61850 MMS and GOOSE, HART-IP, Omron FINS, MELSEC, Codesys are port-only or missing |
| G5 | **Zones and conduits (IEC 62443)** | User-defined zones, conduits with allowed protocols, violations computed from observed traffic |
| G6 | **Network architecture diagram** | Subnets, VLANs, gateways, and firewalls as a layered diagram, separate from the Purdue view; manual placeholders for devices never seen on the wire (firewalls, data diodes) |
| G7 | **Multi-capture merge with provenance** | Which capture point saw which asset or flow; incremental merge without losing edits; "new since last capture" |
| G8 | **Communication baseline and allowlist** | Mark flows as expected; alert on anything new; export as firewall-rule suggestions |
| G9 | **Vulnerability context** | Match vendor, model, and firmware against an offline ICS advisory feed (CISA ICSA / CVE) |
| G10 | **Deliverable-grade exports** | Asset register (CSV/XLSX), editable diagrams (SVG, draw.io), DOCX/PDF report, one-click engagement bundle (zip), re-importable project file |
| G11 | **Classification evidence and confidence** | "Why is this a PLC at L1?" (already in the backlog) |
| G12 | **Global query language** | `protocol:modbus level:1 risk>70` (already in the backlog) |
| G13 | **Optional live capture** | Capture from a local interface into the current engagement (later phase; offline pcap stays primary) |

---

## 3. Decisions

_To be filled in as we decide, one item at a time._

| # | Topic | Decision | Notes |
|---|---|---|---|
| D1 | Frontend stack | **React + TypeScript** (Vite build; built static bundle shipped so client sites need no internet or Node) | Chosen for ecosystem depth: React Flow for editable Purdue and architecture diagrams, mature data grids for the asset inventory, and the widest contributor and tooling familiarity. D3 kept where custom charts need it. Decided 2026-11-06 |
| D2 | Primary workflow and navigation | **Engagement-first, plus a Quick look mode** | Main path: create engagement → add captures (tagged with capture point) → Assets → Purdue map → Architecture → Findings → Report. Quick look analyzes a pcap without an engagement and can be promoted to one later. Decided 2026-11-06 |
| D3 | Persistence and deployment | **Two deployment modes, one codebase.** Laptop mode: one local SQLite database for all engagements (in the data folder, next to `captures/` and `exports/`); each engagement exports as a self-contained `.pcapvis` bundle (its data + original pcaps) for handover. *(Refined during M0 from "one SQLite file per engagement" so laptop and server modes share the identical schema.)* Team server mode: PostgreSQL + server/S3-compatible capture storage, Docker Compose | SQLAlchemy + Alembic so both databases share code and migrations. Server mode adds user accounts and roles, per-engagement membership, a per-field audit trail (who, when, old, new, reason), optimistic locking for concurrent edits, live updates, a background parse worker with progress and cancel, and laptop→server engagement import with merge. Optional SQLCipher encryption in laptop mode. Never run the SQLite file from a network share. Login: **local accounts** with roles to start; authentication sits behind an interface so SSO (Entra ID, Okta, LDAP) can be added later. Real-time: **edits appear for others within seconds** (server push) with conflict detection; live presence and co-editing are out of scope for now. Decided 2026-11-06 |
| D4 | Look and feel | **Workbench layout; light and dark themes, light by default** | Left rail = workflow stages (Overview, Captures, Assets, Purdue, Architecture, Flows, Findings, Report); center = canvas or table; right = editable inspector for the selection (fields, evidence, change history); bottom = timeline. Minimal header (engagement switcher, search, user). Light default suits client screen-shares and exports. A proper icon set replaces emoji; colours come from a design-token system so every view supports both themes. Decided 2026-11-06 |
| D5 | Migration approach | **Full rewrite from scratch**, including the parsing engine, in new folders on `develop` | Today's app stays on `master` as the **reference oracle** until parity: the existing 375 tests are ported as behaviour specs, and a differential harness runs old and new engines on the same pcaps (demo fixture + a growing regression corpus) and diffs hosts, flows, protocols, and anomalies. Old app retired only when the diff is clean or each difference is an intentional fix. Decided 2026-11-06 |
| D6 | Backend framework | **FastAPI** | Pydantic models → OpenAPI → generated TypeScript client, so frontend and backend types can't drift. Server-sent events/WebSockets for live updates. Background parse worker with progress and cancel. Decided 2026-11-06 |
| D7 | Scope of v1.0 | **All four groups:** feature parity + core workflow; passive device fingerprinting; zones, conduits and architecture diagram; report-ready exports | Large scope, so it ships through the milestones in section 4; each milestone is usable on its own. Decided 2026-11-06 |
| D8 | Packet dissection engine | **tshark (Wireshark) decodes all packets** | Minimum Wireshark 4.x, pinned in the container image. Use field output (`-T fields`/`-T ek`), not PDML/JSON trees, for speed; split large captures into chunks (`editcap`) and dissect in parallel across CPU cores; run the deep OT/identity pass only on OT and discovery traffic. Expect about 1–3 min per million packets, with progress. The app checks for tshark at startup and refuses to start with OS-specific install steps if it's missing or too old. tshark runs as a separate process, so its GPL licence doesn't affect this project's MIT licence. Decided 2026-11-06 |
| D9 | Packaging and distribution | **Container image is the primary distribution for both modes** | One image: tshark + Python backend + built React frontend. Laptop: `docker run -p 8080:8080 -v ./engagements:/data pcapvis`. Server: `docker compose up` (app, parse worker, PostgreSQL). Air-gapped: `docker save` / `docker load`. Works with Docker Engine (Linux), Docker Desktop (paid licence at larger companies), Podman Desktop, or Rancher Desktop. Native Linux install stays supported, guarded by the tshark startup check. Live capture (later) will need extra container permissions. Decided 2026-11-06 |

---

## 4. Target design (draft)

### 4.1 Repository layout

```
backend/                 FastAPI app (Python package `pcapvis`)
  pcapvis/
    ingest/              capture reader, L2-L4 decoding, flow table (directional)
    protocols/           one module per protocol: parse + fingerprint + OT command extraction
    rules/               one module per anomaly rule, shared rule interface
    assets/              asset identity (MAC/IP merge), classification with evidence, Purdue
    zones/               zones, conduits, violation detection
    reports/             XLSX, DOCX/PDF, SVG/draw.io, engagement bundle
    db/                  SQLAlchemy models, Alembic migrations (SQLite + PostgreSQL)
    api/                 routers, auth (local accounts behind an interface), SSE events
    jobs/                background parse worker (progress, cancel)
  tests/                 unit + differential tests against the legacy engine
frontend/                React + TypeScript (Vite), generated API client
legacy/                  today's app, frozen as the reference oracle until parity
docs/, site/             docs site (rewritten for v2 at the end)
```

### 4.2 Core data model

Engagement → Captures (file, hash, capture point, time range) → Observations (what each capture saw) →
**Assets** (merged identity: MACs, IPs, names; each field has an auto value, an optional manual
override, a reason, and evidence) → Flows (directional, per protocol, with provenance) →
Zones and Conduits → Findings (from rules or manual) → Audit log (who, when, field, old, new, reason).

Manual edits live on the asset, never on a capture, so new captures merge in without losing work.

### 4.3 Milestones (each one usable on its own)

| M | Content |
|---|---|
| M0 ✅ | Foundations: repo layout, FastAPI + React skeleton, design tokens and both themes, DB + migrations, local accounts, CI (tests, lint, type-check, build) |
| M1 ✅ | Engine: capture reader, directional flows, host and asset identity, IT/OT/IoT protocol parsers, anomaly rules; differential harness against legacy |
| M2 ✅ | Engagements and captures: create and open engagements, upload with background parsing and progress, capture points, Quick look, `.pcapvis` export and import |
| M3 ✅ | Asset inventory: grid with bulk edit, inspector with per-field overrides and reasons, evidence, change history, live updates between users |
| M4 | Purdue map: editable (React Flow), level and zone assignment by drag, dropdown, or bulk; matrix; OT command log |
| M5 | Passive fingerprinting: EtherNet/IP ListIdentity, Modbus FC43/14, S7 SZL, BACnet I-Am, PROFINET DCP, LLDP, DHCP, NetBIOS, SNMP |
| M6 | Zones, conduits, and architecture diagram: violation detection, editable layered diagram with manual devices |
| M7 | Network and forensic parity: graph, flows table, DNS, VLAN views and matrices, diff/baseline, packet inspector, credentials, file carving, dashboard |
| M8 | Findings and reports: findings workspace, asset register XLSX, SVG/draw.io, DOCX/PDF report, engagement bundle |
| M9 | Server mode hardening, laptop→server import with merge, docs rewrite, legacy retirement |

### 4.4 Milestone log

**M0, foundations: done (v0.2.0, 2026-11-06).**
- Repo split: `backend/` (FastAPI, `uv`), `frontend/` (React 19 + TypeScript 5.9, Vite), `legacy/` (v1, still green).
- Backend: settings via `PCAPVIS_*`; tshark startup gate with OS-specific install hints; SQLAlchemy 2 +
  Alembic (SQLite WAL / PostgreSQL), UTC-aware datetimes; local accounts (argon2id), DB-backed sessions
  storing only token hashes, login throttling, roles with last-admin protection, session revocation on
  role/password/deactivation changes; CSRF header guard, strict CSP and security headers; SPA serving
  with path-traversal protection; CLI (`serve`, `check`, `create-user`, `db-upgrade`, `openapi`).
- Frontend: workbench shell (header, stage rail, inspector, timeline), design tokens with light (default)
  and dark themes and no-flash theme restore, sign-in, account (password change), user admin; API
  types generated from OpenAPI.
- Packaging: multi-stage Dockerfile (tshark 4.4 in Debian, non-root, health check; ~700 MB, mostly
  Wireshark libraries, so trimming is a later task); `docker-compose.yml` for team server + PostgreSQL.
- CI: backend on SQLite and PostgreSQL, ruff, frontend lint/types/tests/build, API-types drift check,
  Playwright e2e against the production build, legacy suite, container build + health check.
- Tests: backend 104 (SQLite) / 103 + 1 SQLite-only skip (PostgreSQL), frontend 35, e2e 7, legacy 375.

**M1, packet engine: done (v0.3.0, 2026-11-06).**
- `pcapvis.engine`: tshark (EK JSON, fed through stdin) → typed packets → order-independent aggregator →
  hosts, directional flows, OT commands, credentials, files, anomalies. `pcapvis analyze <capture>` CLI.
- Directional flows (handshake, ICMP echo, port heuristics, late-SYN correction); per-direction counts.
- Hosts with evidence and confidence for host type and Purdue level; Wireshark's full OUI database;
  router-MAC detection; DNS/DHCP/LLDP/CDP names; TLS SNI/JA3/JA4; ENIP ListIdentity and BACnet I-Am identity.
- OT command extraction for Modbus, DNP3, S7comm, EtherNet/IP/CIP, IEC-104, BACnet with spec-based
  read/write classification; function names from Wireshark's tables (never hand-maintained).
- Credentials (FTP, POP3, IMAP, SMTP, HTTP Basic/form/bearer, MQTT, SNMP, Telnet); file extraction via
  tshark object export (HTTP, SMB, FTP-data, TFTP, IMF) with hashing and an interesting-file flag.
- 34 anomaly rules: direction-aware, grouped per (rule, src, dst), MITRE ATT&CK IDs, new default-password rule.
- Parallel, memory-bounded analysis (host-pair partitions in worker processes), byte-for-byte identical
  to single-process analysis.
- Legacy parity harness (`pcapvis.devtools.legacy_parity`, CI job `parity`): 0 unexplained differences on
  the demo capture and two synthetic OT/IT captures; every difference carries its reason.
- Tests: backend 257 (engine, protocols, rules, parallel, parity, CLI, plus M0's), frontend 35, e2e 7, legacy 375.

Findings while building M1 (decisions taken, details in `backlog.md`):
- **AppArmor:** Ubuntu's tshark profile only reads files under `/tmp`; the engine always feeds captures
  through stdin, so native installs work with any data folder.
- **TCP sequence analysis off:** with it on, tshark skips payloads of out-of-order segments, hiding
  credentials and PLC commands in SPAN captures with reordering. True retransmissions are de-duplicated
  by the engine instead.
- **tshark memory:** about 1.5 KB per packet in one process (480 MB for 300k packets), which is why large
  captures are split into ~64 MB host-pair partitions processed by a bounded worker pool.
- **Throughput:** about 9-12k packets/s on a 4-core laptop CPU; parallelism is hardware-bound there
  (~1.3x) and scales with physical cores on servers. Field extraction and Python decoding are the next
  optimisation targets (M2+).
- **Legacy bugs confirmed by the harness:** DNP3 parser reads the transport byte as the function code;
  EtherNet/IP parser never decodes CIP services; BACnet parser reads the service from the wrong byte and its
  service table is shifted (readProperty counted as a write); DNP3 "unusual function" labels wrong; port-scan
  and exfiltration direction bugs; OT rules only saw the first 50 packets per connection.

**M2, engagements and captures: done (v0.4.0, 2026-11-06).**
- Engagements (create, edit, archive, delete), per-engagement members with roles capped by the user's
  global role (server mode), capture points, audit log of every action.
- Capture upload (streamed, hashed, format-checked, size-limited, de-duplicated) and background analysis:
  a DB-backed job queue claimed atomically, so it runs in the web process (laptop) or in separate
  `pcapvis worker` processes / a `worker` container (team server), with heartbeat, crash recovery,
  progress and cancel. Results stored as gzip JSON next to the original captures.
- Live updates via server-sent events driven by a per-engagement revision counter (works across processes).
- Quick look: a personal engagement per capture, promotable to a real engagement by leads/admins.
- `.pcapvis` export/import with defensive import (path whitelist, zip-bomb and size guards, hash
  re-verification, result validation, all-or-nothing).
- UI: engagements home, engagement switcher, engagement-aware stage rail, overview (totals, members,
  export, settings, activity), Captures (capture points, drag-and-drop upload with progress, live status
  table), capture report (findings with ATT&CK IDs, hosts with evidence in the inspector, OT commands,
  masked credentials, files), Quick look page.
- docker-compose: web app + analysis worker + PostgreSQL; verified end to end.
- Tests: backend 337, frontend 62, e2e 11 (journey with live analysis, export/re-import, Quick look,
  viewer/outsider permissions), legacy 375.
- Routine: CI auto-merges owner PRs into `develop` once every check passes.

**M3, asset inventory: done (v0.5.0, 2026-11-06).**
- Assets merged across captures: identity by the host's own MAC (DHCP-safe), else IP; router MACs and
  over-shared MACs never merge a subnet; IP-only assets adopt a MAC once seen directly. Each host is a
  sighting (provenance: capture, capture point, IP, MAC), and detected values are recomputed from
  sightings, so re-analysing or deleting a capture is exact.
- Editable fields: name, type, Purdue level (0-5, 3.5, external), zone, criticality, vendor, model,
  firmware, serial, location, owner, tags, notes. Detected values come from classification, fingerprints
  (ENIP identity, BACnet, CDP) and MAC vendor; manual values carry who/when/why and survive new captures.
- Per-field history (manual edits, resets, detected changes with the capture that caused them), audit
  events for edits, optimistic locking (409 + "keep mine / discard mine" in the UI), bulk edit, manual
  assets (firewalls, diodes) that later captures merge into.
- Exports: CSV asset register (formula-escaped, Excel-friendly); `.pcapvis` format v2 carries the whole
  inventory with history, and v1 bundles still import (inventory derived from results).
- Existing finished captures are merged on upgrade (backfill at worker start); a merge failure never loses
  an analysis and is retried.
- UI: Assets stage with search, level/type filters, edited-only and external toggles, sorting, selection
  and bulk bar; inspector with Details (auto vs manual, reset, reason), Evidence (classification evidence,
  identity, services, sightings linked to capture reports) and History. Live updates between users.
- Tests: backend 405 (merge identity and edge cases, API permissions and conflicts, PostgreSQL concurrency,
  bundle v2 round trip and hostile asset data), frontend 75, e2e 13 (edit/bulk/CSV journey, live update
  across two browser sessions), legacy 375.
