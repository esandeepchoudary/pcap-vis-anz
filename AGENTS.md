# AGENTS.md

This file provides guidance to coding agents when working with code in this repository. It's the canonical, detailed agent-facing doc — `CLAUDE.md` just points here (Claude Code looks for that filename by convention).

> **A full rebuild (v2) is in progress on the `develop` branch.** The plan and every agreed decision live in
> [`REFACTOR.md`](REFACTOR.md) — read it before changing architecture. New work goes into `backend/` and
> `frontend/`. Today's app lives in `legacy/`, frozen as the **reference oracle** the new engine is compared
> against; only fix it if a legacy bug blocks comparison.

## Repository layout

| Path | What |
|---|---|
| `backend/` | v2 FastAPI backend (Python package `pcapvis`, managed with `uv`) |
| `frontend/` | v2 React + TypeScript app (Vite), API types generated from the backend |
| `legacy/` | v1 Flask app + its 375 tests (reference oracle until v2 reaches parity) |
| `Dockerfile`, `docker-compose.yml` | Container image (tshark + backend + built frontend); compose = team server with PostgreSQL |
| `REFACTOR.md` | Feature inventory, gap analysis, decisions D1–D9, target design, milestones M0–M9 |
| `VERSION`, `CHANGELOG.md`, `scripts/` | Versioning (see Workflow) |
| `docs/`, `site/`, `tours/`, `fixtures/` | Docs site + demo capture (see "Beyond the core app") |

## Branching

- `master` — released code. `develop` — the v2 integration branch.
- Do v2 work on `feature/<short-description>` branched from `develop`, and open the PR into `develop`.
- Major changes (new protocol/rule, data-model or API changes, cross-cutting refactors) always get a feature branch.
  Minor changes (typos, CSS tweaks) can go straight onto `develop`.

```bash
git checkout develop && git checkout -b feature/<short-description>
```

Once a feature is fully implemented and tests pass, ask the user to review and merge:

> "Feature is complete and tests pass. Please review and merge `feature/<name>` into `develop` when ready."

## Workflow

After completing any change:
1. Update `README.md` to reflect the change, and `REFACTOR.md` if a decision or milestone changed.
2. Update `backlog.md` -- mark completed items `[x]`, add newly discovered bugs or ideas.
3. **Bump the version** -- every change, on every branch, before it is merged:
   `python scripts/bump_version.py <patch|minor|major> "one-line summary"`.
   Use `patch` for fixes/tweaks, `minor` for new features, `major` for breaking changes
   (project/session file format, public API schema). This updates `VERSION` and
   `CHANGELOG.md`; commit both. Bump once per branch/PR, not per commit -- if the branch
   already bumped, edit its `CHANGELOG.md` entry instead. CI (`.github/workflows/version.yml`)
   fails PRs into `master` that don't raise the version and tags `master` as `v<VERSION>` on merge.
   During the v2 rebuild each milestone is one minor bump (M0 = 0.2.0, …); v2 ships as 1.0.0.
4. **Test as you build, rigorously** -- write tests alongside the code (happy paths, edge cases, failure
   and security paths) and run every suite you touched (see Testing). Never leave a failing test.
5. Start the app and check it runs without errors (see Running the app) before reporting the task complete.
6. Commit and push to GitHub:

```bash
git add <changed files>
git commit -m "your message"
git push
```

## Testing

| Suite | Command | Notes |
|---|---|---|
| Backend | `cd backend && uv run pytest -q` | SQLite by default |
| Backend on PostgreSQL | `PCAPVIS_TEST_DATABASE_URL=postgresql+psycopg://u:p@host/db uv run pytest -q` | Wipes that DB's `public` schema per test — use a throwaway DB |
| Backend lint | `cd backend && uv run ruff check .` | |
| Frontend | `cd frontend && npm test` (vitest), `npm run typecheck`, `npm run lint` | Component tests stub `fetch` via `src/test/utils.tsx` |
| API types | `cd frontend && npm run gen:api` | Regenerate after any backend schema change and commit `src/api/schema.d.ts`; CI fails if stale |
| End-to-end | `cd frontend && npm run build && npm run e2e` | Playwright against the production build served by the real backend (server mode, tshark required) |
| Legacy | `cd legacy && python -m pytest tests/ -q` | Reference oracle; must stay green |

CI (`.github/workflows/ci.yml`) runs all of these plus a container build/health check on every push and PR.

## Running the app

**v2 (development, hot reload):**

```bash
cd backend && uv sync && uv run pcapvis serve --reload            # API on 127.0.0.1:8000 (laptop mode)
cd frontend && npm ci && npm run dev                                # UI on http://<host>:5173, proxies /api
PCAPVIS_MODE=server PCAPVIS_ADMIN_USERNAME=admin PCAPVIS_ADMIN_PASSWORD='…10+ chars…' uv run pcapvis serve --reload
```

`pcapvis serve` refuses to start without tshark 4.0+ (`uv run pcapvis check` to diagnose). Settings are
`PCAPVIS_*` environment variables — see `backend/pcapvis/config.py`.

**v2 (container):** `docker build -t pcapvis . && docker run -p 8080:8080 -v ./engagements:/data pcapvis`
(laptop mode), or `docker compose up -d` for team-server mode with PostgreSQL (configure `.env` from `.env.example`).

**Legacy v1:**

```bash
pip install -r legacy/requirements.txt   # first time; add --break-system-packages on Kali/Debian
python legacy/app.py                     # serves on http://localhost:5000 (--public, --port 8080 also work)
```

## v2 architecture (M0 foundations)

- **Backend (`backend/pcapvis/`)**: `app.py` is the factory (`create_app(settings)`): tshark gate → Alembic
  migrations → user bootstrap → routers → CSRF + security-header middleware → SPA serving. `config.py`
  (pydantic-settings), `tshark.py` (detection/version check), `db/` (SQLAlchemy models, `UTCDateTime`,
  engine with SQLite WAL pragmas, programmatic migrations in `pcapvis/migrations/`), `auth/service.py`
  (argon2 passwords, DB-backed sessions storing only token hashes, login throttle), `api/` (routers +
  Pydantic schemas), `cli.py` (`serve`, `check`, `create-user`, `db-upgrade`, `openapi`).
- **Modes**: `laptop` (no sign-in; a built-in `local` admin user) and `server` (local accounts, roles
  admin > lead > consultant > viewer). Same code; only `PCAPVIS_MODE` / `PCAPVIS_DATABASE_URL` differ.
- **Security invariants** — keep these when adding routes: every unsafe `/api/` request must carry
  `X-PcapVis-Client: 1` (CSRF guard; the frontend client adds it); session cookie is httpOnly +
  SameSite=Strict; strict CSP (no inline scripts — `public/theme-init.js` exists for that reason); never
  store raw session tokens; never return password hashes; admin-only routes use `require_role(Role.admin)`.
- **Schema changes**: edit `db/models.py`, then `cd backend && uv run alembic revision --autogenerate -m "…"`
  and review the file. `tests/test_db.py::test_models_match_migrations` fails if they drift.
- **Frontend (`frontend/src/`)**: `App.tsx` (auth gate + routes), `components/AppShell.tsx` (workbench:
  header, stage rail, main, inspector, timeline), `stages.ts` (the workflow stages and their milestones),
  `api/client.ts` (typed `openapi-fetch` client) + `api/hooks.ts` (TanStack Query), `theme/` (light default,
  dark optional; **all colours come from `theme/tokens.css`** so both themes stay complete), icons from
  `lucide-react` (no emoji).

## Legacy app (v1, in `legacy/`)

Everything below describes the legacy app. Paths are relative to `legacy/`.

### Architecture

A single-page Flask app with three files of substance:

- **`app.py`** -- entire Python backend (~3,785 lines)
- **`static/js/app.js`** -- entire frontend (~9,466 lines, vanilla JS + D3.js v7)
- **`static/css/style.css`** -- dark GitHub-style theme (~3,207 lines)
- **`templates/index.html`** -- static HTML shell, no Jinja logic

D3.js v7 is bundled locally at `static/js/d3.v7.min.js` for air-gapped use; don't CDN-ify it.

#### Backend (`app.py`)

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

**Other routes** beyond `/` and `/upload`: `GET /version` returns `{"version": ...}` from the `VERSION` file; `GET /download/<sha256>` serves a cached file transfer by hash; `GET /gpu-status` reports whether CUDA/cupy acceleration is available; `GET /session-schema` returns a real JSON Schema describing the `/upload` response shape (nodes/edges/anomalies/stats/etc.) -- fetch it directly rather than reverse-engineering the shape from `app.py` if you're integrating against the API.

#### Frontend (`static/js/app.js`)

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

### Key limits (change in `legacy/app.py`)

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
