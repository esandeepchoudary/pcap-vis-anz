# AGENTS.md

This file provides guidance to coding agents when working with code in this repository. It's the canonical, detailed agent-facing doc — `CLAUDE.md` just points here (Claude Code looks for that filename by convention).

> This is **v2** (the rebuild, v1.0.0 onwards). The decisions and milestone log behind it live in
> [`REFACTOR.md`](REFACTOR.md) — read it before changing architecture. The v1 Flask app was retired in M9;
> it's preserved at the git tag `legacy-v1-final`.

## Repository layout

| Path | What |
|---|---|
| `backend/` | v2 FastAPI backend (Python package `pcapvis`, managed with `uv`) |
| `frontend/` | v2 React + TypeScript app (Vite), API types generated from the backend |
| `Dockerfile`, `docker-compose.yml` | Container image (tshark + backend + built frontend); compose = team server with PostgreSQL |
| `REFACTOR.md` | Feature inventory, gap analysis, decisions D1–D9, target design, milestones M0–M9 |
| `VERSION`, `CHANGELOG.md`, `scripts/` | Versioning (see Workflow) |
| `docs/`, `site/`, `fixtures/` | User docs (Docusaurus site) + demo capture (see "Docs") |

## Branching

- `master` — released code. `develop` — the v2 integration branch.
- Do v2 work on `feature/<short-description>` branched from `develop`, and open the PR into `develop`.
- Major changes (new protocol/rule, data-model or API changes, cross-cutting refactors) always get a feature branch.
  Minor changes (typos, CSS tweaks) can go straight onto `develop`.

```bash
git checkout develop && git checkout -b feature/<short-description>
```

Once a feature is fully implemented and tests pass locally, push it and open a PR into `develop`.
**Auto-merge routine:** CI's final `auto-merge` job merges PRs into `develop` automatically once every
check passes (owner's PRs only; skipped for drafts and PRs labelled `no-automerge`; it merges exactly the
tested commit). After opening the PR, watch CI; when it has merged, sync local `develop`
(`git checkout develop && git merge --ff-only origin/develop`) and branch the next feature from it.
If CI fails, fix it on the branch (a new push re-runs CI). Merges into `master` (releases) stay manual:
ask the user.

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
| Docs site | `cd site && npm ci && npm run build` | Fails on broken links |

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

### Engagements and jobs (M2)

- **Access:** every engagement route goes through `EngagementAccess` (`as_viewer` / `as_editor` /
  `as_lead`) in `api/routes_engagements.py`; non-members get **404**, never 403, so names don't leak.
  Engagement roles are capped by global role (`MAX_MEMBER_ROLE`); Quick looks belong only to their creator.
- **Mutations call `eng.touch()`** (bumps `revision`) and `audit.record(...)`. The live-update stream
  (`/events`) and the frontend's cache invalidation depend on the revision changing.
- **Jobs:** `jobs/runner.py`. Claim with a conditional UPDATE (never "select then update"); progress,
  heartbeat and cancel go through the DB so `pcapvis worker` processes behave like the in-app runner.
- **Storage layout:** `engagements/storage.py` is the only place that builds paths; user-supplied names
  go through `safe_filename`. Imported bundles are untrusted: extend `bundle.py`'s whitelist and
  validation, never bypass it.

### Asset inventory (M3)

- **Manual values live on the asset, never on a capture.** `Asset.auto` (derived from traffic) and
  `Asset.overrides` (`{field: {value, reason, by, at}}`) are separate columns; merges only write `auto`,
  `observed`, `macs`, `ips`. The effective value is the override when present (`assets/fields.py`).
- **Editable fields are declared once** in `assets/fields.py` (`FIELDS`); `api/schemas.py`'s `EditableField`
  literal must list the same names (a test of the API checks the fields endpoint).
- **Identity** (`assets/merge.py`): the host's own MAC, else IP (router MACs and MACs carrying >16 IPs are
  ignored). Every host becomes an `AssetSighting` (capture, IP, Host JSON); `recompute` re-derives
  everything from sightings, so deleting or re-analysing a capture is exact. Assets that lose all sightings
  are pruned unless someone edited them (then they keep their last identity so later captures re-match).
- **Locking:** merges and edits first `lock_engagement()` (an UPDATE on the engagement row: a row lock on
  PostgreSQL, the write lock on SQLite). Single edits use a conditional UPDATE on `Asset.version`
  (optimistic lock → 409); merges never bump `version`.
- **History:** every override, reset, detected-value change after creation, and creation is an
  `AssetChange`. Bundles (format v2) carry assets, overrides, sightings and history; v1 bundles still import.
- **CSV:** cells are formula-escaped (`csv_safe`): hostnames and identity strings come from untrusted traffic.

### Purdue map (M4)

- **Links and OT operations** (`AssetLink`, `AssetOtOp`) are built per capture in `merge.build_links`, from
  that capture's sightings (IP → asset), and rebuilt from scratch on every merge of the capture. The API
  (`api/routes_links.py`) aggregates across captures. OT operations are oriented master → device (an error
  response is counted against the request's direction).
- **A migration that adds merge-derived data** must reset `captures.assets_merged_at` so finished captures
  are re-merged at the next start (see `0004`). Re-merging is idempotent.
- **Frontend:** `lib/purdue.ts` holds the pure layout (`layoutPurdue`), drop detection (`dropTarget`) and the
  DMZ-bypass rule (`bypassesDmz`: L4+ ↔ L3 and below); unit-test changes there. The map (`PurdueMap.tsx`,
  React Flow) applies drops through the bulk-edit endpoint with an optimistic cache update. React Flow
  needs the jsdom stubs in `test/setup.ts`; drag behaviour is covered by `e2e/purdue.spec.ts`.

### Passive fingerprinting (M5)

- `engine/fingerprint.py` reads identity a device reveals in its **own responses** (S7 SZL, Modbus FC43/14,
  CIP identity object, PROFINET DCP, SNMP system group, BACnet object-name) into `Host.identity`, with keys
  namespaced by source (`s7_`, `modbus_`, `enip_`, `pn_`, `snmp_`, `bacnet_`). Values are untrusted: always
  go through `clean()`.
- Device-type hints come from the final identity (`type_hints`), not per packet, so parallel == serial holds.
- `assets/merge.py` maps identity keys to asset fields (`IDENTITY_SOURCES`, `SELF_NAMES`) and records where
  each value came from (`observed.auto_sources`, labels in `SOURCE_LABELS`, mirrored in the frontend's
  `lib/assets.ts`). Add a protocol: fields in `fields.py`, extractor + builder + test (verify with `tshark -V`).

### Zones, conduits, architecture (M6)

- `pcapvis/zones/`: a `Zone` row adds metadata (level, SL-T, diagram position) to a zone **name**; assets
  belong to a zone through their `zone` field, so zones used on assets but not defined are listed too.
  Renaming a zone edits each member asset through `assets.service.edit` (history: "Zone renamed from …").
- Violations are computed on read from `assets.links.aggregate_links` (shared with the Purdue map): traffic
  between two zoned assets in different zones needs a conduit; a conduit with an `allowed` list flags other
  protocols (empty list = anything). Bundles (format v3) carry zones and conduits.
- Networks are inferred (private IPv4 /24 from asset addresses); manual firewalls/diodes are manual assets.

### Flows and forensics (M7)

- The packet inspector (`engine/inspect.py`) runs tshark on demand: capture via stdin, the display filter as a
  single argv item (never a shell), tshark's own error for bad filters (→ 400), time and output caps, and
  `-c N` so decoding frame N stops reading there. Editors only: raw packets contain unmasked secrets.
- Per-capture views (flows, DNS, VLANs) read the stored result; engagement views (graph, diff, dashboard) come
  from assets, sightings and links. `lib/graph.ts` holds the deterministic ring layout.

### Security invariants (sweep after M8)

- `tests/test_security_sweep.py` walks the OpenAPI schema: a new route must require sign-in (or be added to
  the explicit public allowlist), return 404 to non-members if engagement-scoped, and need the CSRF header if
  unsafe. Don't weaken it to make a route pass.
- JSON request bodies are capped (`MAX_JSON_BODY`); uploads/imports are multipart with their own limits.

### Findings and reports (M8)

- Rule findings are collected per capture (`FindingHit`, rebuilt each merge) and merged by anomaly id across
  captures; analyst state lives in `Finding` (keyed the same way), so re-analysis never loses triage.
  Manual findings are `Finding` rows with `source="manual"`. Bundles (format v4) carry `Finding` rows.
- Reports (`pcapvis/reports/`) build from one `gather()` snapshot. Every format escapes untrusted text its own
  way: XLSX cells are forced to text (no formulas), draw.io labels use `html=0` and XML escaping, SVG/HTML are
  escaped and script-free, DOCX strips XML-illegal control characters. Keep those tests green.
- PDF comes from printing the HTML report; there's no server-side PDF engine in the image.
- `pcapvis serve` uses a 5 s graceful-shutdown timeout and SSE streams end every 5 min (clients reconnect),
  so open live-update connections can't block restarts.

### Packet engine (`backend/pcapvis/engine/`, M1)

- **Flow:** `analyze.analyze_capture(path)` → `runner.stream_packets` (tshark `-T ek`, capture fed via
  **stdin** because tshark's AppArmor profile blocks most paths) → `packet.decode` → `aggregate.Aggregator`
  → `finish()` → `rules.run_rules` → `model.AnalysisResult`. Large captures go through
  `split.py` + `parallel.py` + `worker.py` (host-pair partitions, worker processes, `Aggregator.merge`).
- **Order independence is a hard invariant:** the Aggregator must give the same result whether it sees the
  whole capture or merged partitions. "First seen" uses packet timestamps (`_first`), ties break by value,
  flows are numbered in `finish()`. `tests/test_parallel.py` asserts parallel == serial; keep it green.
- **Adding a tshark field:** add it to `fields.py`; `test_every_requested_field_exists_in_installed_tshark`
  fails on typos. Enumerated values get names from Wireshark via `tshark_env.NAMED_FIELDS`, never from
  hand-written tables.
- **Adding a protocol/command type:** `ot.py` (one OtEvent per request; responses only add errors).
  **Adding a rule:** a function in `rules.py` decorated with `@rule(...)`; group hits with `Group`.
- **Tests build captures with scapy** (`tests/pcapgen.py`, byte-accurate payload builders) and run real
  tshark. Verify a new builder decodes in Wireshark (`tshark -V`) before asserting on it.
- **Legacy parity** was checked by a differential harness until M9 (0 unexplained differences); it was removed
  with the v1 app. Behaviours it found are pinned by tests in `test_engine_core.py` and friends.

## Docs

- **`docs/`** — the user docs for v2 (Markdown), served by the Docusaurus site in **`site/`** and deployed to
  GitHub Pages on pushes to `master` that touch `docs/` or `site/`. `docs/_sidebar.docsolace.json` orders the
  sidebar; `docs/archive/` keeps the v1 pages (shown under "Archive"). Update the matching page when a feature
  changes; `cd site && npm run build` must pass (it fails on broken links).
- **`tours/archive/`** — DocSolace tours recorded against v1; re-record against v2 for screenshots.
- **`fixtures/network-capture-demo.pcap`** (+ `build_demo_pcap.py`) — synthetic demo capture used by tests,
  e2e and docs.

## Other docs in this repo

- **`README.md`** — the user-facing README (features, install, usage). Keep it current.
- **`backlog.md`** -- a running log of completed work and open ideas, organized roughly chronologically by feature/date. Mostly a historical record at this point (235+ completed items vs. a handful open) -- check it for "is this already done" before assuming a feature doesn't exist.
- **`REVIEW.md`**, **`review-by-claude.md`** -- point-in-time security/logic audit reports (dated 2026-05-17 and 2026-06-15 respectively). Their file:line references drift as the code changes and are already stale relative to the current file sizes above -- useful for the *categories* of issues found, not as a current line-accurate map.
