---
sidebar_position: 20
sidebar_label: "Configuration"
title: "Configuration"
description: "Every PCAPVIS_* setting, with defaults."
---

# Configuration

Settings come from environment variables (or a `.env` file next to the app), all prefixed `PCAPVIS_`.

| Variable | Default | Meaning |
|---|---|---|
| `PCAPVIS_MODE` | `laptop` | `laptop`: single user, no login. `server`: accounts, roles, engagement membership. |
| `PCAPVIS_DATA_DIR` | `./pcapvis-data` (`/data` in the image) | Database (SQLite), captures, results, extracted files. |
| `PCAPVIS_DATABASE_URL` | SQLite in the data folder | For a team server: `postgresql+psycopg://user:password@host/db`. |
| `PCAPVIS_HOST` / `PCAPVIS_PORT` | `127.0.0.1` / `8000` | Where `pcapvis serve` listens (`0.0.0.0:8080` in the image). |
| `PCAPVIS_TSHARK_PATH` | `tshark` | tshark binary. Minimum version: `PCAPVIS_TSHARK_MIN_VERSION` (4.0.0). |
| `PCAPVIS_COOKIE_SECURE` | `false` | Set `true` behind HTTPS: session cookies only travel over TLS, and HSTS is sent. |
| `PCAPVIS_SESSION_TTL_HOURS` | `12` | How long a sign-in lasts. |
| `PCAPVIS_MAX_UPLOAD_BYTES` | 8 GB | Largest capture or bundle accepted. |
| `PCAPVIS_RUN_JOBS_IN_APP` | `true` | Analyse captures in the web process. Set `false` when running `pcapvis worker` separately. |
| `PCAPVIS_JOB_CONCURRENCY` | `1` | Captures analysed at once per process. |
| `PCAPVIS_ANALYSIS_WORKERS` | automatic | tshark processes per capture (large captures are split and analysed in parallel). |
| `PCAPVIS_ADMIN_USERNAME` / `PCAPVIS_ADMIN_PASSWORD` | – | Server mode, first start only: creates this admin if none exists. Remove afterwards. |

`pcapvis check` prints the tshark status and warns about risky server settings (cookies without HTTPS, SQLite
for several users, a short first-admin password). The same warnings appear in the log at startup.

## Command line

| Command | Does |
|---|---|
| `pcapvis serve [--reload]` | Run the web app. |
| `pcapvis worker` | Run analysis jobs (team server; scale by running more). |
| `pcapvis check` | tshark and configuration check. |
| `pcapvis create-user NAME --role admin\|lead\|consultant\|viewer` | Add a user (server mode). |
| `pcapvis db-upgrade` | Apply database migrations (also done automatically at startup). |
| `pcapvis export-all DIR [--no-captures]` | Back up every engagement as `.pcapvis` files. |
| `pcapvis analyze CAPTURE` | Analyse one capture from the command line and print a summary. |
