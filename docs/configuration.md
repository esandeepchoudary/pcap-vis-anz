---
sidebar_position: 4
sidebar_label: "Configuration"
title: "Configuration"
description: "The README documents these settings as constants in app.py (there is no .env file for the application itself): MAXUPLOADFILES (default 100) — maximum files per…"
---

# Configuration

## Backend limits and settings

The README documents these settings as constants in `app.py` (there is no `.env` file for the application itself): `MAX_UPLOAD_FILES` (default 100) — maximum files per upload request; `MAX_CONTENT_LENGTH` (default 1 GB) — maximum total upload size; `MAX_PACKETS` (default 1,000,000) — packets processed per file; `MAX_HOSTS` (default 250,000) — a parse-time backstop on unique hosts per file; `MAX_CONNECTIONS` (default 1,000,000) — a parse-time backstop on unique IP-pairs per file; `MAX_STORED_PER_CONN` (default 50) — packets stored per connection for the packet inspector; `_FILE_CACHE_MAX_BYTES` (default 256 MB) — memory budget for captured file bodies; `RENDER_NODE_CAP` (default 1,500) — maximum SVG node groups drawn in the force graph; `RENDER_EDGE_CAP` (default 4,000) — maximum edges drawn in the force graph; and `MAX_CRED_STATE_ENTRIES` (default 5,000) — half-open credential state entries tracked per protocol. The README notes that CSV exports always use the full parsed dataset regardless of these render caps; a capture exceeding `RENDER_NODE_CAP` shows a banner noting the graph displays only the top-N hosts by traffic while exports remain complete.

## Command-line and environment options

The listening port defaults to 5000 and can be changed with the `--port` flag; the `--public` flag binds the server to `0.0.0.0` for LAN access (see the getting-started page for the associated security warning). The `GEOIP_DB_PATH` environment variable can point the app at a richer, city-level GeoIP database (such as `GeoLite2-City.mmdb` or `dbip-city-lite.mmdb`) in place of the bundled DB-IP Country Lite database; it works with both `python app.py` and gunicorn. Absent that variable, the app also checks the default system path `/usr/share/GeoIP/GeoLite2-City.mmdb` before falling back to the bundled database.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
