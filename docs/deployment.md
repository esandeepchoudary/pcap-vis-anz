---
sidebar_position: 21
sidebar_label: "Team server"
title: "Team server deployment"
description: "Run PCAP Visualizer for a team with Docker Compose, PostgreSQL, workers and HTTPS; backups, upgrades and merging laptop work."
---

# Team server deployment

## Start it

```bash
cp .env.example .env      # set POSTGRES_PASSWORD and PCAPVIS_ADMIN_PASSWORD (16+ characters)
docker compose up -d      # web app + analysis worker + PostgreSQL
```

Sign in as the admin, then **Users** to add people with a role: *admin* (everything), *lead* (create
engagements, manage members), *consultant* (work in engagements they're added to), *viewer* (read-only).
Remove `PCAPVIS_ADMIN_PASSWORD` from `.env` after the first start. Run `docker compose exec app pcapvis check`
for configuration warnings.

**Workers.** Uploaded captures are analysed by the `worker` service. Add more with
`docker compose up -d --scale worker=3`; jobs are shared safely between them, and a worker that dies has its job
picked up again.

## HTTPS

Put the app behind a reverse proxy that terminates TLS, publish the app port on localhost only, and set
`PCAPVIS_COOKIE_SECURE=true`. With [Caddy](https://caddyserver.com):

```
pcapvis.example.internal {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1        # live updates (server-sent events) must not be buffered
    }
}
```

```bash
PCAPVIS_PUBLISH_PORT=127.0.0.1:8080   # in .env
PCAPVIS_COOKIE_SECURE=true
```

## Merging laptop work

Consultants on site work in laptop mode, then **Export .pcapvis** from the engagement's overview. On the server,
a lead opens the engagement and uses **Merge work from another machine**:

- captures already on the server are skipped (same SHA-256); new ones are added and merged into the inventory;
- edits from the laptop are applied where the server has no manual value; where both sides changed the same
  field, the server's value is kept and listed so you can decide;
- zones, conduits, assets added by hand and findings triage are added when missing.

Merging the same bundle twice changes nothing. Importing a bundle as a **new** engagement is on the Home page.

## Backups and upgrades

- **Database:** `docker compose exec db pg_dump -U pcapvis pcapvis > pcapvis.sql`.
- **Files:** the `captures` volume (original captures, results, extracted files).
- **Portable:** `docker compose exec app pcapvis export-all /data/backup` writes one `.pcapvis` per engagement.

Upgrading: pull or build the new image and `docker compose up -d`. Database migrations run automatically at
startup; when a release adds data derived from captures, finished captures are re-merged in the background.

## Air-gapped sites

`docker save pcapvis:latest postgres:17-alpine | gzip > pcapvis-images.tar.gz`, copy it over, then
`docker load -i pcapvis-images.tar.gz`. Nothing calls out to the internet.
