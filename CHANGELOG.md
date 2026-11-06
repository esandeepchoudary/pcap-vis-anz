# Changelog

All notable changes to this project are recorded here. Versions follow
[Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

Bump the version with `python scripts/bump_version.py <major|minor|patch> "summary"`
-- it updates `VERSION` and adds a new entry at the top of this file.

<!-- next-entry -->

## v0.3.0 -- 2026-11-06

- v2 rebuild M1 packet engine: tshark-based analysis (flows, hosts, OT commands, credentials, files, 34 anomaly rules), parallel memory-bounded processing, legacy parity harness, pcapvis analyze CLI

## v0.2.0 -- 2026-11-06

- v2 rebuild M0 foundations: FastAPI backend, React workbench shell with light/dark themes, local accounts and roles, laptop and team-server modes, container image, CI

## v0.1.0 -- 2026-11-06

- First versioned release. Baseline of the existing app: multi-protocol PCAP
  analysis (IT, OT/ICS, IoT), nine views (Graph, Table, DNS Map, OT Map, OT Log,
  VLAN, Diff, Dashboard, Findings), anomaly detection, session save/load, and
  the documentation site.
