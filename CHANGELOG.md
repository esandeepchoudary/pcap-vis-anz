# Changelog

All notable changes to this project are recorded here. Versions follow
[Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

Bump the version with `python scripts/bump_version.py <major|minor|patch> "summary"`
-- it updates `VERSION` and adds a new entry at the top of this file.

<!-- next-entry -->

## v0.7.0 -- 2026-11-06

- v2 rebuild M5 passive fingerprinting: identity from S7 SZL, Modbus device identification, CIP identity object, PROFINET DCP, SNMP and BACnet; type hints from identity; asset fields filled with their source

## v0.6.0 -- 2026-11-06

- v2 rebuild M4 Purdue map: editable lanes and zones by drag, links and OT operations across captures, level matrix with DMZ-bypass detection, OT matrix, engagement-wide OT command log

## v0.5.0 -- 2026-11-06

- v2 rebuild M3 asset inventory: assets merged across captures with provenance, per-field manual overrides with reasons and history, bulk edit, manual assets, conflict detection, CSV asset register, inventory in .pcapvis bundles (format v2)

## v0.4.0 -- 2026-11-06

- v2 rebuild M2 engagements and captures: engagements and members, capture points, uploads with background analysis (in-app or worker), live updates, capture report UI, Quick look, .pcapvis export/import, CI auto-merge routine

## v0.3.0 -- 2026-11-06

- v2 rebuild M1 packet engine: tshark-based analysis (flows, hosts, OT commands, credentials, files, 34 anomaly rules), parallel memory-bounded processing, legacy parity harness, pcapvis analyze CLI

## v0.2.0 -- 2026-11-06

- v2 rebuild M0 foundations: FastAPI backend, React workbench shell with light/dark themes, local accounts and roles, laptop and team-server modes, container image, CI

## v0.1.0 -- 2026-11-06

- First versioned release. Baseline of the existing app: multi-protocol PCAP
  analysis (IT, OT/ICS, IoT), nine views (Graph, Table, DNS Map, OT Map, OT Log,
  VLAN, Diff, Dashboard, Findings), anomaly detection, session save/load, and
  the documentation site.
