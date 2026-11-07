# PCAP Visualizer

Passive OT/ICS network assessment from packet captures. Capture traffic at a client site, load the captures
into an engagement, and get an editable asset inventory, a Purdue map, IEC 62443 zones and conduits, triaged
findings and client-ready reports. Runs on a consultant's laptop or as a team server.

**Docs:** https://esandeepchoudary.github.io/pcap-vis-anz/ (source in [`docs/`](docs/))

## What it does

- **Decodes with tshark** (Wireshark's engine): directional flows, OT commands (Modbus, DNP3, S7comm,
  EtherNet/IP/CIP, IEC 60870-5-104, BACnet), cleartext credentials, files carried in traffic, and 34 detection
  rules mapped to MITRE ATT&CK for ICS. Large captures are analysed in parallel.
- **Asset inventory** merged across captures (matched by MAC, DHCP-safe). Every field has a detected and a manual
  value; manual edits carry a reason, survive new captures, and are recorded in each asset's history. Bulk edit,
  assets added by hand, conflict detection between collaborators.
- **Passive fingerprinting:** vendor, model, firmware and serial from Siemens S7 (SZL), Modbus device
  identification, EtherNet/IP identity, PROFINET DCP, SNMP and BACnet.
- **Purdue map:** drag assets between levels and zones; level matrix flagging DMZ bypass; OT matrix; OT command log.
- **Zones and conduits:** violations from observed traffic, an editable architecture diagram, inferred subnets.
- **Flows and forensics:** network graph by subnet, flow table, DNS, VLANs, capture diff, and a packet inspector
  that runs Wireshark display filters on the server.
- **Findings and reports:** triage (status, severity, recommendation, report inclusion), manual findings, Word
  and HTML (print to PDF) report, Excel asset register, editable draw.io/SVG Purdue diagram.
- **Laptop or team server:** single-user laptop mode with SQLite, or accounts, roles and per-engagement
  membership on PostgreSQL with separate analysis workers. Work moves between them as `.pcapvis` bundles, and a
  laptop bundle can be **merged** into a server engagement.

## Quick start (laptop)

```bash
docker build -t pcapvis .
docker run -p 127.0.0.1:8080:8080 -v "$PWD/engagements:/data" pcapvis
```

Open http://localhost:8080, create an engagement, and drop your captures. Native install, team server
(`docker compose up -d`), HTTPS and backups are in the [docs](docs/deployment.md).

## Development

| | |
|---|---|
| Backend (FastAPI, Python 3.12+, uv) | `cd backend && uv sync && uv run pcapvis serve --reload` |
| Frontend (React + TypeScript, Vite) | `cd frontend && npm ci && npm run dev` |
| Tests | `cd backend && uv run pytest -q` · `cd frontend && npm test && npm run e2e` |

Requires Wireshark/tshark 4.0+. Contributor guide: [`AGENTS.md`](AGENTS.md). Design decisions and milestone log:
[`REFACTOR.md`](REFACTOR.md). Changes: [`CHANGELOG.md`](CHANGELOG.md).

The previous Flask app (v0.1) is retired; it's preserved at the git tag `legacy-v1-final`.

## License

MIT (see [`LICENSE`](LICENSE)). tshark runs as a separate process; Wireshark's GPL doesn't apply to this code.
