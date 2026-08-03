---
sidebar_position: 1
sidebar_label: "Overview"
title: "Overview"
description: "PCAP Network Visualizer is an interactive web-based tool for visualizing network packet captures. It is a single-page Flask application: you upload a .pcap,…"
---

# Overview

## What it is

PCAP Network Visualizer is an interactive web-based tool for visualizing network packet captures. It is a single-page Flask application: you upload a `.pcap`, `.pcapng`, or `.cap` file (up to 1 GB) and it renders the traffic as a live force-directed graph, built with D3.js v7, with host classification, protocol detection, OS fingerprinting, and DNS resolution. The tool ships with a bundled GeoIP database and a locally-bundled copy of D3.js so it can run entirely offline, and it is explicitly designed for air-gapped / offline use — no CDN requests, no external font loading, and the only outbound browser request is the upload itself.

## Who it's for

The feature set is aimed at people who analyze network traffic captures for security and operations purposes: general network/security analysts (port scan, credential, beaconing, and exfiltration detection; a per-host risk score; a findings triage workspace), and OT/ICS and IoT specialists in particular, given dedicated support for industrial protocols (Modbus, DNP3, S7comm, EtherNet/IP, IEC 60870-5-104, BACnet, OPC-UA, PROFINET, HART-IP, GE SRTP, OMRON FINS, Emerson DeltaV), a Purdue Model swimlane view (OT Map), an OT command log, and VLAN segmentation analysis.

## What it does

After a capture is uploaded, the backend streams the file and classifies hosts into one of 38 host types, identifies 80+ protocols by port, fingerprints operating systems from TTL/hop-limit, looks up MAC vendors (including OT and IoT vendors), and reconstructs DNS query logs. It runs 32 anomaly detection rules across general network, OT/ICS, IoT, and VLAN categories (port scans, cleartext credentials, password reuse, beaconing, data exfiltration, suspicious ports, known-bad TLS/JA3 fingerprints, unauthorized PLC writes, VLAN hopping, ARP spoofing, broadcast storms, and more). Nine views are available in the UI — Graph, Table, DNS Map, OT Map, OT Log, VLAN Graph, Diff (baseline comparison), Dashboard, and Findings (an analyst triage workspace) — along with exports to PNG, CSV (connections, hosts, anomalies, credentials, VLAN inventory/traffic), and a Markdown audit report.

## Tutorials

- [Browse the connection Table view and inspect packets](table-view.md) — The Table view — a sortable connection table listing every network connection observed in the capture (Source IP, Destination IP, Protocol(s), Packets, Bytes, Ports, Duration columns, with sortable column headers), plus a live packet-inspector search that filters by any column text once a connection row is opened.

- [Compare a baseline capture against a current capture (Diff view)](diff-view.md) — The Diff view compares two PCAP uploads — a baseline and a current capture — and surfaces new/disappeared hosts, new connections, traffic-volume changes, and new anomalies vs. the baseline. Driven by renderDiff() in static/js/app.js.

- [Explore DNS queries in the DNS Map view](dns-map.md) — The DNS Map view — a DNS query explorer showing hostnames resolved and query logs extracted from captured DNS traffic. Upload a capture, switch to the DNS Map tab, and select a host to see its resolved hostnames and query log.

- [Explore OT/ICS devices in the OT Map Purdue swimlane view](ot-map.md) — The OT Map view — a Purdue Model swimlane view (L0 Field to L6 Public Internet) showing OT/ICS devices grouped by network zone, with a toggle to switch to an OT Communication Matrix (device x device adjacency grid). Upload a capture and switch to the OT Map tab to see the swimlane layout.

- [Explore the VLAN view (super-nodes and cross-VLAN traffic)](vlan-graph.md) — The VLAN view — shows VLANs as super-nodes with hosts clustered inside, cross-VLAN traffic highlighted, plus a VLAN Matrix toggle (VLAN×VLAN flow adjacency grid). This tour covers reaching the VLAN tab after uploading a capture and observing the clustered-graph state; the Matrix toggle itself is not yet covered.

- [Findings — analyst triage workspace](findings-workspace.md) — The Findings view is an analyst triage workspace that automatically derives reviewable findings from anomalies, captured credentials, file transfers, OT write/error command groups, and high-risk hosts. Each finding supports a status (Open/etc.), severity, a "Report" include/exclude checkbox, and free-text notes, so an analyst can triage a capture's results into a report-ready set.

- [Graph view — network visualization surface](graph-view.md) — The Graph view is the default view after uploading a capture: an interactive force-directed graph of hosts and connections, with filtering, search, a node detail panel, layout switching (Force/Radial/ Cluster), pin/isolate, and a minimap. This is the app's primary network visualization surface.

- [Upload a capture and explore the network graph](upload-and-explore.md) — Upload a .pcap/.pcapng/.cap capture file (via the drop zone's click-to-browse file picker) and see it rendered as an interactive network graph. This is the app's entry point — every other view (Table, DNS Map, OT Map, VLAN, Findings, Dashboard, etc.) depends on having uploaded a capture first.

- [View the Dashboard summary](dashboard.md) — The Dashboard view — summary cards, a risk-score bar chart, protocol distribution, and a clickable Top Anomalies list, giving an at-a-glance overview of the analyzed capture.

- [View the OT Log's chronological command history](ot-log.md) — The OT Log view — a chronological table of OT command history (Modbus and S7comm reads, writes, and errors) with protocol and direction filter buttons. Lets an analyst review every industrial-control command exchanged between the engineering workstation and PLCs in a capture, in order.


<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
