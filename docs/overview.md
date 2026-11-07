---
sidebar_position: 1
sidebar_label: "Overview"
title: "Overview"
description: "PCAP Visualizer turns packet captures from an OT site into an editable asset inventory, Purdue map, zone and conduit model, findings and client-ready reports."
---

# Overview

PCAP Visualizer helps consultants assess industrial (OT/ICS) networks from **passive packet captures**. You
capture traffic at a client site (SPAN ports, TAPs), load the captures into an **engagement**, and the tool:

- decodes every packet with **tshark** (Wireshark's engine) and builds hosts, directional flows, OT commands,
  credentials, extracted files and 34 detection rules mapped to MITRE ATT&CK for ICS;
- merges hosts from all captures into one **asset inventory** that you correct and enrich by hand, with every
  change recorded (who, when, why) and never lost when new captures arrive;
- reads **device identity** that controllers reveal about themselves (Siemens S7, Modbus, EtherNet/IP,
  PROFINET, SNMP, BACnet): vendor, model, firmware, serial;
- draws an editable **Purdue map**, flags traffic that **bypasses the DMZ**, and lists every OT read/write;
- lets you define **IEC 62443 zones and conduits** and flags traffic no conduit allows;
- produces **deliverables**: a Word report, an HTML report (print to PDF), an Excel asset register, and an
  editable draw.io Purdue diagram.

It runs on a consultant's **laptop** (single user, nothing to set up) or as a **team server** (accounts, roles,
PostgreSQL, separate analysis workers). Work moves between the two as `.pcapvis` bundles.

## The workflow

| Stage | What you do |
|---|---|
| [Captures](captures.md) | Create an engagement, name your capture points, upload pcaps; analysis runs in the background. |
| [Assets](assets.md) | Review the merged inventory, fix types and levels, add owners, criticality, notes; bulk edit. |
| [Purdue map](purdue-map.md) | Drag assets between levels and zones; check the level matrix and OT command log. |
| [Architecture](architecture.md) | Define zones and conduits, review violations, check subnets and gateways. |
| [Flows](flows.md) | Explore who talks to whom, DNS, VLANs, changes between captures, raw packets. |
| [Findings & reports](findings-and-reports.md) | Triage findings, add your own, download the report and exports. |

Start with [Getting started](getting-started.md).
