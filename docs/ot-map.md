---
sidebar_position: 16
sidebar_label: "Explore OT/ICS devices in the OT Map Purdue swimlane view"
description: "The OT Map view — a Purdue Model swimlane view (L0 Field to L6 Public Internet) showing OT/ICS devices grouped by network zone, with a toggle to switch to an…"
---

# Explore OT/ICS devices in the OT Map Purdue swimlane view

The OT Map view — a Purdue Model swimlane view (L0 Field to L6 Public Internet) showing OT/ICS devices grouped by network zone, with a toggle to switch to an OT Communication Matrix (device x device adjacency grid). Upload a capture and switch to the OT Map tab to see the swimlane layout.


## Steps

1. **Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (OT Map only appears post-upload).
**

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (OT Map only appears post-upload).
](images/ot-map/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (OT Map only appears post-upload).
 (mobile)](images/ot-map/empty-state@mobile.png)

   </details>

   Before any capture is loaded, the app presents a full-page drop zone inviting the user to drop one or more capture files or click to browse, with accepted formats listed as .pcap, .pcapng, and .cap, up to 100 files and 1 GB total. The header stats for Hosts, Connections, and Packets all read a placeholder dash since no data has been parsed yet, and none of the view tabs (Graph, Table, DNS Map, OT Map, OT Log) are functional targets for switching views until a file has been analyzed — the OT Map view described in the rest of this tour only becomes reachable after an upload completes.

2. **OT Map view observed with fixtures/network-capture-demo.pcap: a summary bar reading "29 devices / 5 active levels / 14 cross-zone / 2 cross-level / 5 bridges / 17 anomalies / filtered" plus a callout "Cross-zone traffic detected — review highlighted connections for security violations.", a zone/risk legend (IT Zone / Ind. DMZ / OT Zone; Critical/High/Medium/Low/Info; bridge/cross-zone/same-zone edge styles), a toolbar with Edit, zoom +/-, fit, a "Matrix" toggle button (unused in this tour), "Respect filters", and PNG/JSON export buttons, and the main canvas rendering the Purdue-model swimlane diagram grouping the capture's OT devices (including the Modbus PLCs at 10.0.2.50/10.0.2.51 and the engineering workstation at 10.0.2.10) by network zone, with an anomaly timeline strip along the bottom.
**

   ![OT Map view observed with fixtures/network-capture-demo.pcap: a summary bar reading "29 devices / 5 active levels / 14 cross-zone / 2 cross-level / 5 bridges / 17 anomalies / filtered" plus a callout "Cross-zone traffic detected — review highlighted connections for security violations.", a zone/risk legend (IT Zone / Ind. DMZ / OT Zone; Critical/High/Medium/Low/Info; bridge/cross-zone/same-zone edge styles), a toolbar with Edit, zoom +/-, fit, a "Matrix" toggle button (unused in this tour), "Respect filters", and PNG/JSON export buttons, and the main canvas rendering the Purdue-model swimlane diagram grouping the capture's OT devices (including the Modbus PLCs at 10.0.2.50/10.0.2.51 and the engineering workstation at 10.0.2.10) by network zone, with an anomaly timeline strip along the bottom.
](images/ot-map/ot-map-swimlanes@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![OT Map view observed with fixtures/network-capture-demo.pcap: a summary bar reading "29 devices / 5 active levels / 14 cross-zone / 2 cross-level / 5 bridges / 17 anomalies / filtered" plus a callout "Cross-zone traffic detected — review highlighted connections for security violations.", a zone/risk legend (IT Zone / Ind. DMZ / OT Zone; Critical/High/Medium/Low/Info; bridge/cross-zone/same-zone edge styles), a toolbar with Edit, zoom +/-, fit, a "Matrix" toggle button (unused in this tour), "Respect filters", and PNG/JSON export buttons, and the main canvas rendering the Purdue-model swimlane diagram grouping the capture's OT devices (including the Modbus PLCs at 10.0.2.50/10.0.2.51 and the engineering workstation at 10.0.2.10) by network zone, with an anomaly timeline strip along the bottom.
 (mobile)](images/ot-map/ot-map-swimlanes@mobile.png)

   </details>

   With fixtures/network-capture-demo.pcap uploaded and the OT Map tab selected, the header stats now report 29 hosts, 31 connections, 401 packets, 2 VLANs, and 7% IPv6 hosts (2 of 29), and the sidebar exposes filter groups for Protocols, Host Types, VLANs, IP Version, plus an Anomalies list totaling 31 findings grouped into Network, Credentials & TLS, OT/ICS, IoT, and VLAN categories — including several OT-specific findings such as an unauthorized Modbus write from 10.0.2.10 to 10.0.2.50, an S7comm Write Variable and S7 code download from 10.0.2.10 to 10.0.2.51, a Modbus broadcast to unit_id 0, and Modbus unit-ID polling patterns suggestive of PLC segment mapping. The main canvas renders a Purdue Model swimlane diagram with labeled levels running from L6 Public Internet (7 devices) down through L4 Business Logistics (12 devices, no L5 devices detected), L3 Supervisory/Ops (1 device), L1 PLC/RTU (3 devices, no L2 devices detected), L0 Field Devices (1 device), and an Unclassified bucket (5 devices) for hosts not yet assigned a level; devices are drawn as icons labeled with IP or hostname, several flagged with a warning marker, including the engineering workstation 10.0.2.10 and the two PLCs at 10.0.2.50 and 10.0.2.51. A summary bar above the canvas reads 29 devices, 5 active levels, 14 cross-zone, 2 cross-level, 5 bridges, 17 anomalies, and a filtered indicator, alongside a callout warning that cross-zone traffic was detected and highlighted connections should be reviewed for security violations; a zone legend distinguishes IT Zone, Industrial DMZ, and OT Zone, a risk legend covers Critical/High/Medium/Low/Info severities, and an edge-style legend explains bridge, cross-zone, and same-zone connection styling. The toolbar above the canvas offers an Edit mode, zoom in/out and fit-to-view controls, a Matrix toggle to switch to an alternate device-by-device adjacency grid, a Respect filters option, and PNG/JSON export buttons, and a timeline strip along the bottom of the canvas plots anomaly occurrences across the capture's time range.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
