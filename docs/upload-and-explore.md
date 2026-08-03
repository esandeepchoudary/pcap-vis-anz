---
sidebar_position: 18
sidebar_label: "Upload a capture and explore the network graph"
description: "Upload a .pcap/.pcapng/.cap capture file (via the drop zone's click-to-browse file picker) and see it rendered as an interactive network graph. This is the…"
---

# Upload a capture and explore the network graph

Upload a .pcap/.pcapng/.cap capture file (via the drop zone's click-to-browse file picker) and see it rendered as an interactive network graph. This is the app's entry point — every other view (Table, DNS Map, OT Map, VLAN, Findings, Dashboard, etc.) depends on having uploaded a capture first.


## Steps

1. **Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Graph/Table/DNS Map/OT Map only appear post-upload).
**

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Graph/Table/DNS Map/OT Map only appear post-upload).
](images/upload-and-explore/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Graph/Table/DNS Map/OT Map only appear post-upload).
 (mobile)](images/upload-and-explore/empty-state@mobile.png)

   </details>

   Before any capture is loaded, the app presents a full-page drop zone under the heading "PCAP Network Visualizer," inviting you to drop one or more capture files or click to browse, with supported formats and limits noted below it (.pcap, .pcapng, .cap, up to 100 files, 1 GB total). The header bar shows Hosts, Connections, and Packets stats all as placeholders ("—") since no data has been parsed yet, and only the Graph, Table, DNS Map, OT Map, and OT Log view buttons are present — the additional VLAN, Dashboard, and Findings tabs, along with the VLAN Health panel, only appear once a capture has been analyzed. The left sidebar already has its Search box and Protocols/Host Types section headers in place, but with no entries listed underneath, since there's nothing yet to filter.

2. **Resulting state observed with fixtures/network-capture-demo.pcap: header stats populate (Hosts: 29, Connections: 31, Packets: 401, VLANs: 2, IPv6: 7%), the view-tab bar appears (Graph/Table/DNS Map/ OT Map/OT Log/VLAN/Dashboard/Findings), the left sidebar gains Protocols/Host Types/VLANs/IP Version filters plus an Anomalies list (31 findings) and Credentials/File Transfers panels, and the main canvas renders the interactive force-directed graph on the Graph tab (the default view after upload).
**

   ![Resulting state observed with fixtures/network-capture-demo.pcap: header stats populate (Hosts: 29, Connections: 31, Packets: 401, VLANs: 2, IPv6: 7%), the view-tab bar appears (Graph/Table/DNS Map/ OT Map/OT Log/VLAN/Dashboard/Findings), the left sidebar gains Protocols/Host Types/VLANs/IP Version filters plus an Anomalies list (31 findings) and Credentials/File Transfers panels, and the main canvas renders the interactive force-directed graph on the Graph tab (the default view after upload).
](images/upload-and-explore/graph-view@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Resulting state observed with fixtures/network-capture-demo.pcap: header stats populate (Hosts: 29, Connections: 31, Packets: 401, VLANs: 2, IPv6: 7%), the view-tab bar appears (Graph/Table/DNS Map/ OT Map/OT Log/VLAN/Dashboard/Findings), the left sidebar gains Protocols/Host Types/VLANs/IP Version filters plus an Anomalies list (31 findings) and Credentials/File Transfers panels, and the main canvas renders the interactive force-directed graph on the Graph tab (the default view after upload).
 (mobile)](images/upload-and-explore/graph-view@mobile.png)

   </details>

   After uploading fixtures/network-capture-demo.pcap, the header stats populate with real numbers — Hosts: 29, Connections: 31, Packets: 401, VLANs: 2, and IPv6: 7% (2/29) — and the view-tab bar expands to include VLAN, Dashboard, and Findings alongside Graph, Table, DNS Map, OT Map, and OT Log. The left sidebar now shows a VLAN Health summary (2 VLANs, 2 cross-VLAN flows, 11 VLAN anomalies, and a Segmentation score of 55/100 rated "Poor"), followed by fully populated Protocols, Host Types, VLANs, and IP Version filter lists, each with per-category counts and a checkbox that's checked by default. Below the filters, an Anomalies section reports 31 findings grouped into categories — Network, Credentials & TLS, OT/ICS, IoT, and VLAN — covering issues like a possible port scan from 198.51.100.77, beaconing between 10.0.1.11 and 203.0.113.66, suspected data exfiltration from 10.0.1.12, unauthorized Modbus and S7comm writes to PLCs on the 10.0.2.x segment, cleartext MQTT and Telnet traffic, and hosts observed on multiple VLANs. Further down, a Credentials panel lists 4 captured credential events (HTTP Basic Auth, an HTTP form POST, FTP USER/PASS, and a Telnet login, each with masked password values and a "show" toggle), and a File Transfers panel lists one transfer, a PDF moved from 10.0.1.80 to 10.0.1.10 with its SHA-256 hash displayed. The main canvas renders the interactive force-directed graph, the default Graph view, showing hosts as labeled nodes (IP addresses, hostnames, and host-type icons) connected by traffic edges, with pan/zoom controls, a layout-mode toggle, and a timeline scrubber with playback controls along the bottom for replaying traffic over the capture's duration.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
