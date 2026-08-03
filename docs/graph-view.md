---
sidebar_position: 14
sidebar_label: "Graph view — network visualization surface"
description: "The Graph view is the default view after uploading a capture: an interactive force-directed graph of hosts and connections, with filtering, search, a node…"
---

# Graph view — network visualization surface

The Graph view is the default view after uploading a capture: an interactive force-directed graph of hosts and connections, with filtering, search, a node detail panel, layout switching (Force/Radial/ Cluster), pin/isolate, and a minimap. This is the app's primary network visualization surface.


## Steps

1. **Default Graph view immediately after upload, observed with fixtures/network-capture-demo.pcap: force-directed layout (⊙ Force button active in the top-right graph-controls cluster) showing all 29 hosts as colour-coded nodes (by host type — DNS Server, Linux Host, Web Server, PLC, IP Camera, etc.) connected by protocol-coloured edges. Left sidebar shows Search / VLAN Health / Protocols / Host Types / VLANs / IP Version filters plus Anomalies (31), Credentials (4) and File Transfers (1) panels. Graph-area controls include layout toggles (⊙ Force / ◎ Radial / ⊞ Cluster), zoom (+ / −), fit (⊡), a VLAN colour-by toggle (⬡ VLAN), a colour-blind palette toggle (◑), and an isolate toggle (⊕). A minimap appears in the top-right corner of the canvas.
**

   ![Default Graph view immediately after upload, observed with fixtures/network-capture-demo.pcap: force-directed layout (⊙ Force button active in the top-right graph-controls cluster) showing all 29 hosts as colour-coded nodes (by host type — DNS Server, Linux Host, Web Server, PLC, IP Camera, etc.) connected by protocol-coloured edges. Left sidebar shows Search / VLAN Health / Protocols / Host Types / VLANs / IP Version filters plus Anomalies (31), Credentials (4) and File Transfers (1) panels. Graph-area controls include layout toggles (⊙ Force / ◎ Radial / ⊞ Cluster), zoom (+ / −), fit (⊡), a VLAN colour-by toggle (⬡ VLAN), a colour-blind palette toggle (◑), and an isolate toggle (⊕). A minimap appears in the top-right corner of the canvas.
](images/graph-view/graph-force-default@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Default Graph view immediately after upload, observed with fixtures/network-capture-demo.pcap: force-directed layout (⊙ Force button active in the top-right graph-controls cluster) showing all 29 hosts as colour-coded nodes (by host type — DNS Server, Linux Host, Web Server, PLC, IP Camera, etc.) connected by protocol-coloured edges. Left sidebar shows Search / VLAN Health / Protocols / Host Types / VLANs / IP Version filters plus Anomalies (31), Credentials (4) and File Transfers (1) panels. Graph-area controls include layout toggles (⊙ Force / ◎ Radial / ⊞ Cluster), zoom (+ / −), fit (⊡), a VLAN colour-by toggle (⬡ VLAN), a colour-blind palette toggle (◑), and an isolate toggle (⊕). A minimap appears in the top-right corner of the canvas.
 (mobile)](images/graph-view/graph-force-default@mobile.png)

   </details>

   After a capture finishes processing, the app lands on the Graph tab by default, rendering the 29 hosts from the uploaded file (fixtures/network-capture-demo.pcap) as a force-directed node graph. Each node is colour-coded by host type — Linux Host, Web Server, DNS Server, PLC, IP Camera, IoT Gateway, Router, Windows Host, Network Device, Engineering Workstation, IoT Sensor, and Security Tool — with a legend for these types docked over the lower-left of the canvas, and nodes are connected by edges coloured by the dominant protocol between them; node size scales with traffic volume, shown as a numeric badge on each node. The top banner summarizes the capture at a glance: 29 hosts, 31 connections, 401 packets, 2 VLANs, and 7% (2 of 29) of hosts on IPv6. The left sidebar carries the filtering and findings apparatus: a Search box for IP address or hostname, a VLAN Health panel (2 VLANs, 2 cross-VLAN flows, 11 VLAN anomalies, a Segmentation score of 55/100 rated "Poor"), then checkbox filter lists for Protocols (ARP, DNS, HTTP, HTTPS, Modbus, S7comm, MQTT, CoAP, and more, each with a packet count), Host Types, VLANs (VLAN 10, VLAN 20, Untagged), and IP Version. Below the filters sit three grouped findings panels: Anomalies (31, broken into categories like Network, Credentials & TLS, OT/ICS, IoT, and VLAN, each with a severity badge and a "Review finding" action), Credentials (4, showing captured protocol, timestamp, endpoints, and a masked username/password with a "show" toggle), and File Transfers (1, listing a reconstructed file with its MIME type, size, timestamp, hash, and download/copy actions). The canvas itself has a self-contained control cluster in the top right: three layout toggles (⊙ Force, ◎ Radial, ⊞ Cluster) with Force currently active, zoom controls (+ and −), a fit-to-view button (⊡), a VLAN colour-by toggle (⬡ VLAN), a colour-blind-safe palette toggle (◑), and an isolate toggle (⊕), plus a small minimap thumbnail in the corner showing the full node layout and the current viewport's position within it. A timeline scrubber with play/pause, playback speed selector, and a two-handle range slider sits along the bottom of the canvas for replaying the capture over time.

2. **Same 29-host graph re-rendered in radial layout after clicking the ◎ Radial layout toggle: nodes arranged in a tree/radial pattern radiating from a central hub host, ◎ shown active (highlighted) in the graph-controls cluster instead of ⊙ Force. Filters, minimap and other canvas controls are unchanged from the force-layout state.
**

   ![Same 29-host graph re-rendered in radial layout after clicking the ◎ Radial layout toggle: nodes arranged in a tree/radial pattern radiating from a central hub host, ◎ shown active (highlighted) in the graph-controls cluster instead of ⊙ Force. Filters, minimap and other canvas controls are unchanged from the force-layout state.
](images/graph-view/graph-radial-layout@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Same 29-host graph re-rendered in radial layout after clicking the ◎ Radial layout toggle: nodes arranged in a tree/radial pattern radiating from a central hub host, ◎ shown active (highlighted) in the graph-controls cluster instead of ⊙ Force. Filters, minimap and other canvas controls are unchanged from the force-layout state.
 (mobile)](images/graph-view/graph-radial-layout@mobile.png)

   </details>

   Clicking the ◎ Radial layout toggle re-renders the same 29-host graph in a radial arrangement instead of the force simulation: nodes are laid out around one or more central hub hosts with connections radiating outward, making high-degree hosts (like the erp.corp.local and 10.0.2.10 nodes visible near the centre) easier to pick out as hubs than in the force layout's more even scatter. The graph-controls cluster in the canvas's top-right reflects the switch — the ◎ Radial button is now highlighted active in place of ⊙ Force — while the rest of the interface is unchanged: the same summary banner, VLAN Health metrics, Protocols/Host Types/VLANs/IP Version filters, the Anomalies/Credentials/File Transfers panels, the minimap, and the zoom/fit/VLAN-colour/palette/isolate controls all remain in place, confirming that switching layouts only changes node positioning and not any of the underlying filtered data or findings.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
