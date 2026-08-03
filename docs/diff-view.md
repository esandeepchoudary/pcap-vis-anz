---
sidebar_position: 11
sidebar_label: "Compare a baseline capture against a current capture (Diff view)"
description: "The Diff view compares two PCAP uploads — a baseline and a current capture — and surfaces new/disappeared hosts, new connections, traffic-volume changes, and…"
---

# Compare a baseline capture against a current capture (Diff view)

The Diff view compares two PCAP uploads — a baseline and a current capture — and surfaces new/disappeared hosts, new connections, traffic-volume changes, and new anomalies vs. the baseline. Driven by renderDiff() in static/js/app.js.


## Steps

1. **Initial state before any upload: full-page drop zone, header stats all showing "—", no view tabs or "Set Baseline" button rendered yet.
**

   ![Initial state before any upload: full-page drop zone, header stats all showing "—", no view tabs or "Set Baseline" button rendered yet.
](images/diff-view/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state before any upload: full-page drop zone, header stats all showing "—", no view tabs or "Set Baseline" button rendered yet.
 (mobile)](images/diff-view/empty-state@mobile.png)

   </details>

   Before any capture is loaded, the app presents a full-page drop zone with a camera icon and instructions to drop one or more capture files or click to browse, accepting .pcap, .pcapng, and .cap formats up to 100 files and 1 GB total. The header bar above shows placeholder dashes for Hosts, Connections, and Packets counts, and the view-tab bar is limited to Graph, Table, DNS Map, OT Map, and OT Log — the Diff tab and the Set Baseline button that drive the comparison workflow only appear once a capture has actually been uploaded. The left sidebar's Search, Protocols, and Host Types sections are present but empty, confirming this is the application's true starting point with no data loaded yet.

2. **Diff view observed comparing fixtures/network-capture-demo.pcap against itself (baseline == current, since only one fixture pcap was available): a "Baseline vs Current Capture" panel with a "Clear Baseline" action, and four columns — Hosts, Connections, Anomalies, VLANs — each showing an empty/no-change state ("No host changes", "No connection changes", "No new anomalies", "No VLAN changes") because the two captures are identical. This confirms the Diff tab and its four-column layout render correctly and reach a stable state, but does not demonstrate an actual populated diff (added/ removed hosts, new connections, etc.) — that would require a second, genuinely different capture file, which wasn't available.
**

   ![Diff view observed comparing fixtures/network-capture-demo.pcap against itself (baseline == current, since only one fixture pcap was available): a "Baseline vs Current Capture" panel with a "Clear Baseline" action, and four columns — Hosts, Connections, Anomalies, VLANs — each showing an empty/no-change state ("No host changes", "No connection changes", "No new anomalies", "No VLAN changes") because the two captures are identical. This confirms the Diff tab and its four-column layout render correctly and reach a stable state, but does not demonstrate an actual populated diff (added/ removed hosts, new connections, etc.) — that would require a second, genuinely different capture file, which wasn't available.
](images/diff-view/diff-view@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Diff view observed comparing fixtures/network-capture-demo.pcap against itself (baseline == current, since only one fixture pcap was available): a "Baseline vs Current Capture" panel with a "Clear Baseline" action, and four columns — Hosts, Connections, Anomalies, VLANs — each showing an empty/no-change state ("No host changes", "No connection changes", "No new anomalies", "No VLAN changes") because the two captures are identical. This confirms the Diff tab and its four-column layout render correctly and reach a stable state, but does not demonstrate an actual populated diff (added/ removed hosts, new connections, etc.) — that would require a second, genuinely different capture file, which wasn't available.
 (mobile)](images/diff-view/diff-view@mobile.png)

   </details>

   With a baseline captured and a current capture uploaded, the header now shows populated stats (29 hosts, 31 connections, 401 packets, 2 VLANs, 7% IPv6), the view-tab bar includes an active ⊕ Diff tab alongside Graph, Table, DNS Map, OT Map, OT Log, VLAN, and Dashboard, and the toolbar's baseline button now reads Baseline Set with a checkmark. The main panel is titled "Baseline vs Current Capture" with a Clear Baseline action, followed by four columns — Hosts, Connections, Anomalies, and VLANs — each reporting a no-change state: "No host changes," "No connection changes," "No new anomalies," and "No VLAN changes." Because the baseline and current capture were built from the same fixture file, every column resolves to empty, which demonstrates that the four-column diff layout renders and reaches a stable state, though it does not show what an actual populated diff — with added or removed hosts, new connections, or newly introduced anomalies — would look like.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
