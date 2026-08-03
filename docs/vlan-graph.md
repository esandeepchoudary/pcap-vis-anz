---
sidebar_position: 19
sidebar_label: "Explore the VLAN view (super-nodes and cross-VLAN traffic)"
description: "The VLAN view — shows VLANs as super-nodes with hosts clustered inside, cross-VLAN traffic highlighted, plus a VLAN Matrix toggle (VLAN×VLAN flow adjacency…"
---

# Explore the VLAN view (super-nodes and cross-VLAN traffic)

The VLAN view — shows VLANs as super-nodes with hosts clustered inside, cross-VLAN traffic highlighted, plus a VLAN Matrix toggle (VLAN×VLAN flow adjacency grid). This tour covers reaching the VLAN tab after uploading a capture and observing the clustered-graph state; the Matrix toggle itself is not yet covered.


## Steps

1. **Resulting state observed with fixtures/network-capture-demo.pcap: the VLAN tab is active and the main canvas renders VLANs as large circular super-nodes with member hosts clustered inside — VLAN 10 (18 hosts), VLAN 20 (6 hosts), and an Untagged cluster (9 hosts shown) — connected by a thick red cross-VLAN traffic line between the two tagged VLANs. A stats bar above the canvas shows Cross-VLAN flows: 3, Cross-VLAN bytes: 20.6 MB, Untagged hosts: 17, Multi-VLAN/hopping: 4, Singleton VLANs: 0, Isolated VLANs: 0, and Segmentation: 55/100 (Poor). A "VLAN Segments" legend panel (top right of canvas) lists VLAN 10/VLAN 20/Untagged/Cross-VLAN traffic/Untagged-native color keys. The canvas toolbar includes a "Matrix" toggle button (not exercised in this tour) alongside the usual pan/zoom/layout controls. The left sidebar gains a "VLAN Health" panel (VLANs: 2, Cross-VLAN flows: 2, VLAN anomalies: 11, Segmentation: 55/100 Poor) above the existing Protocols/Host Types/VLANs/IP Version filters.
**

   ![Resulting state observed with fixtures/network-capture-demo.pcap: the VLAN tab is active and the main canvas renders VLANs as large circular super-nodes with member hosts clustered inside — VLAN 10 (18 hosts), VLAN 20 (6 hosts), and an Untagged cluster (9 hosts shown) — connected by a thick red cross-VLAN traffic line between the two tagged VLANs. A stats bar above the canvas shows Cross-VLAN flows: 3, Cross-VLAN bytes: 20.6 MB, Untagged hosts: 17, Multi-VLAN/hopping: 4, Singleton VLANs: 0, Isolated VLANs: 0, and Segmentation: 55/100 (Poor). A "VLAN Segments" legend panel (top right of canvas) lists VLAN 10/VLAN 20/Untagged/Cross-VLAN traffic/Untagged-native color keys. The canvas toolbar includes a "Matrix" toggle button (not exercised in this tour) alongside the usual pan/zoom/layout controls. The left sidebar gains a "VLAN Health" panel (VLANs: 2, Cross-VLAN flows: 2, VLAN anomalies: 11, Segmentation: 55/100 Poor) above the existing Protocols/Host Types/VLANs/IP Version filters.
](images/vlan-graph/vlan-view@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Resulting state observed with fixtures/network-capture-demo.pcap: the VLAN tab is active and the main canvas renders VLANs as large circular super-nodes with member hosts clustered inside — VLAN 10 (18 hosts), VLAN 20 (6 hosts), and an Untagged cluster (9 hosts shown) — connected by a thick red cross-VLAN traffic line between the two tagged VLANs. A stats bar above the canvas shows Cross-VLAN flows: 3, Cross-VLAN bytes: 20.6 MB, Untagged hosts: 17, Multi-VLAN/hopping: 4, Singleton VLANs: 0, Isolated VLANs: 0, and Segmentation: 55/100 (Poor). A "VLAN Segments" legend panel (top right of canvas) lists VLAN 10/VLAN 20/Untagged/Cross-VLAN traffic/Untagged-native color keys. The canvas toolbar includes a "Matrix" toggle button (not exercised in this tour) alongside the usual pan/zoom/layout controls. The left sidebar gains a "VLAN Health" panel (VLANs: 2, Cross-VLAN flows: 2, VLAN anomalies: 11, Segmentation: 55/100 Poor) above the existing Protocols/Host Types/VLANs/IP Version filters.
 (mobile)](images/vlan-graph/vlan-view@mobile.png)

   </details>

   With the VLAN tab selected, the main canvas replaces individual host nodes with large circular super-nodes representing each VLAN segment: VLAN 10 (18 hosts), VLAN 20 (6 hosts), and an Untagged cluster (9 hosts shown), each with member hosts arranged inside or around its ring. A thick red line connects VLAN 10 and VLAN 20 directly, marking cross-VLAN traffic between the two tagged segments, and a VLAN Segments legend in the top-right corner of the canvas explains the color coding for VLAN 10, VLAN 20, Untagged, cross-VLAN traffic, and untagged/native traffic. Above the canvas, a stats bar summarizes segmentation posture: Cross-VLAN flows: 3, Cross-VLAN bytes: 20.6 MB, Untagged hosts: 17, Multi-VLAN/hopping: 4, Singleton VLANs: 0, Isolated VLANs: 0, and an overall Segmentation score of 55/100 rated Poor. The canvas toolbar includes pan/zoom and layout controls plus a Matrix toggle button for switching to a VLAN-by-VLAN flow adjacency grid (not exercised in this view). In the left sidebar, a new VLAN Health panel appears above the existing Protocols, Host Types, VLANs, and IP Version filters, echoing the segmentation summary with VLANs: 2, Cross-VLAN flows: 2, VLAN anomalies: 11, and Segmentation: 55/100 Poor — giving a quick read on VLAN-related risk without leaving the sidebar.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
