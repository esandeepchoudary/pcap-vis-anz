---
sidebar_position: 8
sidebar_label: "Flows"
title: "Flows and forensics"
description: "Network graph, flow table, DNS, VLANs, capture diff and the packet inspector."
---

# Flows and forensics

**Graph.** Assets grouped by subnet, with connections between them (OT in blue, writes in red). Hover or select
an asset to highlight who it talks to. External hosts are hidden unless you ask for them.

**Flows** (per capture). Every conversation, largest first, client → server, with packets, bytes, duration and
OT reads/writes. Click a row to open the connection in the inspector.

**DNS** (per capture). Names queried and which hosts asked: useful for spotting internet dependencies.

**VLANs** (per capture). Frames per VLAN, the broadcast share (high values are flagged) and the assets on each.

**Diff.** Pick a baseline capture and another (for example the same SPAN port on two days) to see new and
missing assets and connections.

**Packets.** Type a Wireshark display filter (for example `modbus.func_code == 6`) to list matching packets,
then click one for its full decode and hex dump. tshark runs on the server, so you don't need Wireshark on your
machine. Editors only: raw packets include unmasked secrets.
