---
sidebar_position: 7
sidebar_label: "Architecture"
title: "Zones, conduits and architecture"
description: "IEC 62443 zones and conduits, violation detection, the architecture diagram and inferred networks."
---

# Zones, conduits and architecture

**Zones.** An asset is in a zone through its Zone field (set in the inventory, on the Purdue map, or in bulk).
Zone names used on assets appear automatically; **Define** them to add a Purdue level, a target security level
(SL-T 1–4) and a description. Renaming a zone moves its assets (recorded in their history). Deleting a zone keeps
the name on its assets.

**Conduits.** An approved path between two zones, with the protocols allowed through it (empty allows anything).

**Violations.** Traffic between assets in different zones with no conduit, or with a protocol the conduit
doesn't allow. From a violation you can **approve** the zone pair as a conduit (allowing every protocol seen
between them) or **allow** a protocol on the existing conduit. Only assets with a zone are checked.

**Diagram.** Zones placed by level; drag them to arrange (positions are saved). Drag from a zone's bottom handle
to another zone to add a conduit. Firewalls, routers and diodes are listed in their zone; unapproved traffic is
drawn in red.

**Networks.** Subnets inferred from asset addresses (private IPv4 /24), with the VLANs, gateways, zones and
levels on each. Add gateways that never appear on the wire as manual assets.
