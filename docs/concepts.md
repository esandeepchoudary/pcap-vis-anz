---
sidebar_position: 3
sidebar_label: "Concepts"
title: "Concepts"
description: "Engagements, captures, assets, detected versus manual values, zones, conduits, findings and bundles."
---

# Concepts

**Engagement.** One assessment (client, site). Everything belongs to an engagement. On a team server it has
members with roles: *lead* (settings, members, merge), *editor* (upload, edit), *viewer* (read-only). People
who aren't members can't see it exists.

**Capture and capture point.** A capture is one uploaded file, identified by its SHA-256 (uploading the same
file twice does nothing). A capture point records where it was taken. Re-analysing a capture replaces its
results exactly.

**Asset.** One device, merged across captures. A host is matched to an asset by its **own MAC address** (so a
DHCP address change doesn't create a new asset), or by IP when the MAC belongs to a router in front of it. Each
capture's view of a host is kept as a *sighting*, which is how the tool knows which capture point saw what.

**Detected vs manual values.** Every editable field (name, type, Purdue level, zone, criticality, vendor,
model, firmware, serial, location, owner, tags, notes) has a *detected* value from traffic and an optional
*manual* value with a reason. The manual value wins and survives new captures; *reset* goes back to the detected
value. Every change is in the asset's **history**. If two people edit the same asset at once, the second save
is refused with a clear message instead of silently overwriting.

**Purdue levels.** 0 process, 1 basic control, 2 supervisory, 3 site operations, 3.5 industrial DMZ, 4 business,
5 enterprise, plus *external* and *unclassified*. Traffic between level 4+ and level 3 or below **bypasses the
DMZ** and is flagged.

**Zones and conduits (IEC 62443).** A zone groups assets (through their Zone field) with a level and a target
security level (SL-T). A conduit is an approved path between two zones, optionally limited to listed
protocols. Cross-zone traffic outside the conduits is a **violation**.

**Findings.** Rule findings (34 rules, ATT&CK-mapped) are merged across captures. Your triage (status,
severity, notes, recommendation, include in report) is stored separately, so it survives re-analysis. You can
also add findings by hand.

**Bundle (`.pcapvis`).** One file with an engagement's captures (optional), results, assets with edits and
history, zones, conduits and findings triage. Import it as a new engagement, or **merge** it into an existing one.
