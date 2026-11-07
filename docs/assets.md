---
sidebar_position: 5
sidebar_label: "Assets"
title: "Asset inventory"
description: "The merged, editable asset inventory: detected and manual values, evidence, history, bulk edit and fingerprints."
---

# Asset inventory

Every device seen in any capture, merged into one row per device.

**The grid.** Search (name, address, vendor, protocol, tag), filter by level and type, show only assets you've
edited, include external (internet) hosts, sort by any column. A pencil marks a value set by hand. External hosts
are hidden by default.

**Editing.** Click an asset to open it in the inspector. Change any field and give a **reason** (it's kept in the
history). The detected value stays visible under a manual one, with where it came from (for example
"From S7 identification (SZL)"); the reset button goes back to it. If someone else changed the asset while you
were editing, you choose to keep theirs or yours instead of overwriting blindly.

**Bulk edit.** Tick assets (or "select all shown") and set a level, type, zone, criticality, location, owner or
tags for all of them at once, or reset a field to the detected value.

**Evidence tab.** Why the asset was classified as it is, its identity (addresses, MAC vendor, OS hint, VLANs,
names) grouped by the protocol that revealed it, services, and which captures (and capture points) saw it.

**Fingerprints.** Devices often describe themselves: Siemens S7 CPUs (order number, firmware, serial, PLC name),
Modbus devices (vendor, product, revision), EtherNet/IP devices (vendor, product, serial, revision), PROFINET
devices (name and type of station, controller or I/O device), SNMP agents (description, name, location) and
BACnet controllers (device name). These fill the vendor, model, firmware, serial, name and location fields and
make classification more certain.

**Assets added by hand.** "Add asset" for things captures never show (firewalls, data diodes, unmanaged
switches). If a later capture sees the same address, it's merged into your asset.

**Export.** "Export CSV" downloads the register (opens in Excel; formulas are neutralised). The Excel version
with more sheets is on the [Report](findings-and-reports.md) page.
