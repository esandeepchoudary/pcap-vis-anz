---
sidebar_position: 6
sidebar_label: "Purdue map"
title: "Purdue map"
description: "Assign assets to Purdue levels and zones by drag and drop; level matrix, OT matrix and OT command log."
---

# Purdue map

**Map.** One lane per Purdue level, one box per zone inside it. **Drag** an asset (or shift-drag to select
several) into another lane or zone box to change its level and zone; the change is recorded in each asset's
history as "Moved on the Purdue map". "New zone…" creates an empty zone box to drag into. Lines show OT traffic
(red when it includes writes, dashed amber when it bypasses the DMZ); untick "OT traffic only" to see all traffic.
Click a line for the connection's protocols, ports and OT commands.

**Level matrix.** Asset pairs talking between levels (rows: client, columns: server). Cells where level 4 or
above talks directly to level 3 or below are highlighted as **DMZ bypass**. Click a cell to list the pairs.

**OT matrix.** Masters (HMIs, SCADA, engineering workstations) against devices; red cells include writes.

**OT commands.** Every OT function seen across all captures, grouped by sender, device, protocol and function,
with counts, first/last seen and a sample (for example a register range or program block). Filter for writes.
