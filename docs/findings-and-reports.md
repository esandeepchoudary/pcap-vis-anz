---
sidebar_position: 9
sidebar_label: "Findings & reports"
title: "Findings and reports"
description: "Triage findings, add your own, and produce the Word/HTML report, Excel register and draw.io diagram."
---

# Findings and reports

**Findings.** Rule findings from every capture, merged (one row per issue with its count, first and last seen,
evidence and affected assets), plus findings you add by hand. Open one to triage it: **status** (open,
confirmed, accepted risk, resolved, false positive), **severity** (override the detected one), a
**recommendation**, analyst **notes**, and whether it goes **in the report** (false positives drop out unless you
include them). Triage survives re-analysis and travels in bundles.

**Report & exports** (the Report stage):

| Deliverable | Format | Contents |
|---|---|---|
| Assessment report | Word (.docx), HTML | Summary, scope, findings with evidence and recommendations, segmentation (zones, conduits, violations), asset register. For PDF, open the HTML report and print it. |
| Asset register | Excel (.xlsx), CSV | Assets with detected and manual fields; sheets for zones, conduits, violations, findings, OT commands. |
| Purdue diagram | draw.io, SVG | Levels, zones and assets with OT connections. The draw.io file opens in diagrams.net for final layout. |
| Engagement bundle | .pcapvis | Everything, to hand over or [merge](deployment.md#merging-laptop-work) elsewhere. |

All text that comes from captured traffic (hostnames, device strings, HTTP data) is neutralised for each format:
no spreadsheet formulas, no markup in diagrams, escaped HTML.
