---
sidebar_position: 4
sidebar_label: "Captures"
title: "Captures"
description: "Upload captures, tag capture points, follow analysis, and read a capture report."
---

# Captures

**Capture points** name where you captured (a switch SPAN port, a TAP, a segment). Pick one before dropping
files so each capture is tagged; you can change it later from the list.

**Upload.** Drop `.pcap`, `.pcapng` or gzipped captures. Files are streamed to disk and hashed; a file that's
already in the engagement is recognised and not stored twice. Analysis runs in the background (in the web app
on a laptop, in worker containers on a team server) with live progress. You can **cancel** a running analysis,
**re-analyse** a capture (for example after an upgrade), download the original, or delete it. Deleting a capture
removes what only it contributed to the inventory; assets you edited are kept.

**Capture report.** Click a finished capture for its own view: summary tiles, findings with ATT&CK ids, hosts
with the evidence behind each classification, OT commands, cleartext credentials (hidden until you reveal them)
and files extracted from the traffic (always downloaded, never opened in the browser: they may be malware).

**Quick look** analyses one file without setting up an engagement. It's private to you and can be turned into a
real engagement from its settings.
