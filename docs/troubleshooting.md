---
sidebar_position: 23
sidebar_label: "Troubleshooting"
title: "Troubleshooting"
description: "Common problems and fixes."
---

# Troubleshooting

**The app won't start: "tshark not found / too old".** Install Wireshark 4.0+ (`sudo apt install tshark`) or use
the container image. `pcapvis check` shows what it found.

**A capture stays "Queued".** On a team server, check the worker is running (`docker compose ps`,
`docker compose logs worker`). On a laptop, analysis runs in the app itself; restart it.

**"Not a pcap, pcapng or gzipped capture".** The file isn't a capture (for example a `.cap` from another tool in a
different format). Convert it with `editcap -F pcapng in.cap out.pcapng`.

**Analysis is slow.** tshark decodes roughly 10k packets per second per core. Large captures are split and
analysed in parallel; give the worker more CPU, or set `PCAPVIS_ANALYSIS_WORKERS`.

**Live updates don't appear behind a proxy.** The proxy is buffering server-sent events; disable buffering for
`/api/engagements/*/events` (see the Caddy example in [Team server](deployment.md#https)).

**"Someone else changed this asset".** Another user saved the asset while you were editing. Choose
"discard mine" to see their change, or "keep mine" and save again.

**Merge reported conflicts.** Both the server and the bundle changed the same field; the server's value was kept.
Open the asset and set the value you want.
