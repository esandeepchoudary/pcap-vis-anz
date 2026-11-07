---
sidebar_position: 2
sidebar_label: "Getting started"
title: "Getting started"
description: "Run PCAP Visualizer on a laptop with Docker or natively, then analyse your first capture."
---

# Getting started

## On a laptop with Docker (recommended)

The image contains everything (tshark, the app, the web UI). No internet access is needed once it's loaded.

```bash
docker build -t pcapvis .            # or: docker load -i pcapvis.tar on an air-gapped machine
docker run -p 127.0.0.1:8080:8080 -v "$PWD/engagements:/data" pcapvis
```

Open http://localhost:8080. Laptop mode has no login: you're the only user. Your data lives in the folder you
mounted (`engagements/`), including the database and the original captures.

## Native install (Linux)

You need Python 3.12+, [uv](https://docs.astral.sh/uv/), Node 22+ (to build the UI once) and **Wireshark 4.0+**
(`sudo apt install tshark`; answer "No" to letting non-root users capture).

```bash
cd frontend && npm ci && npm run build && cd ..
cd backend && uv sync
uv run pcapvis check     # confirms tshark is found and new enough
uv run pcapvis serve     # http://127.0.0.1:8000
```

The app refuses to start without a suitable tshark and tells you how to install it.

## Your first engagement

1. **Home → New engagement.** Give it a name, client and site.
2. **Captures → Capture points**: name where you captured (for example "Core switch SPAN Gi0/24").
3. **Drop pcap/pcapng files** (gzipped is fine). Each is hashed, stored and analysed in the background; the list
   updates live with progress.
4. Open **Assets** to see every device found, then work through the stages in the left rail.

To look at a single capture without an engagement, use **Quick look**; you can turn it into an engagement later.

Next: [Concepts](concepts.md).
