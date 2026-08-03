---
sidebar_position: 5
sidebar_label: "Troubleshooting"
title: "Troubleshooting"
description: "Make sure dependencies were installed inside the correct Python environment (or virtualenv) that the app is being run from."
---

# Troubleshooting

## scapy import error

Make sure dependencies were installed inside the correct Python environment (or virtualenv) that the app is being run from.

## Permission denied reading pcap

Some systems require root to read certain capture files. Try running with `sudo python app.py`.

## Graph is empty after upload

The uploaded file may contain only non-IP traffic (for example pure Bluetooth or USB captures). The tool supports IPv4, IPv6, and ARP packets.

## Very large files are slow

Only the first 1,000,000 packets are processed. For faster results, pre-filter the capture with `tcpdump` before uploading:

```bash
tcpdump -r big.pcap -w filtered.pcap 'tcp or udp'
```

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
