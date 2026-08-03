---
sidebar_position: 3
sidebar_label: "Concepts"
title: "Concepts"
description: "The backend parses each capture into a hosts dictionary and a connections structure. Each host is classified into one of 38 host types (Router, PLC, IP Camera,…"
---

# Concepts

## Hosts and connections

The backend parses each capture into a `hosts` dictionary and a `connections` structure. Each host is classified into one of 38 host types (Router, PLC, IP Camera, Web Server, DNS Server, Windows Host, and others) using TTL-derived OS hints combined with protocol/port evidence, and both IPv4 and IPv6 addresses are tracked, including correct classification of private ranges for both families.

## Protocol detection

Traffic is matched against 80+ protocols by port (HTTP, SSH, DNS, RDP, MySQL, Modbus, MQTT, CoAP, and more), and several protocols get deep inspection beyond port matching: HTTP, Modbus, MQTT, CoAP, DNS, TLS (SNI extraction and JA3 fingerprinting), DNP3, S7comm, EtherNet/IP, IEC 60870-5-104, and BACnet.

## Anomalies and risk score

32 detection rules run automatically after analysis, grouped into general network, OT/ICS, IoT, and VLAN categories — for example port scans, cleartext credentials, password reuse, beaconing, data exfiltration, suspicious ports, known-bad TLS fingerprints, unauthorized Modbus/DNP3/S7/EtherNet/IP/IEC-104/BACnet writes, VLAN hopping, ARP spoofing, and broadcast storms. Each host also gets a 0–100 composite risk score based on anomaly severity, OT write/error counts, internet exposure, and TLS anomalies, shown in the node detail panel and ranked in the audit report.

## OT/ICS and the Purdue Model

For industrial traffic, the tool identifies OT device types (PLC, RTU, IED, HMI, SCADA Server, DCS, Historian, Engineering Workstation, Building Controller, IoT Gateway, Field Device) and OT vendors via MAC OUI fingerprinting. The OT Map view lays devices out by Purdue Reference Model level (L0 Field through L6 Public Internet, including an automatic Public Internet zone for non-RFC1918 addresses), with zone groupings for IT Zone, Industrial DMZ, and OT Zone, and flags devices that bridge OT and IT/Internet zones.

## VLANs

The tool parses 802.1Q single-tag and QinQ double-tag VLAN frames, tracking VLAN membership per host and per connection. The VLAN Graph view shows VLANs as super-node clusters with cross-VLAN traffic highlighted, and includes VLAN-specific security analysis: a segmentation score, ARP spoofing detection, broadcast storm detection, and PCP priority abuse detection.

## Findings workspace

The Findings view automatically derives reviewable findings from anomalies, captured credentials, file transfers, OT write/error command groups, and high-risk hosts, and supports analyst triage actions — status, severity override, notes, report include/exclude, evidence bundling, and false-positive suppression.

## Baseline diff

A capture can be set as a baseline; uploading a second capture and opening the Diff view compares the two, surfacing new/disappeared hosts, new connections, traffic-volume changes, and new anomalies relative to the baseline, entirely client-side with no server round-trip.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
