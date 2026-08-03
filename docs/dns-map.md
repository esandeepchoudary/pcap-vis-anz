---
sidebar_position: 12
sidebar_label: "Explore DNS queries in the DNS Map view"
description: "The DNS Map view — a DNS query explorer showing hostnames resolved and query logs extracted from captured DNS traffic. Upload a capture, switch to the DNS Map…"
---

# Explore DNS queries in the DNS Map view

The DNS Map view — a DNS query explorer showing hostnames resolved and query logs extracted from captured DNS traffic. Upload a capture, switch to the DNS Map tab, and select a host to see its resolved hostnames and query log.


## Steps

1. **Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (DNS Map only appears post-upload).
**

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (DNS Map only appears post-upload).
](images/dns-map/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (DNS Map only appears post-upload).
 (mobile)](images/dns-map/empty-state@mobile.png)

   </details>

   Before any capture is loaded, the app presents a single full-page drop zone inviting you to drop one or more capture files or click to browse, accepting .pcap, .pcapng, or .cap files up to 100 files and 1 GB total. The header stats for Hosts, Connections, and Packets all read "—" since nothing has been parsed yet, and while the Graph, Table, DNS Map, OT Map, and OT Log tabs are already visible in the header, the DNS Map view itself has no data to show until a capture is uploaded — the sidebar's Search box and Protocols/Host Types sections are likewise empty placeholders at this stage.

2. **DNS Map view observed with fixtures/network-capture-demo.pcap: a "Hosts with DNS queries" panel lists the querying hosts (10.0.1.10 ×2, 10.0.1.11 ×1, 10.0.1.20 ×1, 10.0.1.30 ×1, 10.0.1.41 ×1, 10.0.2.10 ×1, fd12:3456:789a::10 ×1) each with a query count badge, plus a "Select a host to view DNS queries" placeholder in the main panel before any host is chosen.
**

   ![DNS Map view observed with fixtures/network-capture-demo.pcap: a "Hosts with DNS queries" panel lists the querying hosts (10.0.1.10 ×2, 10.0.1.11 ×1, 10.0.1.20 ×1, 10.0.1.30 ×1, 10.0.1.41 ×1, 10.0.2.10 ×1, fd12:3456:789a::10 ×1) each with a query count badge, plus a "Select a host to view DNS queries" placeholder in the main panel before any host is chosen.
](images/dns-map/dns-map-host-list@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![DNS Map view observed with fixtures/network-capture-demo.pcap: a "Hosts with DNS queries" panel lists the querying hosts (10.0.1.10 ×2, 10.0.1.11 ×1, 10.0.1.20 ×1, 10.0.1.30 ×1, 10.0.1.41 ×1, 10.0.2.10 ×1, fd12:3456:789a::10 ×1) each with a query count badge, plus a "Select a host to view DNS queries" placeholder in the main panel before any host is chosen.
 (mobile)](images/dns-map/dns-map-host-list@mobile.png)

   </details>

   After uploading the demo capture and switching to the DNS Map tab, the header stats populate (29 hosts, 31 connections, 401 packets, 2 VLANs, IPv6 at 7%) and a "Hosts with DNS queries" panel appears listing every host observed making DNS lookups, each with a badge showing how many queries it issued: 10.0.1.10 with 2, and 10.0.1.11, 10.0.1.20, 10.0.1.30, 10.0.1.41, 10.0.2.10, and the IPv6 host fd12:3456:789a::10 each with 1. The main panel to the right simply reads "Select a host to view DNS queries," since this is the list view before any host has been chosen — the sidebar continues to show the full Protocols, Host Types, VLANs, and Anomalies breakdowns carried over from the rest of the app, giving context on the wider capture alongside the DNS-specific list.

3. **Resulting state observed after selecting host 10.0.1.10: the panel header changes to "DNS queries from 10.0.1.10" and lists resolved hostnames with their answers, e.g. erp.corp.local → 10.0.1.80 and shop.example-corp.com, drawn from the real DNS query/response traffic in the demo capture.
**

   ![Resulting state observed after selecting host 10.0.1.10: the panel header changes to "DNS queries from 10.0.1.10" and lists resolved hostnames with their answers, e.g. erp.corp.local → 10.0.1.80 and shop.example-corp.com, drawn from the real DNS query/response traffic in the demo capture.
](images/dns-map/dns-map-query-log@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Resulting state observed after selecting host 10.0.1.10: the panel header changes to "DNS queries from 10.0.1.10" and lists resolved hostnames with their answers, e.g. erp.corp.local → 10.0.1.80 and shop.example-corp.com, drawn from the real DNS query/response traffic in the demo capture.
 (mobile)](images/dns-map/dns-map-query-log@mobile.png)

   </details>

   Clicking the 10.0.1.10 row in the host list changes the main panel's header to "DNS queries from 10.0.1.10" and lists the hostnames that host actually resolved during the capture: `erp.corp.local`, which resolved to `10.0.1.80`, and `shop.example-corp.com`. This is the drill-down state of the DNS Map — selecting any host from the left-hand list swaps in that host's own query log here, pairing each queried hostname with the IP address it resolved to (where a response was captured) so you can trace what a given host was actually trying to reach on the network.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
