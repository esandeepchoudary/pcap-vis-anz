---
sidebar_position: 17
sidebar_label: "Browse the connection Table view and inspect packets"
description: "The Table view — a sortable connection table listing every network connection observed in the capture (Source IP, Destination IP, Protocol(s), Packets, Bytes,…"
---

# Browse the connection Table view and inspect packets

The Table view — a sortable connection table listing every network connection observed in the capture (Source IP, Destination IP, Protocol(s), Packets, Bytes, Ports, Duration columns, with sortable column headers), plus a live packet-inspector search that filters by any column text once a connection row is opened.


## Steps

1. **Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Table only appears post-upload).
**

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Table only appears post-upload).
](images/table-view/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Table only appears post-upload).
 (mobile)](images/table-view/empty-state@mobile.png)

   </details>

   Before any capture is uploaded, the application shows a single full-page drop zone rather than any populated views: a heading, a short description of what the tool does, and a dashed-border upload panel inviting the user to drop one or more capture files or click to browse, with a note on accepted formats (.pcap, .pcapng, .cap) and the file/size limits (up to 100 files, 1 GB total). The header stats for Hosts, Connections, and Packets all read a dash placeholder since no data has been loaded yet, and only the Graph and Table view-switch buttons are present in the header at this stage — the Table view itself, along with the DNS Map, OT Map, OT Log, and other tabs that appear once a capture is analyzed, is not yet rendered. The left sidebar shows empty Search, Protocols, and Host Types sections with no entries, confirming that every panel is waiting on an upload before it has anything to display.

2. **Table view after uploading fixtures/network-capture-demo.pcap: a sortable connection table with columns Source IP, Destination IP, Protocol(s), Packets, Bytes, Ports, Duration (Source IP, Destination IP, Packets, Bytes, and Duration column headers are clickable/ sortable). Rows observed include 10.0.1.12 → 198.51.100.200 (HTTPS, 189 packets, 10.3 MB), 10.0.2.10 → 10.0.2.50 (Modbus, 27 packets, 2.1 KB), 10.0.1.11 → 203.0.113.66 (Metasploit, 25 packets, 2.0 KB), and 10.0.0.1 → 198.51.100.77 (a connection spanning many protocols: Docker, FTP, HTTP, HTTPS, IMAP, IMAPS, LDAP, MSSQL, MySQL, NNTP, NetBIOS-SSN, POP3, PostgreSQL, RDP, Redis, SMB, SMTP, SNMP, SSH, Telnet, VNC), among the capture's 31 total connections. Clicking a row opens a packet-inspector panel for that connection with its own `#pkt-search` "Filter packets…" text input and a per-packet table (No., Time, Source, Destination, Protocol, Len, Info) — confirmed present on the DOM, but its live-filtering behavior on that packet table was not verified interactively in this session (the click to open the row's packet inspector triggered an unrelated page-state reset before the filter input could be exercised), so no fill/ filter step is included here.
**

   ![Table view after uploading fixtures/network-capture-demo.pcap: a sortable connection table with columns Source IP, Destination IP, Protocol(s), Packets, Bytes, Ports, Duration (Source IP, Destination IP, Packets, Bytes, and Duration column headers are clickable/ sortable). Rows observed include 10.0.1.12 → 198.51.100.200 (HTTPS, 189 packets, 10.3 MB), 10.0.2.10 → 10.0.2.50 (Modbus, 27 packets, 2.1 KB), 10.0.1.11 → 203.0.113.66 (Metasploit, 25 packets, 2.0 KB), and 10.0.0.1 → 198.51.100.77 (a connection spanning many protocols: Docker, FTP, HTTP, HTTPS, IMAP, IMAPS, LDAP, MSSQL, MySQL, NNTP, NetBIOS-SSN, POP3, PostgreSQL, RDP, Redis, SMB, SMTP, SNMP, SSH, Telnet, VNC), among the capture's 31 total connections. Clicking a row opens a packet-inspector panel for that connection with its own `#pkt-search` "Filter packets…" text input and a per-packet table (No., Time, Source, Destination, Protocol, Len, Info) — confirmed present on the DOM, but its live-filtering behavior on that packet table was not verified interactively in this session (the click to open the row's packet inspector triggered an unrelated page-state reset before the filter input could be exercised), so no fill/ filter step is included here.
](images/table-view/table-populated@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Table view after uploading fixtures/network-capture-demo.pcap: a sortable connection table with columns Source IP, Destination IP, Protocol(s), Packets, Bytes, Ports, Duration (Source IP, Destination IP, Packets, Bytes, and Duration column headers are clickable/ sortable). Rows observed include 10.0.1.12 → 198.51.100.200 (HTTPS, 189 packets, 10.3 MB), 10.0.2.10 → 10.0.2.50 (Modbus, 27 packets, 2.1 KB), 10.0.1.11 → 203.0.113.66 (Metasploit, 25 packets, 2.0 KB), and 10.0.0.1 → 198.51.100.77 (a connection spanning many protocols: Docker, FTP, HTTP, HTTPS, IMAP, IMAPS, LDAP, MSSQL, MySQL, NNTP, NetBIOS-SSN, POP3, PostgreSQL, RDP, Redis, SMB, SMTP, SNMP, SSH, Telnet, VNC), among the capture's 31 total connections. Clicking a row opens a packet-inspector panel for that connection with its own `#pkt-search` "Filter packets…" text input and a per-packet table (No., Time, Source, Destination, Protocol, Len, Info) — confirmed present on the DOM, but its live-filtering behavior on that packet table was not verified interactively in this session (the click to open the row's packet inspector triggered an unrelated page-state reset before the filter input could be exercised), so no fill/ filter step is included here.
 (mobile)](images/table-view/table-populated@mobile.png)

   </details>

   The Table view presents every connection from the uploaded capture as a flat, sortable table, an alternative to the graph for scanning traffic at a glance. Column headers for Source IP, Destination IP, Packets, Bytes, and Duration are clickable to re-sort the list, and the visible columns cover Source IP, Destination IP, Protocol(s), Packets, Bytes, Ports, and Duration. Out of 31 total connections in this capture, the top rows by packet count include 10.0.1.12 to 198.51.100.200 over HTTPS (189 packets, 10.3 MB across ports 443 and 46000), 10.0.2.10 to 10.0.2.50 over Modbus (27 packets, 2.1 KB), and 10.0.1.11 to 203.0.113.66 flagged as Metasploit traffic (25 packets, 2.0 KB on port 4444). One row stands out for protocol diversity: 10.0.0.1 to 198.51.100.77 spans twenty-one distinct protocols in a single connection entry, including Docker, FTP, HTTP, HTTPS, IMAP, IMAPS, LDAP, MSSQL, MySQL, NNTP, NetBIOS-SSN, POP3, PostgreSQL, RDP, Redis, SMB, SMTP, SNMP, SSH, Telnet, and VNC across eight distinct ports, a pattern worth investigating on its own. The same left sidebar filters (protocols, host types, VLANs, IP version) and the anomalies and credentials panels from the Graph view remain available alongside the table, so the same capture can be explored either visually or as raw connection data. Clicking a row is documented to open a per-connection packet inspector with its own Filter packets... search box and a packet table (No., Time, Source, Destination, Protocol, Len, Info), letting an analyst drill from a connection summary down to individual packets.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
