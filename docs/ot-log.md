---
sidebar_position: 15
sidebar_label: "View the OT Log's chronological command history"
description: "The OT Log view — a chronological table of OT command history (Modbus and S7comm reads, writes, and errors) with protocol and direction filter buttons. Lets an…"
---

# View the OT Log's chronological command history

The OT Log view — a chronological table of OT command history (Modbus and S7comm reads, writes, and errors) with protocol and direction filter buttons. Lets an analyst review every industrial-control command exchanged between the engineering workstation and PLCs in a capture, in order.


## Steps

1. **Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Graph/Table/DNS Map/OT Map/OT Log only appear post-upload).
**

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Graph/Table/DNS Map/OT Map/OT Log only appear post-upload).
](images/ot-log/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Graph/Table/DNS Map/OT Map/OT Log only appear post-upload).
 (mobile)](images/ot-log/empty-state@mobile.png)

   </details>

   Before any capture file is loaded, the application shows a full-page drop zone inviting the user to drop one or more capture files or click to browse, with a note that it accepts .pcap, .pcapng, and .cap files up to 100 files and 1 GB total. The header stats for Hosts, Connections, and Packets all read as a dash placeholder, and the view-switcher tabs — Graph, Table, DNS Map, OT Map, and OT Log — are visible but inactive, since none of the per-file views can render anything until a capture has actually been parsed. This is the starting point for every analysis session.

2. **Resulting state observed with fixtures/network-capture-demo.pcap: the OT Log tab is active, a "Protocol:" filter row with Modbus/S7comm toggle buttons and a "Direction:" filter row with error/read/write toggle buttons sit above a "41 / 41 commands" counter, and a chronological table (columns Time, Src, Dst, Protocol, Function, Direction, Details) lists every OT command — e.g. Modbus "Write Single Register" (write) and "Read Holding Registers" (read) between 10.0.2.10 and 10.0.2.50, and S7comm "Setup Communication", "Read Variable", "Write Variable", "Request Download", and "PLC Stop" entries between 10.0.2.10 and 10.0.2.51.
**

   ![Resulting state observed with fixtures/network-capture-demo.pcap: the OT Log tab is active, a "Protocol:" filter row with Modbus/S7comm toggle buttons and a "Direction:" filter row with error/read/write toggle buttons sit above a "41 / 41 commands" counter, and a chronological table (columns Time, Src, Dst, Protocol, Function, Direction, Details) lists every OT command — e.g. Modbus "Write Single Register" (write) and "Read Holding Registers" (read) between 10.0.2.10 and 10.0.2.50, and S7comm "Setup Communication", "Read Variable", "Write Variable", "Request Download", and "PLC Stop" entries between 10.0.2.10 and 10.0.2.51.
](images/ot-log/ot-log-view@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Resulting state observed with fixtures/network-capture-demo.pcap: the OT Log tab is active, a "Protocol:" filter row with Modbus/S7comm toggle buttons and a "Direction:" filter row with error/read/write toggle buttons sit above a "41 / 41 commands" counter, and a chronological table (columns Time, Src, Dst, Protocol, Function, Direction, Details) lists every OT command — e.g. Modbus "Write Single Register" (write) and "Read Holding Registers" (read) between 10.0.2.10 and 10.0.2.50, and S7comm "Setup Communication", "Read Variable", "Write Variable", "Request Download", and "PLC Stop" entries between 10.0.2.10 and 10.0.2.51.
 (mobile)](images/ot-log/ot-log-view@mobile.png)

   </details>

   With fixtures/network-capture-demo.pcap uploaded and the OT Log tab selected, the page presents a dedicated chronological view of every industrial-control command captured in the file. A "Protocol:" row offers Modbus and S7comm toggle buttons, and a "Direction:" row offers error, read, and write toggle buttons, letting an analyst narrow the log to a specific protocol or command direction; a counter reading "41 / 41 commands" confirms none of the entries are currently filtered out. Below the filters sits a table with columns for Time, Src, Dst, Protocol, Function, Direction, and Details, listing each command in order — for example, a Modbus Write Single Register command (direction write) sent from 10.0.2.10 to 10.0.2.50 targeting unit 1, register 40001, followed by read commands such as Read Holding Registers and Read Coils between the same two hosts, and later a run of S7comm entries — Setup Communication, Read Variable, Write Variable, Request Download, and PLC Stop — exchanged between 10.0.2.10 and 10.0.2.51. Because each row also carries a Details column (register addresses, unit IDs, or a placeholder for S7comm commands that don't expose that detail), this view lets an analyst trace exactly which PLC registers were read or written, and in what order, across the engineering workstation's session with each controller.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
