---
sidebar_position: 13
sidebar_label: "Findings — analyst triage workspace"
description: "The Findings view is an analyst triage workspace that automatically derives reviewable findings from anomalies, captured credentials, file transfers, OT…"
---

# Findings — analyst triage workspace

The Findings view is an analyst triage workspace that automatically derives reviewable findings from anomalies, captured credentials, file transfers, OT write/error command groups, and high-risk hosts. Each finding supports a status (Open/etc.), severity, a "Report" include/exclude checkbox, and free-text notes, so an analyst can triage a capture's results into a report-ready set.


## Steps

1. **Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Findings only appears post-upload).
**

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Findings only appears post-upload).
](images/findings-workspace/empty-state@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Initial state: full-page drop zone ("Drop one or more capture files here or click to browse"), header stats all showing "—", no view tabs rendered yet (Findings only appears post-upload).
 (mobile)](images/findings-workspace/empty-state@mobile.png)

   </details>

   Before any capture file is loaded, the tool presents a single full-page drop zone centered on the page, with the prompt "Drop one or more capture files here or click to browse" and a note on accepted formats (.pcap, .pcapng, .cap, up to 100 files and 1 GB total). The header above shows Hosts, Connections, and Packets counters all reading em dashes, since nothing has been parsed yet. Only the core Graph, Table, DNS Map, and OT Map view tabs are visible in this state — the Findings tab, along with VLAN, Dashboard, and other post-analysis tabs, only appears once a capture has been uploaded and processed, so there is nothing to triage until data exists.

2. **Resulting state observed with fixtures/network-capture-demo.pcap: the Findings view header shows "49 active / 49 total / 49 in report" plus filter dropdowns (Active/All severities/All sources), and the main list renders one card per derived finding — e.g. "Data exfiltration from 10.0.1.12 (1 connection)" (Anomaly), "FTP credential captured for ftpadmin" (Credential), "High-risk host 10.0.1.30" / 10.0.2.10 / 10.0.2.50 / 10.0.2.51 (Risk Host), "HTTP credential captured for admin" (Credential) — each tagged with a source-type badge (Anomaly/Credential/Risk Host) and severity badge (HIGH), and each row exposes a status dropdown ("Open"), a severity dropdown ("high"), a "Report" include/exclude checkbox (checked by default), a "Note" button, and a "Copy Evidence" button. The left sidebar retains the same Protocols/VLAN Health/Search panels seen on other views.
**

   ![Resulting state observed with fixtures/network-capture-demo.pcap: the Findings view header shows "49 active / 49 total / 49 in report" plus filter dropdowns (Active/All severities/All sources), and the main list renders one card per derived finding — e.g. "Data exfiltration from 10.0.1.12 (1 connection)" (Anomaly), "FTP credential captured for ftpadmin" (Credential), "High-risk host 10.0.1.30" / 10.0.2.10 / 10.0.2.50 / 10.0.2.51 (Risk Host), "HTTP credential captured for admin" (Credential) — each tagged with a source-type badge (Anomaly/Credential/Risk Host) and severity badge (HIGH), and each row exposes a status dropdown ("Open"), a severity dropdown ("high"), a "Report" include/exclude checkbox (checked by default), a "Note" button, and a "Copy Evidence" button. The left sidebar retains the same Protocols/VLAN Health/Search panels seen on other views.
](images/findings-workspace/findings-view@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Resulting state observed with fixtures/network-capture-demo.pcap: the Findings view header shows "49 active / 49 total / 49 in report" plus filter dropdowns (Active/All severities/All sources), and the main list renders one card per derived finding — e.g. "Data exfiltration from 10.0.1.12 (1 connection)" (Anomaly), "FTP credential captured for ftpadmin" (Credential), "High-risk host 10.0.1.30" / 10.0.2.10 / 10.0.2.50 / 10.0.2.51 (Risk Host), "HTTP credential captured for admin" (Credential) — each tagged with a source-type badge (Anomaly/Credential/Risk Host) and severity badge (HIGH), and each row exposes a status dropdown ("Open"), a severity dropdown ("high"), a "Report" include/exclude checkbox (checked by default), a "Note" button, and a "Copy Evidence" button. The left sidebar retains the same Protocols/VLAN Health/Search panels seen on other views.
 (mobile)](images/findings-workspace/findings-view@mobile.png)

   </details>

   After uploading and analyzing a capture, the Findings tab opens a dedicated triage workspace summarized at the top as "49 active / 49 total / 49 in report," alongside three filter dropdowns for status (defaulting to Active), severity (All severities), and source (All sources). Below that, the view lists one card per derived finding, each pulled automatically from a different underlying source: anomalies such as "Data exfiltration from 10.0.1.12 (1 connection)" or "Port scan from 198.51.100.77," captured credentials such as "FTP credential captured for ftpadmin" or "HTTP credential captured for admin," OT/ICS write and error events like "Modbus write Write Single Register" or "S7comm write PLC Stop," a file transfer for quarterly_report.pdf, and risk-scored hosts like "High-risk host 10.0.1.30" (flagged for a risk score of 75/100 as an IP Camera) or "High-risk host 10.0.2.10" (70/100, Engineering Workstation). Each card carries a severity badge (high, medium, or low) and a source-type badge (Anomaly, Credential, Risk Host, File, or OT Command), plus per-row controls: a status dropdown defaulting to Open, a severity dropdown, a checked-by-default Report checkbox for including the item in an exported report, and Note and Copy Evidence buttons for annotating or extracting the finding's supporting detail. The left sidebar keeps the same Search, VLAN Health, and Protocols panels seen throughout the rest of the app, letting an analyst cross-reference a finding against the broader capture context without leaving the view.

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
