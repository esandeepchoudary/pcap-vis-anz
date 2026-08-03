---
sidebar_position: 10
sidebar_label: "View the Dashboard summary"
description: "The Dashboard view — summary cards, a risk-score bar chart, protocol distribution, and a clickable Top Anomalies list, giving an at-a-glance overview of the…"
---

# View the Dashboard summary

The Dashboard view — summary cards, a risk-score bar chart, protocol distribution, and a clickable Top Anomalies list, giving an at-a-glance overview of the analyzed capture.


## Steps

1. **Resulting Dashboard state observed with fixtures/network-capture-demo.pcap: summary cards (e.g. host/connection/anomaly counts), a risk-score bar chart, a protocol distribution breakdown, and a clickable Top Anomalies list (top entry observed: "Port scan from 198.51.100.77 → 1 target", severity "Info", with "Click to inspect in graph" affordance).
**

   ![Resulting Dashboard state observed with fixtures/network-capture-demo.pcap: summary cards (e.g. host/connection/anomaly counts), a risk-score bar chart, a protocol distribution breakdown, and a clickable Top Anomalies list (top entry observed: "Port scan from 198.51.100.77 → 1 target", severity "Info", with "Click to inspect in graph" affordance).
](images/dashboard/dashboard-view@desktop.png)

   <details class="docsolace-viewport docsolace-viewport--mobile">
   <summary>Mobile view</summary>

   ![Resulting Dashboard state observed with fixtures/network-capture-demo.pcap: summary cards (e.g. host/connection/anomaly counts), a risk-score bar chart, a protocol distribution breakdown, and a clickable Top Anomalies list (top entry observed: "Port scan from 198.51.100.77 → 1 target", severity "Info", with "Click to inspect in graph" affordance).
 (mobile)](images/dashboard/dashboard-view@mobile.png)

   </details>

   The Dashboard view opens with summary tiles across the top — 29 Hosts, 31 Connections, 401 Packets, 31 Anomalies, and 33 Protocols — giving an immediate read on the size and diversity of the analyzed capture. Below that, a "Top Hosts by Risk Score" bar chart ranks the most concerning hosts, led by 10.0.1.30 at 75, followed by the three OT hosts 10.0.2.10, 10.0.2.50, and 10.0.2.51 each at 70. A "Protocol Distribution" chart breaks down traffic volume by protocol, with HTTPS dominating at 217 packets ahead of HTTP (46), FTP (35), Telnet (29), RDP (28), SMB (28), Modbus (27), and Metasploit (25), while an "Anomaly Severity" chart tallies findings into 10 High, 13 Medium, 8 Low, and 0 Info. A clickable "Top Anomalies" list surfaces the most notable findings with "Review" buttons, including a port scan from 198.51.100.77 (1 target), data exfiltration from 10.0.1.12, suspicious ports on 10.0.1.11, unauthorized Modbus writes from 10.0.2.10, Telnet access to an IoT device from 198.51.100.77, and an IP camera at 10.0.1.30 sending traffic externally, with a "+24 more" link to the full list. A "Busiest Connections" panel rounds out the view, led by 10.0.1.12 to 198.51.100.200 at 189 packets, well above the next-busiest pairs like 10.0.2.10 to 10.0.2.50 (27 packets) and 10.0.1.11 to 203.0.113.66 (25 packets).

<!-- docsolace:keep -->
<!-- Notes added here are preserved across regeneration. -->
<!-- /docsolace:keep -->
