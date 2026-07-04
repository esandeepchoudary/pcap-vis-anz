/* ── Colour maps ─────────────────────────────────────────────────────────── */
const HOST_COLORS = {
  "Web Server":      "#4FC3F7",
  "SSH Server":      "#FF7043",
  "FTP Server":      "#FF8A65",
  "DNS Server":      "#81C784",
  "DHCP Server":     "#AED581",
  "Mail Server":     "#CE93D8",
  "Database Server": "#FFB74D",
  "Cache Server":    "#FF8A65",
  "Search Server":   "#F06292",
  "Windows Host":    "#64B5F6",
  "Linux Host":      "#FFA726",
  "Linux Server":    "#FF7043",
  "Network Device":  "#4DB6AC",
  "Router":          "#26A69A",
  "VPN Gateway":     "#7E57C2",
  "Container Host":  "#26C6DA",
  "Directory Server":"#EC407A",
  "Log Server":      "#A1887F",
  "NTP Server":      "#8D6E63",
  "Print Server":    "#90A4AE",
  "Security Tool":   "#EF5350",
  "Remote Desktop":  "#5C6BC0",
  "Telnet Server":   "#FF5722",
  "Internet Host":   "#78909C",
  "Broadcast":       "#37474F",
  "Multicast":       "#455A64",
  "Unknown Host":    "#546E7A",
  "PLC":                    "#FF6B35",
  "RTU":                    "#F7C59F",
  "IED":                    "#EFEFD0",
  "HMI":                    "#FF9F1C",
  "SCADA Server":           "#E71D36",
  "DCS":                    "#C77DFF",
  "Historian":              "#7B2D8B",
  "Engineering Workstation":"#2EC4B6",
  "Building Controller":    "#CBF3F0",
  "IoT Gateway":            "#FFBF69",
  "Field Device":           "#A8DADC",
  "IP Camera":        "#00BCD4",
  "Smart Home Hub":   "#8BC34A",
  "Smart Meter":      "#FFC107",
  "IoT Sensor":       "#03A9F4",
  "Smart Speaker":    "#9C27B0",
  "CPE Device":       "#607D8B",
  "DHCP Client":      "#81D4FA",
  "Discovery":        "#4DD0E1",
  "News Server":      "#BA68C8",
};

const PROTO_COLORS = {
  "HTTP":       "#42A5F5",
  "HTTPS":      "#26C6DA",
  "DNS":        "#66BB6A",
  "SSH":        "#FFA726",
  "FTP":        "#EC407A",
  "FTP-Data":   "#EC407A",
  "SMTP":       "#AB47BC",
  "SMTPS":      "#AB47BC",
  "IMAP":       "#7E57C2",
  "IMAPS":      "#7E57C2",
  "POP3":       "#9575CD",
  "POP3S":      "#9575CD",
  "SMB":        "#26A69A",
  "RDP":        "#EF5350",
  "ICMP":       "#BDBDBD",
  "TCP":        "#78909C",
  "UDP":        "#90A4AE",
  "ARP":        "#546E7A",
  "NTP":        "#8D6E63",
  "SNMP":       "#5C6BC0",
  "SNMP-Trap":  "#5C6BC0",
  "MySQL":      "#FF7043",
  "PostgreSQL": "#039BE5",
  "MongoDB":    "#43A047",
  "Redis":      "#E53935",
  "mDNS":       "#66BB6A",
  "SSDP":       "#78909C",
  "DHCP":       "#29B6F6",
  "BGP":        "#4DB6AC",
  "Telnet":     "#FF5722",
  "IP":         "#607D8B",
  "Modbus":       "#FF6B35",
  "EtherNet/IP":  "#FF9F1C",
  "S7comm":       "#2196F3",
  "DNP3":         "#9C27B0",
  "IEC-104":      "#E91E63",
  "BACnet":       "#009688",
  "OPC-UA":       "#FF5722",
  "MQTT":         "#795548",
  "MQTT-TLS":     "#8D6E63",
  "PROFINET":     "#3F51B5",
  "HART-IP":      "#607D8B",
  "GE-SRTP":      "#F44336",
  "OMRON-FINS":   "#4CAF50",
  "Emerson-DeltaV":"#FF9800",
  "PROFIBUS":     "#9E9E9E",
  "CoAP":         "#00BCD4",
  "CoAP-DTLS":    "#0097A7",
  "AMQP":         "#FF5722",
  "AMQPS":        "#BF360C",
  "XMPP":         "#4CAF50",
  "XMPP-TLS":     "#388E3C",
  "RTSP":         "#9C27B0",
  "Matter":       "#673AB7",
  "WS-Discovery": "#607D8B",
  "TR-069":       "#F44336",
  "Tuya-IoT":     "#FF9800",
  "Hikvision":    "#795548",
  "Dahua":        "#8D6E63",
  "AMSP":         "#26C6DA",
  "DLMS":         "#F06292",
  // Windows / NetBIOS
  "NetBIOS-NS":   "#5C6BC0",
  "NetBIOS-DGM":  "#5C6BC0",
  "NetBIOS-SSN":  "#5C6BC0",
  "LLMNR":        "#7986CB",
  // Directory / identity
  "LDAP":         "#EC407A",
  "LDAPS":        "#EC407A",
  // Mail / messaging
  "NNTP":         "#AB47BC",
  // Print / services
  "IPP":          "#8D6E63",
  "Syslog":       "#A1887F",
  // Databases
  "MSSQL":        "#FF7043",
  "Oracle-DB":    "#FF8A65",
  "Elasticsearch":"#F06292",
  // Containers / orchestration
  "Docker":       "#26C6DA",
  "Docker-TLS":   "#00ACC1",
  "K8s-API":      "#0097A7",
  // Remote access
  "VNC":          "#5C6BC0",
  "WinRM":        "#3F51B5",
  "WinRM-S":      "#3949AB",
  // VPN
  "IKE/IPsec":    "#7E57C2",
  "OpenVPN":      "#673AB7",
  "PPTP":         "#9575CD",
  "IPsec-NAT":    "#7B1FA2",
  // Security / C2
  "Metasploit":   "#EF5350",
  // OT / IoT misc
  "Foxboro":      "#FF9800",
  "XIMSS":        "#4CAF50",
  "CAP":          "#FFC107",
};

/* E3: Colour-blind safe palette overrides (deuteranopia — green/red safe) */
const HOST_COLORS_CB = Object.assign({}, HOST_COLORS, {
  "DNS Server":      "#0099bb",
  "DHCP Server":     "#00a8a8",
  "Smart Home Hub":  "#0099bb",
  "Security Tool":   "#ee7733",
  "SCADA Server":    "#ee3377",
  "Linux Server":    "#cc5500",
  "Telnet Server":   "#cc5500",
  "OMRON-FINS":      "#0099bb",
});
const PROTO_COLORS_CB = Object.assign({}, PROTO_COLORS, {
  "DNS":         "#0099bb",
  "mDNS":        "#0099bb",
  "MongoDB":     "#0099bb",
  "OMRON-FINS":  "#0099bb",
  "XMPP":        "#0099bb",
  "XMPP-TLS":    "#007799",
  "Redis":       "#ee7733",
  "RDP":         "#ee7733",
  "GE-SRTP":     "#ee7733",
  "TR-069":      "#ee7733",
});

function protoColor(protocols) {
  if (!protocols || !protocols.length) return "#607D8B";
  const map = colorBlindMode ? PROTO_COLORS_CB : PROTO_COLORS;
  const priority = [
    "HTTPS","HTTP","SSH","RDP","DNS","SMTP","SMTPS","IMAP","IMAPS",
    "POP3","POP3S","FTP","FTP-Data","MySQL","PostgreSQL","MongoDB",
    "Redis","SMB","SNMP","DHCP","NTP","BGP","ICMP","TCP","UDP",
  ];
  for (const p of priority) {
    if (protocols.includes(p)) return map[p] || "#607D8B";
  }
  return map[protocols[0]] || "#607D8B";
}

function hostColor(type) {
  return (colorBlindMode ? HOST_COLORS_CB : HOST_COLORS)[type] || "#546E7A";
}

// Hash-based HSL color for VLAN IDs — no palette collision (VLANs 1, 21, 41 no longer clash)
function vlanColor(vid) {
  if (vid === "untagged" || vid == null) return "#546E7A";
  const s = String(vid);
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `hsl(${(h * 47) % 360}, 62%, 62%)`;
}

// Infer /24 subnets from a list of IPv4 addresses (IPv6 skipped)
function inferSubnets(ips) {
  const prefixes = new Set();
  ips.forEach(ip => {
    if (!ip.includes(":")) {
      const p = ip.split(".");
      if (p.length === 4) prefixes.add(`${p[0]}.${p[1]}.${p[2]}.0/24`);
    }
  });
  return [...prefixes].sort();
}

// Canonical anomaly type → family mapping (used by buildAnomalySidebar)
const ANOMALY_FAMILIES = [
  {
    id: "network",
    label: "Network",
    icon: "🌐",
    types: new Set(["port_scan","suspicious_port","beaconing","exfiltration","dns_tunneling"]),
  },
  {
    id: "credentials",
    label: "Credentials & TLS",
    icon: "🔑",
    types: new Set(["cleartext_credentials","password_reuse","unusual_ja3"]),
  },
  {
    id: "ot",
    label: "OT / ICS",
    icon: "⚙",
    types: new Set([
      "ot_modbus_write","ot_modbus_bulk_read","ot_modbus_broadcast","ot_modbus_exception",
      "ot_multiunit_poll","ot_dnp3_control","ot_dnp3_unusual_fc","ot_s7_critical",
      "ot_s7_write","ot_s7_code_download","ot_enip_write","ot_iec104_command",
      "ot_bacnet_write","ot_internet_exposure","ot_cleartext",
    ]),
  },
  {
    id: "iot",
    label: "IoT",
    icon: "📡",
    types: new Set(["iot_mqtt_cleartext","iot_telnet","iot_camera_exfil","iot_tr069"]),
  },
  {
    id: "vlan",
    label: "VLAN",
    icon: "🔒",
    types: new Set([
      "vlan_hopping","vlan_native_leak","vlan_qinq","vlan_cross_segment_ot",
      "arp_spoofing","broadcast_storm","pcp_abuse",
    ]),
  },
];

/* C1: Inline explanations for each anomaly type */
const ANOMALY_EXPLANATIONS = {
  port_scan: {
    what: "A host rapidly probed many ports on one or more targets.",
    why:  "Port scanning is reconnaissance — attackers map open services before exploiting them.",
    steps: ["Verify whether the scanning host is authorised (e.g. a pentesting tool).", "Check firewall/IDS logs for blocked probe attempts.", "If unexpected, treat the source as potentially compromised."],
  },
  suspicious_port: {
    what: "Traffic was observed on a port commonly associated with malware or unauthorised services.",
    why:  "Well-known malware families use predictable ports (e.g. 4444, 6667) for C2 channels.",
    steps: ["Identify the process listening on that port.", "Cross-reference against known malware port lists.", "Block or quarantine the host if no legitimate use is found."],
  },
  beaconing: {
    what: "A host sent repeated, evenly-spaced connections (low inter-arrival time variance).",
    why:  "C2 implants beacon home at regular intervals to receive commands; low timing variance is a strong signal.",
    steps: ["Capture a packet sample and inspect the payload for known C2 signatures.", "Block the destination at the perimeter and isolate the host.", "Run EDR/AV on the beaconing endpoint."],
  },
  exfiltration: {
    what: "A large volume of data was transferred to an external IP.",
    why:  "Data exfiltration is a late-stage attacker goal; large outbound flows to unknown IPs are a red flag.",
    steps: ["Identify the external destination and check reputation (threat intel).", "Review what data resides on the source host.", "Block the destination and preserve network logs for forensics."],
  },
  dns_tunneling: {
    what: "Unusually long or numerous DNS queries suggest data is being smuggled in DNS payloads.",
    why:  "DNS is often allowed through firewalls; attackers embed C2 traffic or exfiltrate data in DNS labels.",
    steps: ["Capture and decode the suspect DNS queries.", "Check if the queried domain resolves or behaves like a tunnel server.", "Block the domain and inspect the querying host."],
  },
  cleartext_credentials: {
    what: "Username/password pairs were transmitted in plaintext over the network.",
    why:  "Cleartext credentials (HTTP Basic, FTP, Telnet, etc.) can be trivially intercepted by any on-path observer.",
    steps: ["Force TLS/SSH for all relevant services.", "Rotate any captured credentials immediately.", "Audit which hosts are still using legacy cleartext protocols."],
  },
  password_reuse: {
    what: "The same credential was observed authenticating to multiple distinct services.",
    why:  "Credential stuffing attacks exploit password reuse — one breach gives attackers access everywhere.",
    steps: ["Enforce unique passwords per service via a password manager or SSO.", "Investigate whether those services were accessed by an authorised user.", "Enable MFA on all reachable services."],
  },
  unusual_ja3: {
    what: "A TLS client fingerprint (JA3) was seen that does not match known browser or tool baselines.",
    why:  "Malware often has distinctive TLS handshake parameters; an unknown JA3 hash may indicate a novel or obfuscated client.",
    steps: ["Look up the JA3 hash against public threat intel databases.", "Identify the process generating the TLS connection on the host.", "If unrecognised, treat the host as potentially compromised."],
  },
  ot_modbus_write: {
    what: "A Modbus write command (FC 5/6/15/16) was sent to a device.",
    why:  "Write commands can alter PLC coils and registers, directly affecting physical processes.",
    steps: ["Verify the source is an authorised engineering workstation.", "Confirm the target register/coil is expected to change at this time.", "Review the change management log for a matching work order."],
  },
  ot_modbus_bulk_read: {
    what: "An unusually large number of Modbus read requests were sent in a short time.",
    why:  "Bulk reads may indicate reconnaissance of process variables or automated enumeration of connected devices.",
    steps: ["Check whether the source is a known SCADA/HMI system.", "Review the specific registers being read for sensitive process data.", "Alert the OT security team if source is unknown."],
  },
  ot_modbus_broadcast: {
    what: "A Modbus request was sent to the broadcast address (unit ID 0).",
    why:  "Broadcast commands affect all devices on the bus simultaneously and are rarely used in production.",
    steps: ["Determine whether a broadcast was intentionally sent by an operator.", "Check for replay attacks if the same broadcast was sent repeatedly.", "Disable broadcast address support on PLCs if not required."],
  },
  ot_modbus_exception: {
    what: "A PLC returned a Modbus exception response (error code).",
    why:  "Exceptions indicate the device rejected a command or is in an error state, which can signal misuse or misconfiguration.",
    steps: ["Identify the exception code and the function code that triggered it.", "Determine if the command came from a legitimate HMI.", "Investigate the device health if exceptions are frequent."],
  },
  ot_multiunit_poll: {
    what: "One host polled many different Modbus unit IDs, suggesting device discovery.",
    why:  "Scanning multiple unit IDs is a classic OT reconnaissance technique used to enumerate devices on a serial or network segment.",
    steps: ["Confirm whether the source IP belongs to a known asset management tool.", "Restrict Modbus access to the HMI/SCADA range via ACLs.", "Alert the OT team if the source is unrecognised."],
  },
  ot_dnp3_control: {
    what: "A DNP3 control operation (operate, direct operate) was sent.",
    why:  "DNP3 control messages can actuate field devices (breakers, valves) and cause physical impact if unauthorised.",
    steps: ["Verify the operator workstation sent the command.", "Cross-reference with the SCADA alarm log for a corresponding operator action.", "Enforce DNP3 application-layer authentication (SAv5/6)."],
  },
  ot_dnp3_unusual_fc: {
    what: "A rarely-used DNP3 function code was observed.",
    why:  "Unusual function codes may indicate fuzzing, an exploit attempt, or a misconfigured master station.",
    steps: ["Log the specific function code and the source master station.", "Check the DNP3 standard documentation for the function's purpose.", "Consider blocking unsupported function codes in DNP3 proxy firewalls."],
  },
  ot_s7_critical: {
    what: "A critical S7 command (CPU start/stop, cold restart) was sent to a Siemens PLC.",
    why:  "These commands directly control PLC execution state and can halt a process if misused.",
    steps: ["Confirm the command came from an authorised programming device (PG/PC).", "Review the maintenance schedule for any planned CPU restarts.", "Restrict S7 control functions by source IP and authentication."],
  },
  ot_s7_write: {
    what: "An S7 write to DB or I/O area was observed.",
    why:  "Writing to data blocks or I/O areas alters process variables and setpoints, potentially causing unsafe conditions.",
    steps: ["Confirm the write was issued by an authorised HMI or engineering station.", "Identify what data block and offset was modified.", "Enable write protection on critical DBs in the PLC program."],
  },
  ot_s7_code_download: {
    what: "An S7 program download was detected.",
    why:  "Downloading modified PLC code is the highest-impact OT attack vector (cf. Stuxnet).",
    steps: ["Immediately verify that the download was authorised and matches a known change request.", "Compare the downloaded program against the golden backup.", "Isolate the programming PC if the download was unexpected."],
  },
  ot_enip_write: {
    what: "An EtherNet/IP explicit message write (set attribute) was sent.",
    why:  "EtherNet/IP write commands alter Allen-Bradley or other CIP device parameters at runtime.",
    steps: ["Confirm the source is an authorised Logix or Studio 5000 workstation.", "Log the target tag name and new value.", "Enable CIP security (CIP Security v2) if the controller supports it."],
  },
  ot_iec104_command: {
    what: "An IEC 60870-5-104 command (type ID ≥ 45) was sent.",
    why:  "IEC 104 commands are used to control substation equipment; unauthorised commands can trip breakers or actuate switches.",
    steps: ["Verify the source is the authorised control centre.", "Cross-reference with the SCADA journal for the scheduled operation.", "Enable IEC 62351-5 authentication if possible."],
  },
  ot_bacnet_write: {
    what: "A BACnet WriteProperty command was observed.",
    why:  "BACnet WriteProperty can alter HVAC/BAS setpoints, enabling temperature, airflow, or access control manipulation.",
    steps: ["Confirm the source is a known BAS workstation or BACnet operator terminal.", "Check what object and property was modified.", "Restrict BACnet traffic to the building automation subnet."],
  },
  ot_internet_exposure: {
    what: "An OT/ICS device communicated directly with an external (internet-routable) IP.",
    why:  "OT devices should never be internet-accessible; this path is a prime attack vector for ransomware and sabotage.",
    steps: ["Immediately block the connection at the firewall.", "Identify how the route to the internet was established (misconfigured router, VPN misconfiguration).", "Assess whether any data was exfiltrated or commands were received."],
  },
  ot_cleartext: {
    what: "OT protocol traffic was observed in cleartext between segments that should be isolated.",
    why:  "Unencrypted OT traffic can be intercepted and replayed, enabling man-in-the-middle attacks on industrial processes.",
    steps: ["Deploy a protocol-aware OT firewall to segment the traffic.", "Consider protocol-level encryption where supported (e.g. IEC 62351).", "Use unidirectional gateways (data diodes) for flows that only need one-way data."],
  },
  iot_mqtt_cleartext: {
    what: "MQTT traffic was observed on port 1883 (unencrypted).",
    why:  "Cleartext MQTT exposes IoT telemetry and commands to anyone on the network segment.",
    steps: ["Migrate all MQTT brokers to port 8883 (TLS-encrypted).", "Enforce client certificate authentication on the broker.", "Segment IoT devices onto a dedicated VLAN."],
  },
  iot_telnet: {
    what: "Telnet (port 23) traffic was detected to or from a device.",
    why:  "Telnet transmits credentials and commands in plaintext; it is exploited by IoT botnets (e.g. Mirai) to spread.",
    steps: ["Disable Telnet on all devices and replace with SSH.", "Change default credentials immediately on any device still running Telnet.", "Block port 23 at the network perimeter and between VLANs."],
  },
  iot_camera_exfil: {
    what: "A device classified as an IP camera sent an unusually large amount of data to an external host.",
    why:  "Compromised cameras have been used to stream footage to attacker-controlled servers.",
    steps: ["Verify whether the destination IP is the camera vendor's cloud service.", "Check firmware version and apply any security patches.", "Block outbound connections from cameras to unexpected external IPs."],
  },
  iot_tr069: {
    what: "TR-069 (CWMP) traffic was observed — often used for ISP remote management of CPE.",
    why:  "TR-069 has a history of vulnerabilities; attackers have hijacked ACS servers to compromise millions of routers.",
    steps: ["Confirm the ACS server IP belongs to the authorised ISP.", "Disable TR-069 if remote management is not required.", "Firewall port 7547 (TR-069) so only the ISP ACS can reach CPE."],
  },
  vlan_hopping: {
    what: "A frame with double 802.1Q tags (QinQ or tag stacking) was detected in a non-QinQ context.",
    why:  "VLAN hopping exploits switch trunk negotiation to inject frames into a VLAN the attacker should not reach.",
    steps: ["Set all access ports to 'access' mode (not auto/desirable) to prevent DTP negotiation.", "Change the native VLAN to an unused VLAN ID on all trunk ports.", "Enable BPDU Guard and port security on end-user access ports."],
  },
  vlan_native_leak: {
    what: "Untagged frames were seen on a trunk port's native VLAN, potentially crossing VLAN boundaries.",
    why:  "Native VLAN mismatches allow traffic to leak between VLANs transparently.",
    steps: ["Explicitly tag all VLANs on trunk ports and set native VLAN to an unused ID.", "Ensure native VLAN is consistent on both ends of every trunk.", "Enable 'vlan dot1q tag native' on all trunk interfaces."],
  },
  vlan_qinq: {
    what: "QinQ (802.1ad) double-tagged frames were observed.",
    why:  "Unexpected QinQ frames may indicate a VLAN hopping attempt or misconfigured tunnelling.",
    steps: ["Verify whether QinQ is intentionally provisioned for carrier VLAN services.", "If not intentional, investigate the source port for VLAN stacking capability.", "Restrict QinQ on ports where it is not required."],
  },
  vlan_cross_segment_ot: {
    what: "Traffic was detected flowing directly between the OT network VLAN and a non-OT VLAN.",
    why:  "Cross-segment OT traffic bypasses the security zone boundary and can expose PLCs to IT threats.",
    steps: ["Identify the source and destination hosts and whether a firewall rule permits this flow.", "Block the flow at the L3 boundary and route OT traffic through the DMZ.", "Audit ACLs on the OT VLAN interface."],
  },
  arp_spoofing: {
    what: "A host sent ARP replies claiming an IP address that belongs to another host.",
    why:  "ARP spoofing enables man-in-the-middle attacks, allowing an attacker to intercept, modify, or drop traffic.",
    steps: ["Enable Dynamic ARP Inspection (DAI) on all access switches.", "Use static ARP entries for critical hosts (gateways, servers).", "Investigate the host sending the spoofed ARP and check for malware."],
  },
  broadcast_storm: {
    what: "An unusually high volume of broadcast frames was detected.",
    why:  "Broadcast storms can saturate a switch fabric, causing a denial-of-service for the entire VLAN.",
    steps: ["Enable STP (Spanning Tree Protocol) with BPDU Guard and PortFast on access ports.", "Enable storm control on switch uplinks with an appropriate threshold.", "Identify the source of the storm (misconfigured NIC, switching loop, or malware)."],
  },
  pcp_abuse: {
    what: "802.1Q Priority Code Point (PCP) bits were set to high-priority values on traffic that should not be prioritised.",
    why:  "Attackers can abuse QoS priority bits to gain preferential queuing or to fingerprint VLAN infrastructure.",
    steps: ["Apply ingress QoS policing at access ports to reclassify or drop frames with suspicious PCP values.", "Restrict who can set PCP values (typically only trusted voice/video endpoints).", "Review QoS policy documentation and audit PCP markings."],
  },
};

function fmtBytes(b) {
  if (!Number.isFinite(b) || b < 0) return "0 B";
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  return (b / 1048576).toFixed(1) + " MB";
}

function fmtNum(n) {
  return Number.isFinite(n) ? n.toLocaleString() : "0";
}

/** Display helper: show first n items and an "+K more" suffix if the array is longer. */
function sliceMore(arr, n) {
  if (!Array.isArray(arr) || arr.length === 0) return "";
  const shown = arr.slice(0, n).map(String);
  return arr.length > n ? shown.join(", ") + ` … +${arr.length - n} more` : shown.join(", ");
}

/* ── Toast notifications ─────────────────────────────────────────────────── */
function showToast(msg, type = "info", duration = 4000) {
  const icons = { error: "✕", success: "✓", info: "ℹ", warn: "⚠" };
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span>
    <span class="toast-msg">${escHtml(msg)}</span>
    <button class="toast-close" aria-label="Dismiss">×</button>`;
  container.appendChild(el);

  const remove = () => {
    el.classList.add("removing");
    el.addEventListener("animationend", () => el.remove(), { once: true });
  };
  el.querySelector(".toast-close").addEventListener("click", remove);
  if (duration > 0) setTimeout(remove, duration);
}

function openTextModal({ title, value = "", placeholder = "", clearLabel = "Clear" }) {
  return new Promise(resolve => {
    const overlay = document.getElementById("text-modal");
    const titleEl = document.getElementById("text-modal-title");
    const input = document.getElementById("text-modal-input");
    const closeBtn = document.getElementById("text-modal-close");
    const cancelBtn = document.getElementById("text-modal-cancel");
    const clearBtn = document.getElementById("text-modal-clear");
    const saveBtn = document.getElementById("text-modal-save");
    if (!overlay || !titleEl || !input || !closeBtn || !cancelBtn || !clearBtn || !saveBtn) {
      resolve(null);
      return;
    }

    let done = false;
    const cleanup = (result) => {
      if (done) return;
      done = true;
      overlay.classList.add("hidden");
      closeBtn.removeEventListener("click", onCancel);
      cancelBtn.removeEventListener("click", onCancel);
      clearBtn.removeEventListener("click", onClear);
      saveBtn.removeEventListener("click", onSave);
      overlay.removeEventListener("click", onOverlay);
      input.removeEventListener("keydown", onKeydown);
      resolve(result);
    };
    const onCancel = () => cleanup(null);
    const onClear = () => cleanup("");
    const onSave = () => cleanup(input.value);
    const onOverlay = (e) => { if (e.target === overlay) cleanup(null); };
    const onKeydown = (e) => {
      if (e.key === "Escape") cleanup(null);
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") cleanup(input.value);
    };

    titleEl.textContent = title || "Edit Text";
    input.value = value || "";
    input.placeholder = placeholder || "";
    clearBtn.textContent = clearLabel || "Clear";
    overlay.classList.remove("hidden");
    closeBtn.addEventListener("click", onCancel);
    cancelBtn.addEventListener("click", onCancel);
    clearBtn.addEventListener("click", onClear);
    saveBtn.addEventListener("click", onSave);
    overlay.addEventListener("click", onOverlay);
    input.addEventListener("keydown", onKeydown);
    setTimeout(() => {
      input.focus();
      input.selectionStart = input.selectionEnd = input.value.length;
    }, 0);
  });
}

function countryFlag(code) {
  if (!code || code.length !== 2) return "";
  const offset = 127397;
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
}

/** Return "Name (CC)" for a node's geo data, or "" if unavailable. */
function geoCountryStr(node) {
  if (!node || !node.geo) return "";
  const name = node.geo.country, code = node.geo.country_code;
  if (name && code) return `${name} (${code})`;
  return name || code || "";
}

/* ── State ───────────────────────────────────────────────────────────────── */
let graphData    = null;
let simulation   = null;
let selectedNode     = null;
let activeProtos     = new Set();
let activeTypes      = new Set();
let activeVlans      = new Set();
let activeIpVersions = new Set();
let searchTerm       = "";
let packetData   = {};
let currentView  = "graph";  // "graph" | "table" | "dns" | "ot" | "otlog" | "vlangraph" | "diff" | "dashboard" | "findings"
let vlanSimulation   = null;
let _vlanRendered    = false;
let _vlanLayout      = "force";
let vlanSelectedNode = null;  // separate from main selectedNode — no cross-view leakage
let baselineData = null;
let findings = [];
let findingsById = new Map();
let currentCaptureKey = "";
let findingFilters = { status: "active", severity: "all", source: "all" };
let currentLayout  = "force"; // "force" | "radial" | "cluster"
let colorByVlan    = false;   // when true, main graph nodes are colored by VLAN not host type
let _tlVisibleIps  = null;    // Set of IPs in the current timeline window, null = no filter
let _currentPktList = [];    // packets for the currently-open inspector panel
let anomalyNodeIps = {};     // ip → highest severity
let credIpSet = new Set();   // IPs with captured credentials
let tableSort = { col: "packet_count", dir: "desc" };
let highlightAnomsMode = false;   // D4
let colorBlindMode = false;        // E3
let filterPresets = [];            // E2

// Render caps — graph draws only top-N by traffic; exports always use the full dataset.
// Raise these constants if you want to render more (at a browser performance cost).
const RENDER_NODE_CAP = 1500;  // max SVG node groups drawn in the force graph
const RENDER_EDGE_CAP = 4000;  // max edges drawn (SVG or canvas)

// Canvas edge rendering (GPU-composited, activated for large graphs)
const CANVAS_THRESHOLD = 150;  // node count above which canvas edges are used
let useCanvasEdges = false;
let currentZoomTransform = d3.zoomIdentity;
let _canvasLinks = [];
let _canvasPLevel = {};
let _canvasMaxEdgePkt = 1;

// Timeline state
let tlPlaying = false;
let tlTimer = null;
let _zoomFitTimer = null;  // L3: cleared on re-render
let tlWindowPct = 100; // full width by default
let tlSpeed = 1;
let tlAbsTime = true;  // true = absolute HH:MM:SS, false = relative +Ns
let _tlMinT = 0;       // capture start time (seconds)
let _tlSpan = 1;       // capture duration (seconds)

// Graph power-user state (B1, B2, B3)
const pinnedNodes = new Set();
let isolatedNodeIp = null;
let _minimapInitialized = false;
let _minimapNodes = [];
let _visibleNodeIds  = new Set();  // updated by applyFilters / highlightNode; read by drawCanvasEdges
let _renderedNodeIds = new Set();  // set at render time; used for O(1) _isRendered()
let _minimapTickCount = 0;         // for minimap throttle
let _allVlans  = [];               // hoisted from applyFilters — constant per graphData
let _allIpVers = [];               //   ""

/* ── DOM refs ────────────────────────────────────────────────────────────── */
const svg            = d3.select("#graph-svg");
const tooltip        = document.getElementById("tooltip");
const detailPanel    = document.getElementById("detail-panel");
const modalOverlay   = document.getElementById("modal-overlay");
const loadingOverlay = document.getElementById("loading-overlay");
const fileInput      = document.getElementById("file-input");
const dropZone       = document.getElementById("drop-zone");
const modalError     = document.getElementById("modal-error");
const truncBanner    = document.getElementById("trunc-banner");
const capBanner      = document.getElementById("cap-banner");
const searchBox      = document.getElementById("search-box");
const graphWrap      = document.getElementById("graph-wrap");
const tableView      = document.getElementById("table-view");
const dnsView        = document.getElementById("dns-view");
const otMapView      = document.getElementById("ot-map-view");
const otLogView      = document.getElementById("otlog-view");
const diffView       = document.getElementById("diff-view");
const vlanView       = document.getElementById("vlan-view");
const dashboardView  = document.getElementById("dashboard-view");
const findingsView   = document.getElementById("findings-view");
const ctxMenu        = document.getElementById("ctx-menu");

/* ── SVG setup ───────────────────────────────────────────────────────────── */
const zoomGroup  = svg.append("g").attr("id", "zoom-group");
const linksGroup = zoomGroup.append("g").attr("id", "links-layer");
const nodesGroup = zoomGroup.append("g").attr("id", "nodes-layer");

const zoom = d3.zoom()
  .scaleExtent([0.05, 8])
  .on("zoom", (e) => {
    zoomGroup.attr("transform", e.transform);
    currentZoomTransform = e.transform;
    if (useCanvasEdges) drawCanvasEdges();
    updateMinimapViewport();
  });
svg.call(zoom);

/* ── Upload modal ─────────────────────────────────────────────────────────── */
document.getElementById("upload-btn").addEventListener("click", openModal);
dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) uploadFiles(fileInput.files);
});

dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length > 0) uploadFiles(e.dataTransfer.files);
});

modalOverlay.addEventListener("click", (e) => {
  if (e.target === modalOverlay && graphData) closeModal();
});

function openModal() {
  modalError.textContent = "";
  modalOverlay.classList.remove("hidden");
}
function closeModal() {
  modalOverlay.classList.add("hidden");
  fileInput.value = "";
}

// Loading progress stages: [threshold_pct, label]
const LOAD_STAGES = [
  [0,  "Uploading capture…"],
  [22, "Parsing packets…"],
  [52, "Classifying hosts…"],
  [74, "Detecting anomalies…"],
  [90, "Building graph…"],
];

function startLoadingProgress() {
  const bar   = document.getElementById("loading-bar");
  const stage = document.getElementById("loading-stage");
  if (!bar || !stage) return null;

  let pct = 0;
  bar.style.transition = "none";
  bar.style.width = "0%";

  const tick = setInterval(() => {
    // Advance quickly to 20%, then slow to 90%
    const step = pct < 20 ? 3 : pct < 60 ? 0.8 : pct < 85 ? 0.3 : 0.05;
    pct = Math.min(90, pct + step);
    bar.style.transition = "width 0.3s ease";
    bar.style.width = pct + "%";

    const current = LOAD_STAGES.filter(([t]) => pct >= t).pop();
    if (current) stage.textContent = current[1];
  }, 120);

  return { stop() {
    clearInterval(tick);
    bar.style.transition = "width 0.2s ease";
    bar.style.width = "100%";
    if (stage) stage.textContent = "Done";
  }};
}

async function uploadFiles(files) {
  // Copy to array immediately — closeModal() clears the live FileList via fileInput.value=""
  const fileArray = Array.from(files);
  const MAX_UPLOAD_FILES = 100; // keep in sync with app.py MAX_UPLOAD_FILES
  if (fileArray.length > MAX_UPLOAD_FILES) {
    modalError.textContent = `Too many files (${fileArray.length}). Upload at most ${MAX_UPLOAD_FILES} at a time.`;
    return;
  }
  const allowed = ["pcap","pcapng","cap"];
  for (const file of fileArray) {
    const ext = file.name.split(".").pop().toLowerCase();
    if (!allowed.includes(ext)) {
      modalError.textContent = `Unsupported file type: ${file.name}. Use .pcap, .pcapng, or .cap`;
      return;
    }
  }
  modalError.textContent = "";
  closeModal();
  loadingOverlay.classList.remove("hidden");
  const progress = startLoadingProgress();

  const form = new FormData();
  for (const file of fileArray) form.append("file", file);

  try {
    const resp = await fetch("/upload", { method: "POST", body: form });
    let data;
    try {
      data = await resp.json();
    } catch(_) {
      const raw = await resp.text().catch(() => "");
      throw new Error(`Server returned non-JSON (${resp.status}): ${raw.slice(0, 120)}`);
    }
    if (!resp.ok) throw new Error(data?.error || `Server error ${resp.status}: ${resp.statusText}`);
    progress && progress.stop();
    if (data.error) {
      showToast(data.error, "error");
      openModal();
      return;
    }
    loadGraph(data);
  } catch (err) {
    progress && progress.stop();
    showToast("Upload failed: " + err.message, "error");
    openModal();
  } finally {
    loadingOverlay.classList.add("hidden");
  }
}

/* ── Graph rendering ─────────────────────────────────────────────────────── */
function loadGraph(data) {
  graphData = data;
  packetData = data.packets || {};
  _otLogRendered = false;
  _otLogActiveProtoF = null;
  _otLogActiveDirF   = null;
  _vlanRendered  = false;
  _tlVisibleIps  = null;
  document.getElementById("vlan-tab-btn").classList.add("hidden");
  document.getElementById("dashboard-tab-btn").classList.add("hidden");
  document.getElementById("findings-tab-btn").classList.add("hidden");
  document.getElementById("vlan-filters-section").style.display = "none";
  document.getElementById("stat-vlans-wrap").style.display = "none";
  document.getElementById("stat-ipver-wrap").style.display = "none";
  document.getElementById("ipver-filters-section").style.display = "none";
  colorByVlan = false;
  const colorVlanBtn = document.getElementById("btn-color-vlan");
  if (colorVlanBtn) { colorVlanBtn.style.display = "none"; colorVlanBtn.classList.remove("active"); }
  const vlanSearchReset = document.getElementById("vlan-search");
  if (vlanSearchReset) { vlanSearchReset.value = ""; vlanSearchReset.style.display = "none"; }
  const vlanSummarySec = document.getElementById("vlan-summary-section");
  if (vlanSummarySec) vlanSummarySec.style.display = "none";
  _vlanMatrixMode = false;
  _vlanMatrixView = "traffic";
  _vlanMatrixMetric = "bytes";
  const matrixBtn = document.getElementById("vlan-matrix-btn");
  if (matrixBtn) { matrixBtn.classList.remove("active"); matrixBtn.textContent = "⊞ Matrix"; }
  const matrixCont = document.getElementById("vlan-matrix-container");
  if (matrixCont) matrixCont.classList.add("hidden");
  const matrixModes = document.getElementById("vlan-matrix-modes");
  if (matrixModes) {
    matrixModes.classList.add("hidden");
    matrixModes.querySelectorAll(".vm-mode-btn").forEach(b => b.classList.toggle("active", b.dataset.vmMode === "traffic"));
    matrixModes.querySelectorAll(".vm-metric-btn").forEach(b => b.classList.toggle("active", b.dataset.vmMetric === "bytes"));
    const metricGroup = document.getElementById("vlan-matrix-metric");
    if (metricGroup) metricGroup.style.display = "";
  }
  const canvasWrap = document.getElementById("vlan-canvas-wrap");
  if (canvasWrap) canvasWrap.classList.remove("hidden");
  const graphCtrl = document.getElementById("vlan-graph-controls");
  if (graphCtrl) graphCtrl.style.display = "";
  if (vlanSimulation) { vlanSimulation.stop(); vlanSimulation = null; }
  vlanSelectedNode = null;
  closePktInspector();
  selectedNode = null;
  pinnedNodes.clear();
  isolatedNodeIp = null;
  _minimapInitialized = false;
  _minimapTickCount = 0;
  const _mmEl = document.getElementById("minimap");
  if (_mmEl) _mmEl.style.display = "none";
  // Reset table sort cache so a new upload never serves the previous capture's rows
  _sortedEdges = []; _sortedEdgesKey = ""; _sortedEdgesNonce++;
  // Reset cluster-collapse state
  collapsedTypes.clear(); _clusterCollapseMode = false;
  const _ccBtn = document.getElementById("cluster-collapse-btn");
  if (_ccBtn) { _ccBtn.classList.remove("active"); _ccBtn.title = "Collapse/expand host-type clusters"; }
  const _clOverlay = document.getElementById("cluster-overlay");
  if (_clOverlay) _clOverlay.innerHTML = "";
  searchTerm = "";
  searchBox.value = "";
  highlightAnomsMode = false;
  const sparklineEl = document.querySelector("#stat-pkts")?.closest(".stat")?.querySelector(".stat-sparkline");
  if (sparklineEl) sparklineEl.remove();
  // Hide view empty states
  document.getElementById("dns-empty-state")?.classList.add("hidden");
  document.getElementById("ot-empty-state")?.classList.add("hidden");
  document.getElementById("dns-host-list") && (document.getElementById("dns-host-list").style.display = "");
  document.getElementById("dns-query-panel") && (document.getElementById("dns-query-panel").style.display = "");
  detailPanel.classList.remove("open");
  const noConnMsgReset = document.getElementById("no-connections-msg");
  if (noConnMsgReset) noConnMsgReset.classList.remove("visible");

  // Reset OT edit state so stale overrides from a prior PCAP don't linger
  Object.keys(otOverrides).forEach(k => delete otOverrides[k]);
  otRemovedIds.clear();
  Object.keys(otRiskLabels).forEach(k => delete otRiskLabels[k]);
  otAddedNodes.length = 0;

  const stats = data.stats || {};

  // Truncation banner (packet cap)
  if (stats.truncated) {
    truncBanner.classList.add("visible");
  } else {
    truncBanner.classList.remove("visible");
  }

  // Hard-cap-hit warning (hosts or connections backstop was exceeded — exports are incomplete)
  if (stats.hosts_truncated || stats.connections_truncated) {
    showToast(
      "⚠ This capture exceeded the host/connection backstop limits — some IPs or connections were dropped and will not appear in exports. Consider splitting the capture.",
      "warn", 12000
    );
  }

  // Reset render-cap banner; renderGraph will re-set it if needed
  capBanner.classList.remove("visible");

  // Processing warnings (partial file failures, anomaly detection failure)
  if (stats.geoip_available === false) {
    showToast("GeoIP database not found — country/city data unavailable. Install GeoLite2-City.mmdb to /usr/share/GeoIP/.", "info", 8000);
  }
  if (stats.parse_errors > 0) {
    showToast(`${stats.parse_errors} packet(s) could not be parsed and were skipped.`, "warn", 6000);
  }
  if (data.anomaly_error) {
    showToast("Anomaly detection failed for this capture — anomaly results may be incomplete.", "warn", 8000);
  }
  if (data.warnings && data.warnings.length) {
    data.warnings.forEach(w => showToast(w, "warn", 10000));
  }

  // Stats
  document.getElementById("stat-hosts").textContent = fmtNum(stats.total_hosts   || 0);
  document.getElementById("stat-conns").textContent = fmtNum(stats.total_connections || 0);
  document.getElementById("stat-pkts").textContent  = fmtNum(stats.total_packets  || 0);
  const vlanCount = (stats.vlans || []).length;
  document.getElementById("stat-vlans").textContent = fmtNum(vlanCount);
  document.getElementById("stat-vlans-wrap").style.display = vlanCount > 0 ? "" : "none";
  if (vlanCount > 0) {
    document.getElementById("vlan-tab-btn").classList.remove("hidden");
    document.getElementById("vlan-filters-section").style.display = "";
    document.getElementById("btn-color-vlan").style.display = "";   // show VLAN color toggle
    const vlanSearchShow = document.getElementById("vlan-search");
    if (vlanSearchShow) vlanSearchShow.style.display = "";
  }

  // IPv6 adoption stat
  const v6Count = stats.ipv6_count || 0;
  const v4Count = stats.ipv4_count || 0;
  const totalIpHosts = v4Count + v6Count;
  if (v6Count > 0) {
    const pct = totalIpHosts ? Math.round(v6Count * 100 / totalIpHosts) : 0;
    document.getElementById("stat-ipver").textContent = `${pct}% (${fmtNum(v6Count)}/${fmtNum(totalIpHosts)})`;
    document.getElementById("stat-ipver-wrap").style.display = "";
  }
  // IP version filter section (only shown when both IPv4 and IPv6 are present)
  const ipVerSection = document.getElementById("ipver-filters-section");
  if (ipVerSection) {
    ipVerSection.style.display = (stats.ip_versions || []).length > 1 ? "" : "none";
  }

  // Build filter sets
  activeProtos     = new Set(stats.protocols || []);
  activeTypes      = new Set(stats.host_types || []);
  activeVlans      = new Set((stats.vlans || []).map(String));
  if ((data.nodes || []).some(n => n.vlan_untagged)) activeVlans.add("untagged");
  activeIpVersions = new Set((stats.ip_versions || []).map(String));
  // Hoist constant per-dataset filter metadata so applyFilters() doesn't recompute each call
  _allVlans  = (stats.vlans || []).map(String);
  if ((data.nodes || []).some(n => n.vlan_untagged)) _allVlans.push("untagged");
  _allIpVers = (stats.ip_versions || []).map(String);
  // Restore persisted filter preferences (narrows the sets above to last-used selection)
  loadFilterState(stats.protocols || [], stats.host_types || []);

  buildFilters(data);
  buildVlanSummary(data);
  buildLegend(data);
  buildAnomalySidebar(data.anomalies || []);
  buildCredentialsSidebar(data.credentials || []);
  buildFilesSidebar(data.files || []);
  initializeFindings(data);
  buildTimeline(data);
  renderPresetList();
  // setView("graph") before renderGraph so graphWrap is visible when renderGraph
  // reads svg.clientWidth/Height (needed for correct cx/cy and canvas sizing)
  setView("graph");
  renderGraph(data);

  // Show baseline button now that data is loaded
  document.getElementById("baseline-btn").style.display = "";
  // Dashboard is always available once data is loaded
  document.getElementById("dashboard-tab-btn").classList.remove("hidden");
  document.getElementById("findings-tab-btn").classList.remove("hidden");
  // If a baseline was already set, show the diff tab
  if (baselineData) {
    document.getElementById("diff-tab-btn").classList.remove("hidden");
  }

  // Load annotations from localStorage
  applyAnnotations();
}

/* ── View switching ──────────────────────────────────────────────────────── */
document.querySelectorAll(".vt-btn").forEach(btn => {
  btn.addEventListener("click", () => setView(btn.dataset.view));
});

function setView(view) {
  if (!graphData && view !== "graph") {
    // Show empty state for views accessible before upload
    if (view === "dns") {
      dnsView.classList.remove("hidden");
      const es = document.getElementById("dns-empty-state");
      if (es) es.classList.remove("hidden");
      document.getElementById("dns-host-list")?.style && (document.getElementById("dns-host-list").style.display = "none");
      document.getElementById("dns-query-panel")?.style && (document.getElementById("dns-query-panel").style.display = "none");
    } else if (view === "ot") {
      otMapView.classList.remove("hidden");
      const es = document.getElementById("ot-empty-state");
      if (es) es.classList.remove("hidden");
    }
    return;
  }
  currentView = view;
  document.querySelectorAll(".vt-btn").forEach(b => b.classList.toggle("active", b.dataset.view === view));

  const graphEl = document.getElementById("graph-svg");
  const tlBar   = document.getElementById("timeline-bar");
  const pktIns  = document.getElementById("packet-inspector");

  if (view === "graph") {
    graphWrap.style.display = "";
    graphEl.style.display = "";
    tlBar.classList.remove("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    document.getElementById("graph-controls").style.display = "";
    document.getElementById("legend").style.display = "";
  } else if (view === "table") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    graphWrap.classList.remove("pkt-open");
    tableView.classList.remove("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    renderConnTable();
  } else if (view === "dns") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.remove("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    renderDnsMap();
  } else if (view === "ot") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.remove("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    renderOTMap(graphData);
    renderOTTimeline();
  } else if (view === "otlog") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.remove("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    renderOtLog(graphData.ot_commands || []);
  } else if (view === "vlangraph") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.remove("hidden");
    findingsView.classList.add("hidden");
    if (!_vlanRendered) renderVlanGraph(graphData);
  } else if (view === "diff") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.remove("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    renderDiff();
  } else if (view === "dashboard") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    findingsView.classList.add("hidden");
    dashboardView.classList.remove("hidden");
    renderDashboard();
  } else if (view === "findings") {
    graphWrap.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    otLogView.classList.add("hidden");
    diffView.classList.add("hidden");
    vlanView.classList.add("hidden");
    dashboardView.classList.add("hidden");
    findingsView.classList.remove("hidden");
    renderFindingsWorkspace();
  }

  if (view !== "vlangraph")  vlanView.classList.add("hidden");
  if (view !== "dashboard") dashboardView.classList.add("hidden");
  if (view !== "findings") findingsView.classList.add("hidden");
}

/* ── VLAN health summary card ────────────────────────────────────────────── */
function buildVlanSummary(data) {
  const section = document.getElementById("vlan-summary-section");
  const body    = document.getElementById("vlan-summary-body");
  if (!section || !body) return;
  const vlans = data.stats?.vlans || [];
  if (!vlans.length) { section.style.display = "none"; return; }

  // Count edges that cross VLAN boundaries
  const nodeByIp = Object.fromEntries((data.nodes || []).map(n => [n.ip, n]));
  const crossFlows = (data.edges || []).filter(e => {
    const s = nodeByIp[e.source], d = nodeByIp[e.target];
    if (!s || !d) return false;
    const sv = s.vlans?.[0], dv = d.vlans?.[0];
    return sv !== undefined && dv !== undefined && sv !== dv;
  }).length;

  const vlanAnomTypes = new Set(["vlan_hopping","vlan_native_leak","vlan_qinq",
    "vlan_cross_segment_ot","arp_spoofing","broadcast_storm","pcp_abuse"]);
  const vlanAnomCount = (data.anomalies || []).filter(a => vlanAnomTypes.has(a.type)).length;

  const seg = computeVlanSegmentationScore();
  const scoreHtml = seg
    ? `<div style="margin-top:2px"><span style="color:${seg.color};font-weight:600">${seg.score}/100</span> <span style="font-size:10px;color:var(--text2)">${seg.label}</span></div>`
    : "—";

  body.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 12px;font-size:11px">
      <div><div style="color:var(--text2)">VLANs</div><strong>${vlans.length}</strong></div>
      <div><div style="color:var(--text2)">Cross-VLAN flows</div><strong>${crossFlows}</strong></div>
      <div><div style="color:var(--text2)">VLAN anomalies</div>
           <strong style="color:${vlanAnomCount > 0 ? "var(--red)" : "var(--text)"}">${vlanAnomCount}</strong></div>
      <div><div style="color:var(--text2)">Segmentation</div>${scoreHtml}</div>
    </div>`;
  section.style.display = "";
}

/* ── Filters ─────────────────────────────────────────────────────────────── */
function buildFilters(data) {
  const stats = data.stats || {};
  buildFilterList("proto-filters", stats.protocols || [], activeProtos, PROTO_COLORS, "proto");
  buildFilterList("type-filters",  stats.host_types || [], activeTypes,  HOST_COLORS,  "type");
  const vlans = (stats.vlans || []).map(String);
  if ((data.nodes || []).some(n => n.vlan_untagged)) vlans.push("untagged");
  buildFilterList("vlan-filters",  vlans, activeVlans, {}, "vlan");
  buildFilterList("ipver-filters", (stats.ip_versions || []).map(String), activeIpVersions, {}, "ipver");
  updateFilterUI();
}

function buildFilterList(containerId, items, activeSet, colorMap, kind) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";

  const counts = {};
  if (graphData) {
    if (kind === "proto") {
      graphData.edges.forEach(e => (e.protocols || []).forEach(p => {
        counts[p] = (counts[p] || 0) + 1;
      }));
    } else if (kind === "vlan") {
      graphData.nodes.forEach(n => {
        (n.vlans || []).forEach(v => {
          counts[String(v)] = (counts[String(v)] || 0) + 1;
        });
        if (n.vlan_untagged) counts["untagged"] = (counts["untagged"] || 0) + 1;
      });
    } else if (kind === "ipver") {
      graphData.nodes.forEach(n => {
        const v = String(n.ip_version || 4);
        counts[v] = (counts[v] || 0) + 1;
      });
    } else {
      graphData.nodes.forEach(n => {
        counts[n.host_type || "Unknown Host"] = (counts[n.host_type || "Unknown Host"] || 0) + 1;
      });
    }
  }

  const IPVER_COLORS = { "4": "#42A5F5", "6": "#AB47BC" };
  items.forEach(item => {
    const color = kind === "vlan"  ? vlanColor(item)
                : kind === "ipver" ? (IPVER_COLORS[item] || "#546E7A")
                : (colorMap[item] || "#546E7A");
    const div = document.createElement("div");
    div.className = "filter-item";
    const iconSpan = kind === "type" ? `<span class="fi-icon">${hostIcon(item)}</span>` : "";
    const label = kind === "vlan"  ? (item === "untagged" ? "Untagged" : `VLAN ${item}`)
                : kind === "ipver" ? (item === "4" ? "IPv4" : "IPv6")
                : item;
    div.innerHTML = `
      <input type="checkbox" id="f-${kind}-${CSS.escape(item)}" ${activeSet.has(item) ? 'checked' : ''}>
      <div class="dot" style="background:${color}"></div>
      ${iconSpan}<label for="f-${kind}-${CSS.escape(item)}">${label}</label>
      <span class="count">${counts[item] || 0}</span>
    `;
    const cb = div.querySelector("input");
    cb.addEventListener("change", () => {
      if (cb.checked) activeSet.add(item);
      else activeSet.delete(item);
      if (kind === "proto" || kind === "type") saveFilterState();
      updateFilterUI();
      applyFilters();
      if (currentView === "table") renderConnTable();
    });
    container.appendChild(div);
  });
}

function updateFilterUI() {
  if (!graphData) return;
  const totalProtos  = (graphData.stats.protocols || []).length;
  const totalTypes   = (graphData.stats.host_types || []).length;
  const totalVlans   = (graphData.stats.vlans || []).length +
                       ((graphData.nodes || []).some(n => n.vlan_untagged) ? 1 : 0);
  const totalIpVers  = (graphData.stats.ip_versions || []).length;
  const hiddenProtos = totalProtos - activeProtos.size;
  const hiddenTypes  = totalTypes  - activeTypes.size;
  const hiddenVlans  = totalVlans  - activeVlans.size;
  const hiddenIpVers = totalIpVers - activeIpVersions.size;
  const hasSearch    = searchTerm.length > 0;
  const isFiltered   = hiddenProtos > 0 || hiddenTypes > 0 || hiddenVlans > 0 ||
                       hiddenIpVers > 0 || hasSearch;

  const protoBadge  = document.getElementById("proto-badge");
  const typeBadge   = document.getElementById("type-badge");
  const vlanBadge   = document.getElementById("vlan-badge");
  const ipVerBadge  = document.getElementById("ipver-badge");
  if (protoBadge) {
    protoBadge.textContent = hiddenProtos > 0 ? hiddenProtos + " hidden" : "";
    protoBadge.classList.toggle("visible", hiddenProtos > 0);
  }
  if (typeBadge) {
    typeBadge.textContent = hiddenTypes > 0 ? hiddenTypes + " hidden" : "";
    typeBadge.classList.toggle("visible", hiddenTypes > 0);
  }
  if (vlanBadge) {
    vlanBadge.textContent = hiddenVlans > 0 ? hiddenVlans + " hidden" : "";
    vlanBadge.classList.toggle("visible", hiddenVlans > 0);
  }
  if (ipVerBadge) {
    ipVerBadge.textContent = hiddenIpVers > 0 ? hiddenIpVers + " hidden" : "";
    ipVerBadge.classList.toggle("visible", hiddenIpVers > 0);
  }

  const protoClearBtn = document.getElementById("proto-clear-btn");
  const typeClearBtn  = document.getElementById("type-clear-btn");
  const vlanClearBtn  = document.getElementById("vlan-clear-btn");
  const ipVerClearBtn = document.getElementById("ipver-clear-btn");
  if (protoClearBtn) {
    protoClearBtn.style.display = totalProtos > 0 ? "" : "none";
    protoClearBtn.textContent   = activeProtos.size === totalProtos ? "Unselect All" : "Select All";
  }
  if (typeClearBtn) {
    typeClearBtn.style.display = totalTypes > 0 ? "" : "none";
    typeClearBtn.textContent   = activeTypes.size === totalTypes ? "Unselect All" : "Select All";
  }
  if (vlanClearBtn) {
    vlanClearBtn.style.display = totalVlans > 0 ? "" : "none";
    vlanClearBtn.textContent   = activeVlans.size === totalVlans ? "Unselect All" : "Select All";
  }
  if (ipVerClearBtn) {
    ipVerClearBtn.style.display = totalIpVers > 0 ? "" : "none";
    ipVerClearBtn.textContent   = activeIpVersions.size === totalIpVers ? "Unselect All" : "Select All";
  }

  const clearSection = document.getElementById("clear-filters-section");
  if (clearSection) clearSection.style.display = isFiltered ? "" : "none";

  // Header chip — always visible on every tab when any filter is active
  const totalHidden = hiddenProtos + hiddenTypes + hiddenVlans + hiddenIpVers + (hasSearch ? 1 : 0);
  const headerChip  = document.getElementById("header-clear-filters-btn");
  const chipCount   = document.getElementById("header-filter-count");
  if (headerChip) {
    headerChip.style.display = isFiltered ? "" : "none";
    if (chipCount) chipCount.textContent = totalHidden > 0
      ? `${totalHidden} filter${totalHidden !== 1 ? "s" : ""} active`
      : "search active";
  }
}

document.getElementById("proto-clear-btn").addEventListener("click", () => {
  if (!graphData) return;
  const all = graphData.stats.protocols || [];
  const selectAll = activeProtos.size < all.length;
  activeProtos.clear();
  if (selectAll) all.forEach(p => activeProtos.add(p));
  document.querySelectorAll("#proto-filters input[type=checkbox]").forEach(cb => { cb.checked = selectAll; });
  saveFilterState(); updateFilterUI(); applyFilters();
  if (currentView === "table") renderConnTable();
});
document.getElementById("type-clear-btn").addEventListener("click", () => {
  if (!graphData) return;
  const all = graphData.stats.host_types || [];
  const selectAll = activeTypes.size < all.length;
  activeTypes.clear();
  if (selectAll) all.forEach(t => activeTypes.add(t));
  document.querySelectorAll("#type-filters input[type=checkbox]").forEach(cb => { cb.checked = selectAll; });
  saveFilterState(); updateFilterUI(); applyFilters();
  if (currentView === "table") renderConnTable();
});
document.getElementById("vlan-clear-btn").addEventListener("click", () => {
  if (!graphData) return;
  const allVlans = (graphData.stats.vlans || []).map(String);
  if ((graphData.nodes || []).some(n => n.vlan_untagged)) allVlans.push("untagged");
  const selectAll = activeVlans.size < allVlans.length;
  activeVlans.clear();
  if (selectAll) allVlans.forEach(v => activeVlans.add(v));
  document.querySelectorAll("#vlan-filters input[type=checkbox]").forEach(cb => { cb.checked = selectAll; });
  updateFilterUI(); applyFilters();
  if (currentView === "table") renderConnTable();
});
document.getElementById("ipver-clear-btn").addEventListener("click", () => {
  if (!graphData) return;
  const all = (graphData.stats.ip_versions || []).map(String);
  const selectAll = activeIpVersions.size < all.length;
  activeIpVersions.clear();
  if (selectAll) all.forEach(v => activeIpVersions.add(v));
  document.querySelectorAll("#ipver-filters input[type=checkbox]").forEach(cb => { cb.checked = selectAll; });
  updateFilterUI(); applyFilters();
  if (currentView === "table") renderConnTable();
});

function clearAllFilters() {
  if (!graphData) return;
  searchBox.value = "";
  searchTerm = "";
  activeProtos.clear();
  (graphData.stats.protocols || []).forEach(p => activeProtos.add(p));
  activeTypes.clear();
  (graphData.stats.host_types || []).forEach(t => activeTypes.add(t));
  activeVlans.clear();
  (graphData.stats.vlans || []).map(String).forEach(v => activeVlans.add(v));
  if ((graphData.nodes || []).some(n => n.vlan_untagged)) activeVlans.add("untagged");
  activeIpVersions.clear();
  (graphData.stats.ip_versions || []).map(String).forEach(v => activeIpVersions.add(v));
  document.querySelectorAll("#proto-filters input[type=checkbox]").forEach(cb  => { cb.checked = true; });
  document.querySelectorAll("#type-filters input[type=checkbox]").forEach(cb   => { cb.checked = true; });
  document.querySelectorAll("#vlan-filters input[type=checkbox]").forEach(cb   => { cb.checked = true; });
  document.querySelectorAll("#ipver-filters input[type=checkbox]").forEach(cb  => { cb.checked = true; });
  updateFilterUI();
  applyFilters();
  if (currentView === "table") renderConnTable();
}
document.getElementById("clear-filters-btn").addEventListener("click", clearAllFilters);
document.getElementById("header-clear-filters-btn").addEventListener("click", clearAllFilters);

document.getElementById("no-results-clear").addEventListener("click", () => {
  document.getElementById("clear-filters-btn").click();
});

function applyFilters(skipFit) {
  if (!graphData) return;

  // Compute isolate-mode neighbour set
  let isolateSet = null;
  if (isolatedNodeIp) {
    isolateSet = new Set([isolatedNodeIp]);
    (graphData.edges || []).forEach(e => {
      if (e.source === isolatedNodeIp) isolateSet.add(e.target);
      if (e.target === isolatedNodeIp) isolateSet.add(e.source);
    });
  }

  const visibleNodeIds = new Set();
  const vlanFilterActive  = _allVlans.length > 0 && activeVlans.size < _allVlans.length;
  const ipVerFilterActive = _allIpVers.length > 1 && activeIpVersions.size < _allIpVers.length;
  nodesGroup.selectAll(".node").each(function(d) {
    const vlanOk    = !vlanFilterActive ||
      (d.vlans || []).some(v => activeVlans.has(String(v))) ||
      (d.vlan_untagged && activeVlans.has("untagged"));
    const ipVerOk   = !ipVerFilterActive || activeIpVersions.has(String(d.ip_version || 4));
    const tlOk      = !_tlVisibleIps || _tlVisibleIps.has(d.ip);
    const isolateOk = !isolateSet || isolateSet.has(d.ip);
    const visible   = activeTypes.has(d.host_type) && vlanOk && ipVerOk && tlOk && isolateOk &&
      (!searchTerm || d.ip.includes(searchTerm) ||
       (d.hostname && d.hostname.toLowerCase().includes(searchTerm)));
    const el = d3.select(this);
    el.classed("faded",      !visible);
    el.classed("isolated",   d.ip === isolatedNodeIp);
    el.classed("anom-faded", highlightAnomsMode && !anomalyNodeIps[d.ip]);
    if (visible) visibleNodeIds.add(d.id);
  });
  _visibleNodeIds = visibleNodeIds;

  linksGroup.selectAll(".link").each(function(d) {
    const protoOk = !(d.protocols && d.protocols.length) ||
                    (d.protocols || []).some(p => activeProtos.has(p));
    const sid = d.source.id || d.source;
    const tid = d.target.id || d.target;
    const visible = protoOk && visibleNodeIds.has(sid) && visibleNodeIds.has(tid);
    d3.select(this).classed("faded", !visible);
  });

  // Sync edge-label faded state with their links
  linksGroup.selectAll(".edge-label").each(function(d) {
    const sid = typeof d.source === "object" ? d.source.id : d.source;
    const tid = typeof d.target === "object" ? d.target.id : d.target;
    d3.select(this).classed("faded", !visibleNodeIds.has(sid) || !visibleNodeIds.has(tid));
  });

  if (useCanvasEdges) drawCanvasEdges();

  // Zero-results feedback — message distinguishes filter type.
  // Special case: if a search term matches nodes in the full dataset but none are
  // rendered (they were capped out), suppress the "no match" overlay and toast instead.
  const noResults = document.getElementById("no-results-msg");
  const noResultsText = document.getElementById("no-results-text");
  if (visibleNodeIds.size === 0 && !!graphData && searchTerm) {
    const cappedMatch = (graphData.nodes || []).some(n =>
      n.ip.includes(searchTerm) || (n.hostname && n.hostname.toLowerCase().includes(searchTerm)));
    if (cappedMatch) {
      if (noResults) noResults.classList.remove("visible");
      showToast(`"${searchTerm}" is outside the rendered top-${RENDER_NODE_CAP} hosts — visible in Table view and exports.`, "info", 6000);
    } else {
      if (noResults) noResults.classList.add("visible");
      if (noResultsText) noResultsText.textContent = "No hosts match the current filters";
    }
  } else {
    if (noResults) noResults.classList.toggle("visible", visibleNodeIds.size === 0 && !!graphData);
    if (noResultsText) {
      noResultsText.textContent = (isolatedNodeIp && visibleNodeIds.size === 0)
        ? "No neighbours found"
        : (_tlVisibleIps !== null && visibleNodeIds.size === 0)
        ? "No activity in this time window"
        : "No hosts match the current filters";
    }
  }

  // Fit viewport to visible nodes (debounced so it doesn't fire during simulation).
  // Compare against the rendered count (not full graphData.nodes.length) so that under
  // the render cap the fit doesn't trigger on every filter cycle.
  const _renderedCount = nodesGroup.selectAll(".node").size();
  if (!skipFit && visibleNodeIds.size > 0 && visibleNodeIds.size < _renderedCount) {
    clearTimeout(applyFilters._fitTimer);
    applyFilters._fitTimer = setTimeout(zoomFitVisible, 300);
  }

  if (otMatrixMode) renderOTMatrix(graphData);
}

function zoomFitVisible() {
  // Compute bounding box of non-faded nodes only
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  nodesGroup.selectAll(".node:not(.faded)").each(function(d) {
    if (d.x == null || d.y == null) return;
    minX = Math.min(minX, d.x); minY = Math.min(minY, d.y);
    maxX = Math.max(maxX, d.x); maxY = Math.max(maxY, d.y);
  });
  if (!isFinite(minX)) return;
  const padding = 60;
  const svgEl = svg.node();
  const w = svgEl.clientWidth, h = svgEl.clientHeight;
  const bw = maxX - minX || 1, bh = maxY - minY || 1;
  const scale = Math.min((w - padding * 2) / bw, (h - padding * 2) / bh, 3);
  const tx = w / 2 - scale * (minX + bw / 2);
  const ty = h / 2 - scale * (minY + bh / 2);
  svg.transition().duration(500)
    .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

/* ── Anomaly sidebar ─────────────────────────────────────────────────────── */
function buildAnomalySidebar(anomalies) {
  const section = document.getElementById("anomaly-section");
  const list = document.getElementById("anomaly-list");
  list.innerHTML = "";

  if (!anomalies || anomalies.length === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "";

  // Stage 1: build ip → worst-severity lookup (drives graph node rings)
  anomalyNodeIps = {};
  const sevOrder = { high: 3, medium: 2, low: 1 };
  anomalies.forEach(a => {
    [a.src, a.dst].filter(Boolean).forEach(ip => {
      const cur = anomalyNodeIps[ip];
      if (!cur || sevOrder[a.severity] > sevOrder[cur]) anomalyNodeIps[ip] = a.severity;
    });
  });

  // Stage 2: group by type+src (collapse repeated instances of the same rule from same host)
  const groups = new Map();
  anomalies.forEach(a => {
    const key = `${a.type}|${a.src || ""}`;
    if (!groups.has(key)) groups.set(key, { rep: a, items: [] });
    groups.get(key).items.push(a);
  });

  // Stage 3: organise groups into semantic families then render
  const typeToFamily = {};
  ANOMALY_FAMILIES.forEach(f => f.types.forEach(t => { typeToFamily[t] = f; }));

  const familyBuckets = new Map();  // family.id → { family, groups[] }
  const otherGroups   = [];

  groups.forEach(({ rep, items }) => {
    const fam = typeToFamily[rep.type];
    if (fam) {
      if (!familyBuckets.has(fam.id)) familyBuckets.set(fam.id, { family: fam, groups: [] });
      familyBuckets.get(fam.id).groups.push({ rep, items });
    } else {
      otherGroups.push({ rep, items });
    }
  });

  // Update count badge
  const countBadge = document.getElementById("anomaly-count-badge");
  if (countBadge) countBadge.textContent = anomalies.length;

  // Render in ANOMALY_FAMILIES declaration order (preserves logical sequence)
  ANOMALY_FAMILIES.forEach(fam => {
    const bucket = familyBuckets.get(fam.id);
    if (bucket) list.appendChild(_renderFamilyGroup(bucket.family, bucket.groups));
  });

  if (otherGroups.length) {
    list.appendChild(_renderFamilyGroup({ id: "other", label: "Other", icon: "…" }, otherGroups));
  }
}

// Renders a collapsible family header wrapping its per-type sub-groups
function _renderFamilyGroup(family, groups) {
  const sevOrder = { high: 3, medium: 2, low: 1 };
  let worstSev = "low", totalCount = 0;
  groups.forEach(({ items }) => {
    totalCount += items.length;
    items.forEach(a => {
      if ((sevOrder[a.severity] || 0) > (sevOrder[worstSev] || 0)) worstSev = a.severity;
    });
  });

  const famDiv = document.createElement("div");
  famDiv.className = "ab-family";

  const header = document.createElement("div");
  header.className = "ab-family-header";
  header.innerHTML = `
    <span class="ab-family-icon">${family.icon || ""}</span>
    <span class="ab-family-title">${escHtml(family.label)}</span>
    <span class="ab-sev ${worstSev}">${worstSev}</span>
    <span class="ab-family-count">×${totalCount}</span>
    <span class="ab-family-toggle">▾</span>
  `;

  const body = document.createElement("div");
  body.className = "ab-family-body";
  groups.forEach(({ rep, items }) => body.appendChild(_renderTypeGroup(rep, items)));

  famDiv.appendChild(header);
  famDiv.appendChild(body);

  let open = true;
  header.addEventListener("click", () => {
    open = !open;
    body.classList.toggle("hidden", !open);
    header.querySelector(".ab-family-toggle").textContent = open ? "▾" : "▸";
  });

  return famDiv;
}

// Renders a single type+src group badge with optional expand button for multiple instances
function _renderTypeGroup(rep, items) {
  const count   = items.length;
  const summary = count > 1
    ? _anomalySummary(rep.type, rep.src, count, items)
    : rep.description;

  const div = document.createElement("div");
  div.className = `anomaly-badge ${rep.severity}`;

  const infoBtn = document.createElement("button");
  infoBtn.className = "ab-info";
  infoBtn.title = "What is this?";
  infoBtn.textContent = "ℹ";

  if (count > 1) {
    div.innerHTML = `
      <span class="ab-sev ${rep.severity}">${rep.severity}</span>
      <span class="ab-desc">${escHtml(summary)}</span>
      <button class="ab-expand" aria-label="Expand">▾ ${count}</button>
      <button class="ab-review" aria-label="Review finding">Review</button>
    `;
    div.appendChild(infoBtn);
    const expandBtn = div.querySelector(".ab-expand");
    let expanded = false;
    const childList = document.createElement("div");
    childList.className = "ab-children hidden";
    items.forEach(a => {
      const child = document.createElement("div");
      child.className = "ab-child";
      child.textContent = a.description;
      child.addEventListener("click", e => { e.stopPropagation(); _jumpToAnomaly(a); });
      childList.appendChild(child);
    });
    div.appendChild(childList);
    expandBtn.addEventListener("click", e => {
      e.stopPropagation();
      expanded = !expanded;
      childList.classList.toggle("hidden", !expanded);
      expandBtn.textContent = (expanded ? "▴" : "▾") + " " + count;
    });
  } else {
    div.innerHTML = `
      <span class="ab-sev ${rep.severity}">${rep.severity}</span>
      <span class="ab-desc">${escHtml(summary)}</span>
      <button class="ab-review" aria-label="Review finding">Review</button>
    `;
    div.appendChild(infoBtn);
  }

  const reviewBtn = div.querySelector(".ab-review");
  if (reviewBtn) {
    reviewBtn.addEventListener("click", e => {
      e.stopPropagation();
      const findingId = _findingId("anom", [rep.type || "", rep.src || "", rep.dst || "", rep.description || ""]);
      openFindingById(findingId);
    });
  }

  // Explanation panel (C1)
  const exp = ANOMALY_EXPLANATIONS[rep.type];
  if (exp) {
    const panel = document.createElement("div");
    panel.className = "ab-explain hidden";
    panel.innerHTML = `
      <div class="ab-explain-what"><strong>What:</strong> ${escHtml(exp.what)}</div>
      <div class="ab-explain-why"><strong>Why:</strong> ${escHtml(exp.why)}</div>
      <div class="ab-explain-steps"><strong>Steps:</strong><ol>${exp.steps.map(s => `<li>${escHtml(s)}</li>`).join("")}</ol></div>
    `;
    panel.addEventListener("click", e => e.stopPropagation());
    div.appendChild(panel);
    infoBtn.addEventListener("click", e => {
      e.stopPropagation();
      panel.classList.toggle("hidden");
      infoBtn.classList.toggle("active", !panel.classList.contains("hidden"));
    });
  } else {
    infoBtn.style.display = "none";
  }

  div.addEventListener("click", () => _jumpToAnomaly(rep));
  return div;
}

/* ── Credentials sidebar ─────────────────────────────────────────────────── */
function buildCredentialsSidebar(creds) {
  const section = document.getElementById("cred-section");
  const list    = document.getElementById("cred-list");
  const badge   = document.getElementById("cred-badge");
  const filterBar = document.getElementById("cred-filter-bar");
  list.innerHTML = "";
  filterBar.innerHTML = "";

  credIpSet = new Set();
  (creds || []).forEach(c => {
    if (c.src) credIpSet.add(c.src);
    if (c.dst) credIpSet.add(c.dst);
  });

  if (!creds || creds.length === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "";
  badge.textContent = creds.length;

  // Build protocol filter buttons
  const protos = [...new Set(creds.map(c => c.protocol))].sort();
  const activeProtoFilter = new Set(protos);

  function renderCredList() {
    list.innerHTML = "";
    const visible = creds.filter(c => activeProtoFilter.has(c.protocol));
    if (visible.length === 0) {
      list.innerHTML = '<div style="color:var(--text2);font-size:11px;padding:4px 0">No credentials match filter</div>';
      return;
    }
    visible.forEach(c => {
      const card = document.createElement("div");
      card.className = "cred-card";
      const protoClass = (c.protocol || "").toLowerCase();
      const ts = c.rel_time != null ? `+${c.rel_time}s` : "";
      const pwId = `pw-${Math.random().toString(36).slice(2)}`;
      card.innerHTML = `
        <div>
          <span class="cred-proto ${protoClass}">${escHtml(c.protocol)}</span>
          <span class="cred-type" style="color:var(--text2);font-size:10px">${escHtml(c.type || "")}</span>
          <span style="float:right;color:var(--text2);font-size:10px">${ts}</span>
        </div>
        <div class="cred-route" style="margin-top:2px">${escHtml(c.src)} → ${escHtml(c.dst)}${c.dport ? ':' + escHtml(String(c.dport)) : ''}</div>
        <div style="margin-top:3px">
          <span class="cred-user">${escHtml(c.username || "(no user)")}</span>
          <span style="color:var(--text2);margin:0 4px">/</span>
          <span class="cred-pw" id="${pwId}">●●●●●●</span>
          <button class="cred-reveal" data-pw="${escHtml(c.password || "")}" data-id="${pwId}" title="Reveal password">show</button>
        </div>`;
      card.querySelector(".cred-reveal").addEventListener("click", function() {
        const el = document.getElementById(this.dataset.id);
        if (this.textContent === "show") {
          el.textContent = this.dataset.pw || "(empty)";
          this.textContent = "hide";
        } else {
          el.textContent = "●●●●●●";
          this.textContent = "show";
        }
      });
      list.appendChild(card);
    });
  }

  protos.forEach(proto => {
    const btn = document.createElement("button");
    btn.className = "cred-filter-btn active";
    btn.textContent = proto;
    btn.addEventListener("click", () => {
      if (activeProtoFilter.has(proto)) {
        activeProtoFilter.delete(proto);
        btn.classList.remove("active");
      } else {
        activeProtoFilter.add(proto);
        btn.classList.add("active");
      }
      renderCredList();
    });
    filterBar.appendChild(btn);
  });

  renderCredList();
}

/* ── File transfers sidebar ───────────────────────────────────────────────── */
function buildFilesSidebar(files) {
  const section = document.getElementById("files-section");
  const list    = document.getElementById("files-list");
  const badge   = document.getElementById("files-badge");
  list.innerHTML = "";

  if (!files || files.length === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "";
  badge.textContent = files.length;

  files.forEach(f => {
    const card = document.createElement("div");
    card.className = "file-card";
    const ts = f.rel_time != null ? `+${f.rel_time}s` : "";
    const size = f.size != null ? _fmtBytes(f.size) : "?";
    const mime = f.mime_type || "application/octet-stream";
    const filename = f.filename || "file";
    const sha256 = f.sha256 || "";
    card.innerHTML = `
      <div class="file-name" title="${escHtml(filename)}">${escHtml(filename)}</div>
      <div class="file-meta">
        <span class="file-mime">${escHtml(mime)}</span>
        <span class="file-size">${size}</span>
        <span style="margin-left:auto;color:var(--text2);font-size:10px">${ts}</span>
        <button class="file-dl-btn" data-file-sha="${escHtml(sha256)}" data-file-name="${escHtml(filename)}" title="Download captured file">⬇</button>
      </div>
      <div class="file-route">${escHtml(f.src)} → ${escHtml(f.dst)}</div>
      <div class="file-hash" title="SHA-256">${escHtml(sha256)}${sha256 ? ` ${copyButton(sha256, "Copy SHA-256")}` : ""}</div>`;
    list.appendChild(card);
  });
}

function _fmtBytes(n) {
  if (n == null) return "?";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

function downloadFile(sha256, filename) {
  fetch(`/download/${sha256}`)
    .then(r => {
      if (!r.ok) {
        return r.json().catch(() => ({})).then(j =>
          showToast(j.error || `Download failed (${r.status})`, "error")
        );
      }
      return r.blob().then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
      });
    })
    .catch(err => showToast("Download failed: " + err.message, "error"));
}

function _anomalySummary(type, src, count, items) {
  const s = src || "?";
  switch (type) {
    // Network
    case "port_scan":            return `Port scan from ${s} → ${count} target${count > 1 ? "s" : ""}`;
    case "beaconing":            return `Beaconing from ${s} to ${count} destination${count > 1 ? "s" : ""}`;
    case "exfiltration":         return `Data exfiltration from ${s} (${count} connection${count > 1 ? "s" : ""})`;
    case "suspicious_port":      return `Suspicious ports on ${s} (${count})`;
    case "dns_tunneling":        return `DNS tunneling suspected from ${s} (${count} query${count > 1 ? " sets" : ""})`;
    // Credentials & TLS
    case "cleartext_credentials": return `Cleartext credentials on ${count} connection${count > 1 ? "s" : ""}`;
    case "password_reuse":       return `Password reused across ${count} service${count > 1 ? "s" : ""}`;
    case "unusual_ja3":          return `Suspicious TLS fingerprint from ${s} (${count})`;
    // OT / ICS
    case "ot_modbus_write":      return `Modbus writes from ${s} (${count} command${count > 1 ? "s" : ""})`;
    case "ot_modbus_bulk_read":  return `Modbus bulk reads from ${s} (${count})`;
    case "ot_modbus_broadcast":  return `Modbus broadcast from ${s} (${count})`;
    case "ot_modbus_exception":  return `Modbus exceptions from ${s} (${count})`;
    case "ot_multiunit_poll":    return `Multi-unit Modbus polling from ${s} (${count} units)`;
    case "ot_dnp3_control":      return `DNP3 control commands from ${s} (${count})`;
    case "ot_dnp3_unusual_fc":   return `DNP3 unusual function codes from ${s} (${count})`;
    case "ot_s7_critical":       return `S7 critical commands from ${s} (${count})`;
    case "ot_s7_write":          return `S7 write operations from ${s} (${count})`;
    case "ot_s7_code_download":  return `S7 code download from ${s} (${count} block${count > 1 ? "s" : ""})`;
    case "ot_enip_write":        return `EtherNet/IP writes from ${s} (${count})`;
    case "ot_iec104_command":    return `IEC-104 commands from ${s} (${count})`;
    case "ot_bacnet_write":      return `BACnet writes from ${s} (${count})`;
    case "ot_internet_exposure": return `OT device exposed to internet (${count} connection${count > 1 ? "s" : ""})`;
    case "ot_cleartext":         return `Cleartext OT protocol from ${s} (${count})`;
    // IoT
    case "iot_mqtt_cleartext":   return `Cleartext MQTT from ${s} (${count} connection${count > 1 ? "s" : ""})`;
    case "iot_telnet":           return `Telnet to IoT device ${s} (${count})`;
    case "iot_camera_exfil":     return `IP camera ${s} sending to external (${count})`;
    case "iot_tr069":            return `TR-069 remote management on ${s} (${count})`;
    // VLAN
    case "vlan_hopping":         return `VLAN hopping: ${count} host${count > 1 ? "s" : ""} on multiple VLANs`;
    case "vlan_native_leak":     return `Native VLAN leakage from ${s} (${count})`;
    case "vlan_qinq":            return `QinQ double-tagging from ${s} (${count})`;
    case "vlan_cross_segment_ot": return `Cross-VLAN OT traffic (${count} violation${count > 1 ? "s" : ""})`;
    case "arp_spoofing":         return `ARP spoofing: ${count} IP conflict${count > 1 ? "s" : ""} detected`;
    case "broadcast_storm":      return `Broadcast storm: ${count} VLAN${count > 1 ? "s" : ""} affected`;
    case "pcp_abuse":            return `PCP priority abuse from ${s} (${count})`;
    default:
      return `${type.replace(/_/g, " ")} — ${count} instance${count > 1 ? "s" : ""}`;
  }
}

const FINDING_STATUSES = ["Open", "Investigating", "False Positive", "Accepted Risk", "Resolved"];
const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"];
const FINDING_SOURCE_LABELS = {
  anomaly: "Anomaly",
  credential: "Credential",
  file_transfer: "File",
  ot_command: "OT Command",
  risk_host: "Risk Host",
};

function _hashString(str) {
  let h = 2166136261;
  const s = String(str == null ? "" : str);
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

function _normalizeSeverity(sev) {
  const s = String(sev || "info").toLowerCase();
  return FINDING_SEVERITIES.includes(s) ? s : "info";
}

function _severityRank(sev) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[_normalizeSeverity(sev)] || 0;
}

function _captureFingerprint(data) {
  const s = data?.stats || {};
  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  const anoms = data?.anomalies || [];
  const sampleNodes = nodes.slice(0, 12).map(n => n.id || n.ip || "").join(",");
  const sampleEdges = edges.slice(0, 8).map(e => `${e.source || ""}>${e.target || ""}:${e.packet_count || 0}`).join(",");
  return _hashString([
    s.total_packets || 0,
    s.total_hosts || nodes.length,
    s.total_connections || edges.length,
    anoms.length,
    sampleNodes,
    sampleEdges,
  ].join("|"));
}

function _findingStorageKey() {
  return currentCaptureKey ? `pv_findings:${currentCaptureKey}` : "";
}

function _findingId(prefix, parts) {
  return `${prefix}:${_hashString(parts.join("|"))}`;
}

function _findingTitleFromAnomaly(a) {
  return _anomalySummary(a.type || "anomaly", a.src || a.dst || "", 1, [a]);
}

function _routeText(src, dst) {
  return [src, dst].filter(Boolean).join(" -> ");
}

function _baseFinding(fields) {
  const severity = _normalizeSeverity(fields.severity);
  return Object.assign({
    id: "",
    source_type: "anomaly",
    title: "Finding",
    severity,
    source_severity: severity,
    status: "Open",
    analyst_note: "",
    evidence_refs: [],
    include_in_report: true,
    description: "",
    route: "",
    created_from: {},
  }, fields);
}

function _deriveAnomalyFindings(data) {
  return (data.anomalies || []).map(a => _baseFinding({
    id: _findingId("anom", [a.type || "", a.src || "", a.dst || "", a.description || ""]),
    source_type: "anomaly",
    title: _findingTitleFromAnomaly(a),
    severity: a.severity || "low",
    source_severity: a.severity || "low",
    description: a.description || "",
    route: _routeText(a.src, a.dst),
    evidence_refs: [
      { type: "anomaly", label: a.type || "anomaly", description: a.description || "" },
      ...(a.src ? [{ type: "host", label: `Source ${a.src}`, ip: a.src }] : []),
      ...(a.dst ? [{ type: "host", label: `Destination ${a.dst}`, ip: a.dst }] : []),
    ],
    created_from: { type: "anomaly", anomaly: a },
  }));
}

function _deriveCredentialFindings(data) {
  return (data.credentials || []).map(c => _baseFinding({
    id: _findingId("cred", [c.protocol || "", c.type || "", c.src || "", c.dst || "", c.dport || "", c.username || "", c.password || ""]),
    source_type: "credential",
    title: `${c.protocol || "Cleartext"} credential captured${c.username ? " for " + c.username : ""}`,
    severity: "high",
    source_severity: "high",
    description: `${c.type || "Credential"} observed in cleartext traffic.`,
    route: _routeText(c.src, c.dst),
    evidence_refs: [
      { type: "credential", label: `${c.protocol || "Credential"} ${c.username || "(no user)"}`, username: c.username || "", protocol: c.protocol || "" },
      ...(c.src ? [{ type: "host", label: `Source ${c.src}`, ip: c.src }] : []),
      ...(c.dst ? [{ type: "host", label: `Destination ${c.dst}`, ip: c.dst }] : []),
    ],
    created_from: { type: "credential", credential: c },
  }));
}

function _deriveFileFindings(data) {
  return (data.files || []).map(f => _baseFinding({
    id: _findingId("file", [f.sha256 || "", f.filename || "", f.src || "", f.dst || ""]),
    source_type: "file_transfer",
    title: `File transfer: ${f.filename || "unnamed file"}`,
    severity: "medium",
    source_severity: "medium",
    description: `${f.mime_type || "application/octet-stream"} transfer, ${_fmtBytes(f.size)}.`,
    route: _routeText(f.src, f.dst),
    evidence_refs: [
      { type: "file", label: f.filename || "file", sha256: f.sha256 || "", mime_type: f.mime_type || "" },
      ...(f.src ? [{ type: "host", label: `Source ${f.src}`, ip: f.src }] : []),
      ...(f.dst ? [{ type: "host", label: `Destination ${f.dst}`, ip: f.dst }] : []),
    ],
    created_from: { type: "file_transfer", file: f },
  }));
}

function _deriveOtCommandFindings(data) {
  const groups = new Map();
  (data.ot_commands || [])
    .filter(c => c.direction === "write" || c.direction === "error")
    .forEach(c => {
      const key = [c.protocol || "", c.direction || "", c.src || "", c.dst || "", c.function_name || c.function_code || ""].join("|");
      if (!groups.has(key)) {
        groups.set(key, { sample: c, count: 0, first: c.rel_time, last: c.rel_time });
      }
      const g = groups.get(key);
      g.count += 1;
      if (c.rel_time != null) {
        if (g.first == null || c.rel_time < g.first) g.first = c.rel_time;
        if (g.last == null || c.rel_time > g.last) g.last = c.rel_time;
      }
    });

  return [...groups.values()].map(g => {
    const c = g.sample;
    const fn = c.function_name || (c.function_code != null ? `FC${c.function_code}` : "command");
    return _baseFinding({
      id: _findingId("otcmd", [c.protocol || "", c.direction || "", c.src || "", c.dst || "", fn]),
      source_type: "ot_command",
      title: `${c.protocol || "OT"} ${c.direction} ${fn}`,
      severity: c.direction === "write" ? "high" : "medium",
      source_severity: c.direction === "write" ? "high" : "medium",
      description: `${g.count} ${c.direction} event${g.count !== 1 ? "s" : ""}${g.first != null ? ` from +${g.first}s to +${g.last}s` : ""}.`,
      route: _routeText(c.src, c.dst),
      evidence_refs: [
        { type: "ot_command", label: `${c.protocol || "OT"} ${fn}`, count: g.count, direction: c.direction || "" },
        ...(c.src ? [{ type: "host", label: `Source ${c.src}`, ip: c.src }] : []),
        ...(c.dst ? [{ type: "host", label: `Destination ${c.dst}`, ip: c.dst }] : []),
      ],
      created_from: { type: "ot_command", command: c, count: g.count },
    });
  });
}

function _deriveRiskHostFindings(data) {
  return (data.nodes || [])
    .filter(n => (n.risk_score || 0) >= 70)
    .map(n => _baseFinding({
      id: _findingId("riskhost", [n.id || n.ip || "", n.risk_score || 0]),
      source_type: "risk_host",
      title: `High-risk host ${n.ip || n.id}`,
      severity: "high",
      source_severity: "high",
      description: `Risk score ${n.risk_score || 0}/100 for ${n.host_type || "Unknown Host"}.`,
      route: n.ip || n.id || "",
      evidence_refs: [
        { type: "risk", label: `Risk ${n.risk_score || 0}/100`, score: n.risk_score || 0 },
        { type: "host", label: n.ip || n.id || "", ip: n.ip || n.id || "" },
      ],
      created_from: { type: "risk_host", node_id: n.id || n.ip || "" },
    }));
}

function deriveFindings(data) {
  return [
    ..._deriveAnomalyFindings(data),
    ..._deriveCredentialFindings(data),
    ..._deriveFileFindings(data),
    ..._deriveOtCommandFindings(data),
    ..._deriveRiskHostFindings(data),
  ].sort((a, b) => _severityRank(b.severity) - _severityRank(a.severity) || a.title.localeCompare(b.title));
}

function _loadFindingOverrides() {
  const key = _findingStorageKey();
  if (!key) return [];
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : [];
  } catch (_) {
    return [];
  }
}

function _mergeFindingEdits(base, edits) {
  const byId = new Map(base.map(f => [f.id, Object.assign({}, f)]));
  (edits || []).forEach(edit => {
    if (!edit || !edit.id) return;
    const cur = byId.get(edit.id) || _baseFinding({ id: edit.id, title: edit.title || "Saved finding", source_type: edit.source_type || "anomaly" });
    ["status", "severity", "analyst_note", "include_in_report", "title", "description", "route", "source_type", "source_severity", "evidence_refs", "created_from"].forEach(k => {
      if (edit[k] !== undefined) cur[k] = edit[k];
    });
    cur.severity = _normalizeSeverity(cur.severity);
    cur.status = FINDING_STATUSES.includes(cur.status) ? cur.status : "Open";
    cur.include_in_report = cur.include_in_report !== false;
    byId.set(edit.id, cur);
  });
  return [...byId.values()].sort((a, b) => _severityRank(b.severity) - _severityRank(a.severity) || a.title.localeCompare(b.title));
}

function initializeFindings(data) {
  currentCaptureKey = _captureFingerprint(data);
  const base = deriveFindings(data);
  const sessionFindings = Array.isArray(data.findings) ? data.findings : [];
  findings = _mergeFindingEdits(base, sessionFindings);
  findings = _mergeFindingEdits(findings, _loadFindingOverrides());
  findingsById = new Map(findings.map(f => [f.id, f]));
  data.findings = findings;
}

function _findingEditableSnapshot(f) {
  return {
    id: f.id,
    status: f.status,
    severity: f.severity,
    analyst_note: f.analyst_note || "",
    include_in_report: f.include_in_report !== false,
  };
}

function persistFindings() {
  findingsById = new Map(findings.map(f => [f.id, f]));
  if (graphData) graphData.findings = findings;
  const key = _findingStorageKey();
  if (!key) return;
  try {
    localStorage.setItem(key, JSON.stringify(findings.map(_findingEditableSnapshot)));
  } catch (_) {
    showToast("Finding edits could not be saved in local storage.", "warn", 5000);
  }
}

function updateFinding(id, patch) {
  const f = findingsById.get(id);
  if (!f) return;
  Object.assign(f, patch);
  f.severity = _normalizeSeverity(f.severity);
  f.status = FINDING_STATUSES.includes(f.status) ? f.status : "Open";
  if (f.status === "False Positive") f.include_in_report = false;
  persistFindings();
  if (currentView === "findings") renderFindingsWorkspace();
}

function _findingStatusVisible(f) {
  if (findingFilters.status === "all") return true;
  if (findingFilters.status === "active") return f.status !== "False Positive" && f.status !== "Resolved";
  return f.status === findingFilters.status;
}

function _findingEvidenceLabel(ref) {
  if (!ref) return "";
  if (ref.type === "host") return ref.label || ref.ip || "Host";
  if (ref.type === "anomaly") return `${ref.label || "Anomaly"}${ref.description ? ": " + ref.description : ""}`;
  if (ref.type === "credential") return `${ref.label || "Credential"}${ref.protocol ? " via " + ref.protocol : ""}`;
  if (ref.type === "file") return `${ref.label || "File"}${ref.sha256 ? " sha256=" + ref.sha256 : ""}`;
  if (ref.type === "ot_command") return `${ref.label || "OT command"}${ref.count ? " x" + ref.count : ""}`;
  if (ref.type === "risk") return ref.label || "Risk score";
  return ref.label || ref.type || "Evidence";
}

function findingEvidenceBundle(f) {
  const lines = [
    `Finding: ${f.title}`,
    `Severity: ${f.severity}`,
    `Status: ${f.status}`,
    `Source: ${FINDING_SOURCE_LABELS[f.source_type] || f.source_type}`,
  ];
  if (f.route) lines.push(`Route: ${f.route}`);
  if (f.description) lines.push(`Description: ${f.description}`);
  if (f.analyst_note) lines.push(`Analyst note: ${f.analyst_note}`);
  if ((f.evidence_refs || []).length) {
    lines.push("Evidence:");
    (f.evidence_refs || []).forEach(ref => lines.push(`- ${_findingEvidenceLabel(ref)}`));
  }
  return lines.join("\n");
}

function _openHostEvidence(ip, label) {
  if (!graphData || !ip) return;
  const node = (graphData.nodes || []).find(n => n.ip === ip || n.id === ip);
  if (!node) {
    showToast(`Host ${ip} is not available in this capture.`, "warn");
    return;
  }
  selectedNode = node;
  showDetailPanel(node, { from: "finding", label: label || "finding" });
  detailPanel.classList.add("open");
  setView("graph");
  if (_isRendered(node.id)) {
    const linkSel = linksGroup.selectAll(".link");
    const nodeSel = nodesGroup.selectAll(".node");
    nodeSel.classed("selected", n => n.id === node.id);
    highlightNode(node, linkSel, nodeSel);
  } else {
    showToast(`${node.ip} is outside the rendered top ${RENDER_NODE_CAP.toLocaleString()} hosts - details shown in the side panel.`, "info", 6000);
  }
}

function openFindingEvidence(id) {
  const f = findingsById.get(id);
  if (!f) return;
  const src = f.created_from || {};
  if (src.type === "anomaly" && src.anomaly) {
    _jumpToAnomaly(src.anomaly);
    return;
  }
  if (src.type === "credential" && src.credential) {
    _openHostEvidence(src.credential.src || src.credential.dst, "credential");
    return;
  }
  if (src.type === "file_transfer" && src.file) {
    _openHostEvidence(src.file.src || src.file.dst, "file transfer");
    return;
  }
  if (src.type === "ot_command" && src.command) {
    const c = src.command;
    if (c.src && c.dst) {
      setView("graph");
      openPktInspector(c.src, c.dst);
    }
    _openHostEvidence(c.src || c.dst, "OT command");
    return;
  }
  const hostRef = (f.evidence_refs || []).find(ref => ref.type === "host" && ref.ip);
  if (hostRef) _openHostEvidence(hostRef.ip, f.title);
}

function openFindingById(id) {
  if (!findingsById.has(id)) {
    showToast("No linked finding was found for this item.", "warn");
    return;
  }
  findingFilters.status = "all";
  findingFilters.severity = "all";
  findingFilters.source = "all";
  setView("findings");
  setTimeout(() => {
    const row = document.querySelector(`[data-finding-id="${CSS.escape(id)}"]`);
    if (!row) return;
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    row.classList.add("finding-flash");
    setTimeout(() => row.classList.remove("finding-flash"), 1400);
  }, 0);
}

function _findingOptions(values, selected, labels) {
  return values.map(v => `<option value="${escHtml(v)}"${v === selected ? " selected" : ""}>${escHtml(labels?.[v] || v)}</option>`).join("");
}

function renderFindingsWorkspace() {
  const view = document.getElementById("findings-view");
  if (!view) return;
  if (!graphData) {
    view.innerHTML = '<div class="findings-empty">No capture loaded</div>';
    return;
  }

  const sourceTypes = [...new Set(findings.map(f => f.source_type))].sort();
  const visible = findings.filter(f =>
    _findingStatusVisible(f) &&
    (findingFilters.severity === "all" || f.severity === findingFilters.severity) &&
    (findingFilters.source === "all" || f.source_type === findingFilters.source)
  );
  const reportCount = findings.filter(f => f.include_in_report !== false && f.status !== "False Positive").length;
  const openCount = findings.filter(f => f.status !== "False Positive" && f.status !== "Resolved").length;

  view.innerHTML = `
    <div id="findings-toolbar">
      <div>
        <div id="findings-title">Findings</div>
        <div id="findings-summary">${fmtNum(openCount)} active / ${fmtNum(findings.length)} total / ${fmtNum(reportCount)} in report</div>
      </div>
      <div id="findings-filters">
        <select id="finding-filter-status" title="Status filter">
          ${_findingOptions(["active", "all", ...FINDING_STATUSES], findingFilters.status, { active: "Active", all: "All statuses" })}
        </select>
        <select id="finding-filter-severity" title="Severity filter">
          ${_findingOptions(["all", ...FINDING_SEVERITIES], findingFilters.severity, { all: "All severities" })}
        </select>
        <select id="finding-filter-source" title="Source filter">
          ${_findingOptions(["all", ...sourceTypes], findingFilters.source, Object.assign({ all: "All sources" }, FINDING_SOURCE_LABELS))}
        </select>
      </div>
    </div>
    <div id="findings-list">
      ${visible.length ? visible.map(_renderFindingRow).join("") : '<div class="findings-empty">No findings match the current filters</div>'}
    </div>
  `;

  document.getElementById("finding-filter-status").addEventListener("change", e => {
    findingFilters.status = e.target.value;
    renderFindingsWorkspace();
  });
  document.getElementById("finding-filter-severity").addEventListener("change", e => {
    findingFilters.severity = e.target.value;
    renderFindingsWorkspace();
  });
  document.getElementById("finding-filter-source").addEventListener("change", e => {
    findingFilters.source = e.target.value;
    renderFindingsWorkspace();
  });

  view.querySelectorAll("[data-finding-field]").forEach(el => {
    el.addEventListener("change", () => {
      const id = el.dataset.findingId;
      const field = el.dataset.findingField;
      const value = el.type === "checkbox" ? el.checked : el.value;
      updateFinding(id, { [field]: value });
    });
  });
  view.querySelectorAll("[data-finding-action]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.findingId;
      const action = btn.dataset.findingAction;
      const f = findingsById.get(id);
      if (!f) return;
      if (action === "open") openFindingEvidence(id);
      if (action === "copy") copyText(findingEvidenceBundle(f));
      if (action === "note") {
        const note = await openTextModal({
          title: `Analyst note: ${f.title}`,
          value: f.analyst_note || "",
          placeholder: "Add analyst context, remediation notes, or false-positive rationale...",
        });
        if (note !== null) updateFinding(id, { analyst_note: note.trim() });
      }
    });
  });
}

function _renderFindingRow(f) {
  const statusOptions = _findingOptions(FINDING_STATUSES, f.status);
  const severityOptions = _findingOptions(FINDING_SEVERITIES, f.severity);
  const source = FINDING_SOURCE_LABELS[f.source_type] || f.source_type || "Finding";
  const evidence = (f.evidence_refs || []).slice(0, 4).map(ref => `<span>${escHtml(_findingEvidenceLabel(ref))}</span>`).join("");
  const include = f.include_in_report !== false;
  return `
    <div class="finding-row sev-${escHtml(f.severity)} status-${escHtml(f.status.toLowerCase().replace(/\s+/g, "-"))}" data-finding-id="${escHtml(f.id)}">
      <div class="finding-main">
        <div class="finding-title-row">
          <span class="finding-sev">${escHtml(f.severity)}</span>
          <strong>${escHtml(f.title)}</strong>
          <span class="finding-source">${escHtml(source)}</span>
        </div>
        <div class="finding-desc">${escHtml(f.description || "")}</div>
        ${f.route ? `<div class="finding-route">${escHtml(f.route)}</div>` : ""}
        ${evidence ? `<div class="finding-evidence">${evidence}</div>` : ""}
        ${f.analyst_note ? `<div class="finding-note">${escHtml(f.analyst_note)}</div>` : ""}
      </div>
      <div class="finding-controls">
        <select data-finding-field="status" data-finding-id="${escHtml(f.id)}" title="Finding status">${statusOptions}</select>
        <select data-finding-field="severity" data-finding-id="${escHtml(f.id)}" title="Severity">${severityOptions}</select>
        <label class="finding-report-toggle">
          <input type="checkbox" data-finding-field="include_in_report" data-finding-id="${escHtml(f.id)}"${include ? " checked" : ""}>
          Report
        </label>
        <button data-finding-action="note" data-finding-id="${escHtml(f.id)}">Note</button>
        <button data-finding-action="copy" data-finding-id="${escHtml(f.id)}">Copy Evidence</button>
        <button data-finding-action="open" data-finding-id="${escHtml(f.id)}">Open</button>
      </div>
    </div>
  `;
}

/** Returns true when the given node ID has an SVG element in the current render. */
function _isRendered(id) {
  return _renderedNodeIds.has(id);
}

function _jumpToAnomaly(a) {
  if (!a.src) return;
  const node = graphData && graphData.nodes.find(n => n.ip === a.src);
  if (!node) return;
  selectedNode = node;
  showDetailPanel(node, { from: "anomaly", label: a.type.replace(/_/g, " ") });
  detailPanel.classList.add("open");
  if (_isRendered(node.id)) {
    const linkSel = linksGroup.selectAll(".link");
    const nodeSel = nodesGroup.selectAll(".node");
    nodeSel.classed("selected", n => n.id === node.id);
    highlightNode(node, linkSel, nodeSel);
  } else {
    showToast(
      `${node.ip} is not in the rendered top ${RENDER_NODE_CAP.toLocaleString()} hosts — details shown above. Use the Table view or Hosts Inventory CSV for the full dataset.`,
      "info", 6000
    );
  }
  setView("graph");
}

/* ── Canvas edge rendering (GPU-composited) ──────────────────────────────── */
function resizeEdgeCanvas() {
  const canvas = document.getElementById("edge-canvas");
  const svgEl  = document.getElementById("graph-svg");
  canvas.width  = svgEl.clientWidth;
  canvas.height = svgEl.clientHeight;
}

function drawCanvasEdges() {
  const canvas = document.getElementById("edge-canvas");
  if (!canvas || !useCanvasEdges) return;
  const ctx = canvas.getContext("2d");
  const t = currentZoomTransform;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  ctx.save();
  ctx.translate(t.x, t.y);
  ctx.scale(t.k, t.k);
  ctx.globalAlpha = 0.7;

  for (const d of _canvasLinks) {
    const protoOk = !(d.protocols && d.protocols.length) ||
                    (d.protocols || []).some(p => activeProtos.has(p));
    const sid = typeof d.source === "object" ? d.source.id : d.source;
    const tid = typeof d.target === "object" ? d.target.id : d.target;
    if (!protoOk || !_visibleNodeIds.has(sid) || !_visibleNodeIds.has(tid)) continue;

    const sx = typeof d.source === "object" ? d.source.x : 0;
    const sy = typeof d.source === "object" ? d.source.y : 0;
    const ex = typeof d.target === "object" ? d.target.x : 0;
    const ey = typeof d.target === "object" ? d.target.y : 0;

    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.lineTo(ex, ey);
    ctx.strokeStyle = d._canvasColor;  // precomputed at render time
    ctx.lineWidth   = d._canvasWidth;  // precomputed at render time
    ctx.stroke();
  }
  ctx.restore();
}

/* ── D3 force graph ──────────────────────────────────────────────────────── */
function renderGraph(data) {
  linksGroup.selectAll("*").remove();
  nodesGroup.selectAll("*").remove();
  if (simulation) { simulation.on("tick", null).on("end", null); simulation.stop(); }
  clearTimeout(_zoomFitTimer);

  // Defensive normalisation: session import validates shapes, but guard here too
  if (!Array.isArray(data.nodes)) data.nodes = [];
  if (!Array.isArray(data.edges)) data.edges = [];

  data.nodes.forEach(n => { n._visible = true; });

  // Build local node/edge copies — the render cap operates only on these locals.
  // graphData.nodes / graphData.edges are NEVER mutated here; exports depend on them being full.
  let nodes = data.nodes.map(d => ({ ...d }));

  // ── Render cap: draw only the top-N hosts by traffic for browser performance ──
  const _totalNodeCount = nodes.length;
  let _capActive = false;
  if (nodes.length > RENDER_NODE_CAP) {
    _capActive = true;
    nodes.sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0));
    nodes = nodes.slice(0, RENDER_NODE_CAP);
  }

  const nodeById = {};
  nodes.forEach(n => nodeById[n.id] = n);
  _renderedNodeIds = new Set(nodes.map(n => n.id));

  let links = data.edges
    .filter(e => nodeById[e.source] && nodeById[e.target] && e.source !== e.target)
    .map(e => ({ ...e, source: e.source, target: e.target }));

  // Edge ceiling backstop: keep highest-traffic edges
  if (links.length > RENDER_EDGE_CAP) {
    _capActive = true;
    links.sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0));
    links = links.slice(0, RENDER_EDGE_CAP);
  }

  // Show overlay when nodes exist but no IP connections (ARP-only or all self-loops)
  const noConnMsg = document.getElementById("no-connections-msg");
  if (noConnMsg) noConnMsg.classList.toggle("visible", links.length === 0 && nodes.length > 0);

  const maxPkt = Math.max(1, nodes.reduce((m, n) => Math.max(m, n.packet_count || 0), 0));
  function nodeRadius(d) {
    return 6 + Math.log1p((d.packet_count || 0) / maxPkt * 200) * 3;
  }

  const maxEdgePkt = Math.max(1, links.reduce((m, e) => Math.max(m, e.packet_count || 0), 0));
  function edgeWidth(d) {
    return 1 + Math.log1p((d.packet_count || 0) / maxEdgePkt * 50) * 1.2;
  }

  // ── Canvas edge mode (GPU-composited rendering for large graphs) ──
  useCanvasEdges = nodes.length > CANVAS_THRESHOLD;
  _canvasMaxEdgePkt = maxEdgePkt;
  const edgeCanvas = document.getElementById("edge-canvas");
  if (useCanvasEdges) {
    edgeCanvas.style.display = "";
    resizeEdgeCanvas();
  } else {
    edgeCanvas.style.display = "none";
  }

  // ── Links ──
  // Build Purdue level lookup for cross-zone highlighting
  const _pLevel = {};
  nodes.forEach(n => { _pLevel[n.id] = n.purdue_level ?? purdueLevel(n); });
  _canvasPLevel = _pLevel;
  // (cross-zone count is used only for edge class assignment below — no sidebar badge)

  const linkSel = linksGroup.selectAll(".link")
    .data(links)
    .join("line")
    .attr("class", d => {
      const sl = _pLevel[typeof d.source === "object" ? d.source.id : d.source] ?? -1;
      const tl = _pLevel[typeof d.target === "object" ? d.target.id : d.target] ?? -1;
      return sl !== -1 && tl !== -1 && sl !== tl ? "link cross-zone" : "link";
    })
    .attr("stroke", d => {
      const sl = _pLevel[typeof d.source === "object" ? d.source.id : d.source] ?? -1;
      const tl = _pLevel[typeof d.target === "object" ? d.target.id : d.target] ?? -1;
      return sl !== -1 && tl !== -1 && sl !== tl ? "#ff8c00" : protoColor(d.protocols);
    })
    .attr("stroke-width", d => edgeWidth(d))
    .on("mouseenter", (event, d) => showTooltipEdge(event, d))
    .on("mousemove", (event) => positionTooltip(event))
    .on("mouseleave", () => hideTooltip())
    .on("click", (event, d) => {
      event.stopPropagation();
      hideTooltip();
      const sid = typeof d.source === "object" ? d.source.id : d.source;
      const tid = typeof d.target === "object" ? d.target.id : d.target;
      openPktInspector(sid, tid);
    });

  // In canvas mode, hide SVG lines and store link data for canvas drawing
  if (useCanvasEdges) {
    _canvasLinks = links;
    // Precompute static per-edge canvas properties; only re-run when data changes
    _canvasLinks.forEach(d => {
      const sid = typeof d.source === "object" ? d.source.id : d.source;
      const tid = typeof d.target === "object" ? d.target.id : d.target;
      const sl = _canvasPLevel[sid] ?? -1;
      const tl = _canvasPLevel[tid] ?? -1;
      d._canvasColor = (sl !== -1 && tl !== -1 && sl !== tl) ? "#ff8c00" : protoColor(d.protocols);
      d._canvasWidth = 1 + Math.log1p((d.packet_count || 0) / _canvasMaxEdgePkt * 50) * 1.2;
    });
    linkSel.style("display", "none");
  }

  // Edge packet-count labels (SVG mode only; hover to reveal)
  if (!useCanvasEdges) {
    linksGroup.selectAll(".link-labels").remove();
    linksGroup.append("g").attr("class", "link-labels")
      .selectAll("text")
      .data(links)
      .join("text")
      .attr("class", "edge-label")
      .text(d => d.packet_count || "");

    linkSel
      .on("mouseenter.label", (event, d) => {
        linksGroup.selectAll(".edge-label").filter(ld => ld === d).style("opacity", 1);
      })
      .on("mouseleave.label", (event, d) => {
        linksGroup.selectAll(".edge-label").filter(ld => ld === d).style("opacity", null);
      });
  }

  // ── Nodes ──
  const nodeSel = nodesGroup.selectAll(".node")
    .data(nodes)
    .join("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        if (pinnedNodes.has(d.ip)) {
          d.fx = event.x; d.fy = event.y; // drag updates the pin position
        } else {
          d.fx = null; d.fy = null;
        }
      })
    )
    .on("mouseenter", (event, d) => {
      showTooltipNode(event, d);
      highlightNode(d, linkSel, nodeSel);
    })
    .on("mousemove", (event) => positionTooltip(event))
    .on("mouseleave", (event, d) => {
      hideTooltip();
      if (!selectedNode || selectedNode.id !== d.id) {
        unhighlightAll(linkSel, nodeSel);
        if (selectedNode) highlightNode(selectedNode, linkSel, nodeSel);
      }
    })
    .on("click", (event, d) => {
      event.stopPropagation();
      ctxMenu.classList.add("hidden");
      if (selectedNode && selectedNode.id === d.id) {
        selectedNode = null;
        unhighlightAll(linkSel, nodeSel);
        nodeSel.classed("selected", false);
        detailPanel.classList.remove("open");
      } else {
        selectedNode = d;
        nodeSel.classed("selected", n => n.id === d.id);
        highlightNode(d, linkSel, nodeSel);
        showDetailPanel(d);
      }
    })
    .on("contextmenu", (event, d) => {
      event.preventDefault();
      event.stopPropagation();
      showCtxMenu(event, d);
    })
    .on("dblclick", (event, d) => {
      event.stopPropagation();
      isolatedNodeIp = (isolatedNodeIp === d.ip) ? null : d.ip;
      applyFilters();
    });

  // Node decorations: anomaly ring, cred icon, circle, host glyph, labels, risk badge
  // IPv6 nodes get a dashed stroke for visual distinction
  appendNodeDecorations(nodeSel, nodeRadius, { ipVersionStroke: true });

  // Click on background → deselect
  svg.on("click", () => {
    selectedNode = null;
    unhighlightAll(linkSel, nodeSel);
    nodeSel.classed("selected", false);
    detailPanel.classList.remove("open");
    ctxMenu.classList.add("hidden");
  });

  // ── Simulation ──
  const cx = svg.node().clientWidth / 2;
  const cy = svg.node().clientHeight / 2;

  simulation = buildSimulation(nodes, links, cx, cy, currentLayout);
  simulation.on("tick", () => {
    if (useCanvasEdges) {
      drawCanvasEdges();
    } else {
      linkSel
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);
      linksGroup.selectAll(".edge-label")
        .attr("x", d => ((d.source.x || 0) + (d.target.x || 0)) / 2)
        .attr("y", d => ((d.source.y || 0) + (d.target.y || 0)) / 2);
    }
    nodeSel.attr("transform", d => `translate(${d.x},${d.y})`);
    if (_minimapInitialized && (++_minimapTickCount % 5 === 0)) updateMinimap();
  });

  simulation.on("end", () => { clearTimeout(_zoomFitTimer); zoomFit(); });
  _zoomFitTimer = setTimeout(() => zoomFit(), 2500);

  // Restore pin visual for nodes that were pinned before a filter cycle
  updatePinVisuals();

  initMinimap(nodes);

  // Toggle the render-cap banner
  if (_capActive) {
    capBanner.textContent =
      `ℹ Graph shows top ${nodes.length.toLocaleString()} of ${_totalNodeCount.toLocaleString()} hosts by traffic — exports contain the full dataset.`;
    capBanner.classList.add("visible");
    showToast(
      `Graph capped to top ${nodes.length.toLocaleString()} of ${_totalNodeCount.toLocaleString()} hosts by traffic. All hosts appear in the Hosts Inventory CSV and Table view.`,
      "info", 8000
    );
  } else {
    capBanner.classList.remove("visible");
  }
}

function buildSimulation(nodes, links, cx, cy, layout) {
  if (simulation) { simulation.on("tick", null).on("end", null); simulation.stop(); }

  const _maxPkt = Math.max(1, nodes.reduce((m, n) => Math.max(m, n.packet_count || 0), 0));
  const sim = d3.forceSimulation(nodes)
    .force("collide", d3.forceCollide().radius(d => {
      return 6 + Math.log1p((d.packet_count || 0) / _maxPkt * 200) * 3 + 12;
    }));

  if (layout === "force") {
    sim
      .force("link", d3.forceLink(links).id(d => d.id).distance(90).strength(0.4))
      .force("charge", d3.forceManyBody().strength(-200).distanceMax(400))
      .force("center", d3.forceCenter(cx, cy));
  } else if (layout === "radial") {
    sim
      .force("link", d3.forceLink(links).id(d => d.id).distance(60).strength(0.3))
      .force("charge", d3.forceManyBody().strength(-100))
      .force("radial", d3.forceRadial(d => d.is_private ? 150 : 350, cx, cy).strength(0.8));
  } else if (layout === "cluster") {
    const typeGroups = {};
    let gIdx = 0;
    nodes.forEach(n => {
      if (!(n.host_type in typeGroups)) typeGroups[n.host_type] = gIdx++;
    });
    const total = gIdx || 1;
    sim
      .force("link", d3.forceLink(links).id(d => d.id).distance(50).strength(0.2))
      .force("charge", d3.forceManyBody().strength(-80))
      .force("x", d3.forceX(d => {
        const gi = typeGroups[d.host_type] || 0;
        return cx + Math.cos((gi / total) * 2 * Math.PI) * 280;
      }).strength(0.5))
      .force("y", d3.forceY(d => {
        const gi = typeGroups[d.host_type] || 0;
        return cy + Math.sin((gi / total) * 2 * Math.PI) * 220;
      }).strength(0.5));
  }

  return sim;
}

/* ── Layout mode buttons ─────────────────────────────────────────────────── */
document.querySelectorAll(".layout-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    if (!graphData) return;
    if (!btn.dataset.layout) return;   // skip VLAN layout buttons (they use data-vlan-layout)
    currentLayout = btn.dataset.layout;
    document.querySelectorAll(".layout-btn").forEach(b => b.classList.toggle("active", b.dataset.layout === currentLayout));
    // Reheat with new forces
    const linkSel = linksGroup.selectAll(".link");
    const nodeSel = nodesGroup.selectAll(".node");
    const nodes = [];
    nodeSel.each(d => nodes.push(d));
    const links = [];
    linkSel.each(d => links.push(d));
    const cx = svg.node().clientWidth / 2;
    const cy = svg.node().clientHeight / 2;
    simulation = buildSimulation(nodes, links, cx, cy, currentLayout);
    // Mirror the canonical renderGraph tick: update edge lines, edge labels, nodes, minimap.
    // Previously this was missing edge-label repositioning, the minimap sync, and the
    // on("end") zoom-fit — all of which are present in the original simulation setup below.
    simulation.on("tick", () => {
      if (useCanvasEdges) {
        drawCanvasEdges();
      } else {
        linkSel
          .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        linksGroup.selectAll(".edge-label")
          .attr("x", d => ((d.source.x || 0) + (d.target.x || 0)) / 2)
          .attr("y", d => ((d.source.y || 0) + (d.target.y || 0)) / 2);
      }
      nodeSel.attr("transform", d => `translate(${d.x},${d.y})`);
      if (_minimapInitialized && (++_minimapTickCount % 5 === 0)) updateMinimap();
    });
    simulation.on("end", () => { clearTimeout(_zoomFitTimer); zoomFit(); });
    _zoomFitTimer = setTimeout(() => zoomFit(), 2500);
    simulation.alpha(0.8).restart();
  });
});

/* ── Highlight helpers ───────────────────────────────────────────────────── */
function highlightNode(d, linkSel, nodeSel) {
  const connectedIds = new Set([d.id]);
  linkSel.each(function(e) {
    const sid = e.source.id || e.source;
    const tid = e.target.id || e.target;
    if (sid === d.id || tid === d.id) {
      connectedIds.add(sid);
      connectedIds.add(tid);
    }
  });

  linkSel.classed("highlighted", e => {
    const sid = e.source.id || e.source;
    const tid = e.target.id || e.target;
    return sid === d.id || tid === d.id;
  }).classed("faded", e => {
    const sid = e.source.id || e.source;
    const tid = e.target.id || e.target;
    return sid !== d.id && tid !== d.id;
  });

  nodeSel.classed("faded", n => !connectedIds.has(n.id));
  _visibleNodeIds = connectedIds;  // keep canvas in sync during hover
}

function unhighlightAll(linkSel, nodeSel) {
  linkSel.classed("highlighted", false).classed("faded", false);
  nodeSel.classed("faded", false);
  applyFilters(true);  // applyFilters will restore _visibleNodeIds
}

/* ── Shared node decoration helper ──────────────────────────────────────── */
// Appends anomaly ring, cred icon, circle (with IPv6 dash), host glyph, IP label,
// country code, note icon, and risk badge to a D3 node selection.
// nodeRadius: function(d) → radius in px
// opts: { ipVersionStroke: bool, showGeo: bool (default true) }
function appendNodeDecorations(nodeSel, nodeRadius, opts = {}) {
  const ipVersionStroke = opts.ipVersionStroke || false;
  const showGeo = opts.showGeo !== false;

  // Anomaly ring
  nodeSel.each(function(d) {
    const sev = anomalyNodeIps[d.ip];
    if (sev) {
      d3.select(this).append("circle")
        .attr("class", `anomaly-ring-${sev}`)
        .attr("r", nodeRadius(d) + 4);
    }
  });

  // Credential key icon
  nodeSel.filter(d => credIpSet.has(d.ip)).append("text")
    .attr("class", "node-cred-icon")
    .attr("dy", d => -(nodeRadius(d) + 4))
    .attr("dx", d => nodeRadius(d) - 2)
    .attr("font-size", "10px")
    .attr("text-anchor", "middle")
    .text("🔑");

  // Circle (IPv6 nodes get a dashed stroke when ipVersionStroke is true)
  // When colorByVlan is true the fill is driven by the node's primary VLAN color.
  const _nodeFillColor = d => colorByVlan
    ? vlanColor((d.vlans && d.vlans.length) ? String(d.vlans[0]) : (d.vlan_untagged ? "untagged" : null))
    : hostColor(d.host_type);
  const circles = nodeSel.append("circle")
    .attr("r", d => nodeRadius(d))
    .attr("fill", _nodeFillColor)
    .attr("fill-opacity", 0.85)
    .attr("stroke", d => { const c = d3.color(_nodeFillColor(d)); return c ? c.brighter(0.5) : "#fff"; });
  if (ipVersionStroke) {
    circles
      .attr("stroke-dasharray", d => d.ip_version === 6 ? "3,2" : null)
      .attr("stroke-width", d => d.ip_version === 6 ? 1.6 : null);
  }

  // Host-type icon glyph
  nodeSel.append("text")
    .attr("class", "node-icon")
    .attr("dy", "0.38em")
    .attr("font-size", d => Math.min(nodeRadius(d) * 1.1, 16) + "px")
    .text(d => hostIcon(d.host_type));

  // IP/hostname label below node
  nodeSel.append("text")
    .attr("class", "ip-label")
    .attr("dy", d => nodeRadius(d) + 11)
    .attr("font-size", "9px")
    .attr("fill", "#8b949e")
    .text(d => d.hostname || d.ip);

  // Country code label
  if (showGeo) {
    nodeSel.each(function(d) {
      if (d.geo && d.geo.country_code) {
        d3.select(this).append("text")
          .attr("class", "node-geo-label")
          .attr("dy", d => nodeRadius(d) + 21)
          .attr("font-size", "8px")
          .text(d.geo.country_code);
      }
    });
  }

  // Note icon (user annotation)
  nodeSel.each(function(d) {
    const note = getAnnotation(d.ip);
    if (note) {
      d3.select(this).append("text")
        .attr("class", "node-note-icon")
        .attr("dy", d => -(nodeRadius(d) + 4))
        .attr("font-size", "10px")
        .text("✎");
    }
  });

  // Risk score badge (top-right corner of node)
  nodeSel.each(function(d) {
    const risk = d.risk_score || 0;
    if (risk <= 0) return;
    const r = nodeRadius(d);
    const badgeClr = risk >= 70 ? "var(--red)" : risk >= 40 ? "var(--yellow)" : "#6e7681";
    const g = d3.select(this);
    g.append("circle")
      .attr("cx", r - 1).attr("cy", -(r - 1))
      .attr("r", 8)
      .attr("fill", "#0d1117")
      .attr("stroke", badgeClr)
      .attr("stroke-width", 1.5);
    g.append("text")
      .attr("x", r - 1).attr("y", -(r - 5))
      .attr("font-size", "7px")
      .attr("fill", badgeClr)
      .attr("text-anchor", "middle")
      .attr("font-family", "var(--font-mono)")
      .attr("font-weight", "bold")
      .text(risk);
  });
}

/* ── Tooltip helpers ─────────────────────────────────────────────────────── */
function showTooltipNode(event, d) {
  const geoStr = d.geo ? ` · ${escHtml(d.geo.country_code || d.geo.country || "")}${d.geo.city ? ", " + escHtml(d.geo.city) : ""}` : "";
  tooltip.innerHTML = `
    <div class="tip-ip">${escHtml(d.ip)}${geoStr ? `<span style="color:var(--text2)">${geoStr}</span>` : ""}</div>
    ${d.hostname ? `<div class="tip-type">${escHtml(d.hostname)}</div>` : ""}
    <div class="tip-type">${escHtml(d.host_type)}${d.os_hint ? " · " + escHtml(d.os_hint) : ""}</div>
    <div class="tip-proto">
      ${(d.protocols || []).slice(0, 6).map(p =>
        `<span style="color:${PROTO_COLORS[p] || '#aaa'}">${escHtml(p)}</span>`
      ).join(" · ")}
    </div>
    <div class="tip-type" style="margin-top:4px">
      ${fmtNum(d.packet_count)} pkts · ${fmtBytes(d.bytes_sent + d.bytes_recv)}
    </div>
    ${anomalyNodeIps[d.ip] ? `<div style="margin-top:4px;font-size:10px;color:${anomalyNodeIps[d.ip]==='high'?'var(--red)':'var(--yellow)'}">⚠ ${escHtml(anomalyNodeIps[d.ip].toUpperCase())} anomaly</div>` : ""}
    ${(d.risk_score || 0) > 0 ? `<div style="margin-top:2px;font-size:10px;color:${d.risk_score>=70?'var(--red)':d.risk_score>=40?'var(--yellow)':'#aaa'}">Risk: ${d.risk_score}/100</div>` : ""}
    ${d.tls_sni && d.tls_sni.length ? `<div style="margin-top:2px;font-size:10px;color:#58a6ff">TLS: ${d.tls_sni.slice(0,2).map(escHtml).join(", ")}</div>` : ""}
  `;
  tooltip.classList.add("visible");
  positionTooltip(event);
}

function showTooltipEdge(event, d) {
  tooltip.innerHTML = `
    <div class="tip-ip" style="font-size:11px">${escHtml(d.source.id || d.source)} ↔ ${escHtml(d.target.id || d.target)}</div>
    <div class="tip-type">${fmtNum(d.packet_count)} pkts · ${fmtBytes(d.bytes)}</div>
    <div class="tip-proto" style="margin-top:4px">
      ${(d.protocols || []).slice(0, 6).map(p =>
        `<span style="color:${PROTO_COLORS[p] || '#aaa'}">${escHtml(p)}</span>`
      ).join(" · ")}
    </div>
    ${(d.ports || []).length ? `<div class="tip-type" style="margin-top:4px">Ports: ${escHtml((d.ports || []).slice(0,8).join(", "))}</div>` : ""}
  `;
  tooltip.classList.add("visible");
  positionTooltip(event);
}

function positionTooltip(event) {
  const x = event.clientX + 14;
  const y = event.clientY - 10;
  tooltip.style.left = x + "px";
  tooltip.style.top  = y + "px";
}

function hideTooltip() {
  tooltip.classList.remove("visible");
}

/* ── Detail panel ─────────────────────────────────────────────────────────── */
function showDetailPanel(d, navCtx) {
  // Breadcrumb: show navigation context if provided (e.g. jumped from anomaly sidebar)
  const bcBar = document.getElementById("breadcrumb-bar");
  if (bcBar) {
    if (navCtx) {
      bcBar.innerHTML = "";
      bcBar.classList.remove("hidden");
      if (navCtx.from === "anomaly") {
        const backBtn = document.createElement("button");
        backBtn.textContent = "Anomalies";
        backBtn.addEventListener("click", () => {
          bcBar.classList.add("hidden");
          bcBar.innerHTML = "";
          // Scroll anomaly sidebar into view
          const anomSidebar = document.querySelector(".sidebar-section .anomaly-badge");
          if (anomSidebar) anomSidebar.scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
        bcBar.appendChild(backBtn);
        const sep = document.createElement("span");
        sep.className = "bc-sep";
        sep.textContent = "›";
        bcBar.appendChild(sep);
        const cur = document.createElement("span");
        cur.className = "bc-cur";
        cur.textContent = navCtx.label;
        bcBar.appendChild(cur);
        const sep2 = document.createElement("span"); sep2.className = "bc-sep"; sep2.textContent = "›";
        bcBar.appendChild(sep2);
        const ip = document.createElement("span"); ip.className = "bc-cur"; ip.textContent = d.ip;
        bcBar.appendChild(ip);
      }
    } else {
      bcBar.classList.add("hidden");
      bcBar.innerHTML = "";
    }
  }

  detailPanel.classList.add("open");
  document.getElementById("dh-ip").innerHTML =
    escHtml(d.ip) + ` ${copyButton(d.ip, "Copy IP")}`;
  const _hostStr = d.hostname || (d.dns_names && d.dns_names[0]) || "";
  document.getElementById("dh-hostname").innerHTML = _hostStr
    ? escHtml(_hostStr) + ` ${copyButton(_hostStr, "Copy hostname")}`
    : "";

  const body = document.getElementById("detail-body");
  const rows = [];

  rows.push(row("Type", badge(d.host_type, hostColor(d.host_type))));
  const OT_TYPES = new Set(["PLC","RTU","IED","HMI","SCADA Server","DCS","Historian","Engineering Workstation","Building Controller","IoT Gateway","Field Device"]);
  const IOT_TYPES = new Set(["IP Camera","Smart Home Hub","Smart Meter","IoT Sensor","Smart Speaker","CPE Device","IoT Gateway"]);
  if (OT_TYPES.has(d.host_type)) {
    rows.push(`<div class="ot-device-badge">&#9881; OT/ICS Device</div>`);
  }
  // Purdue level badge
  {
    const lvl = (d.purdue_level !== undefined) ? d.purdue_level : purdueLevel(d);
    const levelRow = PURDUE_LEVELS.find(r => r.level === lvl);
    const levelLabel = levelRow ? levelRow.label : "? Unclassified";
    const levelColor = LEVEL_COLORS[lvl] ? LEVEL_COLORS[lvl] : "#444";
    rows.push(`<div style="margin-top:4px"><span style="background:${levelColor}55;border:1px solid ${levelColor}99;color:#ccc;padding:2px 8px;border-radius:10px;font-size:10px;font-family:var(--font-mono)">Purdue ${levelLabel}</span></div>`);
  }
  if ((d.risk_score || 0) > 0) {
    const rc = d.risk_score >= 70 ? "#f85149" : d.risk_score >= 40 ? "#e3b341" : "#6e7681";
    rows.push(`<div style="margin-top:4px"><span style="background:${rc}22;border:1px solid ${rc}88;color:${rc};padding:2px 10px;border-radius:10px;font-size:10px;font-family:var(--font-mono);font-weight:bold">&#9760; Risk Score: ${d.risk_score}/100</span></div>`);
  }
  if (IOT_TYPES.has(d.host_type)) {
    rows.push(`<div class="iot-device-badge">&#128267; IoT Device</div>`);
  }
  if (d.os_hint)     rows.push(row("OS guess",   mono(d.os_hint)));
  if (d.mac)         rows.push(row("MAC", mono(d.mac) + (d.mac_vendor ? ` <span style="color:var(--text2)">(${d.mac_vendor})</span>` : "")));
  rows.push(row("Traffic",
    `<span style="color:#3fb950">↑ ${fmtBytes(d.bytes_sent)}</span>  ` +
    `<span style="color:#58a6ff">↓ ${fmtBytes(d.bytes_recv)}</span>`));
  rows.push(row("Packets", mono(fmtNum(d.packet_count))));
  rows.push(row("Private IP", mono(d.is_private ? "Yes" : "No")));

  // Geo info
  if (d.geo) {
    const flagStr = d.geo.country_code ? countryFlag(d.geo.country_code) + " " : "";
    const geoStr = [
      d.geo.country || "",
      d.geo.city || "",
    ].filter(Boolean).join(", ");
    rows.push(row("Location", `${flagStr}${geoStr || "Unknown"}`));
  }

  if ((d.protocols || []).length) {
    rows.push(sectionTitle("Protocols"));
    rows.push(tagList(d.protocols, p => PROTO_COLORS[p] || "#607D8B", true));
  }

  if ((d.services || []).length) {
    rows.push(sectionTitle("Services detected"));
    rows.push(tagList(d.services, () => null, false));
  }

  if ((d.open_ports || []).length) {
    rows.push(sectionTitle("Ports seen"));
    rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;padding-left:0;margin-bottom:6px">${
      escHtml(sliceMore(d.open_ports || [], 30))
    }</div>`);
  }

  if ((d.dns_names || []).length) {
    rows.push(sectionTitle("DNS names"));
    (d.dns_names || []).slice(0, 20).forEach(n => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px">${escHtml(n)}</div>`));
    if ((d.dns_names || []).length > 20) rows.push(`<div class="d-val" style="font-size:11px;color:var(--text2)">… +${(d.dns_names.length - 20)} more (all in CSV export)</div>`);
  }

  if ((d.dns_queries || []).length) {
    rows.push(sectionTitle("DNS queries sent"));
    (d.dns_queries || []).slice(0, 20).forEach(q => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px;color:var(--text2)">${escHtml(q)}</div>`));
    if ((d.dns_queries || []).length > 20) rows.push(`<div class="d-val" style="font-size:11px;color:var(--text2)">… +${(d.dns_queries.length - 20)} more (all in CSV export)</div>`);
  }

  if (d.tls_sni && d.tls_sni.length) {
    rows.push(sectionTitle("TLS SNI (server names)"));
    d.tls_sni.forEach(s => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px;color:#58a6ff">${escHtml(s)}</div>`));
  }

  if (d.tls_ja3 && d.tls_ja3.length) {
    rows.push(sectionTitle("JA3 fingerprints"));
    d.tls_ja3.forEach(j => {
      const knownBad = {
        "e7d705a3286e19ea42f587b344ee6865": "Metasploit Meterpreter",
        "6734f37431670b3ab4292b8f60f29984": "Cobalt Strike",
        "b386946a5a44d1ddcc843bc75336dfce": "Dridex",
        "a0e9f5d64349fb13191bc781f81f42e1": "AgentTesla",
        "c12f54a3f91dc7bafd92cb59fe009a35": "Cobalt Strike Beacon",
        "ada79f3a9e63d0f1f4c6cb3ba9e99fa0": "Emotet",
        "de350869b8c85de67a350c8d186f11e6": "Trickbot",
        "51c64c77e60f3980eea90869b68c58a8": "AsyncRAT",
        "6bca5a6d9bf5b08f9cd95feefc1c2c7e": "QakBot",
        "a106ce68aee22e2f5d82ee41fb5fb22a": "IcedID",
      };
      const threat = knownBad[j];
      rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:10px;margin-bottom:3px">
        <span style="color:${threat ? 'var(--red)' : 'var(--text2)'}">${escHtml(j)}</span>
        ${copyButton(j, "Copy JA3")}
        ${threat ? `<span style="color:var(--red);margin-left:6px">⚠ ${escHtml(threat)}</span>` : ""}
      </div>`);
    });
  }

  // VLAN membership
  if ((d.vlans || []).length || d.vlan_untagged || d.vlan_qinq) {
    rows.push(sectionTitle("VLAN Tags"));
    if ((d.vlans || []).length) {
      const tags = d.vlans.map(v => `<span style="background:${vlanColor(v)};color:#000;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;display:inline-block;margin:1px 2px">VLAN ${v}</span>`).join("");
      rows.push(`<div style="margin-bottom:4px">${tags}</div>`);
    }
    if ((d.vlan_outer || []).length) {
      rows.push(row("QinQ outer VLANs", d.vlan_outer.join(", ")));
    }
    if ((d.vlan_pcps || []).length) {
      rows.push(row("PCP values", d.vlan_pcps.join(", ")));
    }
    if (d.vlan_untagged) rows.push(row("Untagged frames", "Yes"));
    if (d.vlan_qinq)     rows.push(row("QinQ (double-tagged)", "Yes"));
  }

  // Anomalies for this node
  const nodeAnomalies = (graphData.anomalies || []).filter(a => a.src === d.ip || a.dst === d.ip);
  if (nodeAnomalies.length) {
    rows.push(sectionTitle("Anomalies"));
    nodeAnomalies.forEach(a => {
      rows.push(`<div class="anomaly-badge ${a.severity}" style="margin-bottom:4px">
        <span class="ab-sev ${a.severity}">${a.severity}</span>
        <span class="ab-desc">${escHtml(a.description)}</span>
      </div>`);
    });
  }

  // Credentials captured for this node
  const nodeCreds = (graphData.credentials || []).filter(c => c.src === d.ip || c.dst === d.ip);
  if (nodeCreds.length) {
    rows.push(sectionTitle(`Captured Credentials (${nodeCreds.length})`));
    nodeCreds.slice(0, 20).forEach(c => {
      const pwId = `dpw-${Math.random().toString(36).slice(2)}`;
      const ts = c.rel_time != null ? `+${c.rel_time}s` : "";
      rows.push(`<div class="cred-card" style="margin-bottom:4px">
        <div>
          <span class="cred-proto ${escHtml((c.protocol||'').toLowerCase())}">${escHtml(c.protocol||'')}</span>
          <span style="color:var(--text2);font-size:10px">${escHtml(c.type||'')}</span>
          <span style="float:right;color:var(--text2);font-size:10px">${escHtml(ts)}</span>
        </div>
        <div class="cred-route" style="margin-top:2px">${escHtml(c.src||'')} → ${escHtml(c.dst||'')}${c.dport ? ':'+escHtml(String(c.dport)) : ''}</div>
        <div style="margin-top:3px">
          <span class="cred-user">${escHtml(c.username || '(no user)')}</span>
          <span style="color:var(--text2);margin:0 4px">/</span>
          <span class="cred-pw" id="${pwId}">●●●●●●</span>
          <button class="cred-reveal" data-pw="${escHtml(c.password||'')}" data-id="${pwId}">show</button>
        </div>
      </div>`);
    });
    if (nodeCreds.length > 20) {
      rows.push(`<div style="color:var(--text2);font-size:11px">…and ${nodeCreds.length - 20} more</div>`);
    }
  }

  // OT Analysis section (for OT host types)
  const CORE_OT_TYPES = new Set(["PLC","RTU","IED","HMI","SCADA Server","DCS","Historian","Engineering Workstation","Building Controller","Field Device"]);
  if (CORE_OT_TYPES.has(d.host_type) && graphData) {
    rows.push(sectionTitle("OT Analysis"));
    const roleColor = { master: "#3fb950", outstation: "#58a6ff", unknown: "#8b949e" }[d.ot_role || "unknown"] || "#8b949e";
    rows.push(`<div style="margin-bottom:6px"><span style="background:${roleColor};color:#000;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">${(d.ot_role || "unknown").toUpperCase()}</span></div>`);

    // Read/Write ratio bar
    const connEdges = graphData.edges.filter(e => e.source === d.ip || e.target === d.ip);
    const totR = connEdges.reduce((s, e) => s + (e.ot_reads || 0), 0);
    const totW = connEdges.reduce((s, e) => s + (e.ot_writes || 0), 0);
    const totE = connEdges.reduce((s, e) => s + (e.ot_errors || 0), 0);
    if (totR + totW + totE > 0) {
      const tot = totR + totW + totE;
      const rPct = Math.round(totR / tot * 100);
      const wPct = Math.round(totW / tot * 100);
      const ePct = 100 - rPct - wPct;
      rows.push(`<div style="font-size:11px;color:var(--text2);margin-bottom:3px">Reads: ${totR} · Writes: ${totW} · Errors: ${totE}</div>`);
      rows.push(`<div style="display:flex;height:10px;border-radius:4px;overflow:hidden;margin-bottom:8px">
        <div style="width:${rPct}%;background:#3fb950" title="Reads ${rPct}%"></div>
        <div style="width:${wPct}%;background:#f85149" title="Writes ${wPct}%"></div>
        <div style="width:${ePct}%;background:#d29922" title="Errors ${ePct}%"></div>
      </div>`);
    }
    // Per-function-code breakdown
    const allFcCounts = {};
    connEdges.forEach(e => {
      if (e.fc_counts) {
        Object.entries(e.fc_counts).forEach(([k, v]) => {
          allFcCounts[k] = (allFcCounts[k] || 0) + v;
        });
      }
    });
    const fcEntries = Object.entries(allFcCounts).sort((a, b) => b[1] - a[1]);
    if (fcEntries.length > 0) {
      const items = fcEntries.map(([label, count]) =>
        `<div style="display:flex;justify-content:space-between;padding:2px 0;font-size:10px;font-family:var(--font-mono);color:var(--text2)">
          <span>${escHtml(label)}</span>
          <span style="color:#58a6ff;margin-left:8px">${fmtNum(count)}×</span>
        </div>`
      ).join("");
      rows.push(`<details style="margin-top:4px;margin-bottom:6px">
        <summary style="font-size:10px;color:var(--text2);cursor:pointer;user-select:none;list-style:none;padding:2px 0">
          ▸ Function Code Breakdown (${fcEntries.length} type${fcEntries.length !== 1 ? "s" : ""})
        </summary>
        <div style="margin-top:4px;max-height:160px;overflow-y:auto;border-left:2px solid #333;padding-left:8px">
          ${items}
        </div>
      </details>`);
    }
    if (d.modbus_unit_ids && d.modbus_unit_ids.length) {
      rows.push(`<div style="font-size:11px;color:var(--text2)">Modbus unit IDs: <span style="font-family:var(--font-mono)">${d.modbus_unit_ids.map(escHtml).join(", ")}</span></div>`);
    }
    if (d.dnp3_addresses && d.dnp3_addresses.length) {
      rows.push(`<div style="font-size:11px;color:var(--text2);margin-top:3px">DNP3 link addresses: <span style="font-family:var(--font-mono)">${d.dnp3_addresses.map(escHtml).join(", ")}</span></div>`);
    }
  }

  // Conversations (top 5 edges)
  if (graphData) {
    const convEdges = graphData.edges.filter(e => e.source === d.ip || e.target === d.ip)
      .sort((a, b) => b.packet_count - a.packet_count)
      .slice(0, 5);
    if (convEdges.length) {
      rows.push(sectionTitle("Top Conversations"));
      let tableHtml = `<table class="conv-table">
        <thead><tr><th>Peer</th><th>Proto</th><th>Pkts</th><th>Bytes</th></tr></thead>
        <tbody>`;
      convEdges.forEach(e => {
        const peer  = escHtml(e.source === d.ip ? e.target : e.source);
        const proto = (e.protocols || []).slice(0, 2).map(escHtml).join("/");
        const sid   = escHtml(e.source);
        const tid   = escHtml(e.target);
        tableHtml += `<tr data-sid="${sid}" data-tid="${tid}">
          <td title="${peer}">${peer}</td>
          <td>${proto}</td>
          <td>${fmtNum(e.packet_count)}</td>
          <td>${fmtBytes(e.bytes)}</td>
        </tr>`;
      });
      tableHtml += "</tbody></table>";
      rows.push(tableHtml);
    }
  }

  // Annotation
  const note = getAnnotation(d.ip);
  rows.push(sectionTitle("Note"));
  if (note) {
    rows.push(`<div class="annotation-box">${escHtml(note)}</div>`);
    rows.push(`<button class="annotation-edit-btn" id="ann-edit-btn">Edit note</button>`);
  } else {
    rows.push(`<button class="annotation-edit-btn" id="ann-edit-btn">+ Add note</button>`);
  }

  body.innerHTML = rows.join("");

  // Bind credential reveal buttons in detail panel
  body.querySelectorAll(".cred-reveal").forEach(btn => {
    btn.addEventListener("click", function() {
      const el = document.getElementById(this.dataset.id);
      if (this.textContent === "show") {
        el.textContent = this.dataset.pw || "(empty)";
        this.textContent = "hide";
      } else {
        el.textContent = "●●●●●●";
        this.textContent = "show";
      }
    });
  });

  // Bind conversation table click
  body.querySelectorAll(".conv-table tbody tr").forEach(tr => {
    tr.addEventListener("click", () => {
      openPktInspector(tr.dataset.sid, tr.dataset.tid);
    });
  });

  // Bind annotation button
  const annBtn = body.querySelector("#ann-edit-btn");
  if (annBtn) {
    annBtn.addEventListener("click", async () => {
      const existing = getAnnotation(d.ip);
      const input = await openTextModal({
        title: "Host note: " + d.ip,
        value: existing || "",
        placeholder: "Add analyst notes for this host...",
      });
      if (input !== null) {
        saveAnnotation(d.ip, input);
        showDetailPanel(d);  // re-render
        // update node icon
        updateNoteIcon(d.ip, !!input);
      }
    });
  }

  // "View Packets" button
  const vpBtn = document.createElement("button");
  vpBtn.className = "btn-view-pkts";
  vpBtn.textContent = "View Packets for this host";
  vpBtn.addEventListener("click", () => openPktInspectorForHost(d.ip));
  body.appendChild(vpBtn);
}

function row(key, val) {
  return `<div class="d-row"><span class="d-key">${key}</span><span class="d-val">${val}</span></div>`;
}
function mono(val) { return `<code style="font-family:var(--font-mono)">${val}</code>`; }
function sectionTitle(t) { return `<div class="d-section-title">${t}</div>`; }
function badge(text, color) {
  return `<span class="tag" style="background:${color}22;border-color:${color};color:${color}">${text}</span>`;
}
function tagList(items, colorFn, isProto) {
  return `<div class="tag-list">${items.map(i => {
    const c = colorFn(i);
    const style = c ? `style="background:${c}22;border-color:${c};color:${c}"` : "";
    return `<span class="tag${isProto ? " proto" : ""}" ${style}>${i}</span>`;
  }).join("")}</div>`;
}

document.getElementById("detail-close").addEventListener("click", () => {
  detailPanel.classList.remove("open");
  selectedNode = null;
  if (graphData) {
    const linkSel  = linksGroup.selectAll(".link");
    const nodeSel  = nodesGroup.selectAll(".node");
    unhighlightAll(linkSel, nodeSel);
    nodeSel.classed("selected", false);
  }
  // Re-render OT map to reclaim space if it was active
  if (currentView === "ot" && graphData) setTimeout(() => renderOTMap(graphData), 50);
});

/* ── Search ──────────────────────────────────────────────────────────────── */
let _searchTimer;
searchBox.addEventListener("input", () => {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => {
    searchTerm = searchBox.value.trim().toLowerCase();
    updateFilterUI();
    applyFilters();

    if (searchTerm && graphData) {
      const match = graphData.nodes.find(n =>
        n.ip.includes(searchTerm) ||
        (n.hostname && n.hostname.toLowerCase().includes(searchTerm))
      );
      if (match) {
        selectedNode = match;
        showDetailPanel(match);
        detailPanel.classList.add("open");
        if (!_isRendered(match.id)) {
          showToast(
            `${match.ip} is not in the rendered top ${RENDER_NODE_CAP.toLocaleString()} hosts by traffic — details shown in the panel. Use the Table view or Hosts Inventory CSV for the full dataset.`,
            "info", 6000
          );
        }
      }
    }
  }, 300);
});

/* ── Zoom controls ────────────────────────────────────────────────────────── */
document.getElementById("btn-zoom-in").addEventListener("click", () =>
  svg.transition().call(zoom.scaleBy, 1.4)
);
document.getElementById("btn-zoom-out").addEventListener("click", () =>
  svg.transition().call(zoom.scaleBy, 0.7)
);
document.getElementById("btn-zoom-fit").addEventListener("click", zoomFit);

// Color-by-VLAN toggle — re-renders node fills without rebuilding the simulation
document.getElementById("btn-color-vlan").addEventListener("click", () => {
  colorByVlan = !colorByVlan;
  const btn = document.getElementById("btn-color-vlan");
  btn.classList.toggle("active", colorByVlan);
  // Re-apply fill colors to all nodes in the current graph.
  // The anomaly ring is appended first and has a class ("anomaly-ring-*"), so
  // querySelector("circle") returns it for anomalous nodes instead of the main fill
  // circle. Target unambiguously: the main circle has no class attribute.
  nodesGroup.selectAll(".node circle").filter(function() {
    return !this.getAttribute("class");
  }).attr("fill", d => colorByVlan
    ? vlanColor((d.vlans && d.vlans.length) ? String(d.vlans[0]) : (d.vlan_untagged ? "untagged" : null))
    : hostColor(d.host_type)
  ).attr("stroke", d => {
    const col = colorByVlan
      ? vlanColor((d.vlans && d.vlans.length) ? String(d.vlans[0]) : (d.vlan_untagged ? "untagged" : null))
      : hostColor(d.host_type);
    const c = d3.color(col); return c ? c.brighter(0.5) : "#fff";
  });
});

function zoomFit() {
  const bounds = zoomGroup.node().getBBox();
  if (!bounds.width || !bounds.height) return;
  const svgEl = svg.node();
  const w = svgEl.clientWidth;
  const h = svgEl.clientHeight;
  const padding = 40;
  const scale = Math.min(
    (w - padding * 2) / bounds.width,
    (h - padding * 2) / bounds.height,
    2
  );
  const tx = w / 2 - scale * (bounds.x + bounds.width / 2);
  const ty = h / 2 - scale * (bounds.y + bounds.height / 2);
  svg.transition().duration(600)
    .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

/* ── Legend ──────────────────────────────────────────────────────────────── */
function buildLegend(data) {
  const hostLegend = document.getElementById("legend-hosts");
  hostLegend.innerHTML = "";
  data.stats.host_types.forEach(ht => {
    const div = document.createElement("div");
    div.className = "legend-row";
    div.innerHTML = `<span class="legend-icon">${hostIcon(ht)}</span><div class="legend-dot" style="background:${hostColor(ht)}"></div><span>${escHtml(ht)}</span>`;
    hostLegend.appendChild(div);
  });
}

/* ── Host icon ───────────────────────────────────────────────────────────── */
function hostIcon(type) {
  const icons = {
    // IT servers
    "Web Server":      "🌐",
    "DNS Server":      "🔍",
    "DHCP Server":     "🗄️",
    "SSH Server":      "🔒",
    "Telnet Server":   "💻",
    "FTP Server":      "📁",
    "Mail Server":     "✉️",
    "Database Server": "🗄️",
    "Cache Server":    "⚡",
    // IT hosts
    "Windows Host":    "🖥️",
    "Linux Host":      "🐧",
    "Linux Server":    "🐧",
    "Network Device":  "🔀",
    "Router":          "📡",
    "VPN Gateway":     "🛡️",
    "Container Host":  "📦",
    "Internet Host":   "🌍",
    "Broadcast":       "📢",
    "Multicast":       "📢",
    // OT / ICS
    "PLC":                    "⚙️",
    "RTU":                    "📟",
    "IED":                    "⚡",
    "HMI":                    "🖥️",
    "SCADA Server":           "🏭",
    "DCS":                    "🏭",
    "Historian":               "📊",
    "Engineering Workstation": "🔧",
    "Building Controller":     "🏢",
    "IoT Gateway":             "🔗",
    "Field Device":            "🔌",
    // IoT
    "IP Camera":       "📷",
    "Smart Home Hub":  "🏠",
    "Smart Meter":     "📊",
    "IoT Sensor":      "📡",
    "Smart Speaker":   "🔊",
    "CPE Device":      "📡",
  };
  return icons[type] || "❓";
}

/* ── On page load: show upload modal ─────────────────────────────────────── */
window.addEventListener("load", () => {
  loadingOverlay.classList.add("hidden");
  modalOverlay.classList.remove("hidden");
});

window.addEventListener("resize", () => {
  if (useCanvasEdges) {
    resizeEdgeCanvas();
    drawCanvasEdges();
  }
});

/* ── Packet Inspector ─────────────────────────────────────────────────────── */
const pktInspector  = document.getElementById("packet-inspector");
const pktConnLabel  = document.getElementById("pkt-conn-label");
const pktTbody      = document.getElementById("pkt-tbody");
const pktTree       = document.getElementById("pkt-tree");
const pktHex        = document.getElementById("pkt-hex");
const pktTreeEmpty  = document.getElementById("pkt-tree-empty");
const pktHexEmpty   = document.getElementById("pkt-hex-empty");

function _pktsForCurrentConn() {
  return _currentPktList;
}

document.getElementById("pkt-close").addEventListener("click", closePktInspector);
document.getElementById("pkt-tab-pkts").addEventListener("click", () => {
  const pkts = _pktsForCurrentConn();
  _switchPktTab("pkts", pkts);
  renderPktTable(pkts);
});
document.getElementById("pkt-tab-cmds").addEventListener("click", () => {
  _switchPktTab("cmds", _pktsForCurrentConn());
});

document.getElementById("pkt-tab-stream").addEventListener("click", () => {
  _switchPktTab("stream", _pktsForCurrentConn());
});

const OT_PKT_FIELDS = ["modbus","dnp3","s7comm","enip","iec104","bacnet"];

function _switchPktTab(tab, pkts) {
  const listWrap   = document.getElementById("pkt-list-wrap");
  const cmdLog     = document.getElementById("pkt-cmd-log");
  const streamView = document.getElementById("pkt-stream-view");
  const tabPkts    = document.getElementById("pkt-tab-pkts");
  const tabCmds    = document.getElementById("pkt-tab-cmds");
  const tabStream  = document.getElementById("pkt-tab-stream");
  // Hide all panes first
  listWrap.classList.add("hidden");
  cmdLog.classList.add("hidden");
  streamView.classList.add("hidden");
  tabPkts.classList.remove("active");
  tabCmds.classList.remove("active");
  tabStream.classList.remove("active");
  if (tab === "cmds") {
    cmdLog.classList.remove("hidden");
    tabCmds.classList.add("active");
    renderCmdLog(pkts);
  } else if (tab === "stream") {
    streamView.classList.remove("hidden");
    tabStream.classList.add("active");
    renderStream(pkts);
  } else {
    listWrap.classList.remove("hidden");
    tabPkts.classList.add("active");
  }
}

function renderCmdLog(pkts) {
  const cmdLog = document.getElementById("pkt-cmd-log");
  const otPkts = pkts.filter(p => OT_PKT_FIELDS.some(f => p[f]));
  if (!otPkts.length) {
    cmdLog.innerHTML = `<div style="padding:12px;color:var(--text2);font-size:12px">No OT/ICS protocol commands in this capture.</div>`;
    return;
  }
  const t0 = pkts[0]?.time || 0;
  let html = `<table class="pkt-cmd-table"><thead><tr>
    <th>Time</th><th>Protocol</th><th>Direction</th><th>Function</th><th>Detail</th><th>Result</th>
  </tr></thead><tbody>`;
  otPkts.forEach(p => {
    let proto = "", dir = "", fn = "", detail = "", result = "";
    const isW_cls = p.modbus?.is_write || p.dnp3?.is_write || p.s7comm?.is_write || p.enip?.is_write || p.iec104?.is_write || p.bacnet?.is_write;
    if (p.modbus) {
      proto = "Modbus";
      dir = p.modbus.is_response ? "←" : "→";
      fn = `FC${p.modbus.function_code} ${p.modbus.function_name}`;
      if (p.modbus.register_address != null) detail = `@${p.modbus.register_address}`;
      if (p.modbus.quantity != null) detail += ` ×${p.modbus.quantity}`;
      result = p.modbus.exception_code ? `ERR: ${escHtml(p.modbus.exception_name || p.modbus.exception_code)}` : "OK";
    } else if (p.dnp3) {
      proto = "DNP3";
      dir = p.dnp3.role === "master" ? "→" : "←";
      fn = `FC${p.dnp3.function_code} ${p.dnp3.function_name}`;
      if (p.dnp3.data_object_group) detail = p.dnp3.data_object_group;
      result = p.dnp3.is_error ? "ERR" : "OK";
    } else if (p.s7comm) {
      proto = "S7comm";
      dir = p.s7comm.rosctr === 1 ? "→" : "←";
      fn = `${p.s7comm.function_name}`;
      if (p.s7comm.block_type) { detail = p.s7comm.block_type; if (p.s7comm.block_number != null) detail += ` #${p.s7comm.block_number}`; }
      result = p.s7comm.is_error ? "ERR" : "OK";
    } else if (p.enip) {
      proto = "EtherNet/IP";
      dir = p.enip.is_response ? "←" : "→";
      fn = p.enip.cip_service_name || p.enip.command_name;
      result = p.enip.is_error ? "ERR" : "OK";
    } else if (p.iec104) {
      proto = "IEC-104";
      dir = "→";
      fn = p.iec104.type_name || p.iec104.frame_type;
      detail = p.iec104.cot_name || "";
      result = p.iec104.is_error ? "ERR" : "OK";
    } else if (p.bacnet) {
      proto = "BACnet";
      dir = "→";
      fn = p.bacnet.service_name || p.bacnet.pdu_type_name;
      result = p.bacnet.is_error ? "ERR" : "OK";
    }
    const rowCls = result.startsWith("ERR") ? "cmd-err" : (isW_cls ? "cmd-write" : "cmd-read");
    html += `<tr class="${rowCls}">
      <td>${(p.time - t0).toFixed(3)}s</td>
      <td>${proto}</td>
      <td style="font-weight:700">${dir}</td>
      <td style="font-family:var(--font-mono);font-size:11px">${escHtml(fn)}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text2)">${escHtml(detail)}</td>
      <td class="${result.startsWith("ERR") ? "cmd-result-err" : "cmd-result-ok"}">${escHtml(result)}</td>
    </tr>`;
  });
  html += "</tbody></table>";
  cmdLog.innerHTML = html;
}

function renderStream(pkts) {
  const view = document.getElementById("pkt-stream-view");
  const sorted = [...pkts].sort((a, b) => a.time - b.time);
  const payloadPkts = sorted.filter(p => p.payload_hex && p.payload_hex.length > 0);

  if (payloadPkts.length === 0) {
    view.innerHTML = '<div class="stream-empty">No payload data captured for this connection.</div>';
    return;
  }

  // Determine "client" as the src of the first packet with payload
  const clientIp = payloadPkts[0].src;

  function hexToAscii(hex) {
    let out = "";
    for (let i = 0; i < hex.length; i += 2) {
      const code = parseInt(hex.slice(i, i + 2), 16);
      out += (code >= 0x20 && code < 0x7f) ? String.fromCharCode(code) : ".";
    }
    return out;
  }

  // Merge consecutive same-direction packets into blocks
  const blocks = [];
  let cur = null;
  payloadPkts.forEach(p => {
    const dir = p.src === clientIp ? "client" : "server";
    if (!cur || cur.dir !== dir) {
      cur = { dir, chunks: [hexToAscii(p.payload_hex)], time: p.time, count: 1 };
      blocks.push(cur);
    } else {
      cur.chunks.push(hexToAscii(p.payload_hex));
      cur.count++;
    }
  });

  const frag = document.createDocumentFragment();
  blocks.forEach(b => {
    const div = document.createElement("div");
    div.className = `stream-block ${b.dir}`;
    const label = b.dir === "client" ? `→ client (+${b.time.toFixed(3)}s)` : `← server (+${b.time.toFixed(3)}s)`;
    const meta = document.createElement("div");
    meta.className = "stream-meta";
    meta.textContent = label + (b.count > 1 ? `  [${b.count} packets]` : "");
    const data = document.createElement("div");
    data.className = "stream-data";
    data.textContent = b.chunks.join("");
    div.appendChild(meta);
    div.appendChild(data);
    frag.appendChild(div);
  });
  view.innerHTML = "";
  view.appendChild(frag);
}

function openPktInspector(sid, tid) {
  const key = [sid, tid].sort().join("|");
  const pkts = packetData[key] || [];
  _currentPktList = pkts;
  pktConnLabel.textContent = `${sid}  ↔  ${tid}  ·  ${pkts.length} packet${pkts.length !== 1 ? "s" : ""} captured`;
  _switchPktTab("pkts", pkts);
  renderPktTable(pkts);
  const hasOT = pkts.some(p => OT_PKT_FIELDS.some(f => p[f]));
  document.getElementById("pkt-tab-cmds").style.display = hasOT ? "" : "none";
  const hasPayload = pkts.some(p => p.payload_hex && p.payload_hex.length > 0);
  document.getElementById("pkt-tab-stream").style.display = hasPayload ? "" : "none";
  pktInspector.classList.remove("hidden");
  graphWrap.classList.add("pkt-open");
}

function openPktInspectorForHost(ip) {
  const allPkts = [];
  for (const [key, pkts] of Object.entries(packetData)) {
    const [a, b] = key.split("|");
    if (a === ip || b === ip) allPkts.push(...pkts);
  }
  allPkts.sort((a, b) => a.time - b.time);
  _currentPktList = allPkts;
  pktConnLabel.textContent = `Host ${ip}  ·  ${allPkts.length} packet${allPkts.length !== 1 ? "s" : ""} captured`;
  _switchPktTab("pkts", allPkts);
  renderPktTable(allPkts);
  const hasOT = allPkts.some(p => OT_PKT_FIELDS.some(f => p[f]));
  document.getElementById("pkt-tab-cmds").style.display = hasOT ? "" : "none";
  const hasPayloadHost = allPkts.some(p => p.payload_hex && p.payload_hex.length > 0);
  document.getElementById("pkt-tab-stream").style.display = hasPayloadHost ? "" : "none";
  pktInspector.classList.remove("hidden");
  graphWrap.classList.add("pkt-open");
}

function closePktInspector() {
  _currentPktList = [];    // clear stale packets so tabs show nothing after close
  pktInspector.classList.add("hidden");
  graphWrap.classList.remove("pkt-open");
  document.getElementById("legend").style.bottom = "";
  document.getElementById("graph-controls").style.bottom = "";
  pktTbody.innerHTML = "";
  pktTree.innerHTML = "";
  pktHex.innerHTML = "";
  pktTreeEmpty.style.display = "block";
  pktHexEmpty.style.display = "block";
}

const PKT_PAGE_SIZE = 20;

function _appendPktRows(pkts, t0, start, end) {
  for (let i = start; i < end && i < pkts.length; i++) {
    const p = pkts[i];
    const tr = document.createElement("tr");
    tr.className = protoRowClass(p.protocol);
    const srcStr = p.src + (p.sport != null ? ":" + p.sport : "");
    const dstStr = p.dst + (p.dport != null ? ":" + p.dport : "");
    const eSrc = escHtml(srcStr), eDst = escHtml(dstStr);
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td>${(p.time - t0).toFixed(6)}</td>
      <td title="${eSrc}">${eSrc}</td>
      <td title="${eDst}">${eDst}</td>
      <td>${escHtml(p.protocol || "")}</td>
      <td>${p.len | 0}</td>
      <td title="${escHtml(p.info || "")}">${escHtml(p.info || "")}</td>
    `;
    // Cache lowercased text for O(1) search without re-materialising textContent per keystroke
    tr.dataset.searchText = tr.textContent.toLowerCase();
    tr.addEventListener("click", () => {
      pktTbody.querySelectorAll("tr.selected").forEach(r => r.classList.remove("selected"));
      tr.classList.add("selected");
      renderPktDetail(p);
    });
    pktTbody.appendChild(tr);
  }
}

function renderPktTable(pkts) {
  pktTbody.innerHTML = "";
  pktTree.innerHTML = "";
  pktHex.innerHTML = "";
  pktTreeEmpty.style.display = "block";
  pktHexEmpty.style.display = "block";

  const pktSearchEl = document.getElementById("pkt-search");
  if (pktSearchEl) pktSearchEl.value = "";

  const t0 = pkts.length ? pkts[0].time : 0;
  _appendPktRows(pkts, t0, 0, PKT_PAGE_SIZE);

  if (pkts.length > PKT_PAGE_SIZE) {
    const moreRow = document.createElement("tr");
    moreRow.innerHTML = `<td colspan="7" style="text-align:center;cursor:pointer;color:var(--accent)">Load ${pkts.length - PKT_PAGE_SIZE} more packets…</td>`;
    moreRow.addEventListener("click", () => {
      moreRow.remove();
      _appendPktRows(pkts, t0, PKT_PAGE_SIZE, pkts.length);
    });
    pktTbody.appendChild(moreRow);
  }

  applyPktSearch();
}

function protoRowClass(proto) {
  const p = (proto || "").toUpperCase();
  if (p === "HTTP")  return "pr-http";
  if (p === "HTTPS") return "pr-https";
  if (p === "DNS")   return "pr-dns";
  if (p === "SSH")   return "pr-ssh";
  if (p === "ICMP")  return "pr-icmp";
  if (p === "UDP")   return "pr-udp";
  return "pr-tcp";
}

function renderPktDetail(p) {
  pktTree.innerHTML = "";
  pktTreeEmpty.style.display = "none";
  (p.layers || []).forEach(layer => {
    const div = document.createElement("div");
    div.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> ${escHtml(layer.name || "")}`;
    hdr.addEventListener("click", () => div.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    (layer.fields || []).forEach(f => {
      const frow = document.createElement("div");
      frow.className = "pkt-field";
      frow.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv">${escHtml(String(f.v))}</span>`;
      fields.appendChild(frow);
    });
    div.appendChild(hdr);
    div.appendChild(fields);
    pktTree.appendChild(div);
  });

  // HTTP section
  if (p.http) {
    const httpDiv = document.createElement("div");
    httpDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> Hypertext Transfer Protocol`;
    hdr.addEventListener("click", () => httpDiv.classList.toggle("collapsed"));
    const content = document.createElement("div");
    content.className = "pkt-http-section";

    if (p.http.type === "request") {
      content.innerHTML = `
        <div class="pkt-http-request-line">${escHtml(p.http.method)} ${escHtml(p.http.url)} ${escHtml(p.http.version || "")}</div>
        ${buildHttpHeadersTable(p.http.headers)}
        ${p.http.body_preview ? `<div style="font-size:10px;color:var(--text2);margin-bottom:3px">Body preview:</div><pre class="pkt-http-body-preview">${escHtml(p.http.body_preview)}</pre>` : ""}
      `;
    } else if (p.http.type === "response") {
      const statusClass = p.http.status_code >= 400 ? "pkt-http-status-err" : "pkt-http-status-ok";
      content.innerHTML = `
        <div class="pkt-http-status-line ${statusClass}">${escHtml(p.http.version || "")} ${p.http.status_code} ${escHtml(p.http.reason || "")}</div>
        ${buildHttpHeadersTable(p.http.headers)}
        ${p.http.body_preview ? `<div style="font-size:10px;color:var(--text2);margin-bottom:3px">Body preview:</div><pre class="pkt-http-body-preview">${escHtml(p.http.body_preview)}</pre>` : ""}
      `;
    }

    httpDiv.appendChild(hdr);
    httpDiv.appendChild(content);
    pktTree.appendChild(httpDiv);
  }

  // Modbus section
  if (p.modbus) {
    const mb = p.modbus;
    const mbDiv = document.createElement("div");
    mbDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const fcColor = mb.is_write ? "var(--red)" : mb.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${fcColor}">Modbus TCP</span>`;
    hdr.addEventListener("click", () => mbDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const mbFields = [
      {k: "Transaction ID", v: mb.transaction_id},
      {k: "Unit ID",        v: mb.unit_id},
      {k: "Function Code",  v: `${mb.function_code} — ${mb.function_name}`},
      ...Object.entries(mb.details || {}).map(([k, v]) => ({k, v})),
    ];
    if (mb.is_write) mbFields.push({k: "⚠ WARNING", v: "WRITE command — modifies PLC state"});
    mbFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = mb.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    mbDiv.appendChild(hdr);
    mbDiv.appendChild(fields);
    pktTree.appendChild(mbDiv);
  }

  // MQTT section
  if (p.mqtt) {
    const mq = p.mqtt;
    const mqDiv = document.createElement("div");
    mqDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const mqColor = mq.type_name === "PUBLISH" ? "var(--accent)" :
                    mq.type_name === "CONNECT" ? "var(--green)" :
                    mq.type_name.startsWith("DISCONNECT") ? "var(--red)" : "var(--text)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${mqColor}">MQTT — ${escHtml(mq.type_name)}</span>`;
    hdr.addEventListener("click", () => mqDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const mqFields = [
      {k: "Message Type", v: `${mq.type} (${mq.type_name})`},
      {k: "QoS Level",    v: mq.qos},
      {k: "Retain",       v: mq.retain ? "Yes" : "No"},
      ...Object.entries(mq.details || {}).map(([k, v]) => ({k, v})),
    ];
    mqFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    mqDiv.appendChild(hdr);
    mqDiv.appendChild(fields);
    pktTree.appendChild(mqDiv);
  }

  // CoAP section
  if (p.coap) {
    const cp = p.coap;
    const cpDiv = document.createElement("div");
    cpDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const cpColor = cp.is_request ? "var(--accent)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${cpColor}">CoAP — ${escHtml(cp.code_name)}</span>`;
    hdr.addEventListener("click", () => cpDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const cpFields = [
      {k: "Type",       v: cp.type},
      {k: "Code",       v: `${cp.code} (${cp.code_name})`},
      {k: "Message ID", v: cp.message_id},
      ...Object.entries(cp.details || {}).map(([k, v]) => ({k, v})),
    ];
    cpFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    cpDiv.appendChild(hdr);
    cpDiv.appendChild(fields);
    pktTree.appendChild(cpDiv);
  }

  // DNP3 section
  if (p.dnp3) {
    const dn = p.dnp3;
    const dnDiv = document.createElement("div");
    dnDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const dnColor = dn.is_write ? "var(--red)" : dn.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${dnColor}">DNP3</span>`;
    hdr.addEventListener("click", () => dnDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const dnFields = [
      {k: "Src Address", v: dn.src_address},
      {k: "Dst Address", v: dn.dst_address},
      {k: "Function Code", v: `${dn.function_code} — ${dn.function_name}`},
      ...Object.entries(dn.details || {}).map(([k, v]) => ({k, v})),
    ];
    if (dn.is_write) dnFields.push({k: "⚠ WARNING", v: "CONTROL command — modifies RTU/IED state"});
    dnFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = dn.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    dnDiv.appendChild(hdr);
    dnDiv.appendChild(fields);
    pktTree.appendChild(dnDiv);
  }

  // S7comm section
  if (p.s7comm) {
    const s7 = p.s7comm;
    const s7Div = document.createElement("div");
    s7Div.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const s7Color = s7.is_write ? "var(--red)" : s7.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${s7Color}">S7comm</span>`;
    hdr.addEventListener("click", () => s7Div.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const s7Fields = [
      {k: "ROSCTR", v: `${s7.rosctr} — ${s7.rosctr_name}`},
      {k: "PDU Reference", v: s7.pdu_ref},
      ...(s7.function_code != null ? [{k: "Function Code", v: `0x${s7.function_code.toString(16).toUpperCase()} — ${s7.function_name}`}] : []),
      ...Object.entries(s7.details || {}).map(([k, v]) => ({k, v})),
    ];
    if (s7.is_write) s7Fields.push({k: "⚠ WARNING", v: "WRITE/CONTROL command — modifies PLC state"});
    s7Fields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = s7.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    s7Div.appendChild(hdr);
    s7Div.appendChild(fields);
    pktTree.appendChild(s7Div);
  }

  // EtherNet/IP section
  if (p.enip) {
    const ei = p.enip;
    const eiDiv = document.createElement("div");
    eiDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const eiColor = ei.is_write ? "var(--red)" : ei.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${eiColor}">EtherNet/IP</span>`;
    hdr.addEventListener("click", () => eiDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const eiFields = [
      {k: "Command", v: `${ei.command_name} (0x${ei.command.toString(16).toUpperCase()})`},
      {k: "Session Handle", v: ei.session_handle},
      {k: "Status", v: ei.status === 0 ? "OK" : `Error (${ei.status})`},
    ];
    if (ei.cip_service !== null) {
      eiFields.push({k: "CIP Service", v: `${ei.cip_service_name} (0x${ei.cip_service.toString(16).toUpperCase()})${ei.is_response ? " [Response]" : ""}`});
    }
    if (ei.is_write) eiFields.push({k: "⚠ WARNING", v: "CIP WRITE — modifies controller tag/attribute"});
    eiFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = ei.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    eiDiv.appendChild(hdr);
    eiDiv.appendChild(fields);
    pktTree.appendChild(eiDiv);
  }

  // IEC 60870-5-104 section
  if (p.iec104) {
    const ic = p.iec104;
    const icDiv = document.createElement("div");
    icDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const icColor = ic.is_write ? "var(--red)" : ic.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${icColor}">IEC 60870-5-104</span>`;
    hdr.addEventListener("click", () => icDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const icFields = [
      {k: "Frame Type", v: ic.frame_type + (ic.u_type ? ` (${ic.u_type})` : "")},
    ];
    if (ic.type_id !== null) {
      icFields.push({k: "Type ID", v: `${ic.type_id} — ${ic.type_name}`});
      icFields.push({k: "COT", v: `${ic.cot} — ${ic.cot_name}`});
      if (ic.common_address !== null) icFields.push({k: "Common Address", v: ic.common_address});
      if (ic.details && ic.details.test) icFields.push({k: "Test Flag", v: "true"});
    }
    if (ic.is_write) icFields.push({k: "⚠ WARNING", v: "CONTROL command — activates IED output"});
    icFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = ic.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    icDiv.appendChild(hdr);
    icDiv.appendChild(fields);
    pktTree.appendChild(icDiv);
  }

  // BACnet section
  if (p.bacnet) {
    const bn = p.bacnet;
    const bnDiv = document.createElement("div");
    bnDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const bnColor = bn.is_write ? "var(--red)" : bn.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${bnColor}">BACnet/IP</span>`;
    hdr.addEventListener("click", () => bnDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const bnFields = [
      {k: "BVLC Function", v: bn.bvlc_function_name},
      {k: "PDU Type", v: bn.pdu_type_name},
    ];
    if (bn.service_name !== null) bnFields.push({k: "Service", v: bn.service_name});
    if (bn.invoke_id !== null) bnFields.push({k: "Invoke ID", v: bn.invoke_id});
    if (bn.is_write) bnFields.push({k: "⚠ WARNING", v: "WRITE service — modifies building controller property"});
    bnFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = bn.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    bnDiv.appendChild(hdr);
    bnDiv.appendChild(fields);
    pktTree.appendChild(bnDiv);
  }

  // Protocol-coloured hex dump
  const hexStr = p.hex || "";
  if (!hexStr) {
    pktHex.innerHTML = "";
    pktHexEmpty.style.display = "block";
    return;
  }
  pktHexEmpty.style.display = "none";
  const bytes = [];
  for (let i = 0; i < hexStr.length; i += 2) bytes.push(parseInt(hexStr.slice(i, i + 2), 16));

  // Build per-byte color map from layer start/end offsets
  const LAYER_COLORS = {
    "Ethernet":                      "#1f4e79",
    "Internet Protocol":             "#1b4332",
    "Internet Protocol Version 6":   "#1b4332",
    "Transmission Control Protocol": "#4a1942",
    "User Datagram Protocol":        "#44370a",
    "Internet Control Message Protocol": "#3d1a00",
    "Payload":                       "#1a2a1a",
  };
  const byteColor = new Array(bytes.length).fill(null);
  const byteLayer = new Array(bytes.length).fill(null);
  (p.layers || []).forEach(layer => {
    if (layer.start == null || layer.end == null) return;
    const color = LAYER_COLORS[layer.name] || null;
    const label = layer.name;
    for (let b = layer.start; b < Math.min(layer.end, bytes.length); b++) {
      byteColor[b] = color;
      byteLayer[b] = label;
    }
  });

  const ROW = 16;
  let out = "";
  for (let off = 0; off < bytes.length; off += ROW) {
    const chunk = bytes.slice(off, off + ROW);
    const offset = off.toString(16).padStart(4, "0");

    const buildHexSpans = (slice, sliceOff) => slice.map((b, i) => {
      const bi = off + sliceOff + i;
      const col = byteColor[bi];
      const lbl = byteLayer[bi];
      const hex = b.toString(16).padStart(2, "0");
      const style = col ? ` style="background:${col};border-radius:2px"` : "";
      const title = lbl ? ` title="${escHtml(lbl)}"` : "";
      return `<span class="hx-byte"${style}${title}>${hex}</span>`;
    }).join(" ");

    const hex1 = buildHexSpans(chunk.slice(0, 8), 0);
    const hex2 = buildHexSpans(chunk.slice(8), 8);
    const hexPad = chunk.length <= 8 ? "".padEnd((8 - chunk.length) * 3) : "";
    const gap = chunk.length > 8 ? "  " : hexPad + "  ";

    const ascii = chunk.map((b, i) => {
      const bi = off + i;
      const col = byteColor[bi];
      const ch = (b >= 32 && b < 127) ? escHtml(String.fromCharCode(b)) : ".";
      return col ? `<span style="color:${col === "#1a2a1a" ? "#7ec8a0" : "#a0c8ff"};">${ch}</span>` : ch;
    }).join("");

    out += `<span class="hx-off">${offset}</span>  ${hex1}${gap}${hex2}  <span class="hx-asc">${ascii}</span>\n`;
  }
  pktHex.innerHTML = out;
}

function buildHttpHeadersTable(headers) {
  if (!headers || Object.keys(headers).length === 0) return "";
  let html = `<table class="pkt-http-headers-table">`;
  for (const [k, v] of Object.entries(headers)) {
    html += `<tr><td>${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`;
  }
  html += "</table>";
  return html;
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

function copyButton(value, title) {
  return `<button class="copy-btn" data-copy-text="${escHtml(value)}" title="${escHtml(title)}">⧉</button>`;
}

/* ── Packet inspector resize handle ──────────────────────────────────────── */
(function () {
  const handle = document.getElementById("pkt-resize-handle");
  let dragging = false, startY = 0, startH = 0;
  handle.addEventListener("mousedown", e => {
    // When floating, the separate floating-mode drag handler (bound in setFloating)
    // handles repositioning.  Let it run exclusively to avoid the panel simultaneously
    // resizing and moving when the user grabs the handle while detached.
    if (pktInspector.classList.contains("pkt-floating")) return;
    dragging = true; startY = e.clientY; startH = pktInspector.offsetHeight;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "ns-resize";
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    const newH = Math.max(120, Math.min(startH + (startY - e.clientY), window.innerHeight * 0.75));
    pktInspector.style.height = newH + "px";
    const shift = newH + 16;
    document.querySelectorAll("#graph-controls, #legend").forEach(el => {
      if (graphWrap.classList.contains("pkt-open")) el.style.bottom = shift + "px";
    });
  });
  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    document.body.style.userSelect = "";
    document.body.style.cursor = "";
  });
})();

/* ── Connection Table View ───────────────────────────────────────────────── */
/* ── Connection table with virtual scrolling ─────────────────────────────── */
const VT_ROW_H  = 34;   // must match CSS height on tbody tr
const VT_BUFFER = 8;    // extra rows rendered above and below the viewport

let _vtRows = [];        // current sorted + decorated edge array
let _sortedEdges = [];   // PF4: cached sorted edges — rebuilt only when sort key/dir or data changes
let _sortedEdgesKey = ""; // fingerprint: "nonce:col:dir"
let _sortedEdgesNonce = 0; // incremented on every loadGraph so same-edge-count uploads don't reuse stale cache

function _getSortedEdges() {
  const key = `${_sortedEdgesNonce}:${tableSort.col}:${tableSort.dir}`;
  if (key !== _sortedEdgesKey) {
    const edges = graphData?.edges || [];
    _sortedEdges = [...edges].sort((a, b) => {
      // Duration is computed on the fly (edges carry first_seen/last_seen, not duration)
      if (tableSort.col === "duration") {
        const ad = (a.last_seen != null && a.first_seen != null) ? a.last_seen - a.first_seen : -1;
        const bd = (b.last_seen != null && b.first_seen != null) ? b.last_seen - b.first_seen : -1;
        return tableSort.dir === "asc" ? ad - bd : bd - ad;
      }
      const av = a[tableSort.col] || 0, bv = b[tableSort.col] || 0;
      if (typeof av === "string")
        return tableSort.dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
      return tableSort.dir === "asc" ? av - bv : bv - av;
    });
    _sortedEdgesKey = key;
  }
  return _sortedEdges;
}

function _buildConnRows() {
  if (!graphData) return [];
  const nodeMap = {};
  graphData.nodes.forEach(n => { nodeMap[n.ip] = n; });

  return _getSortedEdges()
    .map(e => {
      const srcNode = nodeMap[e.source], dstNode = nodeMap[e.target];
      const protoOk  = (e.protocols || []).some(p => activeProtos.has(p));
      const typeOk   = (!srcNode || activeTypes.has(srcNode.host_type)) &&
                       (!dstNode || activeTypes.has(dstNode.host_type));
      const ipVerFilterActive = (graphData.stats.ip_versions || []).length > 1 &&
                                activeIpVersions.size < (graphData.stats.ip_versions || []).length;
      const ipVerOk  = !ipVerFilterActive ||
                       (!srcNode || activeIpVersions.has(String(srcNode.ip_version || 4))) &&
                       (!dstNode || activeIpVersions.has(String(dstNode.ip_version || 4)));
      const searchOk = !searchTerm ||
        e.source.includes(searchTerm) || e.target.includes(searchTerm);
      const faded    = !protoOk || !typeOk || !ipVerOk || !searchOk;
      const duration = (e.first_seen != null && e.last_seen != null)
        ? (e.last_seen - e.first_seen).toFixed(3) + "s" : "—";
      return { e, faded, duration };
    });
}

function _buildConnTr({ e, faded, duration }) {
  const tr = document.createElement("tr");
  if (faded) tr.className = "ct-faded";
  const src   = escHtml(e.source);
  const dst   = escHtml(e.target);
  const protos = (e.protocols || []).map(escHtml).join(", ");
  const ports  = (e.ports || []).slice(0, 8).map(escHtml).join(", ");
  tr.innerHTML = `
    <td title="${src}">${src}</td>
    <td title="${dst}">${dst}</td>
    <td>${protos}</td>
    <td>${fmtNum(e.packet_count)}</td>
    <td>${fmtBytes(e.bytes)}</td>
    <td>${ports}</td>
    <td>${duration}</td>
  `;
  tr.addEventListener("click", () => {
    setView("graph");
    setTimeout(() => openPktInspector(e.source, e.target), 100);
  });
  return tr;
}

function _drawConnRows() {
  const wrap  = document.getElementById("conn-table-wrap");
  const tbody = document.getElementById("conn-tbody");
  if (!wrap || !tbody) return;

  const scrollTop     = wrap.scrollTop;
  const containerH    = wrap.clientHeight;
  const start         = Math.max(0, Math.floor(scrollTop / VT_ROW_H) - VT_BUFFER);
  const end           = Math.min(_vtRows.length,
                          Math.ceil((scrollTop + containerH) / VT_ROW_H) + VT_BUFFER);

  const frag = document.createDocumentFragment();

  if (start > 0) {
    const s = document.createElement("tr");
    s.className = "vt-spacer";
    s.style.height = (start * VT_ROW_H) + "px";
    s.innerHTML = `<td colspan="7" style="padding:0;border:none"></td>`;
    frag.appendChild(s);
  }

  for (let i = start; i < end; i++) frag.appendChild(_buildConnTr(_vtRows[i]));

  const remaining = _vtRows.length - end;
  if (remaining > 0) {
    const s = document.createElement("tr");
    s.className = "vt-spacer";
    s.style.height = (remaining * VT_ROW_H) + "px";
    s.innerHTML = `<td colspan="7" style="padding:0;border:none"></td>`;
    frag.appendChild(s);
  }

  tbody.innerHTML = "";
  tbody.appendChild(frag);
}

function renderConnTable() {
  _vtRows = _buildConnRows();
  _drawConnRows();
}

// Scroll handler — redraws visible slice on scroll
let _vtScrollTimer = null;
document.getElementById("conn-table-wrap").addEventListener("scroll", () => {
  clearTimeout(_vtScrollTimer);
  _vtScrollTimer = setTimeout(_drawConnRows, 16);
});

// Table sort click handlers
document.querySelectorAll("#conn-table th.sortable").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    if (tableSort.col === col) {
      tableSort.dir = tableSort.dir === "asc" ? "desc" : "asc";
    } else {
      tableSort.col = col;
      tableSort.dir = "desc";
    }
    document.querySelectorAll("#conn-table th").forEach(h => {
      h.classList.remove("sort-asc", "sort-desc");
    });
    th.classList.add(tableSort.dir === "asc" ? "sort-asc" : "sort-desc");
    renderConnTable();
  });
});

/* ── OT Map Edit State ───────────────────────────────────────────────────── */
let otEditMode   = false;
let otFilterAll  = false;       // bypass activeTypes filter in OT map
let otLaneY      = {};          // level → y start (promoted from renderOTMap)
let otLaneH      = {};          // level → height  (promoted from renderOTMap)
let otZoom       = null;        // d3 zoom behavior (created once)
let otZoomState  = d3.zoomIdentity; // persists across re-renders

const otOverrides  = {};        // nodeId → override purdue_level
const otRiskLabels = {};        // nodeId → { label, note }
const otAddedNodes = [];        // manually added nodes
const otRemovedIds = new Set(); // manually removed node IDs

const OT_RISK_COLORS = {
  Critical: "#f85149", High: "#ff8c00", Medium: "#d29922",
  Low:      "#3fb950", Info: "#58a6ff",
};

/* ── OT Map View (Purdue Model) ──────────────────────────────────────────── */
const PURDUE_LEVELS = [
  { level: 6,   label: "L6 — Public Internet",    types: new Set([]) /* all is_private:false */ },
  { level: 5,   label: "L5 — Enterprise/Internet", types: new Set([]) /* internal corporate edge */ },
  { level: 4,   label: "L4 — Business Logistics",  types: new Set(["Windows Host","Web Server","Mail Server","Directory Server","Database Server"]) },
  { level: 3.5, label: "L3.5 — Industrial DMZ",    types: new Set(["VPN Gateway","Security Tool","Remote Desktop"]) },
  { level: 3,   label: "L3 — Supervisory / Ops",   types: new Set(["SCADA Server","Historian","Engineering Workstation"]) },
  { level: 2,   label: "L2 — Control / HMI",       types: new Set(["HMI","DCS"]) },
  { level: 1,   label: "L1 — PLC / RTU",           types: new Set(["PLC","RTU","IED","Building Controller"]) },
  { level: 0,   label: "L0 — Field Devices",       types: new Set(["Field Device","IoT Sensor","Smart Meter"]) },
  { level: -1,  label: "? — Unclassified",          types: new Set([]) /* catch-all */ },
];
const LEVEL_COLORS = {
  6: "#100a20",
  5: "#1a2a4a", 4: "#1f3a5f", 3.5: "#3a2800",
  3: "#2d5a27", 2: "#5a4a00", 1: "#5a1a00", 0: "#2a1a3a", [-1]: "#2a2a2a",
};
const PURDUE_DESC = {
  6:   "Public internet, cloud services, and external hosts (non-RFC1918 IPs)",
  5:   "Corporate network / internet edge",
  4:   "ERP, business servers, IT management",
  3.5: "Firewall/gateway buffer between OT and IT",
  3:   "Historians, SCADA servers, engineering workstations",
  2:   "HMI, DCS operator consoles",
  1:   "PLCs, RTUs, safety controllers",
  0:   "Sensors, actuators, field instruments",
  [-1]: "Devices not yet classified to a Purdue level",
};

// Zone groupings for bridge detection
const PURDUE_ZONES = [
  { name: "Public Internet", levels: new Set([6]),       color: "#2a1a5a" },
  { name: "IT Zone",         levels: new Set([5, 4]),    color: "#2a6aac" },
  { name: "Industrial DMZ",  levels: new Set([3.5]),     color: "#c87000" },
  { name: "OT Zone",         levels: new Set([3,2,1,0]), color: "#4a8a1a" },
];

function purdueLevel(node) {
  // Public internet: any non-private IP, regardless of geo data availability
  if (node.is_private === false) return 6;
  // Legacy: geo-resolved external hosts (GeoIP database present)
  if (node.country || (node.geo && node.geo.country_code)) return 5;
  for (const row of PURDUE_LEVELS) {
    if (row.types.has(node.host_type)) {
      // L4 hosts with OT protocol evidence are demoted to L3 (supervisory)
      if (row.level === 4) {
        const hasOtEvidence = (node.ot_role && node.ot_role !== "unknown")
          || (node.modbus_unit_ids && node.modbus_unit_ids.length > 0)
          || (node.dnp3_addresses && node.dnp3_addresses.length > 0);
        return hasOtEvidence ? 3 : 4;
      }
      return row.level;
    }
  }
  return -1;
}

function renderOTMap(data) {
  if (!data) return;
  if (!Array.isArray(data.nodes)) data.nodes = [];
  if (!Array.isArray(data.edges)) data.edges = [];
  const svg = document.getElementById("ot-map-svg");
  svg.innerHTML = "";

  const W = svg.parentElement.clientWidth || 900;
  const ns = "http://www.w3.org/2000/svg";

  // Layout constants
  const ZONE_HEADER_H = 28;
  const LANE_H_BASE   = 76;
  const ROW_H         = 58;
  const MAX_PER_ROW   = 8;
  const LABEL_W       = 210;
  const nodeR         = 16;

  // Zone layout — order defines top-to-bottom rendering
  const ZONE_LAYOUT = [
    { name: "Public Internet", desc: "External/internet-facing hosts (non-private IPs)",  color: "#2a1a5a", levels: [6]         },
    { name: "IT Zone",         desc: "Enterprise & business network",                     color: "#2a6aac", levels: [5, 4]      },
    { name: "Industrial DMZ",  desc: "Firewall/gateway buffer between zones",             color: "#c87000", levels: [3.5]       },
    { name: "OT Zone",         desc: "Operational Technology (ICS / SCADA)",              color: "#4a8a1a", levels: [3, 2, 1, 0]},
    { name: "Unclassified",    desc: "Devices not yet assigned to a level",               color: "#555",    levels: [-1]        },
  ];

  // Zone membership for cross-zone detection (zone boundary crossing = security concern)
  const nodeZone = (lvl) => {
    if (lvl === 6) return "Internet";
    if (lvl >= 4 && lvl <= 5) return "IT";
    if (lvl === 3.5) return "DMZ";
    if (lvl >= 0 && lvl <= 3) return "OT";
    return null;
  };

  // ── Effective node set (edit overrides + optional activeTypes filter) ──────
  let baseNodes = data.nodes.filter(n => !otRemovedIds.has(n.id));
  if (!otFilterAll && activeTypes.size > 0) {
    baseNodes = baseNodes.filter(n => activeTypes.has(n.host_type));
  }
  const effectiveNodes = [...baseNodes, ...otAddedNodes];

  // ── Compute node levels ────────────────────────────────────────────────────
  const nodeLevel = {};
  effectiveNodes.forEach(n => {
    nodeLevel[n.id] = (otOverrides[n.id] !== undefined)
      ? otOverrides[n.id]
      : (n.purdue_level !== undefined ? n.purdue_level : purdueLevel(n));
  });

  // ── Identify bridge nodes (O(E) via adjacency index, not O(N·E)) ────────────
  const peerLevelsByNode = {};
  data.edges.forEach(e => {
    if (!(e.source in peerLevelsByNode)) peerLevelsByNode[e.source] = new Set();
    if (!(e.target in peerLevelsByNode)) peerLevelsByNode[e.target] = new Set();
    peerLevelsByNode[e.source].add(nodeLevel[e.target] ?? -1);
    peerLevelsByNode[e.target].add(nodeLevel[e.source] ?? -1);
  });
  const bridgeIds = new Set();
  effectiveNodes.forEach(n => {
    const peerLevels = peerLevelsByNode[n.id] || new Set();
    const hasOT = [...peerLevels].some(l => l >= 0 && l <= 3);
    const hasIT = [...peerLevels].some(l => l >= 4 && l <= 6);
    if (hasOT && hasIT) bridgeIds.add(n.id);
  });

  // ── Build anomaly set from existing global anomalyNodeIps ─────────────────
  // anomalyNodeIps is populated by buildAnomalyList (global: ip → 'high'|'medium'|'low')
  const anomalyIpSet = new Set(Object.keys(anomalyNodeIps));

  // ── Count cross-zone (security boundary) vs cross-level (same zone) edges ─
  let crossZoneCount = 0;   // crosses IT↔DMZ, DMZ↔OT, IT↔OT boundaries
  let crossLevelCount = 0;  // different levels but same zone (e.g., L4↔L3... wait L4 is IT L3 is OT)
  data.edges.forEach(e => {
    const sl = nodeLevel[e.source] ?? -1, tl = nodeLevel[e.target] ?? -1;
    if (sl < 0 || tl < 0 || sl === tl) return;
    const sz = nodeZone(sl), tz = nodeZone(tl);
    if (sz && tz && sz !== tz) crossZoneCount++;
    else if (sz && tz && sz === tz && sl !== tl) crossLevelCount++;
  });
  const bridgeCount = bridgeIds.size;
  const anomalyCount = effectiveNodes.filter(n => anomalyIpSet.has(n.ip)).length;

  // ── Stats chips in header ─────────────────────────────────────────────────
  function chip(text, color) {
    return `<span class="ot-stat-chip" style="color:${color};border-color:${color}55;background:${color}18">${text}</span>`;
  }
  const activeLevelSet = new Set(effectiveNodes.map(n => nodeLevel[n.id] ?? -1).filter(l => l >= 0));
  document.getElementById("ot-stats-bar").innerHTML = [
    chip(`${effectiveNodes.length} devices`, "#58a6ff"),
    chip(`${activeLevelSet.size} active levels`, "#8b949e"),
    crossZoneCount > 0 ? chip(`⚠ ${crossZoneCount} cross-zone`, "#ff8c00") : chip("✓ no cross-zone", "#3fb950"),
    crossLevelCount > 0 ? chip(`${crossLevelCount} cross-level`, "#d29922") : null,
    bridgeCount > 0 ? chip(`⚠ ${bridgeCount} bridge${bridgeCount > 1 ? "s" : ""}`, "#ff6b35") : null,
    anomalyCount > 0 ? chip(`⚠ ${anomalyCount} anomal${anomalyCount > 1 ? "ies" : "y"}`, "#f85149") : null,
    !otFilterAll && activeTypes.size > 0 ? chip("filtered", "#8b949e") : null,
  ].filter(Boolean).join("");
  document.getElementById("ot-zone-count").textContent =
    crossZoneCount > 0 || bridgeCount > 0
      ? `Cross-zone traffic detected — review highlighted connections for security violations.`
      : "All connections stay within their security zone.";

  // ── Pre-pass: compute dynamic lane heights and Y positions ────────────────
  // Suppress "Public Internet" and "Unclassified" zones when they have no devices
  const activeZoneLayout = ZONE_LAYOUT.filter(zone => {
    if (zone.name === "Unclassified" || zone.name === "Public Internet") {
      return zone.levels.some(lvl =>
        effectiveNodes.some(n => (nodeLevel[n.id] ?? -1) === lvl)
      );
    }
    return true;
  });

  const laneH = {};
  const laneY = {};
  const zoneHeaderY = {};
  let currentY = 0;
  activeZoneLayout.forEach(zone => {
    zoneHeaderY[zone.name] = currentY;
    currentY += ZONE_HEADER_H;
    zone.levels.forEach(lvl => {
      const count = effectiveNodes.filter(n => (nodeLevel[n.id] ?? -1) === lvl).length;
      const numRows = Math.max(1, Math.ceil(count / MAX_PER_ROW));
      laneH[lvl] = LANE_H_BASE + (numRows - 1) * ROW_H;
      laneY[lvl] = currentY;
      currentY += laneH[lvl];
    });
  });
  const totalH = currentY || 400;
  otLaneY = laneY;
  otLaneH = laneH;

  // Detect which lanes have a high-severity anomaly (for tinting)
  const laneHasHighAnomaly = {};
  effectiveNodes.forEach(n => {
    if (anomalyNodeIps[n.ip] === "high") {
      const lvl = nodeLevel[n.id] ?? -1;
      laneHasHighAnomaly[lvl] = true;
    }
  });

  svg.setAttribute("viewBox", `0 0 ${W} ${totalH}`);
  svg.setAttribute("width", W);
  svg.setAttribute("height", totalH);
  svg.style.height = totalH + "px";

  // ── SVG defs: arrow marker for cross-zone edges ───────────────────────────
  const defs = document.createElementNS(ns, "defs");
  defs.innerHTML = `<marker id="ot-arrow" markerWidth="7" markerHeight="7" refX="5.5" refY="3.5" orient="auto">
    <path d="M0,0 L0,7 L7,3.5 z" fill="#ff8c00" opacity="0.9"/>
  </marker>`;
  svg.appendChild(defs);

  // ── Zoom group wraps all rendered content ─────────────────────────────────
  const zoomGroup = document.createElementNS(ns, "g");
  zoomGroup.setAttribute("id", "ot-zoom-group");
  svg.appendChild(zoomGroup);

  // ── SVG layers (inside zoom group) ───────────────────────────────────────
  const bgLayer   = document.createElementNS(ns, "g");
  const edgeLayer = document.createElementNS(ns, "g");
  const nodeLayer = document.createElementNS(ns, "g");
  zoomGroup.appendChild(bgLayer);
  zoomGroup.appendChild(edgeLayer);
  zoomGroup.appendChild(nodeLayer);

  // ── Draw zone header strips ───────────────────────────────────────────────
  activeZoneLayout.forEach(zone => {
    const y = zoneHeaderY[zone.name];

    const strip = document.createElementNS(ns, "rect");
    strip.setAttribute("x", 0); strip.setAttribute("y", y);
    strip.setAttribute("width", W); strip.setAttribute("height", ZONE_HEADER_H);
    strip.setAttribute("fill", zone.color); strip.setAttribute("opacity", "0.2");
    bgLayer.appendChild(strip);

    const accent = document.createElementNS(ns, "rect");
    accent.setAttribute("x", 0); accent.setAttribute("y", y);
    accent.setAttribute("width", 4); accent.setAttribute("height", ZONE_HEADER_H);
    accent.setAttribute("fill", zone.color);
    bgLayer.appendChild(accent);

    const nameEl = document.createElementNS(ns, "text");
    nameEl.setAttribute("x", 12); nameEl.setAttribute("y", y + 12);
    nameEl.setAttribute("fill", "#eee"); nameEl.setAttribute("font-size", "11");
    nameEl.setAttribute("font-weight", "700"); nameEl.setAttribute("font-family", "var(--font-mono)");
    nameEl.textContent = zone.name.toUpperCase();
    bgLayer.appendChild(nameEl);

    const descEl = document.createElementNS(ns, "text");
    descEl.setAttribute("x", 12); descEl.setAttribute("y", y + 23);
    descEl.setAttribute("fill", "#888"); descEl.setAttribute("font-size", "9");
    descEl.setAttribute("font-family", "var(--font-mono)");
    descEl.textContent = zone.desc;
    bgLayer.appendChild(descEl);
  });

  // ── Draw lane backgrounds + headers ───────────────────────────────────────
  // Only render lanes that are part of the active zone layout
  const activeLevels = new Set(activeZoneLayout.flatMap(z => z.levels));
  PURDUE_LEVELS.filter(row => activeLevels.has(row.level)).forEach(row => {
    const y = laneY[row.level];
    const h = laneH[row.level];
    if (y === undefined) return;
    const laneNodes = effectiveNodes.filter(n => (nodeLevel[n.id] ?? -1) === row.level);
    const hasAnomaly = laneHasHighAnomaly[row.level];

    // Lane background
    const bg = document.createElementNS(ns, "rect");
    bg.setAttribute("x", 0); bg.setAttribute("y", y);
    bg.setAttribute("width", W); bg.setAttribute("height", h);
    bg.setAttribute("fill", LEVEL_COLORS[row.level]); bg.setAttribute("opacity", "0.28");
    bgLayer.appendChild(bg);

    // High-anomaly tint overlay
    if (hasAnomaly) {
      const tint = document.createElementNS(ns, "rect");
      tint.setAttribute("x", 0); tint.setAttribute("y", y);
      tint.setAttribute("width", W); tint.setAttribute("height", h);
      tint.setAttribute("fill", "#f85149"); tint.setAttribute("opacity", "0.06");
      bgLayer.appendChild(tint);
    }

    // Vertical divider between label area and node canvas
    const divider = document.createElementNS(ns, "line");
    divider.setAttribute("x1", LABEL_W); divider.setAttribute("y1", y);
    divider.setAttribute("x2", LABEL_W); divider.setAttribute("y2", y + h);
    divider.setAttribute("stroke", "#333"); divider.setAttribute("stroke-width", "1");
    bgLayer.appendChild(divider);

    // Level label — with Purdue description tooltip on hover
    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("x", 8); lbl.setAttribute("y", y + 14);
    lbl.setAttribute("fill", "#ddd"); lbl.setAttribute("font-size", "11");
    lbl.setAttribute("font-weight", "600"); lbl.setAttribute("font-family", "var(--font-mono)");
    lbl.textContent = row.label;
    lbl.style.cursor = "help";
    lbl.addEventListener("mouseenter", (ev) => {
      tooltip.innerHTML = `<div class="tip-ip" style="font-size:11px">${row.label}</div>
        <div class="tip-type">${PURDUE_DESC[row.level]}</div>`;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    lbl.addEventListener("mousemove", positionTooltip);
    lbl.addEventListener("mouseleave", hideTooltip);
    bgLayer.appendChild(lbl);

    // Description subtitle
    const desc = document.createElementNS(ns, "text");
    desc.setAttribute("x", 8); desc.setAttribute("y", y + 27);
    desc.setAttribute("fill", "#666"); desc.setAttribute("font-size", "8.5");
    desc.setAttribute("font-family", "var(--font-mono)");
    desc.textContent = PURDUE_DESC[row.level] || "";
    bgLayer.appendChild(desc);

    // Device count
    if (laneNodes.length > 0) {
      const cnt = document.createElementNS(ns, "text");
      cnt.setAttribute("x", LABEL_W - 6); cnt.setAttribute("y", y + 14);
      cnt.setAttribute("fill", "#8b949e"); cnt.setAttribute("font-size", "9");
      cnt.setAttribute("font-family", "var(--font-mono)"); cnt.setAttribute("text-anchor", "end");
      cnt.textContent = `${laneNodes.length} device${laneNodes.length !== 1 ? "s" : ""}`;
      bgLayer.appendChild(cnt);
    }

    // Empty lane placeholder
    if (laneNodes.length === 0) {
      const ph = document.createElementNS(ns, "text");
      ph.setAttribute("x", LABEL_W + (W - LABEL_W) / 2); ph.setAttribute("y", y + h / 2 + 4);
      ph.setAttribute("fill", "#444"); ph.setAttribute("font-size", "11");
      ph.setAttribute("font-family", "var(--font-mono)"); ph.setAttribute("text-anchor", "middle");
      ph.setAttribute("font-style", "italic");
      ph.textContent = "no devices detected";
      bgLayer.appendChild(ph);
    }
  });

  // ── Position nodes (multi-row) ────────────────────────────────────────────
  const nodePos = {};
  PURDUE_LEVELS.filter(row => activeLevels.has(row.level)).forEach(row => {
    const laneNodes = effectiveNodes.filter(n => (nodeLevel[n.id] ?? -1) === row.level);
    if (laneY[row.level] === undefined) return;
    const usableW = W - LABEL_W - 24;
    const yTop = laneY[row.level] + 38;
    laneNodes.forEach((n, j) => {
      const rowIdx = Math.floor(j / MAX_PER_ROW);
      const colIdx = j % MAX_PER_ROW;
      const nodesInRow = Math.min(MAX_PER_ROW, laneNodes.length - rowIdx * MAX_PER_ROW);
      const x = LABEL_W + 12 + (colIdx + 0.5) * (usableW / nodesInRow);
      const y = yTop + nodeR + rowIdx * ROW_H;
      nodePos[n.id] = { x, y };
    });
  });

  // ── Draw edges: traffic-weighted, S-bend bezier curves ───────────────────
  // Build nodeEdgeMap for hover highlighting
  const nodeEdgeMap = {};   // nodeId → [pathElement]
  const allEdgePaths = [];  // all drawn path elements

  // Log-scale edge width matching force-graph edgeWidth()
  const maxPkt = data.edges.reduce((m, e) => Math.max(m, e.packet_count || 1), 1);
  const edgeW = (pkt) => 1 + Math.log1p(pkt) / Math.log1p(maxPkt) * 3;

  data.edges.forEach(e => {
    const sp = nodePos[e.source], tp = nodePos[e.target];
    if (!sp || !tp) return;
    const sl = nodeLevel[e.source] ?? -1, tl = nodeLevel[e.target] ?? -1;
    const sz = nodeZone(sl), tz = nodeZone(tl);
    const isCrossZone = sz && tz && sz !== tz;

    const rawDy = tp.y - sp.y;
    const sign = rawDy >= 0 ? 1 : -1;
    const endX = tp.x, endY = tp.y - sign * (nodeR + 3);
    const midY = (sp.y + endY) / 2;

    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", `M ${sp.x} ${sp.y} C ${sp.x} ${midY}, ${endX} ${midY}, ${endX} ${endY}`);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", isCrossZone ? "#ff8c00" : "#555");
    path.setAttribute("stroke-width", edgeW(e.packet_count || 1) * (isCrossZone ? 1.5 : 1));
    path.setAttribute("opacity", isCrossZone ? "0.85" : "0.45");
    if (isCrossZone) path.setAttribute("marker-end", "url(#ot-arrow)");

    // Edge tooltip
    path.addEventListener("mouseenter", (ev) => {
      const otR = e.ot_reads || 0, otW = e.ot_writes || 0;
      tooltip.innerHTML = `
        <div class="tip-ip" style="font-size:11px">${e.source} ↔ ${e.target}</div>
        <div class="tip-type">${fmtNum(e.packet_count || 0)} pkts · ${fmtBytes(e.bytes || 0)}</div>
        ${otR || otW ? `<div class="tip-type">OT reads: ${otR} · writes: ${otW}</div>` : ""}
        ${isCrossZone ? `<div style="color:#ff8c00;font-size:10px;margin-top:3px">⚠ Cross-zone: ${sz}→${tz}</div>` : ""}
      `;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    path.addEventListener("mousemove", positionTooltip);
    path.addEventListener("mouseleave", hideTooltip);

    edgeLayer.appendChild(path);
    allEdgePaths.push({ path, src: e.source, tgt: e.target });

    if (!nodeEdgeMap[e.source]) nodeEdgeMap[e.source] = [];
    if (!nodeEdgeMap[e.target]) nodeEdgeMap[e.target] = [];
    nodeEdgeMap[e.source].push(path);
    nodeEdgeMap[e.target].push(path);
  });

  // ── Draw nodes ────────────────────────────────────────────────────────────
  effectiveNodes.forEach(n => {
    const pos = nodePos[n.id];
    if (!pos) return;
    const lvl = nodeLevel[n.id] ?? -1;
    const levelRow = PURDUE_LEVELS.find(r => r.level === lvl);
    const isBridge = bridgeIds.has(n.id);
    const hasAnomaly = anomalyIpSet.has(n.ip);
    const anomalySev = anomalyNodeIps[n.ip];
    const connCount = data.edges.filter(e => e.source === n.id || e.target === n.id).length;
    const risk = otRiskLabels[n.id];

    const g = document.createElementNS(ns, "g");
    g.setAttribute("transform", `translate(${pos.x},${pos.y})`);
    g.style.cursor = "pointer";

    // Risk ring (outermost)
    if (risk?.label) {
      const rRing = document.createElementNS(ns, "circle");
      rRing.setAttribute("r", nodeR + (isBridge ? 12 : 6));
      rRing.setAttribute("fill",         OT_RISK_COLORS[risk.label] + "22");
      rRing.setAttribute("stroke",       OT_RISK_COLORS[risk.label]);
      rRing.setAttribute("stroke-width", "2");
      g.appendChild(rRing);
    }

    // Bridge ring
    if (isBridge) {
      const ring = document.createElementNS(ns, "circle");
      ring.setAttribute("r", nodeR + 6);
      ring.setAttribute("fill", "none");
      ring.setAttribute("stroke", "#ff8c00");
      ring.setAttribute("stroke-width", "2.5");
      ring.setAttribute("class", "bridge-ring");
      g.appendChild(ring);
    }

    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("r", nodeR);
    circle.setAttribute("fill", hostColor(n.host_type));
    circle.setAttribute("stroke", otEditMode ? "#aaa" : "#fff");
    circle.setAttribute("stroke-width", "1.5");
    g.appendChild(circle);

    const icon = document.createElementNS(ns, "text");
    icon.setAttribute("text-anchor", "middle"); icon.setAttribute("dy", "0.35em");
    icon.setAttribute("font-size", "12");
    icon.textContent = hostIcon(n.host_type);
    g.appendChild(icon);

    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("text-anchor", "middle"); lbl.setAttribute("dy", nodeR + 12);
    lbl.setAttribute("fill", "#bbb"); lbl.setAttribute("font-size", "9");
    lbl.setAttribute("font-family", "var(--font-mono)");
    lbl.textContent = n.hostname || n.ip;
    g.appendChild(lbl);

    // Risk badge below label
    if (risk?.label) {
      const badge = document.createElementNS(ns, "text");
      badge.setAttribute("text-anchor", "middle"); badge.setAttribute("dy", nodeR + 24);
      badge.setAttribute("fill", OT_RISK_COLORS[risk.label]);
      badge.setAttribute("font-size", "8"); badge.setAttribute("font-weight", "700");
      badge.setAttribute("font-family", "var(--font-mono)");
      badge.textContent = risk.label.toUpperCase();
      g.appendChild(badge);
    }

    // Anomaly badge (! circle, top-right of node)
    if (hasAnomaly && !risk?.label) {
      const badgeR = 6;
      const badgeCx = nodeR - 1, badgeCy = -(nodeR - 1);
      const badgeColor = anomalySev === "high" ? "#f85149" : anomalySev === "medium" ? "#d29922" : "#58a6ff";
      const bc = document.createElementNS(ns, "circle");
      bc.setAttribute("cx", badgeCx); bc.setAttribute("cy", badgeCy);
      bc.setAttribute("r", badgeR); bc.setAttribute("fill", badgeColor);
      bc.setAttribute("stroke", "#0d1117"); bc.setAttribute("stroke-width", "1.5");
      g.appendChild(bc);
      const bt = document.createElementNS(ns, "text");
      bt.setAttribute("x", badgeCx); bt.setAttribute("y", badgeCy);
      bt.setAttribute("text-anchor", "middle"); bt.setAttribute("dominant-baseline", "central");
      bt.setAttribute("font-size", "8"); bt.setAttribute("font-weight", "700");
      bt.setAttribute("fill", "#fff"); bt.setAttribute("pointer-events", "none");
      bt.textContent = "!";
      g.appendChild(bt);
    }

    // Edit mode: delete "×" button
    if (otEditMode) {
      const del = document.createElementNS(ns, "text");
      del.setAttribute("x", nodeR - 1); del.setAttribute("y", -nodeR + 1);
      del.setAttribute("fill", "#f85149"); del.setAttribute("font-size", "13");
      del.setAttribute("font-weight", "700"); del.setAttribute("text-anchor", "middle");
      del.setAttribute("dominant-baseline", "middle");
      del.style.cursor = "pointer";
      del.textContent = "×";
      del.addEventListener("click", e => {
        e.stopPropagation();
        otRemovedIds.add(n.id);
        const ai = otAddedNodes.findIndex(a => a.id === n.id);
        if (ai !== -1) otAddedNodes.splice(ai, 1);
        renderOTMap(data);
      });
      g.appendChild(del);
    }

    // Custom tooltip (replaces native SVG <title>)
    g.addEventListener("mouseenter", (ev) => {
      // Highlight connected edges, dim others
      if (allEdgePaths.length > 0) {
        const connectedPaths = new Set(nodeEdgeMap[n.id] || []);
        allEdgePaths.forEach(({ path }) => {
          path.style.opacity = connectedPaths.has(path) ? "1" : "0.08";
        });
      }
      if (!otEditMode) g.setAttribute("transform", `translate(${pos.x},${pos.y}) scale(1.1)`);

      const levelLabel = escHtml(levelRow ? levelRow.label : "Unclassified");
      const safeIp      = escHtml(n.ip);
      const safeType    = escHtml(n.host_type || "Unknown Host");
      const anomalyLine = anomalySev
        ? `<div style="color:${anomalySev === "high" ? "var(--red)" : anomalySev === "medium" ? "var(--yellow)" : "var(--accent)"};margin-top:3px;font-size:10px">⚠ ${escHtml(anomalySev.toUpperCase())} anomaly</div>`
        : "";
      const protos = (n.protocols || []);
      tooltip.innerHTML = `
        <div class="tip-ip">${safeIp}${n.hostname ? `<span style="color:var(--text2)"> (${escHtml(n.hostname)})</span>` : ""}</div>
        <div class="tip-type">${safeType} · ${levelLabel}</div>
        ${protos.length ? `<div class="tip-proto">${protos.slice(0,6).map(p => `<span style="color:${PROTO_COLORS[p]||'#aaa'}">${escHtml(p)}</span>`).join(" · ")}</div>` : ""}
        <div class="tip-type" style="margin-top:4px">${connCount} connection${connCount !== 1 ? "s" : ""}${isBridge ? " · <span style='color:#ff8c00'>⚠ bridge</span>" : ""}</div>
        ${risk?.label ? `<div style="color:${OT_RISK_COLORS[risk.label]};font-size:10px">Risk: ${escHtml(risk.label)}${risk.note ? " — " + escHtml(risk.note) : ""}</div>` : ""}
        ${anomalyLine}
      `;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    g.addEventListener("mousemove", positionTooltip);
    g.addEventListener("mouseleave", () => {
      g.setAttribute("transform", `translate(${pos.x},${pos.y})`);
      // Restore all edge opacities
      allEdgePaths.forEach(({ path, src, tgt }) => {
        const sl = nodeLevel[src] ?? -1, tl = nodeLevel[tgt] ?? -1;
        const sz = nodeZone(sl), tz = nodeZone(tl);
        const isCross = sz && tz && sz !== tz;
        path.style.opacity = isCross ? "0.85" : "0.45";
      });
      hideTooltip();
    });

    // Click: risk panel in edit mode, detail panel otherwise
    g.addEventListener("click", e => {
      if (otEditMode) { e.stopPropagation(); showOTRiskPanel(n, pos, svg); }
      else { selectedNode = n; showDetailPanel(n); detailPanel.classList.add("open"); }
    });

    // Drag to reclassify (edit mode only)
    if (otEditMode) {
      g.addEventListener("mousedown", e => startOTDrag(e, n, pos, svg, zoomGroup));
    }

    nodeLayer.appendChild(g);
  });

  // ── Attach D3 zoom ───────────────────────────────────────────────────────
  if (!otZoom) {
    otZoom = d3.zoom()
      .scaleExtent([0.15, 6])
      .filter(event => {
        // Ctrl+wheel zooms; plain wheel scrolls the container; drag pans
        if (event.type === "wheel") return event.ctrlKey || event.metaKey;
        return !event.button;
      })
      .on("zoom", (event) => {
        otZoomState = event.transform;
        const zg = document.getElementById("ot-zoom-group");
        if (zg) d3.select(zg).attr("transform", event.transform);
      });
  }
  d3.select(svg).call(otZoom);
  d3.select(svg).call(otZoom.transform, otZoomState);

  // ── Render legend ─────────────────────────────────────────────────────────
  renderOTLegend();
}

/* ── OT Map legend ───────────────────────────────────────────────────────── */
function renderOTLegend() {
  const header = document.getElementById("ot-map-header");
  let legend = document.getElementById("ot-legend");
  if (!legend) {
    legend = document.createElement("div");
    legend.id = "ot-legend";
    header.appendChild(legend);
  }
  const zoneSwatches = [
    { label: "IT Zone",   color: "#2a6aac" },
    { label: "Ind. DMZ",  color: "#c87000" },
    { label: "OT Zone",   color: "#4a8a1a" },
  ];
  const riskDots = Object.entries(OT_RISK_COLORS).map(([k, c]) =>
    `<span class="ot-legend-group"><span class="ot-legend-dot" style="background:${c}"></span>${k}</span>`
  ).join("");
  const zoneHtml = zoneSwatches.map(s =>
    `<span class="ot-legend-group"><span class="ot-legend-swatch" style="background:${s.color}44;border:1px solid ${s.color}"></span>${s.label}</span>`
  ).join("");
  legend.innerHTML = `
    <span style="font-size:9px;color:var(--text2);font-family:var(--font-mono);margin-right:4px">Zones:</span>${zoneHtml}
    <span style="font-size:9px;color:var(--text2);font-family:var(--font-mono);margin:0 4px">Risk:</span>${riskDots}
    <span class="ot-legend-group"><svg width="22" height="10"><circle cx="5" cy="5" r="4" fill="none" stroke="#ff8c00" stroke-width="1.5"/></svg>bridge</span>
    <span class="ot-legend-group"><svg width="28" height="10"><line x1="0" y1="5" x2="28" y2="5" stroke="#ff8c00" stroke-width="1.5"/></svg>cross-zone</span>
    <span class="ot-legend-group"><svg width="28" height="10"><line x1="0" y1="5" x2="28" y2="5" stroke="#555" stroke-width="1.5"/></svg>same-zone</span>
    <span style="font-size:9px;color:var(--text2);font-family:var(--font-mono)">Ctrl+scroll or +/− to zoom · drag to pan</span>
  `;
}

/* ── OT Map drag-to-reclassify ───────────────────────────────────────────── */
function startOTDrag(evt, node, origPos, svgEl, zoomGroup) {
  evt.preventDefault(); evt.stopPropagation();
  const ns = "http://www.w3.org/2000/svg";
  const svgRect = svgEl.getBoundingClientRect();
  const svgW = parseFloat(svgEl.getAttribute("width"))  || svgRect.width;
  const svgH = parseFloat(svgEl.getAttribute("height")) || svgRect.height;
  const scaleX = svgW / svgRect.width;
  const scaleY = svgH / svgRect.height;

  // Ghost and highlight rect live in the zoom group so their coordinates match content space
  const group = zoomGroup || svgEl;

  const ghost = document.createElementNS(ns, "circle");
  ghost.setAttribute("r", 16); ghost.setAttribute("fill", hostColor(node.host_type));
  ghost.setAttribute("opacity", "0.55"); ghost.setAttribute("stroke", "#fff");
  ghost.setAttribute("stroke-width", "2"); ghost.setAttribute("pointer-events", "none");
  group.appendChild(ghost);

  const hi = document.createElementNS(ns, "rect");
  hi.setAttribute("x", 0); hi.setAttribute("width", svgW);
  hi.setAttribute("fill", "#ffffff"); hi.setAttribute("opacity", "0.07");
  hi.setAttribute("pointer-events", "none"); hi.setAttribute("height", 0);
  group.appendChild(hi);

  let targetLevel = null;

  function onMove(e) {
    // Re-read bounding rect each move to handle window resize/scroll during drag
    const liveRect = svgEl.getBoundingClientRect();
    const liveSvgW = parseFloat(svgEl.getAttribute("width"))  || liveRect.width;
    const liveSvgH = parseFloat(svgEl.getAttribute("height")) || liveRect.height;
    const liveScaleX = liveSvgW / liveRect.width;
    const liveScaleY = liveSvgH / liveRect.height;
    // Convert screen coords to SVG user space, then to zoom-group content space
    const svgX = (e.clientX - liveRect.left) * liveScaleX;
    const svgY = (e.clientY - liveRect.top)  * liveScaleY;
    const k = Math.max(0.01, otZoomState.k); // guard against zero scale
    const contentX = (svgX - otZoomState.x) / k;
    const contentY = (svgY - otZoomState.y) / k;
    ghost.setAttribute("cx", contentX); ghost.setAttribute("cy", contentY);
    targetLevel = null;
    for (const [lvlStr, y] of Object.entries(otLaneY)) {
      const lvl = parseFloat(lvlStr);
      const h   = otLaneH[lvl] ?? 76;
      if (contentY >= y && contentY < y + h) {
        targetLevel = lvl;
        hi.setAttribute("y", y); hi.setAttribute("height", h);
        return;
      }
    }
    hi.setAttribute("height", 0);
  }

  function onUp() {
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup",   onUp);
    if (group.contains(ghost)) group.removeChild(ghost);
    if (group.contains(hi)) group.removeChild(hi);
    const currentLvl = otOverrides[node.id] ?? node.purdue_level ?? purdueLevel(node);
    if (targetLevel !== null && targetLevel !== currentLvl) {
      otOverrides[node.id] = targetLevel;
      renderOTMap(graphData);
    }
  }

  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup",   onUp);
}

/* ── OT Map risk annotation panel ───────────────────────────────────────── */
function showOTRiskPanel(node, nodePos, svgEl) {
  const panel    = document.getElementById("ot-risk-panel");
  const existing = otRiskLabels[node.id] || { label: "", note: "" };
  document.getElementById("ot-rp-label").textContent = node.hostname || node.ip;
  document.getElementById("ot-rp-note").value = existing.note || "";

  const btns = document.getElementById("ot-rp-btns");
  btns.innerHTML = Object.entries(OT_RISK_COLORS).map(([lvl, col]) =>
    `<button class="ot-risk-btn${existing.label === lvl ? " active" : ""}"
      data-level="${lvl}" style="border-color:${col};color:${col}">${lvl}</button>`
  ).join("") +
  `<button class="ot-risk-btn" data-level="" style="border-color:#555;color:#666">✕ Clear</button>`;

  btns.querySelectorAll(".ot-risk-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const lbl  = btn.dataset.level;
      const note = document.getElementById("ot-rp-note").value.trim();
      if (!lbl) { delete otRiskLabels[node.id]; }
      else      { otRiskLabels[node.id] = { label: lbl, note }; }
      panel.classList.add("hidden");
      renderOTMap(graphData);
    });
  });

  // Position near the clicked node, clamped to viewport
  if (nodePos && svgEl) {
    const svgRect = svgEl.getBoundingClientRect();
    const svgW = parseFloat(svgEl.getAttribute("width")) || svgRect.width;
    const svgH = parseFloat(svgEl.getAttribute("height")) || svgRect.height;
    const scaleX = svgRect.width / svgW;
    const scaleY = svgRect.height / svgH;
    // Convert content coords → screen coords accounting for zoom
    const screenX = (nodePos.x * otZoomState.k + otZoomState.x) * scaleX + svgRect.left;
    const screenY = (nodePos.y * otZoomState.k + otZoomState.y) * scaleY + svgRect.top;
    const container = document.getElementById("ot-map-view").getBoundingClientRect();
    const panelW = 220, panelH = 160;
    let left = screenX - container.left + 20;
    let top  = screenY - container.top  - panelH / 2;
    // Clamp to container bounds
    left = Math.max(8, Math.min(container.width - panelW - 8, left));
    top  = Math.max(8, Math.min(container.height - panelH - 8, top));
    panel.style.left  = left + "px";
    panel.style.top   = top  + "px";
    panel.style.right = "auto";
  } else {
    panel.style.top   = "80px";
    panel.style.right = "12px";
    panel.style.left  = "auto";
  }
  panel.classList.remove("hidden");
}

/* ── OT Map export (PNG + JSON) ──────────────────────────────────────────── */
function exportOTMapPng() {
  if (!graphData) return;
  const DPR      = window.devicePixelRatio || 2;
  const HEADER_H = 56;
  const FOOTER_H = 48;
  const PAD      = 12;

  // Save zoom state; reset zoom group to identity so full diagram is captured
  const zoomGroup = document.getElementById("ot-zoom-group");
  const savedTransform = zoomGroup ? zoomGroup.getAttribute("transform") : null;
  if (zoomGroup) zoomGroup.setAttribute("transform", "translate(0,0) scale(1)");

  // Clone SVG; compute bounding box of the zoom-group content for fit-to-full export
  const svgEl  = document.getElementById("ot-map-svg");
  let svgW   = parseFloat(svgEl.getAttribute("width"))  || 900;
  let svgH   = parseFloat(svgEl.getAttribute("height")) || 600;
  let viewBox = null;
  if (zoomGroup) {
    try {
      const bb = zoomGroup.getBBox();
      if (bb.width > 0 && bb.height > 0) {
        const P = 20;
        viewBox = `${bb.x - P} ${bb.y - P} ${bb.width + P * 2} ${bb.height + P * 2}`;
        svgW = bb.width + P * 2;
        svgH = bb.height + P * 2;
      }
    } catch(_) {}
  }
  const clone  = svgEl.cloneNode(true);
  if (viewBox) clone.setAttribute("viewBox", viewBox);
  clone.setAttribute("width",  svgW);
  clone.setAttribute("height", svgH);
  const bgRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  bgRect.setAttribute("x", viewBox ? viewBox.split(" ")[0] : "0");
  bgRect.setAttribute("y", viewBox ? viewBox.split(" ")[1] : "0");
  bgRect.setAttribute("width",  viewBox ? viewBox.split(" ")[2] : svgW);
  bgRect.setAttribute("height", viewBox ? viewBox.split(" ")[3] : svgH);
  bgRect.setAttribute("fill", "#0d1117");
  clone.insertBefore(bgRect, clone.firstChild);
  const svgStr = new XMLSerializer().serializeToString(clone);
  const url    = URL.createObjectURL(new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" }));

  // Restore zoom immediately so the interactive view is not disrupted
  if (zoomGroup && savedTransform !== null) zoomGroup.setAttribute("transform", savedTransform);

  // Build 2× canvas: header + diagram + footer
  const totalH = HEADER_H + svgH + FOOTER_H;
  const canvas  = document.createElement("canvas");
  canvas.width  = Math.round(svgW   * DPR);
  canvas.height = Math.round(totalH * DPR);
  const ctx = canvas.getContext("2d");
  ctx.scale(DPR, DPR);

  const img = new Image();
  img.onload = () => {
    // Background
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, svgW, totalH);

    // ── Diagram ──────────────────────────────────────────────────────────────
    ctx.drawImage(img, 0, HEADER_H, svgW, svgH);
    URL.revokeObjectURL(url);

    // ── Header strip ─────────────────────────────────────────────────────────
    ctx.fillStyle = "#161b22";
    ctx.fillRect(0, 0, svgW, HEADER_H);
    // Divider line
    ctx.fillStyle = "#30363d";
    ctx.fillRect(0, HEADER_H - 1, svgW, 1);

    ctx.fillStyle = "#e6edf3";
    ctx.font = "bold 15px monospace";
    ctx.fillText("OT Network Security Map", PAD, 22);

    const statsText = (document.getElementById("ot-stats-bar")?.textContent || "")
      .replace(/\s+/g, " ").trim().slice(0, 130);
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.fillText(statsText, PAD, 40);

    ctx.textAlign = "right";
    ctx.fillStyle = "#444c56";
    ctx.font = "10px monospace";
    ctx.fillText(new Date().toLocaleString(), svgW - PAD, 22);
    ctx.textAlign = "left";

    // ── Footer legend strip ───────────────────────────────────────────────────
    const footerY = HEADER_H + svgH;
    ctx.fillStyle = "#161b22";
    ctx.fillRect(0, footerY, svgW, FOOTER_H);
    ctx.fillStyle = "#30363d";
    ctx.fillRect(0, footerY, svgW, 1);

    ctx.fillStyle = "#555";
    ctx.font = "9px monospace";
    ctx.fillText("ZONES:", PAD, footerY + 14);

    let lx = PAD + 50;
    [
      { label: "IT Zone",  color: "#2a6aac" },
      { label: "Ind. DMZ", color: "#c87000" },
      { label: "OT Zone",  color: "#2d6b2d" },
    ].forEach(z => {
      ctx.fillStyle = z.color + "44";
      ctx.strokeStyle = z.color;
      ctx.lineWidth = 1;
      ctx.fillRect(lx, footerY + 5, 13, 9);
      ctx.strokeRect(lx, footerY + 5, 13, 9);
      ctx.fillStyle = "#8b949e";
      ctx.font = "9px monospace";
      ctx.fillText(z.label, lx + 16, footerY + 14);
      lx += 16 + ctx.measureText(z.label).width + 10;
    });

    lx += 8;
    ctx.fillStyle = "#555";
    ctx.fillText("RISK:", lx, footerY + 14);
    lx += ctx.measureText("RISK:").width + 8;

    Object.entries(OT_RISK_COLORS).forEach(([name, color]) => {
      ctx.beginPath();
      ctx.arc(lx + 4, footerY + 9, 4, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.fillStyle = "#8b949e";
      ctx.font = "9px monospace";
      ctx.fillText(name, lx + 11, footerY + 13);
      lx += 11 + ctx.measureText(name).width + 8;
    });

    // Cross-zone edge indicator
    lx += 6;
    ctx.strokeStyle = "#ff8c00";
    ctx.lineWidth = 2;
    ctx.setLineDash([3, 2]);
    ctx.beginPath();
    ctx.moveTo(lx, footerY + 9);
    ctx.lineTo(lx + 20, footerY + 9);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "#8b949e";
    ctx.font = "9px monospace";
    ctx.fillText("cross-zone", lx + 24, footerY + 13);

    // Trigger download
    const a = document.createElement("a");
    a.download = `ot-map-${new Date().toISOString().slice(0, 10)}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
  };
  img.src = url;
}

function exportOTMatrixPng() {
  if (!graphData) return;
  const DPR = window.devicePixelRatio || 2;
  const LABEL_W = 96, LABEL_H = 96;
  const colsSvg  = document.getElementById("ot-matrix-cols");
  const rowsSvg  = document.getElementById("ot-matrix-rows");
  const cellsSvg = document.getElementById("ot-matrix-cells");
  const colsW  = parseFloat(colsSvg.getAttribute("width"))  || 0;
  const rowsH  = parseFloat(rowsSvg.getAttribute("height")) || 0;
  const cellsW = parseFloat(cellsSvg.getAttribute("width")) || 0;
  const cellsH = parseFloat(cellsSvg.getAttribute("height")) || 0;
  if (cellsW === 0) return;
  const totalW = LABEL_W + cellsW;
  const totalH = LABEL_H + cellsH;

  const serializeSvg = (svgEl, w, h) => {
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("width", w); bg.setAttribute("height", h); bg.setAttribute("fill", "#0d1117");
    const clone = svgEl.cloneNode(true);
    clone.insertBefore(bg, clone.firstChild);
    return new XMLSerializer().serializeToString(clone);
  };
  const loadImg = (svgStr) => new Promise(resolve => {
    const url = URL.createObjectURL(new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" }));
    const img = new Image();
    img.onload = () => resolve({ img, url });
    img.src = url;
  });

  Promise.all([
    loadImg(serializeSvg(colsSvg, colsW, LABEL_H)),
    loadImg(serializeSvg(rowsSvg, LABEL_W, rowsH)),
    loadImg(serializeSvg(cellsSvg, cellsW, cellsH)),
  ]).then(([cols, rows, cells]) => {
    const canvas = document.createElement("canvas");
    canvas.width  = Math.round(totalW * DPR);
    canvas.height = Math.round(totalH * DPR);
    const ctx = canvas.getContext("2d");
    ctx.scale(DPR, DPR);
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, totalW, totalH);
    ctx.drawImage(cols.img,  LABEL_W, 0,       colsW,  LABEL_H);
    ctx.drawImage(rows.img,  0,       LABEL_H, LABEL_W, rowsH);
    ctx.drawImage(cells.img, LABEL_W, LABEL_H, cellsW,  cellsH);
    [cols, rows, cells].forEach(x => URL.revokeObjectURL(x.url));
    const a = document.createElement("a");
    a.download = `ot-matrix-${new Date().toISOString().slice(0, 10)}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
  });
}

function exportOTMapJson() {
  if (!graphData) return;
  const effectiveNodes = [
    ...graphData.nodes.filter(n => !otRemovedIds.has(n.id)),
    ...otAddedNodes,
  ];
  const nodeLvl = {};
  effectiveNodes.forEach(n => {
    nodeLvl[n.id] = (otOverrides[n.id] !== undefined)
      ? otOverrides[n.id]
      : (n.purdue_level !== undefined ? n.purdue_level : purdueLevel(n));
  });
  const payload = {
    exported_at: new Date().toISOString(),
    edit_session: {
      level_overrides: Object.keys(otOverrides).length,
      risk_labels:     Object.keys(otRiskLabels).length,
      added_nodes:     otAddedNodes.length,
      removed_nodes:   otRemovedIds.size,
    },
    nodes: effectiveNodes.map(n => ({
      ip: n.ip, hostname: n.hostname || null,
      host_type: n.host_type,
      purdue_level: nodeLvl[n.id],
      purdue_level_original: n.purdue_level ?? purdueLevel(n),
      purdue_level_overridden: otOverrides[n.id] !== undefined,
      risk_label: otRiskLabels[n.id]?.label || null,
      risk_note:  otRiskLabels[n.id]?.note  || null,
      protocols:  n.protocols,
      mac: n.mac, mac_vendor: n.mac_vendor,
      is_private: n.is_private,
      added_manually: n.added_manually || false,
    })),
    edges: graphData.edges
      .filter(e => !otRemovedIds.has(e.source) && !otRemovedIds.has(e.target))
      .map(e => ({ source: e.source, target: e.target,
        protocols: e.protocols, packet_count: e.packet_count, bytes: e.bytes })),
  };
  const ts   = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `ot-map-${ts}.json`; a.click();
  URL.revokeObjectURL(url);
}

/* ── OT Anomaly Timeline ─────────────────────────────────────────────────── */
function renderOTTimeline() {
  const strip = document.getElementById("ot-timeline-strip");
  const svgEl = document.getElementById("ot-timeline-svg");
  if (!graphData || !strip || !svgEl) return;

  const anomalies  = (graphData.anomalies || []).filter(a => a.first_seen != null);
  const capStart   = graphData.stats?.capture_start;
  const capEnd     = graphData.stats?.capture_end;

  if (!capStart || !capEnd || capEnd <= capStart || anomalies.length === 0) {
    strip.classList.add("hidden");
    return;
  }
  strip.classList.remove("hidden");

  const W = strip.clientWidth || 800;
  const H = 52;
  svgEl.setAttribute("width", W);
  svgEl.setAttribute("height", H);
  svgEl.innerHTML = "";
  const ns   = "http://www.w3.org/2000/svg";
  const LPAD = 52;
  const RPAD = 10;
  const span = capEnd - capStart;
  const xOf  = (ts) => LPAD + ((ts - capStart) / span) * (W - LPAD - RPAD);

  const SEV_COLORS = { high: "#f85149", medium: "#ff8c00", low: "#3fb950" };
  const axisY = 34;

  // Axis
  const axisLine = document.createElementNS(ns, "line");
  axisLine.setAttribute("x1", LPAD); axisLine.setAttribute("x2", W - RPAD);
  axisLine.setAttribute("y1", axisY); axisLine.setAttribute("y2", axisY);
  axisLine.setAttribute("stroke", "#333"); axisLine.setAttribute("stroke-width", "1");
  svgEl.appendChild(axisLine);

  // "Anomaly" label
  const lbl = document.createElementNS(ns, "text");
  lbl.setAttribute("x", 4); lbl.setAttribute("y", axisY + 4);
  lbl.setAttribute("fill", "#555"); lbl.setAttribute("font-size", "9");
  lbl.setAttribute("font-family", "monospace");
  lbl.textContent = "Anomaly";
  svgEl.appendChild(lbl);

  // Start / end time labels
  const fmt = (ts) => new Date(ts * 1000).toISOString().slice(11, 19);
  const t1 = document.createElementNS(ns, "text");
  t1.setAttribute("x", LPAD); t1.setAttribute("y", H - 3);
  t1.setAttribute("fill", "#444"); t1.setAttribute("font-size", "8");
  t1.setAttribute("font-family", "monospace");
  t1.textContent = fmt(capStart);
  svgEl.appendChild(t1);

  const t2 = document.createElementNS(ns, "text");
  t2.setAttribute("x", W - RPAD); t2.setAttribute("y", H - 3);
  t2.setAttribute("fill", "#444"); t2.setAttribute("font-size", "8");
  t2.setAttribute("font-family", "monospace");
  t2.setAttribute("text-anchor", "end");
  t2.textContent = fmt(capEnd);
  svgEl.appendChild(t2);

  // One tick per anomaly
  anomalies.forEach(a => {
    const x     = xOf(a.first_seen);
    const color = SEV_COLORS[a.severity] || "#58a6ff";

    const tick = document.createElementNS(ns, "line");
    tick.setAttribute("x1", x); tick.setAttribute("x2", x);
    tick.setAttribute("y1", axisY - 13); tick.setAttribute("y2", axisY + 3);
    tick.setAttribute("stroke", color); tick.setAttribute("stroke-width", "2");
    tick.setAttribute("opacity", "0.85");
    tick.style.cursor = "pointer";

    tick.addEventListener("mouseenter", (ev) => {
      const srcStr = a.src || "";
      const dstStr = a.dst && a.dst !== a.src ? ` → ${a.dst}` : "";
      tooltip.innerHTML = `
        <div class="tip-ip">${escHtml(a.type)}</div>
        <div class="tip-type">${escHtml(srcStr + dstStr)}</div>
        <div class="tip-type">${escHtml(a.description || "")}</div>
        <div style="color:${color};font-size:10px;margin-top:3px">${(a.severity || "").toUpperCase()}</div>
      `;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    tick.addEventListener("mousemove", positionTooltip);
    tick.addEventListener("mouseleave", hideTooltip);

    tick.addEventListener("click", () => {
      if (otMatrixMode) {
        otMatrixMode = false;
        document.getElementById("ot-matrix-btn").classList.remove("active");
        document.getElementById("ot-map-svg").classList.remove("hidden");
        document.getElementById("ot-matrix-container").classList.add("hidden");
      }
      if (a.src) {
        const node = graphData.nodes.find(n => n.ip === a.src);
        if (node) showDetailPanel(node);
      }
    });

    svgEl.appendChild(tick);
  });
}

/* ── OT Communication Matrix ─────────────────────────────────────────────── */
let otMatrixMode = false;

function renderOTMatrix(data) {
  if (!data) return;
  const ns = "http://www.w3.org/2000/svg";
  const CELL = 20, LABEL_W = 96, LABEL_H = 96;

  const truncMid = (s, max) =>
    s.length <= max ? s : s.slice(0, Math.ceil(max / 2 - 1)) + "…" + s.slice(-(Math.floor(max / 2 - 1)));

  // Build effective node set
  let baseNodes = data.nodes.filter(n => !otRemovedIds.has(n.id));
  if (!otFilterAll && activeTypes.size > 0)
    baseNodes = baseNodes.filter(n => activeTypes.has(n.host_type));
  const effectiveNodes = [...baseNodes, ...otAddedNodes];

  const connCount = {};
  effectiveNodes.forEach(n => { connCount[n.id] = 0; });
  data.edges.forEach(e => {
    if (connCount[e.source] !== undefined) connCount[e.source]++;
    if (connCount[e.target] !== undefined) connCount[e.target]++;
  });

  const nodeZone = (n) => {
    // Use the manual override first, then the stored purdue_level, then fall back to
    // purdueLevel() inference — matching the OT map's nodeLevel computation so nodes
    // without a pre-computed purdue_level are still zoned correctly.
    let lvl = (otOverrides && otOverrides[n.id] !== undefined) ? otOverrides[n.id] : n.purdue_level;
    if (lvl === undefined || lvl === null) lvl = purdueLevel(n);
    if (lvl === 6) return "Internet";
    if (lvl >= 4)  return "IT";
    if (lvl === 3.5) return "DMZ";
    if (lvl >= 0)  return "OT";
    return null;
  };

  // Sort by zone then connection count
  const ZONE_ORDER = { OT: 0, DMZ: 1, IT: 2, Internet: 3 };
  const totalNodes = effectiveNodes.length;
  const matrixNodes = [...effectiveNodes]
    .sort((a, b) => {
      const za = ZONE_ORDER[nodeZone(a)] ?? 9;
      const zb = ZONE_ORDER[nodeZone(b)] ?? 9;
      if (za !== zb) return za - zb;
      return (connCount[b.id] || 0) - (connCount[a.id] || 0);
    })
    .slice(0, 40);
  const N = matrixNodes.length;

  const colsSvg  = document.getElementById("ot-matrix-cols");
  const rowsSvg  = document.getElementById("ot-matrix-rows");
  const cellsSvg = document.getElementById("ot-matrix-cells");

  if (N === 0) {
    [colsSvg, rowsSvg].forEach(s => { s.innerHTML = ""; s.setAttribute("width", "0"); s.setAttribute("height", "0"); });
    cellsSvg.innerHTML = "";
    cellsSvg.setAttribute("width", "320"); cellsSvg.setAttribute("height", "60");
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", "12"); t.setAttribute("y", "32");
    t.setAttribute("fill", "#8b949e"); t.setAttribute("font-size", "12");
    t.textContent = "No devices match the current filters.";
    cellsSvg.appendChild(t);
    return;
  }

  const edgeMap = {};
  data.edges.forEach(e => {
    edgeMap[`${e.source}|${e.target}`] = e;
    edgeMap[`${e.target}|${e.source}`] = e;
  });
  const anomalyEdgeSet = new Set();
  (data.anomalies || []).forEach(a => {
    if (a.src && a.dst) anomalyEdgeSet.add(`${a.src}|${a.dst}`);
  });

  const OT_PROTO_ORDER = ["Modbus","DNP3","S7comm","EtherNet/IP","IEC-104","BACnet","CoAP","MQTT"];
  const dominantProto = (e) => {
    if (!e) return null;
    const protos = e.protocols || [];
    for (const p of OT_PROTO_ORDER) if (protos.includes(p)) return p;
    return protos[0] || null;
  };

  // ── Column headers SVG ──────────────────────────────────────────────────────
  colsSvg.innerHTML = "";
  colsSvg.setAttribute("width", N * CELL);
  colsSvg.setAttribute("height", LABEL_H);

  const colLabelEls = [];
  matrixNodes.forEach((n, j) => {
    const x = j * CELL + CELL / 2;
    const lbl = n.hostname || n.ip;
    const txt = document.createElementNS(ns, "text");
    txt.setAttribute("x", x);
    txt.setAttribute("y", LABEL_H - 4);
    txt.setAttribute("transform", `rotate(-55,${x},${LABEL_H - 4})`);
    txt.setAttribute("fill", "#8b949e");
    txt.setAttribute("font-size", "9");
    txt.setAttribute("font-family", "monospace");
    txt.setAttribute("text-anchor", "end");
    txt.textContent = truncMid(lbl, 14);
    const ttl = document.createElementNS(ns, "title"); ttl.textContent = lbl;
    txt.appendChild(ttl);
    colsSvg.appendChild(txt);
    colLabelEls.push(txt);
  });

  // ── Row headers SVG ─────────────────────────────────────────────────────────
  rowsSvg.innerHTML = "";
  rowsSvg.setAttribute("width", LABEL_W);
  rowsSvg.setAttribute("height", N * CELL);

  const rowLabelEls = [];
  matrixNodes.forEach((n, i) => {
    const lbl = n.hostname || n.ip;
    const txt = document.createElementNS(ns, "text");
    txt.setAttribute("x", LABEL_W - 4);
    txt.setAttribute("y", i * CELL + CELL / 2 + 3);
    txt.setAttribute("fill", "#8b949e");
    txt.setAttribute("font-size", "9");
    txt.setAttribute("font-family", "monospace");
    txt.setAttribute("text-anchor", "end");
    txt.textContent = truncMid(lbl, 15);
    const ttl = document.createElementNS(ns, "title"); ttl.textContent = lbl;
    txt.appendChild(ttl);
    rowsSvg.appendChild(txt);
    rowLabelEls.push(txt);
  });

  // ── Cells SVG ───────────────────────────────────────────────────────────────
  const LEGEND_H = 28;
  const cellsW = N * CELL;
  const cellsH = N * CELL + LEGEND_H;
  cellsSvg.innerHTML = "";
  cellsSvg.setAttribute("width", cellsW);
  cellsSvg.setAttribute("height", cellsH);

  // Crosshair highlight rects (behind cells)
  const rowHi = document.createElementNS(ns, "rect");
  rowHi.setAttribute("fill", "#58a6ff"); rowHi.setAttribute("opacity", "0.07");
  rowHi.setAttribute("x", "0"); rowHi.setAttribute("height", CELL);
  rowHi.setAttribute("width", cellsW); rowHi.setAttribute("pointer-events", "none");
  rowHi.style.display = "none";
  cellsSvg.appendChild(rowHi);

  const colHi = document.createElementNS(ns, "rect");
  colHi.setAttribute("fill", "#58a6ff"); colHi.setAttribute("opacity", "0.07");
  colHi.setAttribute("y", "0"); colHi.setAttribute("width", CELL);
  colHi.setAttribute("height", N * CELL); colHi.setAttribute("pointer-events", "none");
  colHi.style.display = "none";
  cellsSvg.appendChild(colHi);

  // Zone boundary indices
  const zoneBoundaries = [];
  let prevZone = nodeZone(matrixNodes[0]);
  matrixNodes.forEach((n, i) => {
    const z = nodeZone(n);
    if (i > 0 && z !== prevZone) zoneBoundaries.push(i);
    prevZone = z;
  });

  // Draw cells
  matrixNodes.forEach((rowNode, i) => {
    matrixNodes.forEach((colNode, j) => {
      if (i === j) {
        const rect = document.createElementNS(ns, "rect");
        rect.setAttribute("x", j * CELL + 1); rect.setAttribute("y", i * CELL + 1);
        rect.setAttribute("width", CELL - 2); rect.setAttribute("height", CELL - 2);
        rect.setAttribute("rx", "2"); rect.setAttribute("fill", "#0a0f15");
        rect.setAttribute("opacity", "0.8");
        cellsSvg.appendChild(rect);
        return;
      }

      const edge = edgeMap[`${rowNode.id}|${colNode.id}`];
      const rzn = nodeZone(rowNode), czn = nodeZone(colNode);
      const isCrossZone = edge && rzn && czn && rzn !== czn;
      const isAnomaly = anomalyEdgeSet.has(`${rowNode.id}|${colNode.id}`)
                     || anomalyEdgeSet.has(`${colNode.id}|${rowNode.id}`);
      const proto = dominantProto(edge);
      let fill    = edge ? (PROTO_COLORS[proto] || "#555") : "#161b22";
      let opacity = edge ? "0.8" : "0.15";
      if (isCrossZone) { fill = "#ff8c00"; opacity = "0.7"; }

      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", j * CELL + 1); rect.setAttribute("y", i * CELL + 1);
      rect.setAttribute("width", CELL - 2); rect.setAttribute("height", CELL - 2);
      rect.setAttribute("rx", "2");
      rect.setAttribute("fill", fill);
      rect.setAttribute("opacity", opacity);
      if (isAnomaly) {
        rect.setAttribute("stroke", "#f85149");
        rect.setAttribute("stroke-width", isCrossZone ? "2" : "1.5");
      }
      if (edge) rect.style.cursor = "pointer";
      cellsSvg.appendChild(rect);

      if (edge) {
        rect.addEventListener("mouseenter", (ev) => {
          rowHi.setAttribute("y", i * CELL); rowHi.style.display = "";
          colHi.setAttribute("x", j * CELL); colHi.style.display = "";
          rowLabelEls.forEach((el, k) => el.setAttribute("fill", k === i ? "#e6edf3" : "#8b949e"));
          colLabelEls.forEach((el, k) => el.setAttribute("fill", k === j ? "#e6edf3" : "#8b949e"));
          const otR = edge.ot_reads || 0, otW = edge.ot_writes || 0;
          tooltip.innerHTML = `
            <div class="tip-ip" style="font-size:11px">${escHtml(rowNode.ip)} ↔ ${escHtml(colNode.ip)}</div>
            <div class="tip-type">${fmtNum(edge.packet_count)} pkts · ${fmtBytes(edge.bytes)}</div>
            <div class="tip-proto">${(edge.protocols || []).slice(0, 5).map(escHtml).join(" · ")}</div>
            ${otR || otW ? `<div class="tip-type">OT reads: ${otR} · writes: ${otW}</div>` : ""}
            ${isCrossZone ? `<div style="color:#ff8c00;font-size:10px">⚠ Cross-zone</div>` : ""}
            ${isAnomaly   ? `<div style="color:#f85149;font-size:10px">⚠ Anomaly detected</div>` : ""}
            <div style="color:#555;font-size:10px;margin-top:4px">Click to inspect packets</div>
          `;
          tooltip.classList.add("visible");
          positionTooltip(ev);
        });
        rect.addEventListener("mousemove", positionTooltip);
        rect.addEventListener("mouseleave", () => {
          hideTooltip();
          rowHi.style.display = "none"; colHi.style.display = "none";
          rowLabelEls.forEach(el => el.setAttribute("fill", "#8b949e"));
          colLabelEls.forEach(el => el.setAttribute("fill", "#8b949e"));
        });
        rect.addEventListener("click", (ev) => {
          ev.stopPropagation();
          otMatrixMode = false;
          document.getElementById("ot-matrix-btn").classList.remove("active");
          document.getElementById("ot-map-svg").classList.remove("hidden");
          document.getElementById("ot-matrix-container").classList.add("hidden");
          setView("graph");
          setTimeout(() => openPktInspector(rowNode.id, colNode.id), 50);
        });
      }
    });
  });

  // Zone boundary separator lines
  zoneBoundaries.forEach(idx => {
    const hl = document.createElementNS(ns, "line");
    hl.setAttribute("x1", "0"); hl.setAttribute("x2", cellsW);
    hl.setAttribute("y1", idx * CELL); hl.setAttribute("y2", idx * CELL);
    hl.setAttribute("stroke", "#30363d"); hl.setAttribute("stroke-width", "1");
    hl.setAttribute("pointer-events", "none");
    cellsSvg.appendChild(hl);
    const vl = document.createElementNS(ns, "line");
    vl.setAttribute("y1", "0"); vl.setAttribute("y2", N * CELL);
    vl.setAttribute("x1", idx * CELL); vl.setAttribute("x2", idx * CELL);
    vl.setAttribute("stroke", "#30363d"); vl.setAttribute("stroke-width", "1");
    vl.setAttribute("pointer-events", "none");
    cellsSvg.appendChild(vl);
  });

  // Protocol color legend
  const OT_PROTO_KEY = ["Modbus","DNP3","S7comm","EtherNet/IP","IEC-104","BACnet","CoAP","MQTT"];
  let lx = 0;
  const ly = N * CELL + 16;
  OT_PROTO_KEY.forEach(p => {
    const clr = PROTO_COLORS[p] || "#555";
    const sw = document.createElementNS(ns, "rect");
    sw.setAttribute("x", lx); sw.setAttribute("y", ly - 8);
    sw.setAttribute("width", "8"); sw.setAttribute("height", "8");
    sw.setAttribute("rx", "1"); sw.setAttribute("fill", clr);
    cellsSvg.appendChild(sw);
    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("x", lx + 10); lbl.setAttribute("y", ly);
    lbl.setAttribute("fill", "#8b949e"); lbl.setAttribute("font-size", "8");
    lbl.setAttribute("font-family", "monospace");
    lbl.textContent = p;
    cellsSvg.appendChild(lbl);
    lx += 10 + p.length * 5.2 + 6;
  });
  const suffixTxt = document.createElementNS(ns, "text");
  suffixTxt.setAttribute("x", lx); suffixTxt.setAttribute("y", ly);
  suffixTxt.setAttribute("fill", "#555"); suffixTxt.setAttribute("font-size", "8");
  suffixTxt.setAttribute("font-family", "monospace");
  suffixTxt.textContent = "· orange = cross-zone · red border = anomaly";
  cellsSvg.appendChild(suffixTxt);

  if (totalNodes > 40) {
    const hint = document.createElementNS(ns, "text");
    hint.setAttribute("x", "0"); hint.setAttribute("y", N * CELL + 26);
    hint.setAttribute("fill", "#555"); hint.setAttribute("font-size", "8");
    hint.setAttribute("font-family", "monospace");
    hint.textContent = `· Showing top 40 of ${totalNodes} devices (by zone + connection count)`;
    cellsSvg.appendChild(hint);
  }
}

/* ── DNS Map View ────────────────────────────────────────────────────────── */
function renderDnsMap() {
  if (!graphData) return;
  const hostsEl = document.getElementById("dns-hosts");
  hostsEl.innerHTML = "";

  const dnsHosts = graphData.nodes.filter(n => n.dns_queries && n.dns_queries.length > 0);

  if (dnsHosts.length === 0) {
    hostsEl.innerHTML = `<div style="padding:12px;font-size:12px;color:var(--text2)">No DNS queries found in this capture.</div>`;
    return;
  }

  const tunnelSuspects = new Set(
    (graphData.anomalies || [])
      .filter(a => a.type === "dns_tunneling" && a.src)
      .map(a => a.src)
  );

  dnsHosts.forEach(n => {
    const row = document.createElement("div");
    row.className = "dns-host-row";
    const tunnelBadge = tunnelSuspects.has(n.ip)
      ? `<span class="badge badge-warn" title="DNS tunneling indicators detected">DNS Tunnel?</span>`
      : "";
    row.innerHTML = `
      <span style="font-family:var(--font-mono);font-size:11px">${escHtml(n.ip)}</span>
      ${tunnelBadge}
      <span class="dns-count">${(n.dns_queries || []).length}</span>
    `;
    row.addEventListener("click", () => {
      document.querySelectorAll(".dns-host-row").forEach(r => r.classList.remove("selected"));
      row.classList.add("selected");
      showDnsQueries(n);
    });
    hostsEl.appendChild(row);
  });
}

function showDnsQueries(node) {
  const title = document.getElementById("dns-query-title");
  const list = document.getElementById("dns-queries-list");
  title.textContent = `DNS queries from ${node.ip}`;
  list.innerHTML = "";

  node.dns_queries.forEach(q => {
    const div = document.createElement("div");
    div.className = "dns-query-entry";
    // Try to find resolved IPs from dns_names of other nodes
    const resolvedIps = [];
    if (graphData) {
      graphData.nodes.forEach(n => {
        if (n.dns_names && n.dns_names.some(name => name === q || name.endsWith("." + q))) {
          resolvedIps.push(n.ip);
        }
      });
    }
    div.innerHTML = `
      <div class="dns-q-name">${escHtml(q)}</div>
      ${resolvedIps.length ? `<div class="dns-resolved">→ ${resolvedIps.map(escHtml).join(", ")}</div>` : ""}
    `;
    list.appendChild(div);
  });
}

/* ── Baseline Diff ───────────────────────────────────────────────────────── */
document.getElementById("baseline-btn").addEventListener("click", () => {
  if (!graphData) return;
  baselineData = JSON.parse(JSON.stringify(graphData));
  document.getElementById("baseline-btn").textContent = "Baseline Set ✓";
  document.getElementById("diff-tab-btn").classList.remove("hidden");
  showToast("Baseline set. Upload another PCAP then click ⊕ Diff to compare.", "info");
});

document.getElementById("diff-clear-btn").addEventListener("click", () => {
  baselineData = null;
  document.getElementById("baseline-btn").textContent = "Set Baseline";
  document.getElementById("diff-tab-btn").classList.add("hidden");
  setView("graph");
});

/* ── VLAN Graph ──────────────────────────────────────────────────────────── */
function renderVlanGraph(data) {
  _vlanRendered = true;
  vlanSelectedNode = null;   // clear any stale selection from a previous render
  const svgEl = document.getElementById("vlan-svg");
  const emptyEl = document.getElementById("vlan-empty");

  const allVlans = ((data.stats || {}).vlans) || [];
  const hasUntagged = data.nodes.some(n => n.vlan_untagged);
  const totalVlans = allVlans.length + (hasUntagged ? 1 : 0);

  if (totalVlans === 0) {
    emptyEl.style.display = "";
    svgEl.style.display = "none";
    return;
  }
  emptyEl.style.display = "none";
  svgEl.style.display = "";

  // Build VLAN super-nodes (label includes user-assigned name if set)
  const vlanNodes = allVlans.map(vid => {
    const defaultLabel = `VLAN ${vid}`;
    return {
      id: `vlan-${vid}`,
      kind: "vlan",
      label: vlanDisplayName(String(vid), defaultLabel),
      defaultLabel,
      vid: String(vid),
      color: vlanColor(vid),
      hostCount: 0,
    };
  });
  if (hasUntagged) {
    vlanNodes.push({ id: "vlan-untagged", kind: "vlan", label: vlanDisplayName("untagged", "Untagged"), defaultLabel: "Untagged", vid: "untagged", color: "#546E7A", hostCount: 0 });
  }
  const vlanById = Object.fromEntries(vlanNodes.map(v => [v.id, v]));

  // Build host nodes + membership (one node per host, member-links to ALL its VLANs)
  const hostNodes = data.nodes.map(n => {
    const vids = (n.vlans || []).map(String);
    const parents = vids.length
      ? vids.map(v => `vlan-${v}`)
      : (n.vlan_untagged ? ["vlan-untagged"] : []);
    parents.forEach(pid => { if (vlanById[pid]) vlanById[pid].hostCount++; });
    // Spread full source node so node decorations (risk, geo, anomaly, cred) have all fields
    return {
      ...n,
      id: n.ip,
      kind: "host",
      label: n.hostname || n.ip,
      parentVlans: parents,
      color: hostColor(n.host_type),
      multiVlan: vids.length > 1,
    };
  });

  // Cap host count to keep the simulation responsive for large captures
  const MAX_VLAN_HOSTS = 300;
  if (hostNodes.length > MAX_VLAN_HOSTS) {
    showToast(`VLAN graph: showing top ${MAX_VLAN_HOSTS} hosts by traffic (${hostNodes.length} total — see VLAN inventory CSV for full list).`, "info");
    hostNodes.sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0));
    hostNodes.splice(MAX_VLAN_HOSTS);
    // hostCount on super-nodes reflects the full capture (tallied before truncation) — intentional
  }

  // Scale VLAN super-node radius by host count (min 30, max 80)
  vlanNodes.forEach(v => { v.r = Math.min(80, Math.max(30, 20 + v.hostCount * 4)); });

  // Pre-built lookup: eliminates O(hosts) linear search per edge in the loop below
  const nodeByIp = Object.fromEntries(data.nodes.map(n => [n.ip, n]));

  // Build cross-VLAN traffic links (VLAN → VLAN, aggregated across all VLAN pairs)
  const crossVlanMap = {};
  data.edges.forEach(e => {
    const src = nodeByIp[e.source];
    const dst = nodeByIp[e.target];
    if (!src || !dst) return;
    const sv = (src.vlans || []).map(v => `vlan-${v}`).concat(src.vlan_untagged ? ["vlan-untagged"] : []);
    const dv = (dst.vlans || []).map(v => `vlan-${v}`).concat(dst.vlan_untagged ? ["vlan-untagged"] : []);
    sv.forEach(a => dv.forEach(b => {
      if (a === b) return;
      const key = [a, b].sort().join("|");
      if (!crossVlanMap[key]) crossVlanMap[key] = { source: a, target: b, packets: 0, bytes: 0 };
      crossVlanMap[key].packets += e.packet_count || 0;
      crossVlanMap[key].bytes   += e.bytes || 0;
    }));
  });
  const crossLinks = Object.values(crossVlanMap).map(l => Object.assign(l, { kind: "cross" }));
  const maxPkts = crossLinks.reduce((m, l) => Math.max(m, l.packets), 1);

  // Membership links (host → each parent VLAN) for clustering force; multi-VLAN hosts link to all
  const memberLinks = hostNodes.flatMap(n => n.parentVlans.map(pid => ({ source: n.id, target: pid, kind: "member" })));

  const allNodes = [...vlanNodes, ...hostNodes];
  const allLinks = [...crossLinks, ...memberLinks];

  // Position VLAN super-nodes deterministically on first render
  const W = svgEl.clientWidth  || 900;
  const H = svgEl.clientHeight || 650;
  vlanNodes.forEach((v, i) => {
    const angle = (2 * Math.PI * i) / vlanNodes.length;
    v.x = W / 2 + (Math.min(W, H) * 0.32) * Math.cos(angle);
    v.y = H / 2 + (Math.min(W, H) * 0.32) * Math.sin(angle);
  });
  // Scatter host nodes near their first parent VLAN (multi-VLAN hosts start between segments)
  hostNodes.forEach(n => {
    const parent = n.parentVlans.length ? vlanById[n.parentVlans[0]] : null;
    n.x = parent ? parent.x + (Math.random() - 0.5) * 80 : W / 2 + (Math.random() - 0.5) * 200;
    n.y = parent ? parent.y + (Math.random() - 0.5) * 80 : H / 2 + (Math.random() - 0.5) * 200;
  });

  // D3 setup
  d3.select(svgEl).selectAll("*").remove();
  if (vlanSimulation) vlanSimulation.stop();

  const svgSel = d3.select(svgEl).attr("width", W).attr("height", H);
  const vlanZoom = d3.zoom().scaleExtent([0.1, 8]).on("zoom", e => {
    gRoot.attr("transform", e.transform);
  });
  svgSel.call(vlanZoom);
  const gRoot = svgSel.append("g");

  // Convex hull layer (bottom-most — drawn before edges and nodes)
  const hullG = gRoot.append("g").attr("class", "vlan-hulls");

  // Cross-VLAN edge layer
  const crossEdgeG = gRoot.append("g").attr("class", "vlan-cross-edges");
  const crossEdgeSel = crossEdgeG.selectAll(".vcross")
    .data(crossLinks)
    .join("line")
      .attr("class", "vcross")
      .attr("stroke", "#ef5350")
      .attr("stroke-opacity", 0.8)
      .attr("stroke-width", d => 2 + 5 * (d.packets / maxPkts));

  // Cross-edge tooltip — uses shared positionTooltip/hideTooltip for consistency
  crossEdgeSel
    .style("cursor", "default")
    .on("mouseenter", (event, d) => {
      const src = (typeof d.source === "object" ? d.source.id : d.source).replace("vlan-", "VLAN ");
      const dst = (typeof d.target === "object" ? d.target.id : d.target).replace("vlan-", "VLAN ");
      tooltip.innerHTML = `<strong>Cross-VLAN traffic</strong><br>${escHtml(src)} ↔ ${escHtml(dst)}<br>Packets: ${fmtNum(d.packets)}<br>Bytes: ${fmtBytes(d.bytes)}`;
      tooltip.classList.add("visible");
      positionTooltip(event);
    })
    .on("mousemove", (event) => positionTooltip(event))
    .on("mouseleave", () => hideTooltip());

  // VLAN super-node layer
  const vlanG = gRoot.append("g").attr("class", "vlan-supernodes");
  const vlanCircles = vlanG.selectAll(".vsuper")
    .data(vlanNodes)
    .join("g").attr("class", "vsuper")
      .style("cursor", "pointer")
      .call(d3.drag()
        .on("start", (e, d) => { if (!e.active) vlanSimulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag",  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end",   (e, d) => { if (!e.active) vlanSimulation.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on("click", (event, d) => {
        event.stopPropagation();
        showVlanDetailPanel(d);
      })
      .on("dblclick", async (event, d) => {
        event.stopPropagation();
        hideTooltip();
        const current = getVlanLabel(d.vid);
        const name = await openTextModal({
          title: `VLAN label: ${d.defaultLabel}`,
          value: current,
          placeholder: "Leave blank to clear the custom label",
        });
        if (name === null) return;  // cancelled
        saveVlanLabel(d.vid, name.trim());
        // Update the label in data and redraw the text element
        d.label = vlanDisplayName(d.vid, d.defaultLabel);
        d3.select(event.currentTarget).select("text").text(d.label);
        // Refresh legend
        const li = document.getElementById("vlan-legend-items");
        if (li) li.querySelector(`[data-vid="${CSS.escape(d.vid)}"]`)
          && (li.querySelector(`[data-vid="${CSS.escape(d.vid)}"]`).textContent = d.label);
      })
      .on("mouseenter", (event, d) => {
        tooltip.innerHTML = `<strong>${escHtml(d.label)}</strong><br>${d.hostCount} host${d.hostCount !== 1 ? "s" : ""}<br><span style="font-size:10px;color:#8b949e">Double-click to rename</span>`;
        tooltip.classList.add("visible");
        positionTooltip(event);
      })
      .on("mousemove", (event) => positionTooltip(event))
      .on("mouseleave", () => hideTooltip());

  vlanCircles.append("circle")
    .attr("r", d => d.r)
    .attr("fill", d => d.color)
    .attr("fill-opacity", 0.13)
    .attr("stroke", d => d.color)
    .attr("stroke-width", 2);

  vlanCircles.append("text")
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "central")
    .attr("font-size", 13)
    .attr("font-weight", "bold")
    .attr("fill", d => d.color)
    .text(d => d.label);

  vlanCircles.append("text")
    .attr("text-anchor", "middle")
    .attr("y", 18)
    .attr("dominant-baseline", "central")
    .attr("font-size", 10)
    .attr("fill", "#8b949e")
    .text(d => `${d.hostCount} host${d.hostCount !== 1 ? "s" : ""}`);

  // Host node layer
  const hostG = gRoot.append("g").attr("class", "vlan-hosts");
  const hostCircles = hostG.selectAll(".vhost")
    .data(hostNodes)
    .join("g").attr("class", "vhost")
      .style("cursor", "pointer")
      .call(d3.drag()
        .on("start", (e, d) => { if (!e.active) vlanSimulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag",  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end",   (e, d) => { if (!e.active) vlanSimulation.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on("mouseenter", (event, d) => {
        showTooltipNode(event, d);
        highlightVlanNode(d);
      })
      .on("mousemove", (event) => positionTooltip(event))
      .on("mouseleave", (event, d) => {
        hideTooltip();
        if (!vlanSelectedNode || vlanSelectedNode.id !== d.id) {
          unhighlightVlan();
          if (vlanSelectedNode) highlightVlanNode(vlanSelectedNode);
        }
      })
      .on("click", (event, d) => {
        event.stopPropagation();
        if (vlanSelectedNode && vlanSelectedNode.id === d.id) {
          vlanSelectedNode = null;
          unhighlightVlan();
          detailPanel.classList.remove("open");
        } else {
          vlanSelectedNode = d;
          highlightVlanNode(d);
          showDetailPanel(d);
        }
      });

  // Lightweight host decorations — 2-3 elements per node (main graph helper is 4-8, too heavy here)
  // Anomaly ring: single colored circle, visible even at 7px
  hostCircles.each(function(d) {
    const sev = anomalyNodeIps[d.ip];
    if (sev) {
      d3.select(this).append("circle")
        .attr("class", `anomaly-ring-${sev}`)
        .attr("r", 11);
    }
  });
  // Circle — host-type color; IPv6 gets a dashed stroke
  hostCircles.append("circle")
    .attr("r", 6)
    .attr("fill", d => hostColor(d.host_type))
    .attr("fill-opacity", 0.9)
    .attr("stroke", d => d3.color(hostColor(d.host_type)).brighter(0.4))
    .attr("stroke-width", d => d.ip_version === 6 ? 1.5 : 0.8)
    .attr("stroke-dasharray", d => d.ip_version === 6 ? "2,1.5" : null);
  // Host-type icon glyph — same emoji as the main graph (reuses hostIcon() + .node-icon CSS).
  // Must set fill explicitly: .node-icon base rule is fill:transparent; the .node text
  // override that rescues main-graph icons doesn't apply here because VLAN groups use
  // class "vhost", not "node".
  hostCircles.append("text")
    .attr("class", "node-icon")
    .attr("dy", "0.35em")
    .attr("text-anchor", "middle")
    .attr("font-size", "9px")
    .attr("fill", "var(--text)")
    .attr("pointer-events", "none")
    .text(d => hostIcon(d.host_type));
  // IP / hostname label below the dot
  hostCircles.append("text")
    .attr("class", "ip-label")
    .attr("dy", 16)
    .attr("font-size", "8px")
    .attr("fill", "#8b949e")
    .text(d => d.hostname || d.ip);

  // B5: Gateway overlay — inter-VLAN routers get a larger ring + "GW" badge
  const _gwTypes = new Set(["Router", "Network Device", "VPN Gateway"]);
  hostCircles.filter(d => _gwTypes.has(d.host_type) && d.parentVlans.length > 1)
    .each(function(d) {
      const g = d3.select(this);
      // Outer accent ring
      g.insert("circle", "circle")
        .attr("r", 10)
        .attr("fill", "none")
        .attr("stroke", "#e3b341")
        .attr("stroke-width", 1.5)
        .attr("stroke-dasharray", "3,2");
      // "GW" label above the dot
      g.append("text")
        .attr("dy", -12)
        .attr("font-size", "7px")
        .attr("font-weight", "bold")
        .attr("fill", "#e3b341")
        .attr("text-anchor", "middle")
        .text("GW");
    });

  // Force simulation
  vlanSimulation = d3.forceSimulation(allNodes)
    .alphaDecay(0.05)       // converges ~2× faster than default 0.0228 (~130 ticks vs ~300)
    .velocityDecay(0.5)     // slightly more damping for a smoother stop
    .force("link", d3.forceLink(allLinks).id(d => d.id)
      .distance(d => d.kind === "member" ? 60 : 200)
      .strength(d => d.kind === "member" ? 0.6 : 0.2))
    .force("charge", d3.forceManyBody()
      .strength(d => d.kind === "vlan" ? -300 : -30)
      .distanceMax(250))    // cap pairwise repulsion range — removes O(n²) long-range work
    .force("collide", d3.forceCollide(d => d.kind === "vlan" ? (d.r + 20) : 14))
    .force("center", d3.forceCenter(W / 2, H / 2).strength(0.05))
    .on("tick", () => {
      crossEdgeSel
        .attr("x1", d => (typeof d.source === "object" ? d.source.x : 0))
        .attr("y1", d => (typeof d.source === "object" ? d.source.y : 0))
        .attr("x2", d => (typeof d.target === "object" ? d.target.x : 0))
        .attr("y2", d => (typeof d.target === "object" ? d.target.y : 0));
      vlanCircles.attr("transform", d => `translate(${d.x},${d.y})`);
      hostCircles.attr("transform", d => `translate(${d.x},${d.y})`);
      // B1: Redraw convex hull polygons around each VLAN's member hosts
      hullG.selectAll(".vlan-hull").data(vlanNodes, d => d.id).join("path")
        .attr("class", "vlan-hull")
        .attr("fill", d => d.color)
        .attr("fill-opacity", 0.06)
        .attr("stroke", d => d.color)
        .attr("stroke-opacity", 0.35)
        .attr("stroke-width", 1.5)
        .attr("stroke-dasharray", "4,3")
        .attr("d", d => {
          const pts = hostNodes
            .filter(n => n.parentVlans.includes(d.id) && n.x != null && n.y != null)
            .map(n => [n.x, n.y]);
          if (pts.length < 3) return null;
          const hull = d3.polygonHull(pts);
          return hull ? `M${hull.map(p => p.join(",")).join("L")}Z` : null;
        });
    });

  // Fit button
  document.getElementById("vlan-zoom-fit").onclick = () => {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    allNodes.forEach(n => {
      if (n.x == null) return;
      minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x); maxY = Math.max(maxY, n.y);
    });
    if (!isFinite(minX)) return;
    const pad = 60;
    const bw = maxX - minX || 1, bh = maxY - minY || 1;
    const scale = Math.min((W - pad * 2) / bw, (H - pad * 2) / bh, 3);
    const tx = W / 2 - scale * (minX + bw / 2);
    const ty = H / 2 - scale * (minY + bh / 2);
    svgSel.transition().duration(500).call(vlanZoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  };

  // Background click → deselect host node and close panel
  svgSel.on("click", () => {
    vlanSelectedNode = null;
    unhighlightVlan();
    detailPanel.classList.remove("open");
  });

  // Layout switcher — use onclick (not addEventListener) to avoid accumulating
  // handlers on the same buttons across successive PCAP loads
  document.querySelectorAll("[data-vlan-layout]").forEach(btn => {
    btn.onclick = function() {
      document.querySelectorAll("[data-vlan-layout]").forEach(b => b.classList.remove("active"));
      this.classList.add("active");
      _vlanLayout = this.dataset.vlanLayout;
      applyVlanLayout();
    };
  });

  function applyVlanLayout() {
    if (!vlanSimulation) return;
    vlanSimulation.stop();
    if (_vlanLayout === "radial") {
      // VLAN super-nodes equally spaced on outer ring
      vlanNodes.forEach((v, i) => {
        const angle = (2 * Math.PI * i) / vlanNodes.length;
        const r = Math.min(W, H) * 0.35;
        v.fx = W / 2 + r * Math.cos(angle);
        v.fy = H / 2 + r * Math.sin(angle);
      });
    } else if (_vlanLayout === "cluster") {
      // Grid layout for VLAN super-nodes
      const cols = Math.ceil(Math.sqrt(vlanNodes.length));
      vlanNodes.forEach((v, i) => {
        const col = i % cols, row = Math.floor(i / cols);
        const spacing = Math.min(W, H) / (cols + 1);
        v.fx = spacing + col * spacing;
        v.fy = 80 + row * spacing;
      });
    } else {
      // Force: release fixed positions
      vlanNodes.forEach(v => { v.fx = null; v.fy = null; });
    }
    vlanSimulation.alpha(0.5).restart();
  }

  // Stats bar — traffic metrics, sprawl metrics, segmentation score
  const totalCrossBytes = crossLinks.reduce((s, l) => s + (l.bytes || 0), 0);
  const untaggedHosts   = hostNodes.filter(n => n.vlan_untagged).length;
  const multiVlanHosts  = hostNodes.filter(n => n.multiVlan).length;

  // C3: Sprawl metrics
  const crossLinkedVlanIds = new Set();
  crossLinks.forEach(l => {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    crossLinkedVlanIds.add(s); crossLinkedVlanIds.add(t);
  });
  const singletonVlans = vlanNodes.filter(v => v.hostCount === 1).length;
  const isolatedVlans  = vlanNodes.filter(v => !crossLinkedVlanIds.has(v.id)).length;

  // A1: Segmentation score
  const segScore = computeVlanSegmentationScore();

  const statsBar = document.getElementById("vlan-stats-bar");
  if (statsBar) {
    const scorePill = segScore
      ? `<span style="margin-left:auto">Segmentation: <strong style="color:${segScore.color}">${segScore.score}/100</strong> <span style="color:${segScore.color};font-size:10px">(${segScore.label})</span></span>`
      : "";
    statsBar.innerHTML = [
      `<span>Cross-VLAN flows: <strong>${crossLinks.length}</strong></span>`,
      `<span>Cross-VLAN bytes: <strong>${fmtBytes(totalCrossBytes)}</strong></span>`,
      `<span>Untagged hosts: <strong>${untaggedHosts}</strong></span>`,
      `<span>Multi-VLAN / hopping: <strong>${multiVlanHosts}</strong></span>`,
      `<span>Singleton VLANs: <strong>${singletonVlans}</strong></span>`,
      `<span>Isolated VLANs: <strong>${isolatedVlans}</strong></span>`,
      scorePill,
    ].filter(Boolean).join("");
  }

  // Legend (F): VLAN swatches + cross-VLAN indicator + untagged key
  const legendItems = document.getElementById("vlan-legend-items");
  legendItems.innerHTML = "";
  vlanNodes.forEach(v => {
    const el = document.createElement("div");
    el.style.cssText = "display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:12px";
    el.innerHTML = `<div style="width:14px;height:14px;border-radius:50%;background:${v.color};border:2px solid ${v.color};flex-shrink:0"></div><span data-vid="${escHtml(v.vid)}">${escHtml(v.label)}</span> <span style="color:#8b949e">(${v.hostCount})</span>`;
    legendItems.appendChild(el);
  });
  if (crossLinks.length) {
    const el = document.createElement("div");
    el.style.cssText = "display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:12px";
    el.innerHTML = `<div style="width:14px;height:3px;background:#ef5350;flex-shrink:0;border-radius:2px"></div>Cross-VLAN traffic`;
    legendItems.appendChild(el);
  }
  if (untaggedHosts) {
    const el = document.createElement("div");
    el.style.cssText = "display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:12px";
    el.innerHTML = `<div style="width:14px;height:14px;border-radius:50%;background:#546E7A;flex-shrink:0"></div>Untagged / native`;
    legendItems.appendChild(el);
  }

  // ── Inner helper functions (closures over the VLAN graph selections) ────────

  // Neighbor highlighting for host nodes.
  // Cross edges connect VLAN↔VLAN IDs (e.g. "vlan-10"↔"vlan-20"), never host IPs,
  // so there's no point searching crossEdgeSel for host d.id — they never match.
  function highlightVlanNode(d) {
    const conn = new Set([d.id, ...(d.parentVlans || [])]);
    hostCircles.classed("faded", n => !conn.has(n.id));
    vlanCircles.classed("faded", v => !conn.has(v.id));
    crossEdgeSel.classed("faded", true);   // all cross-VLAN edges fade on host hover
  }

  function unhighlightVlan() {
    hostCircles.classed("faded", false);
    vlanCircles.classed("faded", false);
    crossEdgeSel.classed("faded", false);
  }

  // VLAN super-node detail panel (reuses #detail-panel DOM and row/badge/sectionTitle helpers)
  function showVlanDetailPanel(v) {
    detailPanel.classList.add("open");
    document.getElementById("dh-ip").textContent = v.label;
    document.getElementById("dh-hostname").textContent = `${v.hostCount} host${v.hostCount !== 1 ? "s" : ""}`;

    const body = document.getElementById("detail-body");
    const rows = [];

    rows.push(`<div style="margin-bottom:8px">
      <button class="header-btn" id="vlan-spotlight-btn" data-vid="${escHtml(v.vid)}"
        style="width:100%;font-size:11px">🔍 Spotlight in Graph view</button>
    </div>`);
    rows.push(row("VLAN ID", v.vid === "untagged"
      ? `<span style="color:#8b949e">Untagged / native VLAN</span>`
      : `<code style="font-family:var(--font-mono)">${escHtml(String(v.vid))}</code>`));
    rows.push(row("Host count", String(v.hostCount)));

    // Members of this VLAN
    const members = hostNodes.filter(n => n.parentVlans.includes(v.id));

    // Per-VLAN aggregate risk score
    if (members.length) {
      const maxRisk = Math.max(...members.map(n => n.risk_score || 0));
      const avgRisk = Math.round(members.reduce((s, n) => s + (n.risk_score || 0), 0) / members.length);
      if (maxRisk > 0) {
        const rc = maxRisk >= 70 ? "var(--red)" : maxRisk >= 40 ? "var(--yellow)" : "#6e7681";
        rows.push(row("Risk (VLAN)", `<span style="color:${rc}">Avg ${avgRisk} · Max ${maxRisk}/100</span>`));
      }
    }

    // C1: VLAN-to-subnet mapping
    const subnets = inferSubnets(members.map(m => m.ip));
    if (subnets.length) {
      rows.push(row("IP subnet(s)", subnets.map(s =>
        `<code style="font-family:var(--font-mono)">${escHtml(s)}</code>`
      ).join(", ")));
    }

    // PCP distribution across members
    const pcpCounts = {};
    members.forEach(n => (n.vlan_pcps || []).forEach(p => { pcpCounts[p] = (pcpCounts[p] || 0) + 1; }));
    if (Object.keys(pcpCounts).length) {
      const pcpStr = Object.entries(pcpCounts).sort((a, b) => a[0] - b[0])
        .map(([p, c]) => `PCP ${p} (${c}×)`).join(", ");
      rows.push(row("PCP values", pcpStr));
    }

    // QinQ double-tagged members
    const qinqMembers = members.filter(n => n.vlan_qinq);
    if (qinqMembers.length) {
      rows.push(row("QinQ (double-tagged)", `${qinqMembers.length} host${qinqMembers.length !== 1 ? "s" : ""}`));
      const outerSet = new Set(qinqMembers.flatMap(n => n.vlan_outer || []));
      if (outerSet.size) rows.push(row("Outer VLAN IDs", [...outerSet].join(", ")));
    }

    // Untagged/native traffic in this segment
    const nativeMembers = members.filter(n => n.vlan_untagged).length;
    if (nativeMembers) rows.push(row("Native/untagged hosts", String(nativeMembers)));

    // Cross-VLAN partners
    const partnerLinks = crossLinks.filter(l => {
      const s = typeof l.source === "object" ? l.source.id : l.source;
      const t = typeof l.target === "object" ? l.target.id : l.target;
      return s === v.id || t === v.id;
    });
    if (partnerLinks.length) {
      rows.push(sectionTitle("Cross-VLAN partners"));
      partnerLinks.forEach(l => {
        const s = typeof l.source === "object" ? l.source.id : l.source;
        const t = typeof l.target === "object" ? l.target.id : l.target;
        const partner = (s === v.id ? t : s).replace("vlan-", "VLAN ").replace("VLAN untagged", "Untagged");
        rows.push(row(partner, `${fmtNum(l.packets)} pkts · ${fmtBytes(l.bytes)}`));
      });
    }

    // Member host list (capped at 30)
    if (members.length) {
      rows.push(sectionTitle(`Member Hosts (${members.length})`));
      members.slice(0, 30).forEach(n => {
        // Use data-ip instead of inline onclick to avoid JS injection via IP strings
        rows.push(`<div class="vlan-member-host" data-ip="${escHtml(n.ip)}" style="padding:2px 0;font-size:11px;cursor:pointer;color:var(--link)">${escHtml(n.hostname || n.ip)}${n.multiVlan ? ' <span style="color:var(--yellow);font-size:10px">⚡ multi-VLAN</span>' : ''}</div>`);
      });
      if (members.length > 30) rows.push(`<div style="color:var(--text2);font-size:11px">…and ${members.length - 30} more</div>`);
    }

    body.innerHTML = rows.join("");

    // B4: Spotlight button — show only this VLAN in the main graph
    const spotBtn = body.querySelector("#vlan-spotlight-btn");
    if (spotBtn) {
      spotBtn.addEventListener("click", () => {
        const vid = spotBtn.dataset.vid;
        setView("graph");
        activeVlans.clear();
        activeVlans.add(vid);
        // Sync sidebar checkboxes
        document.querySelectorAll("#vlan-filters input[type=checkbox]").forEach(cb => {
          cb.checked = cb.id === `f-vlan-${CSS.escape(vid)}`;
        });
        updateFilterUI();
        applyFilters();
        showToast(`Spotlighting VLAN ${vid === "untagged" ? "Untagged" : vid} in graph view`, "info");
      });
    }

    // Bind member-host click handlers after innerHTML assignment (avoids inline onclick XSS)
    body.querySelectorAll(".vlan-member-host").forEach(el => {
      el.addEventListener("click", () => {
        const f = graphData.nodes.find(x => x.ip === el.dataset.ip);
        if (f) showDetailPanel(f);
      });
    });
  }

  // D1: VLAN search — wire up after selections are in scope
  const vlanSearchEl = document.getElementById("vlan-search");
  if (vlanSearchEl) {
    vlanSearchEl.value = "";
    vlanSearchEl.oninput = () => {
      const q = vlanSearchEl.value.trim().toLowerCase();
      if (!q) { unhighlightVlan(); return; }
      const matchedVlans = new Set();
      hostCircles.classed("faded", n => {
        const hit = n.ip.includes(q)
          || (n.hostname && n.hostname.toLowerCase().includes(q))
          || (n.label   && n.label.toLowerCase().includes(q));
        if (hit) n.parentVlans.forEach(p => matchedVlans.add(p));
        return !hit;
      });
      vlanCircles.classed("faded", v => !matchedVlans.has(v.id));
      crossEdgeSel.classed("faded", true);
    };
  }
}

/* ── Cross-VLAN flow matrix ───────────────────────────────────────────────── */
let _vlanMatrixMode   = false;
let _vlanMatrixView   = "traffic";   // "traffic" | "ot" | "anomaly" | "protocol"
let _vlanMatrixMetric = "bytes";     // "bytes" | "packets"  (Traffic-view sub-toggle)

// OT/ICS protocol labels the backend can actually emit (cross-checked against PORT_MAP in
// app.py and PROTO_COLORS above) — kept as a single source of truth instead of the two
// separate 8-item arrays duplicated by the OT matrix (OT_PROTO_ORDER / OT_PROTO_KEY).
const VLAN_OT_PROTOCOLS = new Set([
  "Modbus","DNP3","S7comm","EtherNet/IP","IEC-104","BACnet","OPC-UA","PROFINET",
  "HART-IP","GE-SRTP","OMRON-FINS","Emerson-DeltaV","DLMS","CoAP","MQTT"
]);

const VM_SEV_COLORS = { high: "#f85149", medium: "#d29922", low: "#58a6ff" };  // matches app.js anomaly-badge convention

// Full VLAN membership for a host (matches the VLAN graph view, :5843-5851) — replaces the
// old primaryVlan()/node.vlans[0] approach which under-counted multi-VLAN hosts.
const vlansOf = n => !n ? [] :
  (n.vlans || []).map(String).concat(n.vlan_untagged ? ["untagged"] : []);

/**
 * Pure data-layer builder for the VLAN flow matrix: aggregates edges + anomalies into
 * per-VLAN-pair cells keyed by a canonical sorted "a|b" key (undirected, no double-counting
 * even though a host can belong to several VLANs and thus contribute to several pair keys).
 */
function buildVlanFlowMatrix(data) {
  const nodeByIp = Object.fromEntries((data.nodes || []).map(n => [n.ip, n]));
  const vids = [...(data.stats?.vlans || []).map(String)];
  if ((data.nodes || []).some(n => n.vlan_untagged)) vids.push("untagged");

  const cells = {};                      // "a|b" (sorted) -> cell; diagonal = "a|a"
  const key = (a, b) => [a, b].sort().join("|");
  const getCell = k => cells[k] ||= { packets: 0, bytes: 0, protocols: new Set(),
    otPackets: 0, otBytes: 0, otProtocols: new Set(), otReads: 0, otWrites: 0,
    anomalies: [], maxSeverity: null };

  (data.edges || []).forEach(e => {
    const sv = vlansOf(nodeByIp[e.source]), dv = vlansOf(nodeByIp[e.target]);
    const pairKeys = new Set();
    sv.forEach(a => dv.forEach(b => pairKeys.add(key(a, b))));  // a===b → diagonal (intra-VLAN)
    const otProtos = (e.protocols || []).filter(p => VLAN_OT_PROTOCOLS.has(p));
    pairKeys.forEach(k => {
      const c = getCell(k);
      c.packets += e.packet_count || 0;  c.bytes += e.bytes || 0;
      (e.protocols || []).forEach(p => c.protocols.add(p));
      if (otProtos.length) {
        c.otPackets += e.packet_count || 0;  c.otBytes += e.bytes || 0;
        otProtos.forEach(p => c.otProtocols.add(p));
        c.otReads += e.ot_reads || 0;  c.otWrites += e.ot_writes || 0;
      }
    });
  });

  // ALL anomaly types (previously only vlan_cross_segment_ot was mapped)
  const SEV_RANK = { high: 3, medium: 2, low: 1 };
  (data.anomalies || []).forEach(a => {
    const sv = vlansOf(nodeByIp[a.src]), dv = a.dst ? vlansOf(nodeByIp[a.dst]) : null;
    const pairKeys = new Set();
    if (dv && dv.length) sv.forEach(x => dv.forEach(y => pairKeys.add(key(x, y))));
    else sv.forEach(x => pairKeys.add(key(x, x)));       // single-host anomaly → diagonal
    pairKeys.forEach(k => {
      const c = getCell(k);
      c.anomalies.push(a);
      if (!c.maxSeverity || SEV_RANK[a.severity] > SEV_RANK[c.maxSeverity]) c.maxSeverity = a.severity;
    });
  });

  // Scale maxima: cross-pair only for the ramp domains (intra-VLAN volume would flatten it);
  // track both metrics for the Bytes|Packets toggle.
  let maxBytes = 0, maxPackets = 0, maxOtBytes = 0, maxOtPackets = 0, maxDiagBytes = 0, maxDiagPackets = 0;
  Object.entries(cells).forEach(([k, c]) => {
    const [a, b] = k.split("|");
    if (a === b) { maxDiagBytes = Math.max(maxDiagBytes, c.bytes); maxDiagPackets = Math.max(maxDiagPackets, c.packets); }
    else {
      maxBytes = Math.max(maxBytes, c.bytes);       maxPackets = Math.max(maxPackets, c.packets);
      maxOtBytes = Math.max(maxOtBytes, c.otBytes); maxOtPackets = Math.max(maxOtPackets, c.otPackets);
    }
  });
  return { vids, cells, key, maxBytes, maxPackets, maxOtBytes, maxOtPackets, maxDiagBytes, maxDiagPackets };
}

/** Log-scale heat helper: exposes both the d3 color scale and a 0-1 normalized position
 *  (used to pick readable in-cell text color against bright fills). */
function makeHeatScale(maxVal, stops) {
  const domainMax = Math.max(2, maxVal || 0);
  const scale = d3.scaleSequentialLog().domain([1, domainMax]).clamp(true).interpolator(d3.interpolateRgbBasis(stops));
  const t = v => {
    if (!(v > 0)) return 0;
    const clamped = Math.min(Math.max(v, 1), domainMax);
    return Math.log(clamped) / Math.log(domainMax);
  };
  return { scale, t };
}

/** Pure per-cell styling for the active matrix mode. Returns {fill, opacity, stroke,
 *  strokeWidth, text, textFill}. `scales` = { metric, traffic:{scale,t}, ot:{scale,t} }. */
function vlanCellStyle(mode, cell, isDiag, scales) {
  const metric = scales.metric;
  const v  = cell ? (metric === "packets" ? cell.packets   : cell.bytes)   : 0;
  const ov = cell ? (metric === "packets" ? cell.otPackets : cell.otBytes) : 0;
  const hasTraffic = v > 0;
  const hasOt      = ov > 0;
  const hasAnomaly = !!cell && cell.anomalies.length > 0;

  const EMPTY      = { fill: "#161b22", opacity: 0.4, stroke: null, strokeWidth: 0, text: "", textFill: "#8b949e" };
  const NOT_RELEV  = { fill: "#21262d", opacity: 0.5, stroke: null, strokeWidth: 0, text: "", textFill: "#8b949e" };
  const DIAG_EMPTY = { fill: "#0a0f15", opacity: 0.8, stroke: null, strokeWidth: 0, text: "", textFill: "#8b949e" };

  if (mode === "traffic") {
    if (!hasTraffic) return isDiag ? DIAG_EMPTY : EMPTY;
    const t = scales.traffic.t(v);
    return {
      fill: scales.traffic.scale(v),
      opacity: isDiag ? 0.55 : 0.9,
      stroke: isDiag ? "#30363d" : null,
      strokeWidth: isDiag ? 1 : 0,
      text: metric === "packets" ? fmtNum(cell.packets) : fmtBytes(cell.bytes),
      textFill: t > 0.6 ? "#0d1117" : "#e6edf3",
    };
  }

  if (mode === "ot") {
    if (!hasOt) return hasTraffic ? NOT_RELEV : (isDiag ? DIAG_EMPTY : EMPTY);
    const t = scales.ot.t(ov);
    const writes = cell.otWrites > 0;
    return {
      fill: scales.ot.scale(ov),
      opacity: isDiag ? 0.55 : 0.9,
      stroke: writes ? "#ff8c00" : (isDiag ? "#30363d" : null),
      strokeWidth: writes ? 1.5 : (isDiag ? 1 : 0),
      text: v > 0 ? Math.round(100 * ov / v) + "%" : "",
      textFill: t > 0.6 ? "#0d1117" : "#e6edf3",
    };
  }

  if (mode === "anomaly") {
    if (!hasAnomaly) return hasTraffic ? NOT_RELEV : EMPTY;
    return {
      fill: VM_SEV_COLORS[cell.maxSeverity] || "#58a6ff",
      opacity: 0.85,
      stroke: null, strokeWidth: 0,
      text: String(cell.anomalies.length),
      textFill: "#ffffff",
    };
  }

  // protocol (legacy) — diagonal always dark, matching the original rendering
  if (isDiag) return DIAG_EMPTY;
  if (!cell || !cell.protocols.size) return EMPTY;
  const isOtAnom = cell.anomalies.some(a => a.type === "vlan_cross_segment_ot" || a.type.startsWith("ot_"));
  return {
    fill: isOtAnom ? "#ff8c00" : (protoColor([...cell.protocols]) || "#555"),
    opacity: 0.75,
    stroke: isOtAnom ? "#f85149" : null,
    strokeWidth: isOtAnom ? 1.5 : 0,
    text: "", textFill: "#e6edf3",
  };
}

function vlanBaseLabel(vid) { return vid === "untagged" ? "Untagged" : `VLAN ${vid}`; }

function vlanCellTooltipHtml(mode, rowVid, colVid, cell, isDiag) {
  const rowLabel = vlanDisplayName(rowVid, vlanBaseLabel(rowVid));
  const header = isDiag
    ? `${escHtml(rowLabel)} (intra-VLAN)`
    : `${escHtml(rowLabel)} ↔ ${escHtml(vlanDisplayName(colVid, vlanBaseLabel(colVid)))}`;

  if (!cell) return `<strong>${header}</strong><br>No data`;

  if (mode === "traffic") {
    const protos = [...cell.protocols];
    return `<strong>${header}</strong><br>
      ${fmtNum(cell.packets)} pkts · ${fmtBytes(cell.bytes)}<br>
      ${protos.slice(0, 5).map(escHtml).join(" · ")}`;
  }
  if (mode === "ot") {
    if (!cell.otProtocols.size) {
      return `<strong>${header}</strong><br><span style="color:#8b949e">No OT/ICS traffic on this pair</span>`;
    }
    const share = cell.bytes > 0 ? Math.round(100 * cell.otBytes / cell.bytes) : 0;
    return `<strong>${header}</strong><br>
      ${[...cell.otProtocols].map(escHtml).join(" · ")}<br>
      ${fmtBytes(cell.otBytes)} OT-carrying traffic (${share}% of total)<br>
      ${fmtNum(cell.otReads)} reads / ${fmtNum(cell.otWrites)} writes`;
  }
  if (mode === "anomaly") {
    if (!cell.anomalies.length) return `<strong>${header}</strong><br>No anomalies`;
    const shown = cell.anomalies.slice(0, 5);
    const rows = shown.map(a =>
      `<span style="color:${VM_SEV_COLORS[a.severity] || '#58a6ff'}">●</span> ${escHtml(a.severity || "")} · ${escHtml(a.type)} · ${escHtml(a.src || "")}${a.dst ? " → " + escHtml(a.dst) : " → —"}`
    ).join("<br>");
    const more = cell.anomalies.length > 5 ? `<br>+${cell.anomalies.length - 5} more` : "";
    const firstDesc = shown[0]?.description
      ? `<br><span style="font-size:10px;color:#8b949e">${escHtml(shown[0].description)}</span>` : "";
    return `<strong>${header}</strong><br>${rows}${more}${firstDesc}`;
  }
  // protocol
  const protos = [...cell.protocols];
  const isOtAnom = cell.anomalies.some(a => a.type === "vlan_cross_segment_ot" || a.type.startsWith("ot_"));
  return `<strong>${header}</strong><br>
    ${fmtNum(cell.packets)} pkts · ${fmtBytes(cell.bytes)}<br>
    ${protos.slice(0, 5).map(escHtml).join(" · ")}
    ${isOtAnom ? `<br><span style="color:#f85149;font-size:10px">⚠ OT anomaly</span>` : ""}`;
}

/** Declarative legend spec shared by the on-screen legend and the PNG export footer. */
function vlanMatrixLegendSpec(mode, m) {
  const metric = _vlanMatrixMetric;
  if (mode === "traffic") {
    return {
      kind: "gradient",
      stops: ["#0d366b", "#1c5cab", "#2a78d6", "#5598e7", "#9ec5f4"],
      minLabel: "low",
      maxLabel: metric === "packets" ? fmtNum(m.maxPackets) : fmtBytes(m.maxBytes),
      note: `log scale · cell = total ${metric === "packets" ? "packets" : "bytes"} between VLAN pair · diagonal = intra-VLAN`,
    };
  }
  if (mode === "ot") {
    return {
      kind: "gradient",
      stops: ["#431407", "#9a3412", "#ea580c", "#fb923c", "#fdba74"],
      minLabel: "low",
      maxLabel: metric === "packets" ? fmtNum(m.maxOtPackets) : fmtBytes(m.maxOtBytes),
      note: "OT/ICS-carrying traffic (log) · orange border = OT writes cross this boundary · gray = traffic but no OT",
    };
  }
  if (mode === "anomaly") {
    return {
      kind: "swatches",
      items: [
        { color: VM_SEV_COLORS.high,   label: "high" },
        { color: VM_SEV_COLORS.medium, label: "medium" },
        { color: VM_SEV_COLORS.low,    label: "low" },
      ],
      note: "number = anomaly count · diagonal = single-host anomalies",
    };
  }
  return {
    kind: "swatches",
    items: [],
    note: "Cell color = dominant protocol · Orange = cross-VLAN OT anomaly · Red border = VLAN anomaly",
  };
}

function updateVlanMatrixLegend(spec) {
  const el = document.getElementById("vlan-matrix-legend");
  if (!el) return;
  el.innerHTML = "";
  if (spec.kind === "gradient") {
    const minL = document.createElement("span"); minL.textContent = spec.minLabel;
    const grad = document.createElement("span");
    grad.className = "vm-legend-grad";
    grad.style.background = `linear-gradient(90deg, ${spec.stops.join(", ")})`;
    const maxL = document.createElement("span"); maxL.textContent = spec.maxLabel;
    el.appendChild(minL); el.appendChild(grad); el.appendChild(maxL);
  } else if (spec.kind === "swatches") {
    spec.items.forEach(item => {
      const sw = document.createElement("span");
      sw.className = "vm-legend-swatch";
      sw.style.background = item.color;
      const lbl = document.createElement("span"); lbl.textContent = item.label;
      el.appendChild(sw); el.appendChild(lbl);
    });
  }
  if (spec.note) {
    const note = document.createElement("span");
    note.style.marginLeft = "10px"; note.style.color = "var(--text2)";
    note.textContent = spec.note;
    el.appendChild(note);
  }
}

document.getElementById("vlan-matrix-btn").addEventListener("click", () => {
  _vlanMatrixMode = !_vlanMatrixMode;
  const btn = document.getElementById("vlan-matrix-btn");
  btn.classList.toggle("active", _vlanMatrixMode);
  btn.textContent = _vlanMatrixMode ? "↩ Graph" : "⊞ Matrix";
  // Canvas / matrix swap
  document.getElementById("vlan-canvas-wrap").classList.toggle("hidden", _vlanMatrixMode);
  document.getElementById("vlan-matrix-container").classList.toggle("hidden", !_vlanMatrixMode);
  document.getElementById("vlan-matrix-modes").classList.toggle("hidden", !_vlanMatrixMode);
  // Graph-specific controls (layout buttons + fit) hide in matrix mode
  const graphCtrl = document.getElementById("vlan-graph-controls");
  if (graphCtrl) graphCtrl.style.display = _vlanMatrixMode ? "none" : "";
  // Search bar: hide in matrix mode; restore to "" (may still be hidden by loadGraph if no VLANs)
  const srchEl = document.getElementById("vlan-search");
  if (srchEl) srchEl.style.display = _vlanMatrixMode ? "none" : (graphData?.stats?.vlans?.length ? "" : "none");
  if (_vlanMatrixMode && graphData) renderVlanMatrix(graphData);
});

// Delegated listener for the mode/metric segmented controls next to the matrix
document.getElementById("vlan-matrix-modes").addEventListener("click", ev => {
  const modeBtn = ev.target.closest(".vm-mode-btn");
  if (modeBtn) {
    _vlanMatrixView = modeBtn.dataset.vmMode;
    document.querySelectorAll("#vlan-matrix-modes .vm-mode-btn").forEach(b => b.classList.toggle("active", b === modeBtn));
    const metricGroup = document.getElementById("vlan-matrix-metric");
    if (metricGroup) metricGroup.style.display = _vlanMatrixView === "traffic" ? "" : "none";
    if (graphData) renderVlanMatrix(graphData);
    return;
  }
  const metricBtn = ev.target.closest(".vm-metric-btn");
  if (metricBtn) {
    _vlanMatrixMetric = metricBtn.dataset.vmMetric;
    document.querySelectorAll("#vlan-matrix-modes .vm-metric-btn").forEach(b => b.classList.toggle("active", b === metricBtn));
    if (graphData) renderVlanMatrix(graphData);
    return;
  }
});

document.getElementById("vlan-matrix-export-btn").addEventListener("click", ev => {
  if (ev.shiftKey) exportVlanMatrixAllViews();
  else exportVlanMatrixPng();
});

function renderVlanMatrix(data) {
  const ns = "http://www.w3.org/2000/svg";
  const m = buildVlanFlowMatrix(data);
  if (!m.vids.length) return;

  // Adaptive cell size: larger for small VLAN counts, smaller for large ones
  const N = m.vids.length;
  const CELL = N > 20 ? Math.max(24, Math.floor(1100 / N))
                      : Math.max(44, Math.min(60, Math.floor(240 / Math.max(N, 1))));
  const LABEL = 90;  // must match #vlan-matrix-layout grid-template-columns in CSS
  const SHOW_TEXT = CELL >= 34;

  const colsSvg  = document.getElementById("vlan-matrix-cols");
  const rowsSvg  = document.getElementById("vlan-matrix-rows");
  const cellsSvg = document.getElementById("vlan-matrix-cells");
  [colsSvg, rowsSvg, cellsSvg].forEach(s => { s.innerHTML = ""; });

  const vidLabel = vid => {
    const full = vlanDisplayName(vid, vlanBaseLabel(vid));
    return full.length > 14 ? full.slice(0, 13) + "…" : full;
  };

  // Column headers (rotated) — overflow:visible lets rotated text extend outside SVG viewport
  colsSvg.setAttribute("width",  N * CELL);
  colsSvg.setAttribute("height", LABEL);
  colsSvg.setAttribute("overflow", "visible");
  m.vids.forEach((vid, j) => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("transform", `translate(${j * CELL + CELL / 2 + 2},${LABEL - 4}) rotate(-60)`);
    t.setAttribute("font-size", "10"); t.setAttribute("fill", "#8b949e");
    t.setAttribute("text-anchor", "end");
    t.textContent = vidLabel(vid);
    colsSvg.appendChild(t);
  });

  // Row headers
  rowsSvg.setAttribute("width",  LABEL);
  rowsSvg.setAttribute("height", N * CELL);
  m.vids.forEach((vid, i) => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", LABEL - 4); t.setAttribute("y", i * CELL + CELL * 0.65);
    t.setAttribute("font-size", "10"); t.setAttribute("fill", "#8b949e");
    t.setAttribute("text-anchor", "end");
    t.textContent = vidLabel(vid);
    rowsSvg.appendChild(t);
  });

  // Color scales (built once per render; value accessor honors the Bytes|Packets toggle)
  const metric  = _vlanMatrixMetric;
  const maxVal   = metric === "packets" ? m.maxPackets   : m.maxBytes;
  const maxOtVal = metric === "packets" ? m.maxOtPackets : m.maxOtBytes;
  const scales = {
    metric,
    traffic: makeHeatScale(maxVal,   ["#0d366b", "#1c5cab", "#2a78d6", "#5598e7", "#9ec5f4"]),
    ot:      makeHeatScale(maxOtVal, ["#431407", "#9a3412", "#ea580c", "#fb923c", "#fdba74"]),
  };

  // Cells
  cellsSvg.setAttribute("width",  N * CELL);
  cellsSvg.setAttribute("height", N * CELL);

  m.vids.forEach((rowVid, i) => {
    m.vids.forEach((colVid, j) => {
      const isDiag = i === j;
      const cell = m.cells[m.key(rowVid, colVid)] || null;
      const style = vlanCellStyle(_vlanMatrixView, cell, isDiag, scales);

      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", j * CELL + 1); rect.setAttribute("y", i * CELL + 1);
      rect.setAttribute("width", CELL - 2); rect.setAttribute("height", CELL - 2);
      rect.setAttribute("rx", "2");
      rect.setAttribute("fill", style.fill);
      rect.setAttribute("opacity", style.opacity);
      if (style.stroke) { rect.setAttribute("stroke", style.stroke); rect.setAttribute("stroke-width", style.strokeWidth); }

      // Any cell with flow or anomalies is interactive — anomaly-only pairs (no aggregated
      // edge) must still show a tooltip even though packets/bytes are 0.
      const hasData = !!(cell && (cell.packets > 0 || cell.bytes > 0 || cell.anomalies.length > 0));
      if (hasData) {
        rect.style.cursor = "pointer";
        rect.addEventListener("mouseenter", ev => {
          tooltip.innerHTML = vlanCellTooltipHtml(_vlanMatrixView, rowVid, colVid, cell, isDiag);
          tooltip.classList.add("visible"); positionTooltip(ev);
        });
        rect.addEventListener("mousemove", ev => positionTooltip(ev));
        rect.addEventListener("mouseleave", () => hideTooltip());
      }
      cellsSvg.appendChild(rect);

      if (SHOW_TEXT && style.text) {
        const txt = document.createElementNS(ns, "text");
        txt.setAttribute("x", j * CELL + CELL / 2);
        txt.setAttribute("y", i * CELL + CELL * 0.58);
        txt.setAttribute("text-anchor", "middle");
        txt.setAttribute("font-size", "9");
        txt.setAttribute("pointer-events", "none");
        txt.setAttribute("fill", style.textFill);
        if (_vlanMatrixView === "anomaly") txt.setAttribute("font-weight", "700");
        txt.textContent = style.text;
        cellsSvg.appendChild(txt);
      }
    });
  });

  updateVlanMatrixLegend(vlanMatrixLegendSpec(_vlanMatrixView, m));
}

/** Export the currently active matrix view as a self-describing PNG (title header +
 *  legend footer band). Returns a Promise so exportVlanMatrixAllViews() can sequence calls. */
function exportVlanMatrixPng() {
  if (!graphData) return Promise.resolve();
  const DPR = window.devicePixelRatio || 2;
  const LABEL_W = 90, LABEL_H = 90;  // must match LABEL in renderVlanMatrix (not 96 — that's the OT matrix)
  const HEADER_H = 46, FOOTER_H = 48;   // footer holds legend row + note line
  const COL_BLEED = 60;  // rotated column labels overhang the header band into the cells area
  const colsSvg  = document.getElementById("vlan-matrix-cols");
  const rowsSvg  = document.getElementById("vlan-matrix-rows");
  const cellsSvg = document.getElementById("vlan-matrix-cells");
  const colsW  = parseFloat(colsSvg.getAttribute("width"))  || 0;
  const rowsH  = parseFloat(rowsSvg.getAttribute("height")) || 0;
  const cellsW = parseFloat(cellsSvg.getAttribute("width")) || 0;
  const cellsH = parseFloat(cellsSvg.getAttribute("height")) || 0;
  if (cellsW === 0) return Promise.resolve();
  const spec = vlanMatrixLegendSpec(_vlanMatrixView, buildVlanFlowMatrix(graphData));
  const measureCtx = document.createElement("canvas").getContext("2d");
  measureCtx.font = "9px sans-serif";
  const noteW = spec.note ? Math.ceil(measureCtx.measureText(spec.note).width) : 0;
  // Wide enough for the matrix, the header title, and the footer note line
  const totalW = Math.max(380, LABEL_W + cellsW, noteW + 28);
  const totalH = HEADER_H + LABEL_H + cellsH + FOOTER_H;

  const serializeSvg = (svgEl, w, h, withBg = true) => {
    const clone = svgEl.cloneNode(true);
    clone.setAttribute("width", w); clone.setAttribute("height", h);
    if (withBg) {
      const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      bg.setAttribute("width", w); bg.setAttribute("height", h); bg.setAttribute("fill", "#0d1117");
      clone.insertBefore(bg, clone.firstChild);
    }
    return new XMLSerializer().serializeToString(clone);
  };
  const loadImg = (svgStr) => new Promise(resolve => {
    const url = URL.createObjectURL(new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" }));
    const img = new Image();
    img.onload = () => resolve({ img, url });
    img.src = url;
  });

  const VIEW_TITLES = {
    traffic:  `Traffic volume (${_vlanMatrixMetric})`,
    ot:       "OT/ICS flows",
    anomaly:  "Anomalies",
    protocol: "Dominant protocol",
  };

  return Promise.all([
    // No background + extra height: the rotated labels overhang the band and must
    // composite over the cells (like on-screen overflow:visible), not get clipped.
    loadImg(serializeSvg(colsSvg, colsW, LABEL_H + COL_BLEED, false)),
    loadImg(serializeSvg(rowsSvg, LABEL_W, rowsH)),
    loadImg(serializeSvg(cellsSvg, cellsW, cellsH)),
  ]).then(([cols, rows, cells]) => {
    const canvas = document.createElement("canvas");
    canvas.width  = Math.round(totalW * DPR);
    canvas.height = Math.round(totalH * DPR);
    const ctx = canvas.getContext("2d");
    ctx.scale(DPR, DPR);
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, totalW, totalH);

    // Header band
    ctx.fillStyle = "#161b22";
    ctx.fillRect(0, 0, totalW, HEADER_H);
    ctx.fillStyle = "#30363d";
    ctx.fillRect(0, HEADER_H - 1, totalW, 1);
    ctx.fillStyle = "#e6edf3";
    ctx.font = "13px sans-serif";
    ctx.fillText(`VLAN Flow Matrix — ${VIEW_TITLES[_vlanMatrixView] || _vlanMatrixView}`, 14, 20);
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px sans-serif";
    ctx.fillText(new Date().toISOString().slice(0, 10), 14, 36);

    // Matrix — cells first, then the transparent column-label layer on top so the
    // rotated labels can overhang into the cells area without being clipped
    ctx.drawImage(rows.img,  0,       HEADER_H + LABEL_H, LABEL_W, rowsH);
    ctx.drawImage(cells.img, LABEL_W, HEADER_H + LABEL_H, cellsW, cellsH);
    ctx.drawImage(cols.img,  LABEL_W, HEADER_H,           colsW,  LABEL_H + COL_BLEED);
    [cols, rows, cells].forEach(x => URL.revokeObjectURL(x.url));

    // Footer legend band — same declarative spec that drives the on-screen legend
    const footerY = HEADER_H + LABEL_H + cellsH;
    ctx.fillStyle = "#161b22";
    ctx.fillRect(0, footerY, totalW, FOOTER_H);
    ctx.fillStyle = "#30363d";
    ctx.fillRect(0, footerY, totalW, 1);

    const midY = footerY + 16;   // legend row; note gets its own line below
    let lx = 14;
    ctx.font = "9px sans-serif";
    if (spec.kind === "gradient") {
      const gradW = 110, gradH = 8;
      ctx.fillStyle = "#8b949e";
      ctx.fillText(spec.minLabel, lx, midY + 3);
      lx += ctx.measureText(spec.minLabel).width + 6;
      const grad = ctx.createLinearGradient(lx, 0, lx + gradW, 0);
      const n = spec.stops.length;
      spec.stops.forEach((c, idx) => grad.addColorStop(n === 1 ? 0 : idx / (n - 1), c));
      ctx.fillStyle = grad;
      ctx.fillRect(lx, midY - gradH / 2, gradW, gradH);
      lx += gradW + 6;
      ctx.fillStyle = "#8b949e";
      ctx.fillText(spec.maxLabel, lx, midY + 3);
      lx += ctx.measureText(spec.maxLabel).width + 14;
    } else if (spec.kind === "swatches") {
      spec.items.forEach(item => {
        ctx.fillStyle = item.color;
        ctx.fillRect(lx, midY - 5, 10, 10);
        lx += 14;
        ctx.fillStyle = "#8b949e";
        ctx.fillText(item.label, lx, midY + 3);
        lx += ctx.measureText(item.label).width + 12;
      });
    }
    if (spec.note) {
      ctx.fillStyle = "#8b949e";
      ctx.fillText(spec.note, 14, footerY + 36);
    }

    const a = document.createElement("a");
    const suffix = _vlanMatrixView === "traffic" ? `-${_vlanMatrixMetric}` : "";
    a.download = `vlan-matrix-${_vlanMatrixView}${suffix}-${new Date().toISOString().slice(0, 10)}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
  });
}

/** Sequentially exports all 4 matrix views as separate PNGs, then restores the prior view. */
async function exportVlanMatrixAllViews() {
  if (!graphData) return;
  const prevView = _vlanMatrixView;
  for (const mode of ["traffic", "ot", "anomaly", "protocol"]) {
    _vlanMatrixView = mode;
    renderVlanMatrix(graphData);
    await exportVlanMatrixPng();
  }
  _vlanMatrixView = prevView;
  renderVlanMatrix(graphData);
  const modesBar = document.getElementById("vlan-matrix-modes");
  if (modesBar) {
    modesBar.querySelectorAll(".vm-mode-btn").forEach(b => b.classList.toggle("active", b.dataset.vmMode === prevView));
  }
}

/* ── C2: Dashboard / summary view ───────────────────────────────────────── */
function renderDashboard() {
  const view = document.getElementById("dashboard-view");
  if (!graphData || !view) return;
  view.innerHTML = "";

  const stats    = graphData.stats || {};
  const nodes    = graphData.nodes || [];
  const edges    = graphData.edges || [];
  const anomalies = graphData.anomalies || [];

  // Summary cards
  const summaryRow = document.createElement("div");
  summaryRow.className = "db-summary-row";
  [
    { label: "Hosts",       value: fmtNum(nodes.length) },
    { label: "Connections", value: fmtNum(edges.length) },
    { label: "Packets",     value: fmtNum(stats.total_packets || 0) },
    { label: "Anomalies",   value: fmtNum(anomalies.length) },
    { label: "Protocols",   value: fmtNum((stats.protocols || []).length) },
  ].forEach(c => {
    const card = document.createElement("div");
    card.className = "db-card";
    card.innerHTML = `<div class="db-card-val">${c.value}</div><div class="db-card-lbl">${escHtml(c.label)}</div>`;
    summaryRow.appendChild(card);
  });
  view.appendChild(summaryRow);

  const cols = document.createElement("div");
  cols.className = "db-cols";

  // Left column: top risk hosts
  const leftCol = document.createElement("div");
  leftCol.className = "db-left-col";

  const riskPanel = document.createElement("div");
  riskPanel.className = "db-panel";
  riskPanel.innerHTML = `<div class="db-panel-title">Top Hosts by Risk Score</div>`;
  const topHosts = nodes
    .filter(n => (n.risk_score || 0) > 0)
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 10);
  if (topHosts.length === 0) {
    riskPanel.innerHTML += '<div class="db-empty">No risks detected</div>';
  } else {
    const maxRisk = topHosts[0].risk_score || 1;
    const barList = document.createElement("div");
    barList.className = "db-bar-list";
    topHosts.forEach(n => {
      const pct = Math.round(((n.risk_score || 0) / maxRisk) * 100);
      const cls = (n.risk_score || 0) >= 70 ? "high" : (n.risk_score || 0) >= 40 ? "med" : "low";
      const row = document.createElement("div");
      row.className = "db-bar-row";
      row.title = `${n.id}  —  risk ${n.risk_score}`;
      row.innerHTML = `
        <div class="db-bar-label">${escHtml(n.ip || n.id)}</div>
        <div class="db-bar-track"><div class="db-bar-fill ${cls}" style="width:${pct}%"></div></div>
        <div class="db-bar-val">${n.risk_score || 0}</div>`;
      row.addEventListener("click", () => {
        const nd = (graphData.nodes || []).find(x => x.id === n.id);
        if (!nd) return;
        selectedNode = nd;
        showDetailPanel(nd);
        detailPanel.classList.add("open");
        setView("graph");
        setTimeout(() => {
          if (_isRendered(nd.id)) {
            highlightNode(nd, linksGroup.selectAll(".link"), nodesGroup.selectAll(".node"));
          } else {
            showToast(`${nd.id} is outside the rendered top-${RENDER_NODE_CAP} — visible in Table view and exports.`, "info", 5000);
          }
        }, 80);
      });
      barList.appendChild(row);
    });
    riskPanel.appendChild(barList);
  }
  leftCol.appendChild(riskPanel);
  cols.appendChild(leftCol);

  // Right column: protocol dist + anomaly severity + busiest conns
  const rightCol = document.createElement("div");
  rightCol.className = "db-right-col";

  // Protocol distribution
  const protoPanel = document.createElement("div");
  protoPanel.className = "db-panel";
  protoPanel.innerHTML = `<div class="db-panel-title">Protocol Distribution</div>`;
  const protoCounts = {};
  edges.forEach(e => (e.protocols || []).forEach(p => {
    protoCounts[p] = (protoCounts[p] || 0) + (e.packet_count || 1);
  }));
  const sortedProtos = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (sortedProtos.length === 0) {
    protoPanel.innerHTML += '<div class="db-empty">No protocol data</div>';
  } else {
    const maxP = sortedProtos[0][1] || 1;
    const pList = document.createElement("div");
    pList.className = "db-bar-list";
    sortedProtos.forEach(([proto, cnt]) => {
      const pct = Math.round((cnt / maxP) * 100);
      const row = document.createElement("div");
      row.className = "db-bar-row";
      row.innerHTML = `
        <div class="db-bar-label">${escHtml(proto)}</div>
        <div class="db-bar-track"><div class="db-bar-fill proto" style="width:${pct}%"></div></div>
        <div class="db-bar-val">${fmtNum(cnt)}</div>`;
      pList.appendChild(row);
    });
    protoPanel.appendChild(pList);
  }
  rightCol.appendChild(protoPanel);

  // Anomaly severity breakdown
  const anomPanel = document.createElement("div");
  anomPanel.className = "db-panel";
  anomPanel.innerHTML = `<div class="db-panel-title">Anomaly Severity</div>`;
  const sevCounts = { high: 0, medium: 0, low: 0, info: 0 };
  anomalies.forEach(a => { if (a.severity in sevCounts) sevCounts[a.severity]++; });
  const sevRow = document.createElement("div");
  sevRow.className = "db-sev-row";
  [["high","High"],["medium","Med"],["low","Low"],["info","Info"]].forEach(([sev, lbl]) => {
    const chip = document.createElement("div");
    chip.className = `db-sev-chip ${sev}`;
    chip.innerHTML = `<span class="db-sev-count">${sevCounts[sev]}</span><span class="db-sev-lbl">${lbl}</span>`;
    sevRow.appendChild(chip);
  });
  anomPanel.appendChild(sevRow);
  rightCol.appendChild(anomPanel);

  // Top anomalies list (clickable — drills down to graph)
  const topAnomPanel = document.createElement("div");
  topAnomPanel.className = "db-panel";
  topAnomPanel.innerHTML = `<div class="db-panel-title">Top Anomalies</div>`;
  if (!anomalies || anomalies.length === 0) {
    topAnomPanel.innerHTML += '<div class="db-empty">No anomalies detected</div>';
  } else {
    // Group by type+src (same key as the sidebar's stage-2 grouping)
    const anomGroups = new Map();
    anomalies.forEach(a => {
      const key = `${a.type}|${a.src || ""}`;
      if (!anomGroups.has(key)) anomGroups.set(key, { rep: a, items: [] });
      anomGroups.get(key).items.push(a);
    });
    // Sort: severity rank desc, then count desc
    const _topSevOrder = { high: 4, medium: 3, low: 2, info: 1 };
    const sortedAnomGroups = [...anomGroups.values()]
      .sort((a, b) => {
        const sd = (_topSevOrder[b.rep.severity] || 0) - (_topSevOrder[a.rep.severity] || 0);
        return sd !== 0 ? sd : b.items.length - a.items.length;
      });
    const displayAnomGroups = sortedAnomGroups.slice(0, 6);
    const anomRemainder = sortedAnomGroups.length - displayAnomGroups.length;
    const anomList = document.createElement("div");
    anomList.className = "db-anom-list";
    displayAnomGroups.forEach(({ rep, items }) => {
      const row = document.createElement("div");
      row.className = "db-anom-row";
      row.title = "Click to inspect in graph";
      row.innerHTML = `<span class="db-anom-dot ${escHtml(rep.severity)}"></span>` +
        `<span class="db-anom-label">${escHtml(_anomalySummary(rep.type, rep.src, items.length, items))}</span>` +
        `<button class="db-anom-review" title="Review finding">Review</button>`;
      row.addEventListener("click", () => _jumpToAnomaly(rep));
      row.querySelector(".db-anom-review").addEventListener("click", e => {
        e.stopPropagation();
        const findingId = _findingId("anom", [rep.type || "", rep.src || "", rep.dst || "", rep.description || ""]);
        openFindingById(findingId);
      });
      anomList.appendChild(row);
    });
    if (anomRemainder > 0) {
      const moreRow = document.createElement("div");
      moreRow.className = "db-anom-more";
      moreRow.textContent = `+${anomRemainder} more`;
      anomList.appendChild(moreRow);
    }
    topAnomPanel.appendChild(anomList);
  }
  rightCol.appendChild(topAnomPanel);

  // Busiest connections
  const connPanel = document.createElement("div");
  connPanel.className = "db-panel";
  connPanel.innerHTML = `<div class="db-panel-title">Busiest Connections</div>`;
  const topEdges = [...edges].sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0)).slice(0, 6);
  if (topEdges.length === 0) {
    connPanel.innerHTML += '<div class="db-empty">No connection data</div>';
  } else {
    const cList = document.createElement("div");
    cList.className = "db-conn-list";
    topEdges.forEach(e => {
      const row = document.createElement("div");
      row.className = "db-conn-row";
      row.innerHTML = `
        <span class="db-conn-src" title="${escHtml(e.source)}">${escHtml(e.source)}</span>
        <span class="db-conn-arrow">→</span>
        <span class="db-conn-dst" title="${escHtml(e.target)}">${escHtml(e.target)}</span>
        <span class="db-conn-count">${fmtNum(e.packet_count || 0)} pkts</span>`;
      cList.appendChild(row);
    });
    connPanel.appendChild(cList);
  }
  rightCol.appendChild(connPanel);

  cols.appendChild(rightCol);
  view.appendChild(cols);
}

function renderDiff() {
  if (!baselineData || !graphData) return;
  const bNodes = new Map((baselineData.nodes || []).map(n => [n.id, n]));
  const cNodes = new Map((graphData.nodes || []).map(n => [n.id, n]));
  const bEdges = new Set((baselineData.edges || []).map(e => `${e.source}|${e.target}`));
  const cEdges = new Set((graphData.edges || []).map(e => `${e.source}|${e.target}`));
  const bAnoms = new Set((baselineData.anomalies || []).map(a => `${a.type}|${a.src}|${a.dst}`));
  const cAnoms = (graphData.anomalies || []).filter(a => !bAnoms.has(`${a.type}|${a.src}|${a.dst}`));

  // Host diff
  const newHosts  = [...cNodes.values()].filter(n => !bNodes.has(n.id));
  const goneHosts = [...bNodes.values()].filter(n => !cNodes.has(n.id));
  const changedHosts = [...cNodes.values()].filter(n => {
    if (!bNodes.has(n.id)) return false;
    const bn = bNodes.get(n.id);
    if (n.host_type !== bn.host_type) return true;
    if (Math.abs((n.risk_score || 0) - (bn.risk_score || 0)) > 20) return true;
    const bProtos = new Set(bn.protocols || []);
    if ((n.protocols || []).some(p => !bProtos.has(p))) return true;
    const bPorts = new Set((bn.open_ports || []).map(String));
    if ((n.open_ports || []).some(p => !bPorts.has(String(p)))) return true;
    return false;
  });

  // Connection diff
  const newConns  = (graphData.edges || []).filter(e => !bEdges.has(`${e.source}|${e.target}`));
  const goneConns = (baselineData.edges || []).filter(e => !cEdges.has(`${e.source}|${e.target}`));

  // Changed connections: exist in both but byte count shifted significantly (>2× or <0.5×)
  const bEdgeMap = new Map();
  (baselineData.edges || []).forEach(e => {
    bEdgeMap.set(`${e.source}|${e.target}`, e);
    bEdgeMap.set(`${e.target}|${e.source}`, e);
  });
  const changedConns = [];
  (graphData.edges || []).forEach(e => {
    const be = bEdgeMap.get(`${e.source}|${e.target}`) || bEdgeMap.get(`${e.target}|${e.source}`);
    if (!be) return;
    const ob = be.bytes || be.packet_count || 0;
    const nb = e.bytes  || e.packet_count  || 0;
    if (!ob || !nb) return;
    const ratio = nb / ob;
    if (ratio > 2 || ratio < 0.5) changedConns.push({ edge: e, ratio });
  });

  _renderDiffCol("diff-hosts-list", newHosts, goneHosts, changedHosts, bNodes);
  _renderDiffConnsCol("diff-conns-list", newConns, goneConns, changedConns);
  _renderDiffAnomsCol("diff-anomalies-list", cAnoms);

  // VLAN diff: new/gone VLANs + hosts that changed VLAN membership
  const bVlans = new Set((baselineData.stats?.vlans || []).map(String));
  const cVlans = new Set((graphData.stats?.vlans   || []).map(String));
  const newVlans  = [...cVlans].filter(v => !bVlans.has(v));
  const goneVlans = [...bVlans].filter(v => !cVlans.has(v));
  const movedHosts = [];
  bNodes.forEach((bn, id) => {
    const cn = cNodes.get(id);
    if (!cn) return;
    const bv = new Set((bn.vlans || []).map(String));
    const cv = new Set((cn.vlans || []).map(String));
    const added   = [...cv].filter(v => !bv.has(v));
    const removed = [...bv].filter(v => !cv.has(v));
    if (added.length || removed.length) movedHosts.push({ id, added, removed });
  });
  _renderDiffVlansCol("diff-vlans-list", newVlans, goneVlans, movedHosts);
}

function _renderDiffCol(id, added, removed, changed, bNodes) {
  const el = document.getElementById(id);
  el.innerHTML = "";
  if (!added.length && !removed.length && !changed.length) {
    el.innerHTML = '<div class="diff-empty">No host changes</div>';
    return;
  }
  added.forEach(n => {
    const d = document.createElement("div");
    d.className = "diff-item diff-added";
    d.innerHTML = `<span class="diff-badge add">+ NEW</span> <strong>${escHtml(n.id)}</strong> <span class="diff-sub">${escHtml(n.host_type || "")}</span>`;
    el.appendChild(d);
  });
  removed.forEach(n => {
    const d = document.createElement("div");
    d.className = "diff-item diff-removed";
    d.innerHTML = `<span class="diff-badge rem">− GONE</span> <strong>${escHtml(n.id)}</strong> <span class="diff-sub">${escHtml(n.host_type || "")}</span>`;
    el.appendChild(d);
  });
  changed.forEach(n => {
    const bn = bNodes ? bNodes.get(n.id) : null;
    const changes = [];
    if (bn) {
      if (n.host_type !== bn.host_type)
        changes.push(`type: ${bn.host_type || "?"} → ${n.host_type || "?"}`);
      const riskDelta = (n.risk_score || 0) - (bn.risk_score || 0);
      if (Math.abs(riskDelta) > 20)
        changes.push(`risk: ${riskDelta > 0 ? "+" : ""}${riskDelta}`);
      const bProtos = new Set(bn.protocols || []);
      const newProtos = (n.protocols || []).filter(p => !bProtos.has(p));
      if (newProtos.length) changes.push(`new proto: ${newProtos.join(", ")}`);
      const bPorts = new Set((bn.open_ports || []).map(String));
      const newPorts = (n.open_ports || []).filter(p => !bPorts.has(String(p)));
      if (newPorts.length) changes.push(`new port: ${newPorts.join(", ")}`);
    }
    const changeDesc = changes.length ? changes.map(escHtml).join(" · ") : "changed";
    const d = document.createElement("div");
    d.className = "diff-item diff-changed";
    d.innerHTML = `<span class="diff-badge chg">~ CHG</span> <strong>${escHtml(n.id)}</strong> <span class="diff-sub">${changeDesc}</span>`;
    el.appendChild(d);
  });
}

function _renderDiffConnsCol(id, added, removed, changed) {
  const el = document.getElementById(id);
  el.innerHTML = "";
  if (!added.length && !removed.length && !(changed && changed.length)) {
    el.innerHTML = '<div class="diff-empty">No connection changes</div>';
    return;
  }
  added.forEach(e => {
    const d = document.createElement("div");
    d.className = "diff-item diff-added";
    d.innerHTML = `<span class="diff-badge add">+ NEW</span> ${escHtml(e.source)} → ${escHtml(e.target)} <span class="diff-sub">${(e.protocols || []).map(escHtml).join(", ")}</span>`;
    el.appendChild(d);
  });
  removed.forEach(e => {
    const d = document.createElement("div");
    d.className = "diff-item diff-removed";
    d.innerHTML = `<span class="diff-badge rem">− GONE</span> ${escHtml(e.source)} → ${escHtml(e.target)}`;
    el.appendChild(d);
  });
  (changed || []).forEach(({ edge: e, ratio }) => {
    const dir = ratio > 1 ? `▲${ratio.toFixed(1)}×` : `▼${(1 / ratio).toFixed(1)}×`;
    const d = document.createElement("div");
    d.className = "diff-item diff-changed";
    d.innerHTML = `<span class="diff-badge chg">~ ${escHtml(dir)}</span> ${escHtml(e.source)} → ${escHtml(e.target)}`;
    el.appendChild(d);
  });
}

function _renderDiffAnomsCol(id, newAnoms) {
  const el = document.getElementById(id);
  el.innerHTML = "";
  if (!newAnoms.length) {
    el.innerHTML = '<div class="diff-empty">No new anomalies</div>';
    return;
  }
  newAnoms.forEach(a => {
    const d = document.createElement("div");
    d.className = `diff-item diff-added diff-anom-${a.severity || "low"}`;
    const route = [a.src, a.dst].filter(Boolean).join(" → ");
    d.innerHTML = `<span class="diff-badge add">+ NEW</span> <strong>${escHtml(a.type)}</strong><br><span class="diff-sub">${escHtml(route)} — ${escHtml(a.description)}</span>`;
    el.appendChild(d);
  });
}

function _renderDiffVlansCol(id, newVlans, goneVlans, movedHosts) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = "";
  if (!newVlans.length && !goneVlans.length && !movedHosts.length) {
    el.innerHTML = '<div class="diff-empty">No VLAN changes</div>';
    return;
  }
  newVlans.forEach(v => {
    const d = document.createElement("div");
    d.className = "diff-item diff-added";
    d.innerHTML = `<span class="diff-badge add">+ NEW</span> <strong>VLAN ${escHtml(v)}</strong>`;
    el.appendChild(d);
  });
  goneVlans.forEach(v => {
    const d = document.createElement("div");
    d.className = "diff-item diff-removed";
    d.innerHTML = `<span class="diff-badge rem">− GONE</span> <strong>VLAN ${escHtml(v)}</strong>`;
    el.appendChild(d);
  });
  movedHosts.forEach(({ id: hostId, added, removed }) => {
    const d = document.createElement("div");
    d.className = "diff-item diff-changed";
    const parts = [];
    if (added.length)   parts.push(`+VLAN ${added.join(", ")}`);
    if (removed.length) parts.push(`−VLAN ${removed.join(", ")}`);
    d.innerHTML = `<span class="diff-badge chg">~ MOVED</span> <strong>${escHtml(hostId)}</strong> <span class="diff-sub">${parts.map(escHtml).join(" ")}</span>`;
    el.appendChild(d);
  });
}

/* ── OT Log view ─────────────────────────────────────────────────────────── */
let _otLogRendered = false;   // render once per dataset load
// Persist filter Sets at module scope so that button click-handlers created during the
// first render and rebuildTable() called on subsequent view revisits share the same
// objects.  Previously these were local consts, so returning to the view re-created
// all-active Sets while the buttons still closed over the first call's stale Sets.
let _otLogActiveProtoF = null;
let _otLogActiveDirF   = null;

function renderOtLog(cmds) {
  const tbody       = document.getElementById("otlog-tbody");
  const emptyEl     = document.getElementById("otlog-empty");
  const countLabel  = document.getElementById("otlog-count-label");
  const protoBar    = document.getElementById("otlog-filter-protos");
  const dirBar      = document.getElementById("otlog-filter-dirs");

  if (!cmds || cmds.length === 0) {
    tbody.innerHTML = "";
    protoBar.innerHTML = "";
    dirBar.innerHTML = "";
    emptyEl.classList.remove("hidden");
    countLabel.textContent = "0 commands";
    return;
  }
  emptyEl.classList.add("hidden");

  function _dirClass(d) {
    if (d === "write")      return "otlog-dir-write";
    if (d === "error")      return "otlog-dir-error";
    if (d === "diagnostic") return "otlog-dir-diagnostic";
    return "otlog-dir-read";
  }

  function _details(c) {
    const parts = [];
    if (c.unit_id != null)  parts.push(`Unit ${c.unit_id}`);
    if (c.register != null) parts.push(`Reg ${c.register}`);
    if (c.quantity != null) parts.push(`×${c.quantity}`);
    if (c.address != null)  parts.push(`Addr ${c.address}`);
    if (c.data_object)      parts.push(c.data_object);
    return parts.join(" | ") || "—";
  }

  function rebuildTable() {
    const visible = cmds.filter(c => _otLogActiveProtoF.has(c.protocol) && _otLogActiveDirF.has(c.direction));
    countLabel.textContent = `${visible.length.toLocaleString()} / ${cmds.length.toLocaleString()} commands`;
    tbody.innerHTML = "";
    const frag = document.createDocumentFragment();
    visible.forEach(c => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--text2)">+${c.rel_time}s</td>
        <td style="font-family:var(--font-mono);font-size:11px">${escHtml(c.src)}</td>
        <td style="font-family:var(--font-mono);font-size:11px">${escHtml(c.dst)}</td>
        <td><span class="otlog-proto-pill">${escHtml(c.protocol)}</span></td>
        <td>${escHtml(c.function_name || (c.function_code != null ? `FC${c.function_code}` : "—"))}</td>
        <td class="${_dirClass(c.direction)}">${escHtml(c.direction)}</td>
        <td style="color:var(--text2);font-size:11px">${escHtml(_details(c))}</td>`;
      frag.appendChild(tr);
    });
    tbody.appendChild(frag);
  }

  // Build filter buttons only once per dataset; also initialise the persistent Sets here
  // so they share the same object references as the button click-handlers.
  if (!_otLogRendered) {
    const protos = [...new Set(cmds.map(c => c.protocol))].sort();
    const dirs   = [...new Set(cmds.map(c => c.direction))].sort();
    _otLogActiveProtoF = new Set(protos);
    _otLogActiveDirF   = new Set(dirs);

    protoBar.innerHTML = '<span style="font-size:11px;color:var(--text2);margin-right:4px">Protocol:</span>';
    dirBar.innerHTML   = '<span style="font-size:11px;color:var(--text2);margin-right:4px">Direction:</span>';

    protos.forEach(proto => {
      const btn = document.createElement("button");
      btn.className = "otlog-filter-btn active";
      btn.textContent = proto;
      btn.addEventListener("click", () => {
        if (_otLogActiveProtoF.has(proto)) { _otLogActiveProtoF.delete(proto); btn.classList.remove("active"); }
        else { _otLogActiveProtoF.add(proto); btn.classList.add("active"); }
        rebuildTable();
      });
      protoBar.appendChild(btn);
    });

    dirs.forEach(dir => {
      const btn = document.createElement("button");
      btn.className = "otlog-filter-btn active";
      btn.textContent = dir;
      btn.addEventListener("click", () => {
        if (_otLogActiveDirF.has(dir)) { _otLogActiveDirF.delete(dir); btn.classList.remove("active"); }
        else { _otLogActiveDirF.add(dir); btn.classList.add("active"); }
        rebuildTable();
      });
      dirBar.appendChild(btn);
    });

    _otLogRendered = true;
  }

  rebuildTable();
}

/* ── Export ──────────────────────────────────────────────────────────────── */
document.getElementById("export-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  const menu = document.getElementById("export-menu");
  menu.classList.toggle("hidden");
});

document.addEventListener("click", () => {
  document.getElementById("export-menu").classList.add("hidden");
});

document.getElementById("exp-png").addEventListener("click", () => {
  exportPng();
  document.getElementById("export-menu").classList.add("hidden");
});

/* ── OT Map toolbar wiring ───────────────────────────────────────────────── */
document.getElementById("ot-edit-btn").addEventListener("click", () => {
  otEditMode = !otEditMode;
  const btn = document.getElementById("ot-edit-btn");
  btn.textContent = otEditMode ? "✓ Editing" : "✎ Edit";
  btn.classList.toggle("active", otEditMode);
  document.getElementById("ot-add-btn").classList.toggle("hidden", !otEditMode);
  document.getElementById("ot-map-view").classList.toggle("ot-edit-active", otEditMode);
  document.getElementById("ot-risk-panel").classList.add("hidden");
  document.getElementById("ot-edit-hint").classList.toggle("hidden", !otEditMode);
  if (graphData) renderOTMap(graphData);
});

document.getElementById("ot-hint-close-btn").addEventListener("click", () => {
  document.getElementById("ot-edit-hint").classList.add("hidden");
});

document.getElementById("ot-add-btn").addEventListener("click", () =>
  document.getElementById("ot-add-modal").classList.remove("hidden"));

document.getElementById("ot-am-close").addEventListener("click", () =>
  document.getElementById("ot-add-modal").classList.add("hidden"));

document.getElementById("ot-am-confirm").addEventListener("click", () => {
  const ip = document.getElementById("ot-am-ip").value.trim();
  if (!ip) { document.getElementById("ot-am-ip").focus(); return; }
  const errEl = document.getElementById("ot-am-error");
  const _showErr = (msg) => {
    errEl.textContent = msg;
    setTimeout(() => { errEl.textContent = ""; }, 3000);
  };
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || ip.split(".").some(o => parseInt(o) > 255)) {
    _showErr("Invalid IP address format."); return;
  }
  const lvl = parseFloat(document.getElementById("ot-am-level").value);
  if (!isNaN(lvl) && (lvl < -1 || lvl > 6)) {
    _showErr("Purdue level must be between -1 and 6."); return;
  }
  // Prevent duplicate IDs
  if (otAddedNodes.some(a => a.id === ip) || (graphData && graphData.nodes.some(n => n.id === ip))) {
    _showErr(`A device with IP ${ip} already exists.`); return;
  }
  otAddedNodes.push({
    id: ip, ip,
    hostname:  document.getElementById("ot-am-host").value.trim() || null,
    host_type: document.getElementById("ot-am-type").value || "Unknown",
    purdue_level: isNaN(lvl) ? -1 : lvl,
    protocols: [], services: [], open_ports: [], dns_queries: [], dns_names: [],
    mac: null, mac_vendor: null, os_hint: null, is_private: true,
    flags: [], geo: null, ot_role: "unknown",
    modbus_unit_ids: [], dnp3_addresses: [], added_manually: true,
  });
  ["ot-am-ip", "ot-am-host"].forEach(id => document.getElementById(id).value = "");
  document.getElementById("ot-add-modal").classList.add("hidden");
  renderOTMap(graphData);
});

document.getElementById("ot-rp-close").addEventListener("click", () =>
  document.getElementById("ot-risk-panel").classList.add("hidden"));

// Zoom button handlers
document.getElementById("ot-zoom-in-btn").addEventListener("click", () => {
  if (!otZoom) return;
  d3.select("#ot-map-svg").transition().duration(250).call(otZoom.scaleBy, 1.5);
});
document.getElementById("ot-zoom-out-btn").addEventListener("click", () => {
  if (!otZoom) return;
  d3.select("#ot-map-svg").transition().duration(250).call(otZoom.scaleBy, 1 / 1.5);
});
document.getElementById("ot-zoom-fit-btn").addEventListener("click", () => {
  if (!otZoom) return;
  otZoomState = d3.zoomIdentity;
  d3.select("#ot-map-svg").transition().duration(300).call(otZoom.transform, d3.zoomIdentity);
});

// "Show all" filter toggle — wired from a data attribute on the OT toolbar button if present
(function() {
  const filterBtn = document.getElementById("ot-filter-btn");
  if (!filterBtn) return;
  filterBtn.addEventListener("click", () => {
    otFilterAll = !otFilterAll;
    filterBtn.textContent = otFilterAll ? "Filtered: off" : "Respect filters";
    filterBtn.classList.toggle("active", otFilterAll);
    if (graphData) renderOTMap(graphData);
  });
})();

// ResizeObserver: re-render OT map when #ot-map-view size changes
let _otResizeTimer = null;
new ResizeObserver(() => {
  if (currentView !== "ot") return;
  clearTimeout(_otResizeTimer);
  _otResizeTimer = setTimeout(() => {
    if (graphData) {
      if (!otMatrixMode) renderOTMap(graphData);
      renderOTTimeline();
    }
  }, 150);
}).observe(document.getElementById("ot-map-view"));

document.getElementById("ot-export-png-btn").addEventListener("click", () => {
  if (otMatrixMode) exportOTMatrixPng();
  else exportOTMapPng();
});
document.getElementById("ot-export-json-btn").addEventListener("click", exportOTMapJson);

document.getElementById("ot-matrix-btn").addEventListener("click", () => {
  otMatrixMode = !otMatrixMode;
  document.getElementById("ot-matrix-btn").classList.toggle("active", otMatrixMode);
  document.getElementById("ot-map-svg").classList.toggle("hidden", otMatrixMode);
  document.getElementById("ot-matrix-container").classList.toggle("hidden", !otMatrixMode);
  if (otMatrixMode && graphData) renderOTMatrix(graphData);
});
document.getElementById("exp-csv").addEventListener("click", () => {
  exportCsv();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-hosts").addEventListener("click", () => {
  exportHostsCsv();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-anomalies").addEventListener("click", () => {
  exportAnomalies();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-credentials").addEventListener("click", () => {
  exportCredentialsCsv();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-report").addEventListener("click", () => {
  generateAuditReport();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-vlan-inventory").addEventListener("click", () => {
  exportVlanInventoryCsv();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-vlan-traffic").addEventListener("click", () => {
  exportVlanTrafficCsv();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-vlan-svg").addEventListener("click", () => {
  exportVlanSvg();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-vlan-matrix").addEventListener("click", () => {
  document.getElementById("export-menu").classList.add("hidden");
  if (!graphData || !graphData.stats?.vlans?.length) return;
  if (!document.getElementById("vlan-matrix-cells").childElementCount) renderVlanMatrix(graphData);
  exportVlanMatrixPng();
});
document.getElementById("exp-vlan-matrix-all").addEventListener("click", () => {
  document.getElementById("export-menu").classList.add("hidden");
  if (!graphData || !graphData.stats?.vlans?.length) return;
  exportVlanMatrixAllViews();
});
document.getElementById("imp-vlan-names").addEventListener("click", () => {
  document.getElementById("export-menu").classList.add("hidden");
  document.getElementById("vlan-names-file-input").click();
});
document.getElementById("vlan-names-file-input").addEventListener("change", function() {
  const file = this.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    let imported = 0;
    (e.target.result || "").split(/\r?\n/).forEach(line => {
      const comma = line.indexOf(",");
      if (comma === -1) return;
      const vid  = line.slice(0, comma).trim();
      const name = line.slice(comma + 1).trim();
      if (!vid) return;
      saveVlanLabel(vid, name);
      imported++;
    });
    this.value = "";   // reset so same file can be re-imported
    if (imported > 0) {
      showToast(`Imported ${imported} VLAN name${imported !== 1 ? "s" : ""}. Switch to VLAN tab to see labels.`, "info");
      // Force re-render if VLAN view is active
      _vlanRendered = false;
      if (currentView === "vlangraph" && graphData) renderVlanGraph(graphData);
    } else {
      showToast("No valid VLAN names found. Format: vid,name (one per line).", "error");
    }
  };
  reader.onerror = () => showToast("Failed to read VLAN names file.", "error");
  reader.readAsText(file);
});

function exportVlanSvg() {
  if (!(graphData?.stats?.vlans?.length)) {
    showToast("No VLAN data to export.", "info"); return;
  }
  const svgEl = document.getElementById("vlan-svg");
  if (!svgEl) return;
  const clone = svgEl.cloneNode(true);
  clone.setAttribute("style", "background:#0d1117");
  const svgStr = new XMLSerializer().serializeToString(clone);
  const blob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "vlan-diagram.svg"; a.click();
  URL.revokeObjectURL(url);
}

function exportPng() {
  const svgEl = document.getElementById("graph-svg");
  const serializer = new XMLSerializer();
  const svgStr = serializer.serializeToString(svgEl);
  const svgBlob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(svgBlob);
  const img = new Image();
  img.onload = function() {
    const canvas = document.createElement("canvas");
    canvas.width = svgEl.clientWidth || 1200;
    canvas.height = svgEl.clientHeight || 800;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    // Composite canvas edges (drawn separately when node count exceeds threshold)
    if (useCanvasEdges) {
      const edgeCanvas = document.getElementById("edge-canvas");
      if (edgeCanvas) ctx.drawImage(edgeCanvas, 0, 0);
    }
    ctx.drawImage(img, 0, 0);
    URL.revokeObjectURL(url);
    const a = document.createElement("a");
    a.download = "network-graph.png";
    a.href = canvas.toDataURL("image/png");
    a.click();
  };
  img.src = url;
}

function exportCsv() {
  if (!graphData) return;
  const nodeMap = {};
  (graphData.nodes || []).forEach(n => { nodeMap[n.ip || n.id] = n; });
  const rows = [["Source IP", "Source Country", "Destination IP", "Dest Country", "Protocols", "Packets", "Bytes", "Ports", "Duration"]];
  graphData.edges.forEach(e => {
    const duration = (e.first_seen != null && e.last_seen != null)
      ? (e.last_seen - e.first_seen).toFixed(3)
      : "";
    rows.push([
      e.source,
      geoCountryStr(nodeMap[e.source]),
      e.target,
      geoCountryStr(nodeMap[e.target]),
      (e.protocols || []).join(";"),
      e.packet_count,
      e.bytes,
      (e.ports || []).join(";"),
      duration,
    ]);
  });
  downloadCsv(rows, "connections.csv");
}

function exportAnomalies() {
  if (!graphData || !(graphData.anomalies || []).length) {
    showToast("No anomalies to export.", "info");
    return;
  }
  const nodeMap = {};
  (graphData.nodes || []).forEach(n => { nodeMap[n.ip || n.id] = n; });
  const rows = [["Type", "Severity", "Source", "Source Country", "Destination", "Dest Country", "Description"]];
  graphData.anomalies.forEach(a => {
    rows.push([
      a.type, a.severity,
      a.src || "", geoCountryStr(nodeMap[a.src]),
      a.dst || "", geoCountryStr(nodeMap[a.dst]),
      a.description,
    ]);
  });
  downloadCsv(rows, "anomalies.csv");
}

function exportCredentialsCsv() {
  if (!graphData || !(graphData.credentials || []).length) {
    showToast("No credentials to export.", "info");
    return;
  }
  const nodeMap = {};
  (graphData.nodes || []).forEach(n => { nodeMap[n.ip || n.id] = n; });
  const rows = [["Time", "Protocol", "Type", "Source", "Source Country", "Destination", "Dest Country", "Port", "Username", "Password"]];
  graphData.credentials.forEach(c => {
    rows.push([
      c.rel_time != null ? `+${c.rel_time}s` : (c.time || ""),
      c.protocol || "",
      c.type || "",
      c.src || "",
      geoCountryStr(nodeMap[c.src]),
      c.dst || "",
      geoCountryStr(nodeMap[c.dst]),
      c.dport || "",
      c.username || "",
      c.password || "",
    ]);
  });
  downloadCsv(rows, "credentials.csv");
}

function exportVlanInventoryCsv() {
  if (!graphData || !((graphData.stats?.vlans?.length) || (graphData.nodes || []).some(n => n.vlan_untagged))) {
    showToast("No VLAN data to export.", "info"); return;
  }
  const rows = [["VLAN ID", "IP Address", "Country", "Hostname", "Host Type", "IP Version",
                  "Protocols", "Packet Count", "Bytes Sent", "Bytes Recv",
                  "PCP Values", "QinQ", "Untagged Frames", "Outer VLAN IDs", "Risk Score"]];
  const allVlans   = (graphData.stats.vlans || []).map(String);
  const hasUntagged = (graphData.nodes || []).some(n => n.vlan_untagged);

  // One row per (VLAN, host) pair — multi-VLAN hosts appear on multiple rows for easy pivot/filter
  [...allVlans, ...(hasUntagged ? ["untagged"] : [])].forEach(vid => {
    const members = vid === "untagged"
      ? (graphData.nodes || []).filter(n => n.vlan_untagged && !(n.vlans || []).length)
      : (graphData.nodes || []).filter(n => (n.vlans || []).map(String).includes(vid));
    members.forEach(n => rows.push([
      vid,
      n.ip,
      geoCountryStr(n),
      n.hostname || "",
      n.host_type || "",
      n.ip_version || 4,
      (n.protocols || []).join(";"),
      n.packet_count || 0,
      n.bytes_sent || 0,
      n.bytes_recv || 0,
      (n.vlan_pcps || []).join(";"),
      n.vlan_qinq    ? "Yes" : "No",
      n.vlan_untagged ? "Yes" : "No",
      (n.vlan_outer || []).join(";"),
      n.risk_score || 0,
    ]));
  });
  downloadCsv(rows, "vlan-inventory.csv");
}

function exportHostsCsv() {
  if (!graphData || !(graphData.nodes || []).length) {
    showToast("No hosts to export.", "info"); return;
  }
  const rows = [["IP", "Hostname", "MAC", "MAC Vendor", "Host Type", "OS Hint",
    "Protocols", "Open Ports", "Packet Count", "Bytes Sent", "Bytes Recv",
    "VLANs", "Purdue Level", "Risk Score", "Is Private", "Geo Country"]];
  (graphData.nodes || []).forEach(n => rows.push([
    n.ip || n.id || "",
    n.hostname || (n.dns_names && n.dns_names[0]) || "",
    n.mac || "",
    n.mac_vendor || "",
    n.host_type || "",
    n.os_hint || "",
    (n.protocols || []).join(";"),
    (n.open_ports || []).join(";"),
    n.packet_count || 0,
    n.bytes_sent || 0,
    n.bytes_recv || 0,
    (n.vlans || []).join(";"),
    n.purdue_level != null ? n.purdue_level : "",
    n.risk_score || 0,
    n.is_private ? "Yes" : "No",
    geoCountryStr(n),
  ]));
  downloadCsv(rows, "hosts-inventory.csv");
}

function exportVlanTrafficCsv() {
  if (!graphData || !((graphData.stats?.vlans?.length) || (graphData.nodes || []).some(n => n.vlan_untagged))) {
    showToast("No VLAN data to export.", "info"); return;
  }
  const nodeMap = {};
  (graphData.nodes || []).forEach(n => { nodeMap[n.ip] = n; });

  const rows = [["VLAN(s)", "Source IP", "Source Country", "Source VLAN", "Destination IP", "Dest Country", "Dest VLAN",
                  "Cross-VLAN", "Protocols", "Packet Count", "Bytes", "Ports", "Duration (s)"]];

  (graphData.edges || []).forEach(e => {
    const src = nodeMap[e.source], dst = nodeMap[e.target];
    // Use primary VLAN of each endpoint (first tagged VID, or "untagged", or empty)
    const srcVlan = src && (src.vlans || []).length ? String(src.vlans[0])
                  : (src?.vlan_untagged ? "untagged" : "");
    const dstVlan = dst && (dst.vlans || []).length ? String(dst.vlans[0])
                  : (dst?.vlan_untagged ? "untagged" : "");
    const crossVlan = srcVlan && dstVlan && srcVlan !== dstVlan ? "Yes" : "No";
    const duration  = (e.first_seen != null && e.last_seen != null)
      ? (e.last_seen - e.first_seen).toFixed(3) : "";
    rows.push([
      (e.vlans || []).join(";"),
      e.source, geoCountryStr(src), srcVlan,
      e.target, geoCountryStr(dst), dstVlan,
      crossVlan,
      (e.protocols || []).join(";"),
      e.packet_count || 0,
      e.bytes || 0,
      (e.ports || []).join(";"),
      duration,
    ]);
  });
  downloadCsv(rows, "vlan-traffic.csv");
}

/* ── VLAN segmentation security score ───────────────────────────────────────
 * Returns { score: 0-100, label, color, deductions[] } from VLAN anomaly data.
 * Purely computed from graphData.anomalies — no backend change needed.
 */
function computeVlanSegmentationScore() {
  if (!graphData) return null;
  const anomalies = graphData.anomalies || [];
  const vlanTypes = new Set(["vlan_hopping","vlan_native_leak","vlan_qinq","vlan_cross_segment_ot"]);
  const vlanAnoms = anomalies.filter(a => vlanTypes.has(a.type));

  // No VLAN anomalies and VLANs are present → perfect score
  if (!(graphData.stats?.vlans?.length)) return null;

  let score = 100;
  const deductions = [];

  const crossSegOt = vlanAnoms.filter(a => a.type === "vlan_cross_segment_ot");
  if (crossSegOt.length) {
    const d = Math.min(50, crossSegOt.length * 15);
    score -= d;
    deductions.push(`OT cross-segment violations: ${crossSegOt.length} (−${d})`);
  }
  const hopping = vlanAnoms.filter(a => a.type === "vlan_hopping");
  if (hopping.length) {
    const d = Math.min(30, hopping.length * 10);
    score -= d;
    deductions.push(`VLAN hopping hosts: ${hopping.length} (−${d})`);
  }
  const nativeLeak = vlanAnoms.filter(a => a.type === "vlan_native_leak");
  if (nativeLeak.length) {
    const d = Math.min(15, nativeLeak.length * 5);
    score -= d;
    deductions.push(`Native VLAN leakage: ${nativeLeak.length} (−${d})`);
  }
  const qinq = vlanAnoms.filter(a => a.type === "vlan_qinq");
  if (qinq.length) {
    const d = Math.min(10, qinq.length * 5);
    score -= d;
    deductions.push(`QinQ double-tagging: ${qinq.length} (−${d})`);
  }
  score = Math.max(0, score);

  let label, color;
  if (score >= 80)      { label = "Good";     color = "#3fb950"; }
  else if (score >= 60) { label = "Fair";     color = "#e3b341"; }
  else if (score >= 40) { label = "Poor";     color = "#f0883e"; }
  else                  { label = "Critical"; color = "#f85149"; }

  return { score, label, color, deductions };
}

function generateAuditReport() {
  if (!graphData) { showToast("No data loaded.", "error"); return; }
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const s = graphData.stats || {};
  const nodes = graphData.nodes || [];
  const edges = graphData.edges || [];
  const anomalies = graphData.anomalies || [];
  const creds = graphData.credentials || [];
  const xfiles = graphData.files || [];
  const otCmds = graphData.ot_commands || [];
  const suppressedAnomalyFindingIds = new Set((findings || [])
    .filter(f => f.source_type === "anomaly" && (f.include_in_report === false || f.status === "False Positive"))
    .map(f => f.id));
  const reportAnomalies = anomalies.filter(a =>
    !suppressedAnomalyFindingIds.has(_findingId("anom", [a.type || "", a.src || "", a.dst || "", a.description || ""]))
  );

  // Escape a string for use inside a markdown table cell (prevent column breaks)
  const mdCell = s => String(s == null ? "—" : s).replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
  const lines = [];
  const h = (lvl, txt) => lines.push("#".repeat(lvl) + " " + txt);
  const p = txt => lines.push(txt);
  const br = () => lines.push("");

  h(1, "PCAP Network Audit Report");
  p(`Generated: ${now}`);
  br();

  // Capture Summary
  h(2, "Capture Summary");
  p(`| Metric | Value |`);
  p(`|--------|-------|`);
  p(`| Hosts | ${s.total_hosts ?? nodes.length} |`);
  p(`| Connections | ${s.total_connections ?? edges.length} |`);
  p(`| Packets | ${s.total_packets != null ? fmtNum(s.total_packets) : "—"} |`);
  const _totalBytes = edges.reduce((a, e) => a + (e.bytes || 0), 0);
  p(`| Bytes | ${_totalBytes > 0 ? (_totalBytes / 1e6).toFixed(2) + " MB" : "—"} |`);
  p(`| Anomalies | ${anomalies.length} |`);
  p(`| Credentials captured | ${creds.length} |`);
  p(`| File transfers detected | ${xfiles.length} |`);
  p(`| OT commands | ${otCmds.length} |`);
  if ((s.vlans_detected || 0) > 0) {
    p(`| VLANs detected | ${s.vlans_detected} |`);
  }
  br();

  // Curated findings
  const reportFindings = (findings || [])
    .filter(f => f.include_in_report !== false && f.status !== "False Positive")
    .sort((a, b) => _severityRank(b.severity) - _severityRank(a.severity) || a.title.localeCompare(b.title));
  if (reportFindings.length) {
    h(2, `Curated Findings (${reportFindings.length})`);
    p(`| Severity | Status | Source | Finding | Evidence | Analyst Note |`);
    p(`|----------|--------|--------|---------|----------|--------------|`);
    reportFindings.forEach(f => {
      const source = FINDING_SOURCE_LABELS[f.source_type] || f.source_type || "Finding";
      const evidence = (f.evidence_refs || []).slice(0, 4).map(_findingEvidenceLabel).join("; ");
      const finding = f.route ? `${f.title} (${f.route})` : f.title;
      p(`| ${mdCell(f.severity)} | ${mdCell(f.status)} | ${mdCell(source)} | ${mdCell(finding)} | ${mdCell(evidence || f.description || "—")} | ${mdCell(f.analyst_note || "—")} |`);
    });
    br();
  }

  // Risk Overview — top 10 hosts by risk score
  const scored = nodes.filter(n => (n.risk_score ?? 0) > 0)
                       .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
                       .slice(0, 10);
  if (scored.length) {
    h(2, "Risk Overview — Top 10 Hosts");
    p(`| IP | Hostname | Type | Risk | Anomalies |`);
    p(`|----|----------|------|------|-----------|`);
    scored.forEach(n => {
      const host = (n.dns_names && n.dns_names[0]) || n.hostname || "—";
      const risk = n.risk_score ?? 0;
      const aCount = reportAnomalies.filter(a => a.src === n.id || a.dst === n.id).length;
      p(`| ${mdCell(n.id)} | ${mdCell(host)} | ${mdCell(n.host_type || "—")} | ${risk} | ${aCount} |`);
    });
    br();
  }

  // Geographic Distribution — external endpoints grouped by country
  const geoNodes = nodes.filter(n => n.geo && (n.geo.country_code || n.geo.country));
  if (geoNodes.length) {
    h(2, "Geographic Distribution (External Endpoints)");
    // Group by country
    const byCountry = {};
    geoNodes.forEach(n => {
      const key = geoCountryStr(n);
      if (!byCountry[key]) byCountry[key] = { code: n.geo.country_code || "", ips: [] };
      byCountry[key].ips.push(n.ip || n.id);
    });
    // Sort by host count desc
    const countryEntries = Object.entries(byCountry)
      .sort((a, b) => b[1].ips.length - a[1].ips.length);
    p(`| Country | Hosts | IPs |`);
    p(`|---------|-------|-----|`);
    countryEntries.forEach(([label, info]) => {
      const flag = countryFlag(info.code);
      const ipList = info.ips.slice(0, 10).join(", ");
      const overflow = info.ips.length > 10 ? ` +${info.ips.length - 10} more` : "";
      p(`| ${mdCell((flag ? flag + " " : "") + label)} | ${info.ips.length} | ${mdCell(ipList + overflow)} |`);
    });
    br();
  }

  // Anomalies by severity
  if (reportAnomalies.length) {
    h(2, "Anomalies");
    const bySev = {};
    reportAnomalies.forEach(a => { (bySev[a.severity] = bySev[a.severity] || []).push(a); });
    ["critical", "high", "medium", "low"].forEach(sev => {
      if (!bySev[sev]) return;
      h(3, sev.charAt(0).toUpperCase() + sev.slice(1) + ` (${bySev[sev].length})`);
      bySev[sev].forEach(a => {
        const route = [a.src, a.dst].filter(Boolean).join(" → ") || "—";
        p(`- **${a.type}** | ${route} | ${a.description}`);
      });
      br();
    });
  }

  // OT Inventory by Purdue level
  const otNodes = nodes.filter(n => n.purdue_level != null && n.purdue_level >= 0);
  if (otNodes.length) {
    h(2, "OT/ICS Inventory by Purdue Level");
    const levelNames = {
      0: "L0 — Field Devices",
      1: "L1 — PLC / RTU",
      2: "L2 — Control / HMI",
      3: "L3 — Supervisory",
      3.5: "L3.5 — Industrial DMZ",
      4: "L4 — Business Logistics",
      5: "L5 — Enterprise",
      6: "L6 — Public Internet",
    };
    const byLevel = {};
    otNodes.forEach(n => {
      const lv = n.purdue_level;
      (byLevel[lv] = byLevel[lv] || []).push(n);
    });
    Object.keys(byLevel).sort((a, b) => +a - +b).forEach(lv => {
      h(3, levelNames[lv] || `Level ${lv}`);
      byLevel[lv].forEach(n => {
        const host = (n.dns_names && n.dns_names[0]) || n.hostname || "";
        p(`- ${n.id}${host ? " (" + host + ")" : ""} — ${n.host_type || "Unknown"}`);
      });
      br();
    });
  }

  // TLS observations
  const tlsNodes = nodes.filter(n => (n.tls_sni && n.tls_sni.length) || (n.tls_ja3 && n.tls_ja3.length));
  if (tlsNodes.length) {
    h(2, "TLS Observations");
    tlsNodes.forEach(n => {
      h(3, n.id);
      if (n.tls_sni && n.tls_sni.length) p(`- SNI destinations: ${n.tls_sni.slice(0, 10).join(", ")}`);
      if (n.tls_ja3 && n.tls_ja3.length) {
        const _knownBadJa3 = {
          "e7d705a3286e19ea42f587b344ee6865": "Metasploit Meterpreter",
          "6734f37431670b3ab4292b8f60f29984": "Cobalt Strike",
          "b386946a5a44d1ddcc843bc75336dfce": "Dridex",
          "a0e9f5d64349fb13191bc781f81f42e1": "AgentTesla",
          "c12f54a3f91dc7bafd92cb59fe009a35": "Cobalt Strike Beacon",
          "ada79f3a9e63d0f1f4c6cb3ba9e99fa0": "Emotet",
          "de350869b8c85de67a350c8d186f11e6": "Trickbot",
          "51c64c77e60f3980eea90869b68c58a8": "AsyncRAT",
          "6bca5a6d9bf5b08f9cd95feefc1c2c7e": "QakBot",
          "a106ce68aee22e2f5d82ee41fb5fb22a": "IcedID",
        };
        n.tls_ja3.forEach(j => {
          const threat = _knownBadJa3[j];
          const flag = threat ? ` ⚠ ${threat}` : "";
          p(`- JA3: \`${j}\`${flag}`);
        });
      }
      br();
    });
  }

  // DNS tunneling suspects
  const dnsTunnel = reportAnomalies.filter(a => a.type === "dns_tunneling");
  if (dnsTunnel.length) {
    h(2, "DNS Tunneling Suspects");
    dnsTunnel.forEach(a => p(`- **${a.src || "—"}** — ${a.description}`));
    br();
  }

  // Credentials
  if (creds.length) {
    h(2, `Captured Credentials (${creds.length})`);
    p(`| Time | Protocol | Source | Destination | Username | Type |`);
    p(`|------|----------|--------|-------------|----------|------|`);
    creds.slice(0, 100).forEach(c => {
      const t = c.rel_time != null ? `+${c.rel_time}s` : (c.time || "—");
      p(`| ${mdCell(t)} | ${mdCell(c.protocol)} | ${mdCell(c.src)} | ${mdCell(c.dst)} | ${mdCell(c.username || "—")} | ${mdCell(c.type)} |`);
    });
    if (creds.length > 100) p(`\n_…and ${creds.length - 100} more_`);
    br();
  }

  // File transfers
  if (xfiles.length) {
    h(2, `File Transfers Detected (${xfiles.length})`);
    p(`| Time | Filename | MIME | Size | SHA-256 | Src → Dst |`);
    p(`|------|----------|------|------|---------|-----------|`);
    xfiles.slice(0, 50).forEach(f => {
      const t = f.rel_time != null ? `+${f.rel_time}s` : "—";
      const sz = _fmtBytes(f.size);
      p(`| ${mdCell(t)} | ${mdCell(f.filename)} | ${mdCell(f.mime_type || "—")} | ${sz} | \`${(f.sha256 || '').slice(0, 16)}…\` | ${mdCell(f.src)} → ${mdCell(f.dst)} |`);
    });
    if (xfiles.length > 50) p(`_…and ${xfiles.length - 50} more_`);
    br();
  }

  // OT command summary
  if (otCmds.length) {
    h(2, `OT Command Summary (${otCmds.length} total)`);
    const byProto = {};
    otCmds.forEach(c => (byProto[c.protocol] = (byProto[c.protocol] || 0) + 1));
    p(`| Protocol | Commands |`);
    p(`|----------|----------|`);
    Object.entries(byProto).sort((a, b) => b[1] - a[1]).forEach(([pr, cnt]) => p(`| ${pr} | ${cnt} |`));
    br();
    const writes = otCmds.filter(c => c.direction === "write");
    if (writes.length) {
      h(3, `Write Operations (${writes.length})`);
      writes.slice(0, 50).forEach(c => {
        p(`- +${c.rel_time}s **${c.protocol}** ${c.src} → ${c.dst} | ${c.function_name || c.function_code || ""}`);
      });
      if (writes.length > 50) p(`_…and ${writes.length - 50} more_`);
      br();
    }
  }

  // VLAN Security Assessment
  const vlanIds        = (graphData.stats?.vlans || []);
  const hasUntaggedNodes = nodes.some(n => n.vlan_untagged);
  if (vlanIds.length) {
    h(2, "VLAN Security Assessment");
    const seg = computeVlanSegmentationScore();
    if (seg) {
      p(`**Segmentation Score: ${seg.score}/100 — ${seg.label}**`);
      br();
      if (seg.deductions.length) {
        p("Deductions:");
        seg.deductions.forEach(d => p(`- ${d}`));
      } else {
        p("_No VLAN segmentation violations detected._");
      }
      // Sprawl summary
      br();
      const crossLinkedIds2 = new Set();
      (graphData.anomalies || [])
        .filter(a => a.type === "vlan_cross_segment_ot" || a.type === "vlan_hopping")
        .forEach(a => { if (a.src) crossLinkedIds2.add(a.src); });
      const totalVlans2 = vlanIds.length;
      const singletonCount = nodes.reduce((acc, n) => {
        (n.vlans || []).forEach(v => { acc[v] = (acc[v] || 0) + 1; }); return acc;
      }, {});
      const singletons = Object.values(singletonCount).filter(c => c === 1).length;
      p(`| Metric | Value |`);
      p(`|--------|-------|`);
      p(`| VLANs detected | ${totalVlans2} |`);
      p(`| Singleton VLANs (1 host) | ${singletons} |`);
      p(`| Hopping / multi-VLAN hosts | ${nodes.filter(n => (n.vlans||[]).length > 1).length} |`);
      p(`| Untagged / native-VLAN hosts | ${nodes.filter(n => n.vlan_untagged).length} |`);
    }
    br();
  }

  // VLAN Device Inventory
  if (vlanIds.length || hasUntaggedNodes) {
    h(2, "VLAN Device Inventory");
    const allVids = [...vlanIds.map(String), ...(hasUntaggedNodes ? ["untagged"] : [])];
    allVids.forEach(vid => {
      const members = vid === "untagged"
        ? nodes.filter(n => n.vlan_untagged && !(n.vlans || []).length)
        : nodes.filter(n => (n.vlans || []).map(String).includes(vid));
      if (!members.length) return;
      h(3, vid === "untagged" ? "Untagged / Native VLAN" : `VLAN ${vid}`);
      p(`| IP Address | Hostname | Host Type | IP Ver | Protocols | Risk Score |`);
      p(`|------------|----------|-----------|--------|-----------|------------|`);
      members.forEach(n => {
        const host = n.hostname || (n.dns_names && n.dns_names[0]) || "—";
        const protos = (n.protocols || []).slice(0, 5).join(", ") + ((n.protocols||[]).length > 5 ? "…" : "");
        p(`| ${n.ip} | ${host} | ${n.host_type || "—"} | IPv${n.ip_version || 4} | ${protos} | ${n.risk_score || 0} |`);
      });
      br();
    });
  }

  // IP-to-IP Traffic by VLAN
  if (vlanIds.length) {
    h(2, "IP-to-IP Traffic by VLAN");
    const nodeMap2 = {};
    nodes.forEach(n => { nodeMap2[n.ip] = n; });

    // Group edges by VLAN — edges involving both src and dst VLANs are listed in each group
    const edgesByVlan = {};
    const allVidsForTraffic = [...vlanIds.map(String), ...(hasUntaggedNodes ? ["untagged"] : [])];
    allVidsForTraffic.forEach(vid => { edgesByVlan[vid] = []; });

    edges.forEach(e => {
      const srcVids = (nodeMap2[e.source]?.vlans || []).map(String);
      const dstVids = (nodeMap2[e.target]?.vlans || []).map(String);
      const allEdgeVlans = [...new Set([...srcVids, ...dstVids, ...(e.vlans || []).map(String)])];
      if (!allEdgeVlans.length && hasUntaggedNodes) allEdgeVlans.push("untagged");
      allEdgeVlans.forEach(vid => { if (edgesByVlan[vid]) edgesByVlan[vid].push(e); });
    });

    allVidsForTraffic.forEach(vid => {
      const group = edgesByVlan[vid];
      if (!group.length) return;
      h(3, vid === "untagged" ? "Untagged / Native VLAN" : `VLAN ${vid}`);
      p(`| Source IP | Destination IP | Cross-VLAN | Protocols | Packets | Bytes |`);
      p(`|-----------|----------------|------------|-----------|---------|-------|`);
      group.slice(0, 100).forEach(e => {
        const src = nodeMap2[e.source], dst = nodeMap2[e.target];
        const srcV = src && (src.vlans || []).length ? String(src.vlans[0]) : (src?.vlan_untagged ? "untagged" : "");
        const dstV = dst && (dst.vlans || []).length ? String(dst.vlans[0]) : (dst?.vlan_untagged ? "untagged" : "");
        const cross = srcV && dstV && srcV !== dstV ? `✓ (${srcV}→${dstV})` : "—";
        p(`| ${e.source} | ${e.target} | ${cross} | ${(e.protocols || []).join(", ")} | ${fmtNum(e.packet_count)} | ${fmtBytes(e.bytes)} |`);
      });
      if (group.length > 100) p(`_…and ${group.length - 100} more connections_`);
      br();
    });
  }

  p("---");
  p("_Report generated by [PCAP Network Visualizer](https://github.com/esandeepchoudary/pcap-vis-anz)_");

  const md = lines.join("\n");
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "pcap-audit-report.md";
  a.click();
  URL.revokeObjectURL(url);
}

function downloadCsv(rows, filename) {
  // Prefix formula-starting characters to prevent CSV injection in spreadsheet software
  const sanitize = v => { const s = String(v); return /^[=+\-@|%\t]/.test(s) ? "'" + s : s; };
  const csv = rows.map(r => r.map(v => `"${sanitize(v).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Sessions ────────────────────────────────────────────────────────────── */
document.getElementById("save-session-btn").addEventListener("click", () => {
  if (!graphData) { showToast("No data loaded.", "error"); return; }
  const sessionData = {
    nodes: graphData.nodes,
    edges: graphData.edges,
    stats: graphData.stats,
    anomalies: graphData.anomalies || [],
    packets: graphData.packets || {},
    credentials: graphData.credentials || [],
    files: graphData.files || [],
    ot_commands: graphData.ot_commands || [],
    findings: findings || [],
  };
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const blob = new Blob([JSON.stringify(sessionData)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `session-${ts}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById("load-session-btn").addEventListener("click", () => {
  document.getElementById("session-file-input").click();
});

document.getElementById("session-file-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    try {
      const data = JSON.parse(ev.target.result);
      if (!Array.isArray(data.nodes) || !Array.isArray(data.edges)) throw new Error("Invalid session file: nodes and edges must be arrays");
      loadGraph(data);
      closeModal();
    } catch (err) {
      showToast("Failed to load session: " + err.message, "error");
    }
  };
  reader.onerror = () => showToast("Failed to read session file.", "error");
  reader.readAsText(file);
  e.target.value = "";
});

/* ── VLAN labels (user-assigned names, persisted in localStorage) ────────── */
function getVlanLabel(vid) {
  try { return localStorage.getItem("vlan-label:" + vid) || ""; } catch (e) { return ""; }
}
function saveVlanLabel(vid, text) {
  try {
    if (text) localStorage.setItem("vlan-label:" + vid, text);
    else       localStorage.removeItem("vlan-label:" + vid);
  } catch (e) { /* private browsing / quota */ }
}
// Returns display name: user label if set, else the default "VLAN N" / "Untagged"
function vlanDisplayName(vid, defaultLabel) {
  const custom = getVlanLabel(vid);
  return custom ? `${defaultLabel} (${custom})` : defaultLabel;
}

/* ── Node annotations ────────────────────────────────────────────────────── */
function getAnnotation(ip) {
  try { return localStorage.getItem("ann:" + ip) || ""; } catch (e) { return ""; }
}

function saveAnnotation(ip, text) {
  try {
    if (text) localStorage.setItem("ann:" + ip, text);
    else       localStorage.removeItem("ann:" + ip);
  } catch (e) { /* private browsing / quota */ }
}

function applyAnnotations() {
  if (!graphData) return;
  nodesGroup.selectAll(".node").each(function(d) {
    const note = getAnnotation(d.ip);
    const g = d3.select(this);
    g.selectAll(".node-note-icon").remove();
    if (note) {
      const r = 6 + Math.log1p((d.packet_count || 0) / Math.max(1, graphData.nodes.reduce((m, n) => Math.max(m, n.packet_count || 0), 0)) * 200) * 3;
      g.append("text")
        .attr("class", "node-note-icon")
        .attr("dy", -(r + 4))
        .attr("font-size", "10px")
        .text("✎");
    }
  });
}

function updateNoteIcon(ip, hasNote) {
  if (!graphData) return;
  nodesGroup.selectAll(".node").each(function(d) {
    if (d.ip !== ip) return;
    const g = d3.select(this);
    g.selectAll(".node-note-icon").remove();
    if (hasNote) {
      const r = 6 + Math.log1p((d.packet_count || 0) / Math.max(1, graphData.nodes.reduce((m, n) => Math.max(m, n.packet_count || 0), 0)) * 200) * 3;
      g.append("text")
        .attr("class", "node-note-icon")
        .attr("dy", -(r + 4))
        .attr("font-size", "10px")
        .text("✎");
    }
  });
}

/* ── Context menu ────────────────────────────────────────────────────────── */
let ctxTarget = null;

function showCtxMenu(event, d) {
  ctxTarget = d;
  ctxMenu.style.left = event.clientX + "px";
  ctxMenu.style.top  = event.clientY + "px";
  const unpinBtn = document.getElementById("ctx-unpin-all");
  if (unpinBtn) unpinBtn.style.display = pinnedNodes.size > 0 ? "" : "none";
  ctxMenu.classList.remove("hidden");
}

document.getElementById("ctx-add-note").addEventListener("click", async () => {
  ctxMenu.classList.add("hidden");
  if (!ctxTarget) return;
  const existing = getAnnotation(ctxTarget.ip);
  const input = await openTextModal({
    title: "Host note: " + ctxTarget.ip,
    value: existing || "",
    placeholder: "Add analyst notes for this host...",
  });
  if (input !== null) {
    saveAnnotation(ctxTarget.ip, input);
    updateNoteIcon(ctxTarget.ip, !!input);
    if (selectedNode && selectedNode.ip === ctxTarget.ip) {
      showDetailPanel(ctxTarget);
    }
  }
  ctxTarget = null;
});

document.addEventListener("click", () => {
  ctxMenu.classList.add("hidden");
});

/* ── Timeline ────────────────────────────────────────────────────────────── */
function buildTimeline(data) {
  const tlBar = document.getElementById("timeline-bar");

  // Collect all packets: need time, bytes, and (optional) vlan_id
  const allPkts = [];
  for (const pkts of Object.values(data.packets || {})) {
    pkts.forEach(p => { if (p.time != null) allPkts.push(p); });
  }

  if (allPkts.length < 2) {
    tlBar.classList.add("hidden");
    return;
  }

  let minT = Infinity, maxT = -Infinity;
  for (const p of allPkts) {
    if (p.time < minT) minT = p.time;
    if (p.time > maxT) maxT = p.time;
  }
  const span = maxT - minT;

  if (span === 0) {
    tlBar.classList.add("hidden");
    return;
  }

  _tlMinT = minT;
  _tlSpan = span;

  tlBar.classList.remove("hidden");

  // Per-VLAN stacked minimap — bucket bytes per VLAN per bin
  const minimap = document.getElementById("tl-minimap");
  minimap.innerHTML = "";
  const BINS = 60;
  const hasVlans = (data.stats?.vlans?.length || 0) > 0;

  // binBytes[i] = total bytes in bin i; vlanBins[vid][i] = bytes for that VLAN
  const binBytes = new Array(BINS).fill(0);
  const vlanBins = {};   // vid → Float32Array(BINS)

  allPkts.forEach(p => {
    const idx = Math.min(Math.floor(((p.time - minT) / span) * BINS), BINS - 1);
    const bytes = p.len || 1;
    binBytes[idx] += bytes;
    if (hasVlans) {
      const vid = p.vlan_id != null ? String(p.vlan_id) : "untagged";
      if (!vlanBins[vid]) vlanBins[vid] = new Float32Array(BINS);
      vlanBins[vid][idx] += bytes;
    }
  });

  const maxBytes = Math.max(1, ...binBytes);   // safe — only 60 elements
  const vlanVids = Object.keys(vlanBins);

  for (let i = 0; i < BINS; i++) {
    const barH = Math.max(2, (binBytes[i] / maxBytes) * 20);

    if (hasVlans && vlanVids.length > 1) {
      // Stacked bar: one child div per VLAN, heights proportional to that VLAN's bytes
      const container = document.createElement("div");
      container.className = "tl-bar tl-bar-stacked";
      container.style.height = barH + "px";

      // Sort VLANs so the order is stable across bins
      vlanVids.sort().forEach(vid => {
        const vBytes = vlanBins[vid][i];
        if (!vBytes) return;
        const seg = document.createElement("div");
        seg.className = "tl-bar-seg";
        seg.style.height = Math.max(1, (vBytes / binBytes[i]) * barH) + "px";
        seg.style.background = vlanColor(vid === "untagged" ? null : vid);
        seg.title = `VLAN ${vid}: ${fmtBytes(vBytes)}`;
        container.appendChild(seg);
      });
      minimap.appendChild(container);
    } else {
      // No VLAN data — plain density bar (original behaviour)
      const bar = document.createElement("div");
      bar.className = "tl-bar";
      bar.style.height = barH + "px";
      minimap.appendChild(bar);
    }
  }

  const bStart   = document.getElementById("tl-brush-start");
  const bEnd     = document.getElementById("tl-brush-end");
  const timeLabel = document.getElementById("tl-time-label");

  bStart.value = 0;
  bEnd.value   = 100;
  timeLabel.textContent = "All time";
  _updateBrushUI(0, 100);

  let _tlRafPending = false;

  function _applyBrush() {
    if (_tlRafPending) return;
    _tlRafPending = true;
    requestAnimationFrame(() => {
      _tlRafPending = false;
      const sVal = parseInt(bStart.value);
      const eVal = parseInt(bEnd.value);
      _updateBrushUI(sVal, eVal);
      if (sVal <= 0 && eVal >= 100) {
        timeLabel.textContent = "All time";
        applyTimelineFilter(null, null);
      } else {
        const tStart = minT + (sVal / 100) * span;
        const tEnd   = minT + (eVal / 100) * span;
        timeLabel.textContent = tlAbsTime
          ? new Date(tStart * 1000).toISOString().substr(11, 8) + "–" + new Date(tEnd * 1000).toISOString().substr(11, 8)
          : `+${(tStart - minT).toFixed(1)}s–+${(tEnd - minT).toFixed(1)}s`;
        applyTimelineFilter(tStart, tEnd);
      }
    });
  }

  bStart.oninput = () => {
    if (parseInt(bStart.value) > parseInt(bEnd.value)) bStart.value = bEnd.value;
    _applyBrush();
  };
  bEnd.oninput = () => {
    if (parseInt(bEnd.value) < parseInt(bStart.value)) bEnd.value = bStart.value;
    _applyBrush();
  };

  renderStatsSparkline(binBytes, maxBytes);
}

function _updateBrushUI(sVal, eVal) {
  const sel = document.getElementById("tl-selection");
  if (!sel) return;
  sel.style.left  = sVal + "%";
  sel.style.width = (eVal - sVal) + "%";
}

function applyTimelineFilter(tStart, tEnd) {
  if (!graphData) return;

  if (tStart === null) {
    _tlVisibleIps = null;
    applyFilters();
    return;
  }

  // Collect IPs with activity in the time window, then run all filters together
  const visibleIps = new Set();
  for (const [key, pkts] of Object.entries(packetData)) {
    if (pkts.some(p => p.time >= tStart && p.time <= tEnd)) {
      const [a, b] = key.split("|");
      visibleIps.add(a);
      visibleIps.add(b);
    }
  }
  _tlVisibleIps = visibleIps;
  applyFilters(true);  // skipFit — timeline slider moves are frequent
}

// Play button — advances a sliding window across the timeline
document.getElementById("tl-play-btn").addEventListener("click", () => {
  const btn    = document.getElementById("tl-play-btn");
  const bStart = document.getElementById("tl-brush-start");
  const bEnd   = document.getElementById("tl-brush-end");

  if (tlPlaying) {
    clearInterval(tlTimer);
    tlPlaying = false;
    btn.textContent = "▶";
  } else {
    tlPlaying = true;
    btn.textContent = "⏸";
    const DEFAULT_WIN = 20;
    const curWin = parseInt(bEnd.value) - parseInt(bStart.value);
    const winSize = (curWin <= 0 || curWin >= 100) ? DEFAULT_WIN : curWin;
    // If fully expanded, start from the beginning
    if (parseInt(bEnd.value) >= 100 && parseInt(bStart.value) <= 0) {
      bStart.value = 0;
      bEnd.value   = winSize;
    }
    bStart.dispatchEvent(new Event("input"));
    tlTimer = setInterval(() => {
      const s = parseInt(bStart.value);
      const e = parseInt(bEnd.value);
      if (e >= 100) {
        clearInterval(tlTimer);
        tlPlaying = false;
        btn.textContent = "▶";
        bStart.dispatchEvent(new Event("input"));
        return;
      }
      bStart.value = s + 1;
      bEnd.value   = Math.min(100, e + 1);
      bStart.dispatchEvent(new Event("input"));
    }, Math.round(80 / tlSpeed));
  }
});

document.getElementById("tl-speed").addEventListener("change", (e) => {
  tlSpeed = parseFloat(e.target.value) || 1;
  if (tlPlaying) {
    const btn = document.getElementById("tl-play-btn");
    clearInterval(tlTimer);
    tlPlaying = false;
    btn.click(); // restart with new speed
  }
});

// Timeline keyboard shortcuts (Space = play/pause, ←/→ = step)
document.addEventListener("keydown", (e) => {
  const tag = document.activeElement && document.activeElement.tagName;

  // Escape: close shortcuts modal, then fall through to other handlers
  if (e.key === "Escape") {
    const sc = document.getElementById("shortcuts-modal");
    if (sc && sc.style.display !== "none") { sc.style.display = "none"; return; }
  }

  // ? toggles shortcuts modal (skip when typing in an input)
  if (e.key === "?" && tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") {
    const sc = document.getElementById("shortcuts-modal");
    if (sc) sc.style.display = sc.style.display === "none" ? "flex" : "none";
    return;
  }

  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

  // / → focus search box
  if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    const sb = document.getElementById("search-box");
    if (sb) { sb.focus(); sb.select(); }
    return;
  }

  // 1–7 → switch views
  const VIEW_MAP = { "1": "graph", "2": "table", "3": "dns", "4": "ot", "5": "otlog", "6": "vlangraph", "7": "diff", "8": "dashboard", "9": "findings" };
  if (VIEW_MAP[e.key] && graphData) {
    const btn = document.querySelector(`.vt-btn[data-view="${VIEW_MAP[e.key]}"]`);
    if (btn && !btn.classList.contains("hidden")) { setView(VIEW_MAP[e.key]); return; }
  }

  // F → fit graph to screen
  if ((e.key === "f" || e.key === "F") && currentView === "graph" && graphData) {
    zoomFit(); return;
  }

  // P → pin / unpin selected node
  if ((e.key === "p" || e.key === "P") && currentView === "graph") {
    if (!selectedNode || !simulation) return;
    const d = selectedNode;
    if (pinnedNodes.has(d.ip)) {
      pinnedNodes.delete(d.ip);
      d.fx = d.fy = null;
    } else {
      pinnedNodes.add(d.ip);
      d.fx = d.x; d.fy = d.y;
    }
    updatePinVisuals();
    simulation.alpha(0.1).restart();
    return;
  }

  // Space / Arrow keys → timeline controls
  const tlBar = document.getElementById("timeline-bar");
  if (!tlBar || tlBar.classList.contains("hidden")) return;
  const bStart = document.getElementById("tl-brush-start");
  const bEnd   = document.getElementById("tl-brush-end");
  if (e.code === "Space") {
    e.preventDefault();
    document.getElementById("tl-play-btn").click();
  } else if (e.code === "ArrowRight") {
    e.preventDefault();
    const s = parseInt(bStart.value), en = parseInt(bEnd.value), w = en - s;
    if (en < 100) {
      bStart.value = Math.min(100 - w, s + 1);
      bEnd.value   = Math.min(100, en + 1);
      bStart.dispatchEvent(new Event("input"));
    }
  } else if (e.code === "ArrowLeft") {
    e.preventDefault();
    const s = parseInt(bStart.value), en = parseInt(bEnd.value), w = en - s;
    if (s > 0) {
      bStart.value = Math.max(0, s - 1);
      bEnd.value   = Math.max(w, en - 1);
      bStart.dispatchEvent(new Event("input"));
    }
  }
});

/* ── A2: Copy to clipboard ───────────────────────────────────────────────── */
function copyText(text) {
  navigator.clipboard.writeText(text).then(
    () => showToast("Copied", "info", 1500),
    () => showToast("Copy failed", "error", 2000)
  );
}

document.addEventListener("click", (e) => {
  if (!e.target || typeof e.target.closest !== "function") return;

  const copyBtn = e.target.closest("[data-copy-text]");
  if (copyBtn) {
    e.preventDefault();
    e.stopPropagation();
    copyText(copyBtn.dataset.copyText || "");
    return;
  }

  const fileBtn = e.target.closest("[data-file-sha]");
  if (fileBtn) {
    e.preventDefault();
    e.stopPropagation();
    downloadFile(fileBtn.dataset.fileSha || "", fileBtn.dataset.fileName || "file");
  }
});

/* ── A3: Persistent filter state ────────────────────────────────────────── */
function saveFilterState() {
  try {
    localStorage.setItem("pv_activeProtos", JSON.stringify([...activeProtos]));
    localStorage.setItem("pv_activeTypes",  JSON.stringify([...activeTypes]));
  } catch(_) {}
}

function loadFilterState(availProtos, availTypes) {
  try {
    const sp = localStorage.getItem("pv_activeProtos");
    const st = localStorage.getItem("pv_activeTypes");
    if (sp) {
      const saved = new Set(JSON.parse(sp));
      const filtered = availProtos.filter(p => saved.has(p));
      if (filtered.length > 0) activeProtos = new Set(filtered);
    }
    if (st) {
      const saved = new Set(JSON.parse(st));
      const filtered = availTypes.filter(t => saved.has(t));
      if (filtered.length > 0) activeTypes = new Set(filtered);
    }
  } catch(_) {}
}

/* ── A5: Timeline abs/rel toggle ────────────────────────────────────────── */
document.getElementById("tl-abs-btn").addEventListener("click", () => {
  tlAbsTime = !tlAbsTime;
  const btn = document.getElementById("tl-abs-btn");
  if (btn) {
    btn.textContent = tlAbsTime ? "abs" : "rel";
    btn.classList.toggle("active", !tlAbsTime);
    btn.title = tlAbsTime ? "Show relative time" : "Show absolute time (UTC)";
  }
  // Re-dispatch brush input to reformat the label
  const bs = document.getElementById("tl-brush-start");
  if (bs) bs.dispatchEvent(new Event("input"));
});

/* ── B1: Node pinning ───────────────────────────────────────────────────── */
function updatePinVisuals() {
  nodesGroup.selectAll(".node").classed("pinned", d => pinnedNodes.has(d.ip));
}

document.getElementById("ctx-unpin-all").addEventListener("click", () => {
  ctxMenu.classList.add("hidden");
  pinnedNodes.clear();
  nodesGroup.selectAll(".node").each(function(d) { d.fx = d.fy = null; });
  updatePinVisuals();
  if (simulation) simulation.alpha(0.3).restart();
});

/* ── A1: Keyboard shortcuts overlay close button ────────────────────────── */
document.getElementById("shortcuts-close").addEventListener("click", () => {
  document.getElementById("shortcuts-modal").style.display = "none";
});
document.getElementById("shortcuts-modal").addEventListener("click", (e) => {
  if (e.target === document.getElementById("shortcuts-modal")) {
    document.getElementById("shortcuts-modal").style.display = "none";
  }
});

/* ── B3: Minimap ────────────────────────────────────────────────────────── */
const MM_W = 150, MM_H = 100;

function getMmBounds() {
  if (!_minimapNodes || _minimapNodes.length === 0) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of _minimapNodes) {
    if (n.x == null || n.y == null) continue;
    if (n.x < minX) minX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.x > maxX) maxX = n.x;
    if (n.y > maxY) maxY = n.y;
  }
  if (!isFinite(minX)) return null;
  const pad = 40;
  return { minX: minX - pad, minY: minY - pad, maxX: maxX + pad, maxY: maxY + pad };
}

function initMinimap(nodes) {
  const mm = document.getElementById("minimap");
  if (!mm || nodes.length < 2) return;

  _minimapNodes = nodes;
  _minimapInitialized = true;
  mm.style.display = "";

  const mmSel = d3.select(mm);
  mmSel.selectAll("*").remove();

  mmSel.append("g").attr("class", "mm-dots")
    .selectAll("circle")
    .data(nodes)
    .join("circle")
    .attr("class", "mm-node")
    .attr("r", 2)
    .attr("fill", d => hostColor(d.host_type));

  mmSel.append("rect").attr("class", "mm-viewport")
    .attr("x", 0).attr("y", 0)
    .attr("width", MM_W).attr("height", MM_H);

  // Drag on minimap pans the main view
  const mmDrag = d3.drag().on("drag", (event) => {
    const bounds = getMmBounds();
    if (!bounds) return;
    const bw = bounds.maxX - bounds.minX, bh = bounds.maxY - bounds.minY;
    const cx = bounds.minX + (event.x / MM_W) * bw;
    const cy = bounds.minY + (event.y / MM_H) * bh;
    const svgEl = svg.node();
    const w = svgEl.clientWidth, h = svgEl.clientHeight;
    const k = currentZoomTransform.k;
    svg.call(zoom.transform, d3.zoomIdentity.translate(w / 2 - k * cx, h / 2 - k * cy).scale(k));
  });
  d3.select(mm).call(mmDrag);

  updateMinimap();
}

function updateMinimap() {
  if (!_minimapInitialized) return;
  const mm = document.getElementById("minimap");
  if (!mm) return;
  const bounds = getMmBounds();
  if (!bounds) return;
  const bw = Math.max(1, bounds.maxX - bounds.minX);
  const bh = Math.max(1, bounds.maxY - bounds.minY);
  d3.select(mm).selectAll(".mm-node")
    .attr("cx", d => ((d.x || 0) - bounds.minX) / bw * MM_W)
    .attr("cy", d => ((d.y || 0) - bounds.minY) / bh * MM_H);
  updateMinimapViewport(bounds, bw, bh);
}

function updateMinimapViewport(bounds, bw, bh) {
  if (!_minimapInitialized) return;
  const mm = document.getElementById("minimap");
  if (!mm) return;
  if (!bounds) {
    bounds = getMmBounds();
    if (!bounds) return;
    bw = Math.max(1, bounds.maxX - bounds.minX);
    bh = Math.max(1, bounds.maxY - bounds.minY);
  }
  const svgEl = svg.node();
  const w = svgEl.clientWidth, h = svgEl.clientHeight;
  const t = currentZoomTransform;
  const vpMinX = (-t.x) / t.k;
  const vpMinY = (-t.y) / t.k;
  const vpMaxX = (-t.x + w) / t.k;
  const vpMaxY = (-t.y + h) / t.k;
  const rx = (vpMinX - bounds.minX) / bw * MM_W;
  const ry = (vpMinY - bounds.minY) / bh * MM_H;
  const rw = (vpMaxX - vpMinX) / bw * MM_W;
  const rh = (vpMaxY - vpMinY) / bh * MM_H;
  d3.select(mm).select(".mm-viewport")
    .attr("x", rx).attr("y", ry)
    .attr("width", rw).attr("height", rh);
}

/* ── D1: Collapsible sidebar ─────────────────────────────────────────────── */
(function() {
  const sidebar = document.getElementById("sidebar");
  const toggleBtn = document.getElementById("sidebar-toggle");
  if (!sidebar || !toggleBtn) return;

  function setSidebarCollapsed(collapsed) {
    sidebar.classList.toggle("collapsed", collapsed);
    toggleBtn.textContent = collapsed ? "›" : "‹";
    toggleBtn.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
    try {
      if (collapsed) localStorage.setItem("pv_sidebar_collapsed", "1");
      else localStorage.removeItem("pv_sidebar_collapsed");
    } catch(_) {}
  }

  toggleBtn.addEventListener("click", () => {
    setSidebarCollapsed(!sidebar.classList.contains("collapsed"));
  });

  // Restore on load
  if (localStorage.getItem("pv_sidebar_collapsed") === "1") {
    setSidebarCollapsed(true);
  }
})();

/* ── D2: Packet inspector search ─────────────────────────────────────────── */
function applyPktSearch() {
  const input = document.getElementById("pkt-search");
  const countEl = document.getElementById("pkt-search-count");
  if (!input || !pktTbody) return;
  const term = input.value.trim().toLowerCase();

  // When a search term is active, render all packets first so results beyond the
  // first page (PKT_PAGE_SIZE) are not silently excluded and the N/M badge is correct.
  if (term) {
    const moreCell = pktTbody.querySelector("tr td[colspan]");
    if (moreCell) {
      // Trigger the "Load more" <tr>'s own click handler to expand and remove it.
      moreCell.parentElement.click();
    }
  }

  const rows = pktTbody.querySelectorAll("tr");
  let visible = 0;
  let total = 0;
  rows.forEach(row => {
    if (row.querySelector("td[colspan]")) return; // "Load more" row (only present when no term)
    total++;
    // Use cached lowercase text (set at row build time) to avoid re-materialising textContent
    const text = row.dataset.searchText || row.textContent.toLowerCase();
    const show = !term || text.includes(term);
    row.style.display = show ? "" : "none";
    if (show) visible++;
  });
  if (countEl) countEl.textContent = term ? `${visible} / ${total}` : "";
}
let _pktSearchTimer = null;
function applyPktSearchDebounced() {
  clearTimeout(_pktSearchTimer);
  _pktSearchTimer = setTimeout(applyPktSearch, 160);
}

(function() {
  const pktSearch = document.getElementById("pkt-search");
  if (pktSearch) {
    pktSearch.addEventListener("input", applyPktSearchDebounced);
  }
})();

/* ── D3: Stats sparkline ─────────────────────────────────────────────────── */
function renderStatsSparkline(binBytes, maxBytes) {
  const statEl = document.getElementById("stat-pkts")?.closest(".stat");
  if (!statEl) return;
  const existing = statEl.querySelector(".stat-sparkline");
  if (existing) existing.remove();

  const W = 48, H = 12;
  const bins = binBytes.length;
  const barW = W / bins;
  const svgNS = "http://www.w3.org/2000/svg";
  const svgEl = document.createElementNS(svgNS, "svg");
  svgEl.setAttribute("width", W);
  svgEl.setAttribute("height", H);
  svgEl.setAttribute("class", "stat-sparkline");
  svgEl.setAttribute("aria-hidden", "true");

  binBytes.forEach((val, i) => {
    const h = Math.max(1, (val / maxBytes) * H);
    const rect = document.createElementNS(svgNS, "rect");
    rect.setAttribute("x", i * barW);
    rect.setAttribute("y", H - h);
    rect.setAttribute("width", Math.max(1, barW - 0.5));
    rect.setAttribute("height", h);
    rect.setAttribute("fill", "var(--accent)");
    rect.setAttribute("opacity", "0.6");
    svgEl.appendChild(rect);
  });

  statEl.appendChild(svgEl);
}

/* ── D4: Context menu — Highlight Anomalies & Open in Table ──────────────── */
document.getElementById("ctx-highlight-anoms").addEventListener("click", () => {
  ctxMenu.classList.add("hidden");
  highlightAnomsMode = !highlightAnomsMode;
  const item = document.getElementById("ctx-highlight-anoms");
  item.classList.toggle("active", highlightAnomsMode);
  item.textContent = (highlightAnomsMode ? "⬤ Hide Anomaly Highlight" : "⬤ Highlight Anomalies");
  applyFilters(true);
});

document.getElementById("ctx-open-table").addEventListener("click", () => {
  ctxMenu.classList.add("hidden");
  if (!ctxTarget) return;
  const ip = ctxTarget.ip;
  ctxTarget = null;
  setView("table");
  if (searchBox) {
    searchBox.value = ip;
    searchBox.dispatchEvent(new Event("input"));
  }
});

/* ── E1: Light/dark theme toggle ─────────────────────────────────────────── */
(function() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;

  function applyTheme(theme) {
    if (theme === "light") {
      document.body.dataset.theme = "light";
      btn.textContent = "☾";
      btn.title = "Switch to dark theme";
    } else {
      delete document.body.dataset.theme;
      btn.textContent = "☀";
      btn.title = "Switch to light theme";
    }
  }

  // Apply saved theme (also handled by FOUC-prevention script in HTML)
  const saved = localStorage.getItem("pv_theme");
  applyTheme(saved || "dark");

  btn.addEventListener("click", () => {
    const next = document.body.dataset.theme === "light" ? "dark" : "light";
    applyTheme(next);
    try {
      if (next === "light") localStorage.setItem("pv_theme", "light");
      else localStorage.removeItem("pv_theme");
    } catch(_) {}
  });
})();

/* ── E2: Saved filter presets ────────────────────────────────────────────── */
(function() {
  try {
    const raw = localStorage.getItem("pv_filter_presets");
    if (raw) filterPresets = JSON.parse(raw);
  } catch(_) { filterPresets = []; }
})();

function saveCurrentPreset(name) {
  if (!name) return;
  filterPresets = filterPresets.filter(p => p.name !== name);
  filterPresets.push({ name, protos: [...activeProtos], types: [...activeTypes] });
  try { localStorage.setItem("pv_filter_presets", JSON.stringify(filterPresets)); } catch(_) {}
  renderPresetList();
}

function loadPreset(p) {
  if (!graphData) return;
  const stats = graphData.stats || {};
  const availProtos = new Set(stats.protocols || []);
  const availTypes  = new Set(stats.host_types || []);
  activeProtos = new Set((p.protos || []).filter(x => availProtos.has(x)));
  activeTypes  = new Set((p.types  || []).filter(x => availTypes.has(x)));
  if (activeProtos.size === 0) activeProtos = new Set(stats.protocols || []);
  if (activeTypes.size  === 0) activeTypes  = new Set(stats.host_types || []);
  buildFilters(graphData);
  applyFilters();
}

function deleteFilterPreset(name) {
  filterPresets = filterPresets.filter(p => p.name !== name);
  try { localStorage.setItem("pv_filter_presets", JSON.stringify(filterPresets)); } catch(_) {}
  renderPresetList();
}

function renderPresetList() {
  const section = document.getElementById("presets-section");
  const list    = document.getElementById("preset-list");
  const badge   = document.getElementById("presets-badge");
  if (!section || !list) return;

  list.innerHTML = "";
  filterPresets.forEach(p => {
    const chip = document.createElement("div");
    chip.className = "preset-chip";
    chip.title = `${p.protos?.length || 0} protocols, ${p.types?.length || 0} host types`;
    const nameSpan = document.createElement("span");
    nameSpan.className = "preset-chip-name";
    nameSpan.textContent = p.name;
    nameSpan.addEventListener("click", () => loadPreset(p));
    const del = document.createElement("button");
    del.className = "preset-chip-del";
    del.textContent = "✕";
    del.title = "Delete preset";
    del.addEventListener("click", e => { e.stopPropagation(); deleteFilterPreset(p.name); });
    chip.appendChild(nameSpan);
    chip.appendChild(del);
    list.appendChild(chip);
  });

  if (badge) badge.textContent = filterPresets.length || "";
  section.style.display = filterPresets.length > 0 ? "" : "none";
}

(function() {
  const saveBtn   = document.getElementById("preset-save-btn");
  const nameInput = document.getElementById("preset-name-input");
  if (!saveBtn || !nameInput) return;

  saveBtn.addEventListener("click", () => {
    if (nameInput.style.display === "none" || nameInput.style.display === "") {
      nameInput.style.display = "inline-block";
      nameInput.focus();
    } else {
      const name = nameInput.value.trim();
      if (name) {
        saveCurrentPreset(name);
        nameInput.value = "";
        nameInput.style.display = "none";
      }
    }
  });

  nameInput.addEventListener("keydown", e => {
    if (e.key === "Enter") {
      const name = nameInput.value.trim();
      if (name) {
        saveCurrentPreset(name);
        nameInput.value = "";
        nameInput.style.display = "none";
      }
    } else if (e.key === "Escape") {
      nameInput.value = "";
      nameInput.style.display = "none";
    }
  });
})();

/* ── E3: Colour-blind safe palette ───────────────────────────────────────── */
function updateNodeColors() {
  // Only repaint the main fill circle in each node group.
  // Anomaly rings (.anomaly-ring-*) must keep their severity colors.
  // The anomaly ring is appended before the main circle in appendNodeDecorations, so
  // querySelector("circle") returns the ring for anomalous nodes — select by the absence
  // of a class attribute instead (the main circle has none; the ring has "anomaly-ring-*").
  // If VLAN coloring is active, keep that scheme instead of reverting to host-type.
  nodesGroup.selectAll(".node circle").filter(function() {
    return !this.getAttribute("class");
  }).attr("fill", d => {
    if (colorByVlan) {
      // Mirror the VLAN-color handler logic (see btn-color-vlan click at ~2604)
      return vlanColor((d.vlans && d.vlans.length) ? String(d.vlans[0]) : (d.vlan_untagged ? "untagged" : null));
    }
    return hostColor(d.host_type);
  });
  if (graphData) buildFilters(graphData);
  if (useCanvasEdges) drawCanvasEdges();
}

(function() {
  const btn = document.getElementById("cb-mode-btn");
  if (!btn) return;

  if (localStorage.getItem("pv_colorblind") === "1") {
    colorBlindMode = true;
    btn.classList.add("active");
    btn.title = "Colour-blind safe palette (on)";
  }

  btn.addEventListener("click", () => {
    colorBlindMode = !colorBlindMode;
    btn.classList.toggle("active", colorBlindMode);
    btn.title = colorBlindMode ? "Colour-blind safe palette (on)" : "Colour-blind safe palette";
    try {
      if (colorBlindMode) localStorage.setItem("pv_colorblind", "1");
      else localStorage.removeItem("pv_colorblind");
    } catch(_) {}
    updateNodeColors();
  });
})();

/* ── Cluster expand/collapse ──────────────────────────────────────────────── */
const collapsedTypes = new Set();
let _clusterCollapseMode = false;

function renderClusterOverlay() {
  const overlay = document.getElementById("cluster-overlay");
  if (!overlay || !graphData) { if (overlay) overlay.innerHTML = ""; return; }
  overlay.innerHTML = "";
  if (!_clusterCollapseMode || collapsedTypes.size === 0) return;

  const svgEl = document.getElementById("graph-svg");
  const svgRect = svgEl.getBoundingClientRect();
  const wrapRect = document.getElementById("graph-wrap").getBoundingClientRect();
  const t = currentZoomTransform;

  collapsedTypes.forEach(type => {
    const typeNodes = [];
    nodesGroup.selectAll(".node").each(function(d) {
      if (d.host_type === type && d.x != null && d.y != null) typeNodes.push(d);
    });
    if (typeNodes.length === 0) return;

    // Compute centroid in screen space
    const cx = typeNodes.reduce((s, n) => s + n.x, 0) / typeNodes.length;
    const cy = typeNodes.reduce((s, n) => s + n.y, 0) / typeNodes.length;
    const screenX = cx * t.k + t.x + (svgRect.left - wrapRect.left);
    const screenY = cy * t.k + t.y + (svgRect.top  - wrapRect.top);

    const chip = document.createElement("div");
    chip.className = "cluster-chip";
    chip.style.left = screenX + "px";
    chip.style.top  = screenY + "px";
    chip.innerHTML = `${escHtml(type)}<span class="cc-count">${typeNodes.length}</span>`;
    chip.title = `Click to expand ${typeNodes.length} ${type} node(s)`;
    chip.addEventListener("click", () => {
      collapsedTypes.delete(type);
      applyClusterCollapse();
    });
    overlay.appendChild(chip);
  });
}

function applyClusterCollapse() {
  if (!graphData) return;
  nodesGroup.selectAll(".node").each(function(d) {
    const collapsed = _clusterCollapseMode && collapsedTypes.has(d.host_type);
    d3.select(this).classed("faded", function() {
      return d3.select(this).classed("faded") || collapsed;
    });
    d3.select(this).style("display", collapsed ? "none" : "");
  });
  renderClusterOverlay();
}

(function() {
  const btn = document.getElementById("cluster-collapse-btn");
  if (!btn) return;

  // Rebuild overlay after zoom/pan
  const origZoom = svg.on("zoom.cluster");
  svg.on("zoom.clusterOverlay", () => { if (_clusterCollapseMode) renderClusterOverlay(); });

  btn.addEventListener("click", () => {
    if (!graphData) return;
    _clusterCollapseMode = !_clusterCollapseMode;
    btn.classList.toggle("active", _clusterCollapseMode);
    btn.title = _clusterCollapseMode ? "Exit cluster mode (click type in sidebar to collapse)" : "Collapse/expand host-type clusters";

    if (!_clusterCollapseMode) {
      collapsedTypes.clear();
      nodesGroup.selectAll(".node").style("display", "");
      document.getElementById("cluster-overlay").innerHTML = "";
      applyFilters(true);
    } else {
      showToast("Cluster mode: click a host-type filter label to collapse that type.", "info", 4000);
    }
  });

  // Wire host-type filter labels to toggle collapse when in cluster mode
  document.getElementById("type-filters")?.addEventListener("click", e => {
    if (!_clusterCollapseMode) return;
    const item = e.target.closest(".filter-item");
    if (!item) return;
    const labelEl = item.querySelector("label");
    if (!labelEl) return;
    const typeName = labelEl.textContent?.trim();
    if (!typeName) return;
    if (collapsedTypes.has(typeName)) collapsedTypes.delete(typeName);
    else collapsedTypes.add(typeName);
    applyClusterCollapse();
  });
})();

/* ── Floating packet inspector ────────────────────────────────────────────── */
(function() {
  const inspector = document.getElementById("packet-inspector");
  if (!inspector) return;

  let floating = false;
  let _dragStartX = 0, _dragStartY = 0, _dragStartLeft = 0, _dragStartTop = 0;

  // Add float button to inspector header
  const floatBtn = document.createElement("button");
  floatBtn.id = "pkt-float-btn";
  floatBtn.title = "Detach inspector to floating panel";
  floatBtn.textContent = "⧉";
  floatBtn.className = "pkt-hdr-btn";
  const hdr = document.getElementById("pkt-header");
  if (hdr) hdr.appendChild(floatBtn);

  function setFloating(val) {
    floating = val;
    inspector.classList.toggle("pkt-floating", floating);
    floatBtn.textContent = floating ? "⊡" : "⧉";
    floatBtn.title = floating ? "Dock inspector back" : "Detach inspector to floating panel";
    if (floating) {
      const svgRect = document.getElementById("graph-svg")?.getBoundingClientRect() || {left: 100, top: 100};
      inspector.style.left = (svgRect.left + 20) + "px";
      inspector.style.top  = (svgRect.top  + 20) + "px";
      inspector.style.width = "640px";
      inspector.style.height = "420px";
      inspector.style.bottom = "";
      inspector.style.right = "";
      graphWrap.classList.remove("pkt-open");
    } else {
      inspector.style.left = "";
      inspector.style.top  = "";
      inspector.style.width = "";
      inspector.style.height = "";
      // Open state is tracked via the "hidden" class (removed when open), not "open".
      if (!inspector.classList.contains("hidden")) graphWrap.classList.add("pkt-open");
    }
  }

  floatBtn.addEventListener("click", () => setFloating(!floating));

  // Drag to reposition (only when floating)
  const resizeHandle = document.getElementById("pkt-resize-handle");
  if (resizeHandle) {
    resizeHandle.addEventListener("mousedown", e => {
      if (!floating) return; // let existing resize handle work when docked
      _dragStartX = e.clientX; _dragStartY = e.clientY;
      _dragStartLeft = inspector.offsetLeft;
      _dragStartTop  = inspector.offsetTop;
      e.preventDefault(); e.stopPropagation();
      function onMove(ev) {
        inspector.style.left = (_dragStartLeft + ev.clientX - _dragStartX) + "px";
        inspector.style.top  = (_dragStartTop  + ev.clientY - _dragStartY) + "px";
      }
      function onUp() {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup",   onUp);
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup",   onUp);
    });
  }
})();
