"""Engine output. Plain Pydantic models so results serialise straight to the API and the DB."""

from typing import Literal

from pydantic import BaseModel, Field

Confidence = Literal["high", "medium", "low"]
DirectionBasis = Literal["handshake", "request", "port", "first_packet"]


class Evidence(BaseModel):
    """Why the engine concluded something. Shown to consultants next to every classification."""

    kind: str  # e.g. "serves", "lldp", "os_ttl", "gateway_mac", "s7_download"
    detail: str
    weight: int = 1


class Service(BaseModel):
    transport: str
    port: int
    protocol: str
    packets: int
    clients: int


class HostName(BaseModel):
    name: str
    source: Literal["dns", "dhcp", "lldp", "cdp", "nbns"]


class Host(BaseModel):
    ip: str
    ip_version: int
    is_private: bool
    is_multicast: bool = False
    is_broadcast: bool = False
    mac: str | None = None
    macs: list[str] = Field(default_factory=list)
    mac_vendor: str | None = None
    mac_is_gateway: bool = False  # the MAC belongs to a router forwarding this host's traffic
    hostname: str | None = None
    hostnames: list[HostName] = Field(default_factory=list)
    dns_queries: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    os_hint: str | None = None
    ttl: int | None = None
    vlans: list[int] = Field(default_factory=list)
    vlan_outer: list[int] = Field(default_factory=list)
    vlan_pcps: list[int] = Field(default_factory=list)
    vlan_untagged: bool = False
    vlan_qinq: bool = False
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    tls_sni: list[str] = Field(default_factory=list)
    tls_ja3: list[str] = Field(default_factory=list)
    tls_ja4: list[str] = Field(default_factory=list)
    ot_role: Literal["master", "outstation", "both", "unknown"] = "unknown"
    modbus_unit_ids: list[int] = Field(default_factory=list)
    dnp3_addresses: list[int] = Field(default_factory=list)
    identity: dict[str, str] = Field(default_factory=dict)
    host_type: str = "Unknown Host"
    host_type_confidence: Confidence = "low"
    host_type_evidence: list[Evidence] = Field(default_factory=list)
    purdue_level: float = -1
    purdue_evidence: list[Evidence] = Field(default_factory=list)


class Flow(BaseModel):
    """A conversation, oriented client → server."""

    id: int
    transport: str
    client: str
    client_port: int
    server: str
    server_port: int
    protocol: str
    detected_protocols: list[str] = Field(default_factory=list)
    direction_basis: DirectionBasis
    packets_c2s: int = 0
    packets_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    first_seen: float
    last_seen: float
    vlans: list[int] = Field(default_factory=list)
    syn_seen: bool = False
    resets: int = 0
    server_answered: bool = True  # TCP: the server sent something other than a reset (the port is open)
    ot_reads: int = 0
    ot_writes: int = 0
    ot_errors: int = 0
    function_counts: dict[str, int] = Field(default_factory=dict)
    notes: dict[str, list[str]] = Field(default_factory=dict)  # http_requests, mqtt_topics, …
    c2s_times: list[float] = Field(default_factory=list, description="First client→server packet times")

    @property
    def packets(self) -> int:
        return self.packets_c2s + self.packets_s2c

    @property
    def bytes(self) -> int:
        return self.bytes_c2s + self.bytes_s2c


class OtCommand(BaseModel):
    time: float
    flow_id: int
    src: str
    dst: str
    protocol: str
    function_code: int | None
    function: str
    kind: Literal["read", "write", "error", "other"]
    is_request: bool
    unit: int | None = None
    address: int | None = None
    quantity: int | None = None
    detail: str = ""


class Credential(BaseModel):
    protocol: str
    kind: Literal["password", "basic_auth", "form", "community", "token"]
    client: str
    server: str
    server_port: int
    username: str | None
    secret: str | None
    flow_id: int
    first_seen: float
    count: int = 1


class FileTransfer(BaseModel):
    protocol: str
    filename: str
    size: int
    sha256: str
    mime: str
    interesting: bool
    source_url: str | None = None
    stored_path: str | None = None


Severity = Literal["critical", "high", "medium", "low", "info"]


class Anomaly(BaseModel):
    """A rule hit, grouped per (rule, source, destination) with counts and evidence samples."""

    id: str  # stable: hash of rule + src + dst + key
    rule: str
    category: Literal["network", "credentials", "ot", "iot", "vlan"]
    severity: Severity
    title: str
    description: str
    src: str | None = None
    dst: str | None = None
    flow_ids: list[int] = Field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None
    count: int = 1
    evidence: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)  # MITRE ATT&CK technique IDs


class VlanStat(BaseModel):
    vlan: int | None  # None = untagged
    packets: int
    broadcast: int


class ArpClaim(BaseModel):
    vlan: int | None
    ip: str
    macs: list[str]


class CaptureSummary(BaseModel):
    file_name: str
    file_size: int
    packets: int
    bytes: int
    first_seen: float | None
    last_seen: float | None
    link_types: list[str] = Field(default_factory=list)
    malformed_packets: int = 0
    truncated: bool = False
    tshark_version: str | None = None
    warnings: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    capture: CaptureSummary
    hosts: list[Host]
    flows: list[Flow]
    ot_commands: list[OtCommand] = Field(default_factory=list)
    ot_commands_truncated: bool = False
    credentials: list[Credential] = Field(default_factory=list)
    files: list[FileTransfer] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    vlan_stats: list[VlanStat] = Field(default_factory=list)
    arp_claims: list[ArpClaim] = Field(default_factory=list)
