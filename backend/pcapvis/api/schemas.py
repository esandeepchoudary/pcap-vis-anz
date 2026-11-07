"""Request/response models. These feed OpenAPI, which generates the frontend's TypeScript types."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pcapvis.db.models import Role

COORD_MAX = 1e6  # diagram coordinates (zones on the architecture view)


class TsharkInfo(BaseModel):
    ok: bool
    path: str | None
    version: str | None
    min_version: str
    message: str


class SystemInfo(BaseModel):
    version: str
    mode: Literal["laptop", "server"]
    auth_required: bool
    tshark: TsharkInfo


class Health(BaseModel):
    status: Literal["ok"] = "ok"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    display_name: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    role: Role = Role.consultant
    display_name: str = Field(default="", max_length=128)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=1024)


class ErrorOut(BaseModel):
    detail: str


# ── Engagements (M2) ──────────────────────────────────────────────────────────

from pcapvis.db.models import CaptureStatus, EngagementStatus, MemberRole  # noqa: E402


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client: str = Field(default="", max_length=200)
    site: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=10_000)


class EngagementUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    client: str | None = Field(default=None, max_length=200)
    site: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    status: EngagementStatus | None = None
    is_quicklook: Literal[False] | None = None  # promote a Quick look to a real engagement


class EngagementOut(BaseModel):
    id: int
    name: str
    client: str
    site: str
    description: str
    status: EngagementStatus
    is_quicklook: bool
    created_at: datetime
    updated_at: datetime
    revision: int
    my_role: MemberRole
    capture_count: int
    member_count: int


class MemberOut(BaseModel):
    user_id: int
    username: str
    display_name: str
    role: MemberRole
    global_role: Role
    max_role: MemberRole


class MemberSet(BaseModel):
    role: MemberRole


class DirectoryUser(BaseModel):
    id: int
    username: str
    display_name: str
    role: Role


class CapturePointIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=5000)


class CapturePointUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=5000)


class CapturePointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    created_at: datetime


class AuditEventOut(BaseModel):
    id: int
    at: datetime
    user: str | None
    action: str
    target: str
    details: dict | None


class CaptureOut(BaseModel):
    id: int
    engagement_id: int
    capture_point_id: int | None
    capture_point: str | None
    file_name: str
    size: int
    sha256: str
    status: CaptureStatus
    progress: float
    error: str | None
    uploaded_by: str | None
    uploaded_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    summary: dict | None


class CaptureUpdate(BaseModel):
    capture_point_id: int | None = None


class RevisionOut(BaseModel):
    revision: int


# ── Assets (M3) ───────────────────────────────────────────────────────────────

from typing import Any  # noqa: E402

from pcapvis.db.models import AssetOrigin  # noqa: E402
from pcapvis.engine.model import Evidence, HostName, Service  # noqa: E402

FieldValue = str | float | list[str] | None
EditableField = Literal[
    "name",
    "asset_type",
    "purdue_level",
    "zone",
    "criticality",
    "vendor",
    "model",
    "firmware",
    "serial",
    "location",
    "owner",
    "tags",
    "notes",
]
Criticality = Literal["low", "medium", "high", "critical"]


class AssetOut(BaseModel):
    """One row of the inventory: effective values plus the facts the grid shows."""

    id: int
    origin: AssetOrigin
    version: int
    ips: list[str]
    macs: list[str]
    name: str | None
    asset_type: str | None
    purdue_level: float
    zone: str | None
    criticality: Criticality | None
    vendor: str | None
    model: str | None
    firmware: str | None
    serial: str | None
    location: str | None
    owner: str | None
    tags: list[str]
    notes: str | None
    overridden: list[EditableField] = Field(description="Fields with a manual value")
    type_confidence: Literal["high", "medium", "low"] | None
    mac_vendor: str | None
    is_private: bool
    protocols: list[str]
    vlans: list[int] = Field(description="802.1Q VLAN IDs the asset was seen on (empty: untagged)")
    ot_role: str
    os_hint: str | None
    packets: int
    bytes: int
    first_seen: float | None
    last_seen: float | None
    capture_count: int
    updated_at: datetime


class OverrideOut(BaseModel):
    value: FieldValue
    reason: str
    by: str
    at: str


class SightingOut(BaseModel):
    capture_id: int
    file_name: str
    capture_point: str | None
    ip: str
    mac: str | None
    first_seen: float | None
    last_seen: float | None
    packets: int
    host_type: str
    purdue_level: float


class AssetDetail(AssetOut):
    auto: dict[EditableField, FieldValue]
    auto_sources: dict[EditableField, str] = Field(description="Where each detected value came from")
    overrides: dict[EditableField, OverrideOut]
    services: list[Service]
    identity: dict[str, str]
    hostnames: list[HostName]
    tls_sni: list[str]
    modbus_unit_ids: list[int]
    dnp3_addresses: list[int]
    ttl: int | None
    type_evidence: list[Evidence]
    purdue_evidence: list[Evidence]
    sightings: list[SightingOut]


class AssetEdit(BaseModel):
    version: int = Field(ge=1, description="The version you edited; a mismatch returns 409")
    set: dict[EditableField, Any] = Field(default_factory=dict)
    reset: list[EditableField] = Field(default_factory=list, max_length=20)
    reason: str = Field(default="", max_length=1000)


class AssetBulkEdit(BaseModel):
    asset_ids: list[int] = Field(min_length=1, max_length=10_000)
    set: dict[EditableField, Any] = Field(default_factory=dict)
    reset: list[EditableField] = Field(default_factory=list, max_length=20)
    reason: str = Field(default="", max_length=1000)


class AssetBulkResult(BaseModel):
    assets: int
    changes: int


class AssetMerge(BaseModel):
    """Fold other assets into this one (the matcher kept one device apart)."""

    version: int = Field(ge=1, description="The version of this asset you saw; a mismatch returns 409")
    source_ids: list[int] = Field(min_length=1, max_length=50)
    reason: str = Field(default="", max_length=1000)


class AssetSplit(BaseModel):
    """Move some of this asset's IP addresses to a new asset (the matcher joined two devices)."""

    version: int = Field(ge=1)
    ips: list[str] = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=1000)


class AssetSplitResult(BaseModel):
    original: "AssetDetail"
    created: "AssetDetail"


class AssetImportChange(BaseModel):
    asset_id: int
    label: str
    field: EditableField
    old: Any
    new: Any


class AssetImportOut(BaseModel):
    """What an imported register changes (a preview unless ``applied``)."""

    applied: bool
    rows: int
    matched: int
    unmatched: list[str]
    errors: list[str]
    changes: list[AssetImportChange]
    assets_changed: int = 0


class AssetCreate(BaseModel):
    ips: list[str] = Field(default_factory=list, max_length=32)
    macs: list[str] = Field(default_factory=list, max_length=32)
    values: dict[EditableField, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=1000)


class AssetChangeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    actor: str
    kind: Literal["created", "override", "reset", "auto", "import", "merge", "split"]
    field: EditableField | None
    old: FieldValue
    new: FieldValue
    reason: str


class AssetFieldOut(BaseModel):
    name: EditableField
    label: str
    kind: Literal["text", "longtext", "level", "choice", "tags"]
    max_len: int
    auto: bool


class AssetFieldsOut(BaseModel):
    fields: list[AssetFieldOut]
    purdue_levels: list[float]
    purdue_names: dict[str, str]
    criticalities: list[Criticality]
    asset_types: list[str] = Field(description="Types the engine knows (suggestions; any text is allowed)")


# ── Purdue map: links and OT operations (M4) ─────────────────────────────────


class LinkProtocolOut(BaseModel):
    protocol: str
    ports: list[str]
    flows: int
    packets: int
    bytes: int
    ot_reads: int
    ot_writes: int
    ot_errors: int


class LinkOut(BaseModel):
    """All traffic seen from one asset (client) to another (server), across captures."""

    src: int
    dst: int
    protocols: list[LinkProtocolOut]
    is_ot: bool = Field(description="Carries an OT protocol or OT commands")
    flows: int
    packets: int
    bytes: int
    ot_reads: int
    ot_writes: int
    ot_errors: int
    first_seen: float | None
    last_seen: float | None
    captures: list[int]


class OtOperationOut(BaseModel):
    """OT commands of one function from one asset to another, across captures."""

    src: int
    dst: int
    protocol: str
    function: str
    function_code: int | None
    kind: Literal["read", "write", "error", "other"]
    count: int
    first_seen: float
    last_seen: float
    sample: str
    captures: list[int]


# ── Zones, conduits, architecture (M6) ───────────────────────────────────────

SecurityLevel = Literal[1, 2, 3, 4]


class ZoneIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    purdue_level: float | None = None
    security_level: SecurityLevel | None = None
    description: str = Field(default="", max_length=5000)


class ZoneUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    purdue_level: float | None = None
    security_level: SecurityLevel | None = None
    description: str | None = Field(default=None, max_length=5000)
    x: float | None = Field(default=None, ge=-COORD_MAX, le=COORD_MAX)
    y: float | None = Field(default=None, ge=-COORD_MAX, le=COORD_MAX)


class ZoneOut(BaseModel):
    """A defined zone, or (``id`` null) a zone name used on assets but not defined yet."""

    id: int | None
    name: str
    defined: bool
    purdue_level: float | None
    security_level: int | None
    description: str
    x: float | None
    y: float | None
    asset_ids: list[int]


class ConduitIn(BaseModel):
    zone_a_id: int
    zone_b_id: int
    name: str = Field(default="", max_length=100)
    allowed: list[str] = Field(default_factory=list, max_length=50, description="Protocols; empty allows any")
    description: str = Field(default="", max_length=5000)


class ConduitUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    allowed: list[str] | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=5000)


class ConduitOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    zone_a_id: int
    zone_b_id: int
    name: str
    allowed: list[str]
    description: str


class ViolationOut(BaseModel):
    """Observed traffic between zones that no conduit permits."""

    kind: Literal["no_conduit", "protocol_not_allowed"]
    src: int
    dst: int
    src_zone: str
    dst_zone: str
    conduit_id: int | None
    protocols: list[str]
    flows: int
    packets: int
    ot_writes: int
    first_seen: float | None
    last_seen: float | None


class NetworkOut(BaseModel):
    """A subnet inferred from asset addresses (IPv4 /24), with what's seen on it."""

    cidr: str
    vlans: list[int]
    asset_ids: list[int]
    gateways: list[int] = Field(description="Routers and firewalls with an address in this subnet")
    zones: list[str]
    purdue_levels: list[float]


# ── Flows, forensics, dashboard (M7) ─────────────────────────────────────────


class PacketRowOut(BaseModel):
    number: int
    time: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str


class PacketListOut(BaseModel):
    packets: list[PacketRowOut]
    truncated: bool = Field(description="More packets matched than were returned")


class PacketDetailOut(BaseModel):
    number: int
    text: str


class DiffLinkOut(BaseModel):
    src: int
    dst: int
    protocol: str
    packets: int


class DiffOut(BaseModel):
    """What changed between two captures, in asset terms."""

    new_assets: list[int]
    gone_assets: list[int]
    new_links: list[DiffLinkOut]
    gone_links: list[DiffLinkOut]


class DashboardOut(BaseModel):
    captures: int
    captures_done: int
    packets: int
    assets: int
    assets_edited: int
    assets_by_level: dict[str, int]
    assets_by_type: dict[str, int]
    ot_connections: int
    ot_writes: int
    zones: int
    conduits: int
    violations: int
    findings: dict[str, int]
    credentials: int
    files: int


# ── Findings and reports (M8) ────────────────────────────────────────────────

SeverityLit = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "confirmed", "false_positive", "accepted_risk", "resolved"]


class FindingOut(BaseModel):
    """A finding across captures: a rule hit (merged by key) or written by hand, with its triage."""

    key: str
    source: Literal["rule", "manual"]
    rule: str | None
    category: str | None
    title: str
    description: str
    severity: SeverityLit = Field(description="Effective severity (override wins)")
    detected_severity: SeverityLit | None
    attack: list[str]
    evidence: list[str]
    asset_ids: list[int]
    src: str | None
    dst: str | None
    count: int
    first_seen: float | None
    last_seen: float | None
    captures: list[int]
    status: FindingStatus
    notes: str
    recommendation: str
    include_in_report: bool
    updated_by: str
    updated_at: datetime | None


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    severity_override: SeverityLit | None = None
    clear_severity_override: bool = False
    notes: str | None = Field(default=None, max_length=20_000)
    recommendation: str | None = Field(default=None, max_length=20_000)
    include_in_report: bool | None = None
    # Manual findings only:
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20_000)
    asset_ids: list[int] | None = Field(default=None, max_length=1000)


class FindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20_000)
    severity: SeverityLit
    recommendation: str = Field(default="", max_length=20_000)
    asset_ids: list[int] = Field(default_factory=list, max_length=1000)


# ── Merge a bundle into an engagement (M9) ───────────────────────────────────


class MergeConflictOut(BaseModel):
    asset_id: int
    asset: str
    field: str
    kept: FieldValue = Field(description="The value already on this server (kept)")
    imported: FieldValue = Field(description="The value in the bundle (not applied)")


class MergeReportOut(BaseModel):
    captures_added: int
    captures_skipped: int = Field(description="Already in this engagement (same SHA-256)")
    assets_created: int
    assets_updated: int
    fields_applied: int
    conflicts: list[MergeConflictOut]
    zones_added: int
    conduits_added: int
    findings_added: int
