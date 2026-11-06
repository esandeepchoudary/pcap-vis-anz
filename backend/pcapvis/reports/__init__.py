"""Client deliverables: asset register (XLSX), Purdue diagram (draw.io, SVG), report (DOCX, HTML) (M8).

Every generator takes a ``ReportData`` snapshot. All text in it may come from untrusted traffic
(hostnames, identity strings, HTTP data): each format escapes it its own way (see the generators).
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis import __version__
from pcapvis import findings as FN
from pcapvis import zones as Z
from pcapvis.api.schemas import FindingOut, LinkOut, NetworkOut, ViolationOut, ZoneOut
from pcapvis.assets import fields as F
from pcapvis.assets.links import aggregate_links
from pcapvis.db.models import Asset, AssetOtOp, Capture, CaptureStatus, Conduit, Engagement

LEVEL_NAMES = F.PURDUE_NAMES


@dataclass
class AssetRow:
    id: int
    values: dict  # effective editable fields
    ips: list[str]
    macs: list[str]
    mac_vendor: str | None
    protocols: list[str]
    first_seen: float | None
    last_seen: float | None
    captures: int
    overridden: list[str]
    origin: str
    is_private: bool

    @property
    def label(self) -> str:
        return (
            self.values.get("name")
            or (self.ips[0] if self.ips else None)
            or (self.macs[0] if self.macs else f"Asset {self.id}")
        )

    @property
    def level(self) -> float:
        return float(self.values.get("purdue_level", -1))


@dataclass
class ReportData:
    engagement: Engagement
    generated_at: datetime
    app_version: str
    captures: list[Capture]
    assets: list[AssetRow]
    zones: list[ZoneOut]
    conduits: list[Conduit]
    violations: list[ViolationOut]
    findings: list[FindingOut]
    links: list[LinkOut]
    networks: list[NetworkOut]
    ot_ops: list[AssetOtOp] = field(default_factory=list)

    def asset(self, aid: int) -> AssetRow | None:
        return self._by_id.get(aid)

    def __post_init__(self):
        self._by_id = {a.id: a for a in self.assets}

    @property
    def reported_findings(self) -> list[FindingOut]:
        return [f for f in self.findings if f.include_in_report]


def gather(db: Session, eng: Engagement) -> ReportData:
    rows = []
    for a in db.scalars(select(Asset).where(Asset.engagement_id == eng.id).order_by(Asset.id)):
        obs = a.observed or {}
        rows.append(
            AssetRow(
                id=a.id,
                values=F.effective_all(a.auto or {}, a.overrides or {}),
                ips=a.ips or [],
                macs=a.macs or [],
                mac_vendor=obs.get("mac_vendor"),
                protocols=obs.get("protocols", []),
                first_seen=obs.get("first_seen"),
                last_seen=obs.get("last_seen"),
                captures=obs.get("captures", 0),
                overridden=sorted(a.overrides or {}),
                origin=a.origin.value,
                is_private=obs.get("is_private", True),
            )
        )
    rows.sort(key=lambda r: (r.level < 0, -r.level if r.level >= 0 else 0, r.label))
    return ReportData(
        engagement=eng,
        generated_at=datetime.now(UTC),
        app_version=__version__,
        captures=[c for c in eng.captures],
        assets=rows,
        zones=Z.list_zones(db, eng.id),
        conduits=list(
            db.scalars(select(Conduit).where(Conduit.engagement_id == eng.id).order_by(Conduit.id))
        ),
        violations=Z.violations(db, eng.id),
        findings=FN.list_findings(db, eng.id),
        links=aggregate_links(db, eng.id),
        networks=Z.networks(db, eng.id),
        ot_ops=list(
            db.scalars(select(AssetOtOp).where(AssetOtOp.engagement_id == eng.id).order_by(AssetOtOp.id))
        ),
    )


def level_name(level: float) -> str:
    return LEVEL_NAMES.get(int(level) if float(level).is_integer() else level, f"Level {level:g}")


def ts(t: float | None) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M UTC") if t else ""


def done_captures(data: ReportData) -> list[Capture]:
    return [c for c in data.captures if c.status == CaptureStatus.done]
