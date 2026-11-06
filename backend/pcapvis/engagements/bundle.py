"""Engagement bundles (``.pcapvis``): export an engagement to one file and import it elsewhere.

A bundle is a zip archive:

    manifest.json                    what's inside (validated strictly on import), including the
                                     asset inventory: manual values, provenance, history (v2+)
    captures/<key>/<file name>       original captures (optional)
    results/<key>.json.gz            analysis results
    files/<sha256>                   files extracted from traffic (optional)

Imports treat the archive as untrusted: only the paths above are accepted, sizes and compression
ratios are bounded (zip bombs), capture hashes are re-verified, and results are validated before
anything is created. A failed import leaves nothing behind.
"""

import gzip
import hashlib
import json
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from pcapvis import __version__
from pcapvis.assets import fields as F
from pcapvis.assets import merge as asset_merge
from pcapvis.assets.service import MAC_RE, parse_identifiers
from pcapvis.db.base import utcnow
from pcapvis.db.models import (
    Asset,
    AssetChange,
    AssetOrigin,
    AssetSighting,
    Capture,
    CapturePoint,
    CaptureStatus,
    Conduit,
    Engagement,
    EngagementMember,
    MemberRole,
    User,
    Zone,
)
from pcapvis.engagements import audit
from pcapvis.engagements.storage import Storage, safe_filename
from pcapvis.engine.model import AnalysisResult

FORMAT = "pcapvis-engagement"
FORMAT_VERSION = 3  # 2: asset inventory (M3); 3: zones and conduits (M6)
MAX_RATIO = 200  # uncompressed/compressed, per deflated member
CHUNK = 1 << 20
_CAPTURE_PATH = re.compile(r"^captures/(\d{1,12})/([A-Za-z0-9._ -]{1,200})$")
_RESULT_PATH = re.compile(r"^results/(\d{1,12})\.json\.gz$")
_FILE_PATH = re.compile(r"^files/([0-9a-f]{64})$")


class BundleError(Exception):
    """The bundle is invalid or unsafe (message is safe to show)."""


# ── manifest schema ───────────────────────────────────────────────────────────


class _EngagementMeta(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client: str = Field(default="", max_length=200)
    site: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=10_000)


class _PointMeta(BaseModel):
    key: int
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=5000)


class _CaptureMeta(BaseModel):
    key: int
    file_name: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capture_point_key: int | None = None
    status: CaptureStatus
    summary: dict | None = None
    engine_version: str | None = Field(default=None, max_length=32)
    uploaded_at: datetime | None = None
    finished_at: datetime | None = None
    has_file: bool
    has_result: bool


class _OverrideMeta(BaseModel):
    value: Any = None
    reason: str = Field(default="", max_length=F.MAX_REASON)
    by: str = Field(default="", max_length=255)
    at: str = Field(default="", max_length=64)


class _ChangeMeta(BaseModel):
    at: datetime
    actor: str = Field(default="", max_length=255)
    kind: Literal["created", "override", "reset", "auto", "import"]
    field: str | None = Field(default=None, max_length=32)
    old: Any = None
    new: Any = None
    reason: str = Field(default="", max_length=F.MAX_REASON)


class _SightingMeta(BaseModel):
    capture_key: int
    ip: str = Field(max_length=64)
    mac: str | None = Field(default=None, max_length=17)


class _AssetMeta(BaseModel):
    key: int
    origin: AssetOrigin
    ips: list[str] = Field(default_factory=list, max_length=1000)
    macs: list[str] = Field(default_factory=list, max_length=1000)
    declared_ips: list[str] = Field(default_factory=list, max_length=32)
    declared_macs: list[str] = Field(default_factory=list, max_length=32)
    auto: dict[str, Any] = Field(default_factory=dict)
    overrides: dict[str, _OverrideMeta] = Field(default_factory=dict)
    sightings: list[_SightingMeta] = Field(default_factory=list, max_length=100_000)
    history: list[_ChangeMeta] = Field(default_factory=list, max_length=20_000)


class _ZoneMeta(BaseModel):
    key: int
    name: str = Field(min_length=1, max_length=100)
    purdue_level: float | None = None
    security_level: Literal[1, 2, 3, 4] | None = None
    description: str = Field(default="", max_length=5000)
    x: float | None = None
    y: float | None = None


class _ConduitMeta(BaseModel):
    zone_a_key: int
    zone_b_key: int
    name: str = Field(default="", max_length=100)
    allowed: list[str] = Field(default_factory=list, max_length=50)
    description: str = Field(default="", max_length=5000)


class Manifest(BaseModel):
    format: Literal["pcapvis-engagement"]
    format_version: int = Field(ge=1, le=FORMAT_VERSION)
    app_version: str = Field(max_length=32)
    exported_at: datetime
    engagement: _EngagementMeta
    capture_points: list[_PointMeta] = Field(default_factory=list, max_length=10_000)
    captures: list[_CaptureMeta] = Field(default_factory=list, max_length=10_000)
    files: list[str] = Field(default_factory=list, max_length=100_000)
    assets: list[_AssetMeta] | None = Field(default=None, max_length=200_000)  # None: v1, derive from results
    zones: list[_ZoneMeta] = Field(default_factory=list, max_length=10_000)
    conduits: list[_ConduitMeta] = Field(default_factory=list, max_length=50_000)


# ── export ────────────────────────────────────────────────────────────────────


def export_bundle(
    storage: Storage,
    eng: Engagement,
    dest: Path,
    *,
    include_captures: bool = True,
    include_files: bool = True,
) -> None:
    captures, file_hashes = [], []
    files_dir = storage.files_dir(eng.id)
    with zipfile.ZipFile(dest, "w", allowZip64=True) as z:
        for c in eng.captures:
            src = storage.capture_file(eng.id, c.id, c.file_name)
            res = storage.result_path(eng.id, c.id)
            has_file = include_captures and src.is_file()
            has_result = c.status == CaptureStatus.done and res.is_file()
            if has_file:
                z.write(
                    src, f"captures/{c.id}/{safe_filename(c.file_name)}", compress_type=zipfile.ZIP_STORED
                )
            if has_result:
                z.write(res, f"results/{c.id}.json.gz", compress_type=zipfile.ZIP_STORED)
            captures.append(
                _CaptureMeta(
                    key=c.id,
                    file_name=safe_filename(c.file_name),
                    size=c.size,
                    sha256=c.sha256,
                    capture_point_key=c.capture_point_id,
                    status=CaptureStatus.done
                    if has_result
                    else c.status
                    if c.status != CaptureStatus.processing
                    else CaptureStatus.queued,
                    summary=c.summary if has_result else None,
                    engine_version=c.engine_version,
                    uploaded_at=c.uploaded_at,
                    finished_at=c.finished_at,
                    has_file=has_file,
                    has_result=has_result,
                )
            )
        if include_files and files_dir.is_dir():
            for f in sorted(files_dir.iterdir()):
                if f.is_file() and re.fullmatch(r"[0-9a-f]{64}", f.name):
                    z.write(f, f"files/{f.name}", compress_type=zipfile.ZIP_DEFLATED)
                    file_hashes.append(f.name)
        with_result = {c.key for c in captures if c.has_result}
        manifest = Manifest(
            format=FORMAT,
            format_version=FORMAT_VERSION,
            app_version=__version__,
            exported_at=utcnow(),
            engagement=_EngagementMeta(
                name=eng.name, client=eng.client, site=eng.site, description=eng.description
            ),
            capture_points=[
                _PointMeta(key=p.id, name=p.name, description=p.description) for p in eng.capture_points
            ],
            captures=captures,
            files=file_hashes,
            assets=[_asset_meta(a, with_result) for a in eng.assets],
            zones=[
                _ZoneMeta(
                    key=z.id,
                    name=z.name,
                    purdue_level=z.purdue_level,
                    security_level=z.security_level,
                    description=z.description,
                    x=z.x,
                    y=z.y,
                )
                for z in _zones(eng)
            ],
            conduits=[
                _ConduitMeta(
                    zone_a_key=c.zone_a_id,
                    zone_b_key=c.zone_b_id,
                    name=c.name,
                    allowed=c.allowed or [],
                    description=c.description,
                )
                for c in object_session(eng).scalars(select(Conduit).where(Conduit.engagement_id == eng.id))
            ],
        )
        z.writestr("manifest.json", manifest.model_dump_json(indent=2), compress_type=zipfile.ZIP_DEFLATED)


def _asset_meta(a: Asset, with_result: set[int]) -> _AssetMeta:
    declared = a.declared or {}
    return _AssetMeta(
        key=a.id,
        origin=a.origin,
        ips=a.ips or [],
        macs=a.macs or [],
        declared_ips=declared.get("ips", []),
        declared_macs=declared.get("macs", []),
        auto={k: v for k, v in (a.auto or {}).items() if k in F.FIELDS},
        overrides={k: _OverrideMeta(**v) for k, v in (a.overrides or {}).items()},
        sightings=[
            _SightingMeta(capture_key=s.capture_id, ip=s.ip, mac=s.mac)
            for s in sorted(a.sightings, key=lambda s: (s.capture_id, s.ip))
            if s.capture_id in with_result
        ],
        history=[
            _ChangeMeta(
                at=c.at, actor=c.actor, kind=c.kind, field=c.field, old=c.old, new=c.new, reason=c.reason
            )
            for c in sorted(_history(a), key=lambda c: c.id)
        ],
    )


def _zones(eng) -> list[Zone]:
    return list(
        object_session(eng).scalars(select(Zone).where(Zone.engagement_id == eng.id).order_by(Zone.id))
    )


def _import_zones(db, eng, manifest: "Manifest") -> None:
    from pcapvis import zones as Z

    keys: dict[int, int] = {}
    names: set[str] = set()
    for zm in manifest.zones:
        try:
            name, level = Z.clean_name(zm.name), Z.check_level(zm.purdue_level)
        except F.FieldError as exc:
            raise BundleError(f"Invalid zone: {exc}") from exc
        if zm.key in keys or name in names:
            raise BundleError("Invalid manifest: duplicate zones.")
        z = Zone(
            engagement_id=eng.id,
            name=name,
            purdue_level=level,
            security_level=zm.security_level,
            description=zm.description,
            x=zm.x,
            y=zm.y,
        )
        db.add(z)
        db.flush()
        keys[zm.key], names = z.id, names | {name}
    for cm in manifest.conduits:
        a, b = keys.get(cm.zone_a_key), keys.get(cm.zone_b_key)
        if a is None or b is None or a == b:
            raise BundleError("Invalid manifest: a conduit refers to an unknown zone.")
        try:
            allowed = Z.clean_protocols(cm.allowed)
        except F.FieldError as exc:
            raise BundleError(f"Invalid conduit: {exc}") from exc
        db.add(
            Conduit(
                engagement_id=eng.id,
                zone_a_id=a,
                zone_b_id=b,
                name=cm.name.strip(),
                allowed=allowed,
                description=cm.description,
            )
        )
    db.flush()


def _history(a: Asset) -> list[AssetChange]:
    return list(object_session(a).scalars(select(AssetChange).where(AssetChange.asset_id == a.id)))


# ── import ────────────────────────────────────────────────────────────────────


def _check_members(z: zipfile.ZipFile, max_total: int) -> dict[str, zipfile.ZipInfo]:
    members, total = {}, 0
    for info in z.infolist():
        name = info.filename
        if info.is_dir():
            continue
        if name != "manifest.json" and not (
            _CAPTURE_PATH.match(name) or _RESULT_PATH.match(name) or _FILE_PATH.match(name)
        ):
            raise BundleError(f"Unexpected entry in bundle: {name[:100]!r}")
        if name in members:
            raise BundleError(f"Duplicate entry in bundle: {name[:100]!r}")
        if info.flag_bits & 0x1:
            raise BundleError("Encrypted bundles are not supported.")
        if info.compress_type == zipfile.ZIP_DEFLATED and info.file_size > MAX_RATIO * max(
            info.compress_size, 1
        ):
            raise BundleError("Bundle entry is suspiciously compressed (possible zip bomb).")
        total += info.file_size
        if total > max_total:
            raise BundleError("Bundle is too large once unpacked.")
        members[name] = info
    if "manifest.json" not in members:
        raise BundleError("Not a .pcapvis bundle (no manifest.json).")
    return members


def _extract(z: zipfile.ZipFile, info: zipfile.ZipInfo, dest: Path) -> str:
    """Copy one member to dest, enforcing its declared size. Returns its SHA-256."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    digest, written = hashlib.sha256(), 0
    with z.open(info) as src, open(dest, "wb") as out:
        while chunk := src.read(CHUNK):
            written += len(chunk)
            if written > info.file_size:
                raise BundleError("Bundle entry is larger than declared.")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def _unique_name(db: Session, name: str) -> str:
    existing = set(db.scalars(select(Engagement.name).where(Engagement.name.like(f"{name}%"))))
    if name not in existing:
        return name
    for i in range(2, 1000):
        candidate = f"{name} (imported {i})" if i > 2 else f"{name} (imported)"
        if candidate not in existing:
            return candidate
    return f"{name} ({utcnow():%Y%m%d%H%M%S})"


def import_bundle(db: Session, storage: Storage, user: User, bundle: Path, *, max_total: int) -> Engagement:
    try:
        z = zipfile.ZipFile(bundle)
    except zipfile.BadZipFile as exc:
        raise BundleError("Not a .pcapvis bundle (not a zip archive).") from exc
    with z:
        members = _check_members(z, max_total)
        if members["manifest.json"].file_size > 50 * 1024 * 1024:
            raise BundleError("Manifest is too large.")
        try:
            manifest = Manifest.model_validate_json(z.read("manifest.json"))
        except (ValidationError, ValueError) as exc:
            raise BundleError(f"Invalid manifest: {str(exc)[:300]}") from exc
        keys = {c.key for c in manifest.captures}
        if len(keys) != len(manifest.captures) or len({p.key for p in manifest.capture_points}) != len(
            manifest.capture_points
        ):
            raise BundleError("Invalid manifest: duplicate keys.")

        meta = manifest.engagement
        eng = Engagement(
            name=_unique_name(db, meta.name),
            client=meta.client,
            site=meta.site,
            description=meta.description,
            created_by=user.id,
        )
        db.add(eng)
        db.flush()
        try:
            db.add(EngagementMember(engagement_id=eng.id, user_id=user.id, role=MemberRole.lead))
            point_ids = {}
            for p in manifest.capture_points:
                point = CapturePoint(engagement_id=eng.id, name=p.name, description=p.description)
                db.add(point)
                db.flush()
                point_ids[p.key] = point.id
            cap_ids: dict[int, Capture] = {}
            for cm in manifest.captures:
                cap_ids[cm.key] = _import_capture(db, z, members, storage, eng, user, cm, point_ids)
            done = {k: c for k, c in cap_ids.items() if c.status == CaptureStatus.done}
            if manifest.assets is not None:
                _import_assets(db, storage, eng, manifest.assets, done)
            _import_zones(db, eng, manifest)
            for cap in done.values():  # hosts the manifest didn't map (and every host for v1 bundles)
                asset_merge.ingest_capture(
                    db, cap, _load_result(storage, cap), keep_existing=True, actor="import", record_auto=False
                )
            for sha in manifest.files:
                info = members.get(f"files/{sha}")
                if info is None:
                    raise BundleError("Bundle is missing an extracted file listed in its manifest.")
                if _extract(z, info, storage.files_dir(eng.id) / sha) != sha:
                    raise BundleError("Extracted file hash mismatch: the bundle is corrupt or was modified.")
            eng.touch()
            audit.record(
                db,
                user,
                "engagement.import",
                engagement_id=eng.id,
                target=eng.name,
                details={"from_version": manifest.app_version, "captures": len(manifest.captures)},
            )
            db.commit()
        except BaseException:
            db.rollback()
            storage.delete_engagement(eng.id)
            leftover = db.get(Engagement, eng.id)
            if leftover is not None:
                db.delete(leftover)
                db.commit()
            raise
    return eng


def _import_capture(db, z, members, storage: Storage, eng, user, cm: _CaptureMeta, point_ids) -> Capture:
    status = (
        CaptureStatus.done
        if cm.has_result
        else CaptureStatus.queued
        if cm.has_file
        else CaptureStatus.cancelled
    )
    cap = Capture(
        engagement_id=eng.id,
        capture_point_id=point_ids.get(cm.capture_point_key),
        file_name=safe_filename(cm.file_name),
        size=cm.size,
        sha256=cm.sha256,
        status=status,
        progress=1.0 if status == CaptureStatus.done else 0.0,
        uploaded_by=user.id,
        uploaded_at=cm.uploaded_at or utcnow(),
        finished_at=cm.finished_at if cm.has_result else None,
        summary=cm.summary if cm.has_result else None,
        engine_version=cm.engine_version,
        error=None if status != CaptureStatus.cancelled else "Imported without the capture file.",
    )
    db.add(cap)
    db.flush()
    if cm.has_file:
        info = members.get(f"captures/{cm.key}/{safe_filename(cm.file_name)}")
        if info is None:
            raise BundleError(f"Bundle is missing the capture file for {cm.file_name!r}.")
        sha = _extract(z, info, storage.capture_file(eng.id, cap.id, cap.file_name))
        if sha != cm.sha256:
            raise BundleError(
                f"Capture {cm.file_name!r} doesn't match its recorded hash: the bundle is corrupt or was modified."
            )
    if cm.has_result:
        info = members.get(f"results/{cm.key}.json.gz")
        if info is None:
            raise BundleError(f"Bundle is missing the analysis result for {cm.file_name!r}.")
        dest = storage.result_path(eng.id, cap.id)
        _extract(z, info, dest)
        try:
            with gzip.open(dest, "rb") as fh:
                data = fh.read(4 * 1024**3)
            AnalysisResult.model_validate_json(data)
        except (OSError, EOFError, ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise BundleError(f"Invalid analysis result for {cm.file_name!r}.") from exc
    return cap


def _load_result(storage: Storage, cap: Capture) -> AnalysisResult:
    with gzip.open(storage.result_path(cap.engagement_id, cap.id), "rb") as fh:
        return AnalysisResult.model_validate_json(fh.read())


def _clean_values(values: dict[str, Any], what: str) -> dict[str, Any]:
    try:
        return {k: F.validate(k, v) for k, v in values.items()}
    except F.FieldError as exc:
        raise BundleError(f"Invalid asset {what}: {exc}") from exc


def _import_assets(db, storage: Storage, eng, metas: list[_AssetMeta], done: dict[int, Capture]) -> None:
    keys = [m.key for m in metas]
    if len(set(keys)) != len(keys):
        raise BundleError("Invalid manifest: duplicate asset keys.")
    by_capture: dict[int, list[tuple[Asset, _SightingMeta]]] = {}
    for m in metas:
        try:
            ips, macs = parse_identifiers(m.ips, m.macs, limit=2000)
            d_ips, d_macs = parse_identifiers(m.declared_ips, m.declared_macs)
        except F.FieldError as exc:
            raise BundleError(f"Invalid asset address: {exc}") from exc
        overrides = _clean_values({k: o.value for k, o in m.overrides.items()}, "value")
        a = Asset(
            engagement_id=eng.id,
            origin=m.origin,
            ips=ips,
            macs=macs,
            declared={"ips": d_ips, "macs": d_macs} if d_ips or d_macs else {},
            auto=_clean_values(m.auto, "automatic value"),
            observed={"captures": 0},
            overrides={
                k: {"value": overrides[k], "reason": o.reason, "by": o.by, "at": o.at}
                for k, o in m.overrides.items()
            },
        )
        db.add(a)
        db.flush()
        for h in m.history:
            if h.field is not None and h.field not in F.FIELDS:
                raise BundleError(f"Invalid asset history: unknown field {h.field[:32]!r}.")
            db.add(
                AssetChange(
                    asset_id=a.id,
                    engagement_id=eng.id,
                    at=h.at,
                    actor=h.actor,
                    kind=h.kind,
                    field=h.field,
                    old=_jsonable(h.old),
                    new=_jsonable(h.new),
                    reason=h.reason,
                )
            )
        for s in m.sightings:
            if s.capture_key in done:
                by_capture.setdefault(s.capture_key, []).append((a, s))
    for key, pairs in by_capture.items():
        cap = done[key]
        hosts = {h.ip: h for h in _load_result(storage, cap).hosts}
        seen: set[str] = set()
        for a, s in pairs:
            host = hosts.get(s.ip)
            if host is None or s.ip in seen:
                continue  # left for the merge to place
            seen.add(s.ip)
            mac = s.mac.lower() if s.mac and MAC_RE.match(s.mac.lower()) else None
            db.add(
                AssetSighting(
                    asset_id=a.id, capture_id=cap.id, ip=s.ip, mac=mac, host=host.model_dump(mode="json")
                )
            )
    db.flush()


def _jsonable(v: Any) -> Any:
    """History values are shown, never interpreted; keep them small and plain."""
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        return v[:10_000]
    if isinstance(v, list):
        return [str(x)[:200] for x in v[:50]]
    return str(v)[:1000]


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
