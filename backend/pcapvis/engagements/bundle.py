"""Engagement bundles (``.pcapvis``): export an engagement to one file and import it elsewhere.

A bundle is a zip archive:

    manifest.json                    what's inside (validated strictly on import)
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
from typing import Literal

from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis import __version__
from pcapvis.db.base import utcnow
from pcapvis.db.models import (
    Capture,
    CapturePoint,
    CaptureStatus,
    Engagement,
    EngagementMember,
    MemberRole,
    User,
)
from pcapvis.engagements import audit
from pcapvis.engagements.storage import Storage, safe_filename
from pcapvis.engine.model import AnalysisResult

FORMAT = "pcapvis-engagement"
FORMAT_VERSION = 1
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


class Manifest(BaseModel):
    format: Literal["pcapvis-engagement"]
    format_version: int = Field(ge=1, le=FORMAT_VERSION)
    app_version: str = Field(max_length=32)
    exported_at: datetime
    engagement: _EngagementMeta
    capture_points: list[_PointMeta] = Field(default_factory=list, max_length=10_000)
    captures: list[_CaptureMeta] = Field(default_factory=list, max_length=10_000)
    files: list[str] = Field(default_factory=list, max_length=100_000)


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
        )
        z.writestr("manifest.json", manifest.model_dump_json(indent=2), compress_type=zipfile.ZIP_DEFLATED)


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
            for cm in manifest.captures:
                _import_capture(db, z, members, storage, eng, user, cm, point_ids)
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


def _import_capture(db, z, members, storage: Storage, eng, user, cm: _CaptureMeta, point_ids) -> None:
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


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
