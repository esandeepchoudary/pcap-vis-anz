"""Captures: upload, analysis jobs, results, downloads, Quick look, and live update events."""

import asyncio
import hashlib
import shutil
import uuid
from pathlib import Path as FsPath

from fastapi import APIRouter, Depends, File, Form, HTTPException, Path, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.deps import current_user, get_db
from pcapvis.api.routes_engagements import as_editor, as_viewer, create_engagement, engagement_out, storage
from pcapvis.api.schemas import (
    CaptureOut,
    CaptureUpdate,
    EngagementCreate,
    EngagementOut,
    ErrorOut,
    RevisionOut,
)
from pcapvis.assets import merge as asset_merge
from pcapvis.db.models import Capture, CapturePoint, CaptureStatus, Engagement, MemberRole, User
from pcapvis.engagements import access, audit
from pcapvis.engagements.storage import Storage, safe_filename
from pcapvis.engine.model import AnalysisResult

router = APIRouter(prefix="/api", tags=["captures"])
CHUNK = 1 << 20
CAPTURE_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
    b"\x1f\x8b",
)  # pcap (µs/ns, both byte orders), pcapng, gzip
ACTIVE = (CaptureStatus.queued, CaptureStatus.processing)


class UploadResult(BaseModel):
    capture: CaptureOut
    duplicate: bool


class QuickLookOut(BaseModel):
    engagement: EngagementOut
    capture: CaptureOut


def capture_out(db: Session, c: Capture) -> CaptureOut:
    uploader = db.get(User, c.uploaded_by) if c.uploaded_by else None
    return CaptureOut(
        id=c.id,
        engagement_id=c.engagement_id,
        capture_point_id=c.capture_point_id,
        capture_point=c.capture_point.name if c.capture_point else None,
        file_name=c.file_name,
        size=c.size,
        sha256=c.sha256,
        status=c.status,
        progress=c.progress,
        error=c.error,
        uploaded_by=uploader.username if uploader else None,
        uploaded_at=c.uploaded_at,
        started_at=c.started_at,
        finished_at=c.finished_at,
        summary=c.summary,
    )


def _wake_jobs(request: Request) -> None:
    runner = getattr(request.app.state, "job_runner", None)
    if runner is not None:
        runner.wake.set()


def _receive(upload: UploadFile, tmp_dir: FsPath, max_bytes: int) -> tuple[FsPath, str, int]:
    """Stream an upload to a temp file, hashing as we go. Validates format and size."""
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / f".upload-{uuid.uuid4().hex}"
    digest, size = hashlib.sha256(), 0
    try:
        with open(tmp, "wb") as out:
            first = True
            while chunk := upload.file.read(CHUNK):
                if first:
                    if not chunk.startswith(CAPTURE_MAGICS):
                        raise HTTPException(
                            status.HTTP_400_BAD_REQUEST,
                            f"{upload.filename}: not a pcap, pcapng or gzipped capture.",
                        )
                    first = False
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        f"{upload.filename}: larger than the {max_bytes // 2**20} MB limit.",
                    )
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{upload.filename}: empty file.")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp, digest.hexdigest(), size


def _store_upload(
    db: Session,
    store: Storage,
    settings,
    eng: Engagement,
    user: User,
    upload: UploadFile,
    point_id: int | None,
) -> UploadResult:
    tmp, sha, size = _receive(upload, store.engagement_dir(eng.id), settings.max_upload_bytes)
    existing = db.scalar(select(Capture).where(Capture.engagement_id == eng.id, Capture.sha256 == sha))
    if existing is not None:
        tmp.unlink(missing_ok=True)
        return UploadResult(capture=capture_out(db, existing), duplicate=True)
    name = safe_filename(upload.filename or "capture.pcap")
    cap = Capture(
        engagement_id=eng.id,
        capture_point_id=point_id,
        file_name=name,
        size=size,
        sha256=sha,
        uploaded_by=user.id,
        status=CaptureStatus.queued,
    )
    db.add(cap)
    db.flush()
    dest = store.capture_file(eng.id, cap.id, name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(tmp, dest)
    eng.touch()
    audit.record(
        db, user, "capture.upload", engagement_id=eng.id, target=name, details={"sha256": sha, "size": size}
    )
    db.commit()
    return UploadResult(capture=capture_out(db, cap), duplicate=False)


@router.post(
    "/engagements/{engagement_id}/captures",
    response_model=list[UploadResult],
    status_code=201,
    responses={400: {"model": ErrorOut}, 413: {"model": ErrorOut, "description": "Too large"}},
)
def upload_captures(
    request: Request,
    files: list[UploadFile] = File(...),
    capture_point_id: int | None = Form(default=None),
    ctx=Depends(as_editor),
    store: Storage = Depends(storage),
) -> list[UploadResult]:
    eng, _role, user, db = ctx
    if capture_point_id is not None:
        point = db.get(CapturePoint, capture_point_id)
        if point is None or point.engagement_id != eng.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown capture point.")
    results = [
        _store_upload(db, store, request.app.state.settings, eng, user, f, capture_point_id) for f in files
    ]
    _wake_jobs(request)
    return results


@router.post("/quicklook", response_model=QuickLookOut, status_code=201, responses={403: {"model": ErrorOut}})
def quicklook(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    store: Storage = Depends(storage),
) -> QuickLookOut:
    """Analyse one capture without setting up an engagement (a personal, promotable Quick look)."""
    if not access.can_quicklook(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Viewers can't upload captures.")
    eng = create_engagement(
        db, user, EngagementCreate(name=safe_filename(file.filename or "Quick look")), quicklook=True
    )
    try:
        res = _store_upload(db, store, request.app.state.settings, eng, user, file, None)
    except HTTPException:
        db.delete(eng)
        db.commit()
        store.delete_engagement(eng.id)
        raise
    _wake_jobs(request)
    return QuickLookOut(engagement=engagement_out(db, eng, MemberRole.lead), capture=res.capture)


@router.get("/engagements/{engagement_id}/captures", response_model=list[CaptureOut])
def list_captures(ctx=Depends(as_viewer)) -> list[CaptureOut]:
    eng, _role, _user, db = ctx
    return [capture_out(db, c) for c in eng.captures]


def _capture(eng: Engagement, db: Session, cid: int) -> Capture:
    c = db.get(Capture, cid)
    if c is None or c.engagement_id != eng.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found.")
    return c


@router.get("/engagements/{engagement_id}/captures/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: int = Path(ge=1), ctx=Depends(as_viewer)) -> CaptureOut:
    eng, _role, _user, db = ctx
    return capture_out(db, _capture(eng, db, capture_id))


@router.patch("/engagements/{engagement_id}/captures/{capture_id}", response_model=CaptureOut)
def update_capture(body: CaptureUpdate, capture_id: int = Path(ge=1), ctx=Depends(as_editor)) -> CaptureOut:
    eng, _role, user, db = ctx
    c = _capture(eng, db, capture_id)
    if body.capture_point_id is not None:
        p = db.get(CapturePoint, body.capture_point_id)
        if p is None or p.engagement_id != eng.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown capture point.")
    c.capture_point_id = body.capture_point_id
    eng.touch()
    audit.record(
        db,
        user,
        "capture.update",
        engagement_id=eng.id,
        target=c.file_name,
        details={"capture_point_id": body.capture_point_id},
    )
    db.commit()
    return capture_out(db, c)


@router.post("/engagements/{engagement_id}/captures/{capture_id}/cancel", response_model=CaptureOut)
def cancel_capture(capture_id: int = Path(ge=1), ctx=Depends(as_editor)) -> CaptureOut:
    eng, _role, user, db = ctx
    c = _capture(eng, db, capture_id)
    if c.status == CaptureStatus.queued:
        c.status = CaptureStatus.cancelled
    elif c.status == CaptureStatus.processing:
        c.cancel_requested = True  # the worker stops at its next check (about a second)
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, "Only queued or running analyses can be cancelled.")
    eng.touch()
    audit.record(db, user, "capture.cancel", engagement_id=eng.id, target=c.file_name)
    db.commit()
    return capture_out(db, c)


@router.post("/engagements/{engagement_id}/captures/{capture_id}/reanalyze", response_model=CaptureOut)
def reanalyze_capture(request: Request, capture_id: int = Path(ge=1), ctx=Depends(as_editor)) -> CaptureOut:
    eng, _role, user, db = ctx
    c = _capture(eng, db, capture_id)
    if c.status in ACTIVE:
        raise HTTPException(status.HTTP_409_CONFLICT, "This capture is already queued or being analysed.")
    c.status, c.progress, c.error, c.cancel_requested = CaptureStatus.queued, 0.0, None, False
    eng.touch()
    audit.record(db, user, "capture.reanalyze", engagement_id=eng.id, target=c.file_name)
    db.commit()
    _wake_jobs(request)
    return capture_out(db, c)


@router.delete("/engagements/{engagement_id}/captures/{capture_id}", status_code=204)
def delete_capture(
    capture_id: int = Path(ge=1), ctx=Depends(as_editor), store: Storage = Depends(storage)
) -> None:
    eng, _role, user, db = ctx
    c = _capture(eng, db, capture_id)
    if c.status == CaptureStatus.processing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cancel the analysis before deleting the capture.")
    eid, cid, name = eng.id, c.id, c.file_name
    asset_merge.remove_capture(db, c)
    db.delete(c)
    eng.touch()
    audit.record(db, user, "capture.delete", engagement_id=eid, target=name)
    db.commit()
    store.delete_capture(eid, cid)


@router.get(
    "/engagements/{engagement_id}/captures/{capture_id}/result",
    responses={
        200: {"model": AnalysisResult, "description": "Full analysis result (sent gzip-encoded)"},
        409: {"model": ErrorOut},
    },
)
def capture_result(capture_id: int = Path(ge=1), ctx=Depends(as_viewer), store: Storage = Depends(storage)):
    eng, _role, _user, db = ctx
    c = _capture(eng, db, capture_id)
    path = store.result_path(eng.id, c.id)
    if c.status != CaptureStatus.done or not path.is_file():
        raise HTTPException(status.HTTP_409_CONFLICT, "No analysis result yet.")
    # Stored gzipped; browsers and HTTP clients decompress transparently.
    return FileResponse(path, media_type="application/json", headers={"Content-Encoding": "gzip"})


@router.get("/engagements/{engagement_id}/captures/{capture_id}/download")
def download_capture(capture_id: int = Path(ge=1), ctx=Depends(as_viewer), store: Storage = Depends(storage)):
    eng, _role, _user, db = ctx
    c = _capture(eng, db, capture_id)
    path = store.capture_file(eng.id, c.id, c.file_name)
    if not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture file missing.")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=c.file_name)


@router.get("/engagements/{engagement_id}/files/{sha256}")
def download_extracted_file(
    sha256: str = Path(pattern=r"^[0-9a-f]{64}$"),
    name: str = "file.bin",
    ctx=Depends(as_viewer),
    store: Storage = Depends(storage),
):
    """A file carved from traffic. Always an attachment, never rendered: it may be malware."""
    eng, _role, _user, _db = ctx
    path = store.files_dir(eng.id) / sha256
    if not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found.")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=safe_filename(name) + ".bin",
        headers={"X-Content-Type-Options": "nosniff"},
    )


# ── live updates ──────────────────────────────────────────────────────────────


@router.get("/engagements/{engagement_id}/revision", response_model=RevisionOut)
def revision(ctx=Depends(as_viewer)) -> RevisionOut:
    return RevisionOut(revision=ctx[0].revision)


@router.get("/engagements/{engagement_id}/events", responses={200: {"content": {"text/event-stream": {}}}})
async def events(request: Request, engagement_id: int = Path(ge=1), user: User = Depends(current_user)):
    """Server-sent events: 'revision' whenever the engagement or its captures change.

    Polls the engagement's revision counter, so it works when analysis runs in another process.
    """
    factory = request.app.state.session_factory

    def read_revision() -> int | None:
        with factory() as db:
            eng = db.get(Engagement, engagement_id)
            if eng is None or access.member_role(db, user, eng) is None:
                return None
            return eng.revision

    first = await run_in_threadpool(read_revision)
    if first is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found.")
    interval = request.app.state.settings.events_poll_s

    async def stream():
        last, idle = first, 0.0
        yield f"event: revision\ndata: {first}\n\n"
        while not await request.is_disconnected():
            await asyncio.sleep(interval)
            idle += interval
            current = await run_in_threadpool(read_revision)
            if current is None:
                yield "event: gone\ndata: {}\n\n"
                return
            if current != last:
                last, idle = current, 0.0
                yield f"event: revision\ndata: {current}\n\n"
            elif idle >= 15:
                idle = 0.0
                yield ": keep-alive\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
