"""Analysis job runner.

Captures are queued as rows (status=queued). Any number of runners, in the web process or in separate
``pcapvis worker`` processes, claim them with an atomic conditional UPDATE, analyse them, and write the
result next to the capture. Progress, heartbeat and cancel requests all go through the database, so it
works the same for one laptop process or several server workers.
"""

import gzip
import logging
import os
import socket
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from pcapvis import __version__
from pcapvis.assets import merge as asset_merge
from pcapvis.config import Settings
from pcapvis.db.base import utcnow
from pcapvis.db.models import Capture, CaptureStatus, Engagement
from pcapvis.engagements.storage import Storage
from pcapvis.engine.analyze import analyze_capture
from pcapvis.engine.model import AnalysisResult
from pcapvis.engine.runner import CaptureError

log = logging.getLogger("pcapvis.jobs")

HEARTBEAT_S = 5.0
STALE_AFTER = timedelta(seconds=60)  # a job whose worker hasn't reported in this long is re-queued
PROGRESS_EVERY_S = 1.0
POLL_S = 1.0


def summarize(r: AnalysisResult) -> dict:
    sev = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for a in r.anomalies:
        sev[a.severity] += 1
    c = r.capture
    return {
        "packets": c.packets,
        "bytes": c.bytes,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "duration": (c.last_seen - c.first_seen)
        if c.first_seen is not None and c.last_seen is not None
        else 0,
        "hosts": len(r.hosts),
        "flows": len(r.flows),
        "ot_commands": len(r.ot_commands),
        "ot_writes": sum(1 for x in r.ot_commands if x.kind == "write" and x.is_request),
        "credentials": len(r.credentials),
        "files": len(r.files),
        "findings": sev,
        "truncated": c.truncated,
        "malformed": c.malformed_packets,
        "warnings": c.warnings[:5],
        "tshark_version": c.tshark_version,
    }


class JobRunner:
    def __init__(
        self, settings: Settings, session_factory: sessionmaker[Session], *, concurrency: int | None = None
    ):
        self.settings = settings
        self.sf = session_factory
        self.storage = Storage(settings.data_dir)
        self.concurrency = max(1, concurrency or settings.job_concurrency)
        self.name = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.wake = threading.Event()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ── lifecycle ─────────────────────────────────────────────────────────
    def start(self) -> None:
        self.recover_stale()
        self.merge_pending()
        for i in range(self.concurrency):
            t = threading.Thread(target=self._loop, name=f"pcapvis-job-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self, timeout: float = 30) -> None:
        """Stop claiming work; running jobs are interrupted and put back in the queue."""
        self._stop.set()
        self.wake.set()
        for t in self._threads:
            t.join(timeout)
        self._threads.clear()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if not self.run_once():
                    self.wake.wait(POLL_S)
                    self.wake.clear()
            except Exception:  # noqa: BLE001 - keep the worker alive; the job itself is marked failed
                log.exception("job loop error")
                time.sleep(POLL_S)

    # ── queue ─────────────────────────────────────────────────────────────
    def recover_stale(self) -> int:
        """Put jobs back in the queue whose worker stopped reporting (crashed or restarted)."""
        with self.sf() as db:
            cutoff = utcnow() - STALE_AFTER
            stale = list(
                db.scalars(
                    select(Capture).where(
                        Capture.status == CaptureStatus.processing,
                        (Capture.heartbeat_at.is_(None)) | (Capture.heartbeat_at < cutoff),
                    )
                )
            )
            for c in stale:
                self._requeue(db, c)
            db.commit()
            return len(stale)

    def merge_pending(self) -> int:
        """Merge finished captures whose hosts aren't in the asset inventory yet (e.g. after upgrading)."""
        try:
            with self.sf() as db:
                return asset_merge.merge_pending(db, self.storage)
        except Exception:  # noqa: BLE001 - inventory backfill must never stop analysis
            log.exception("asset backfill failed")
            return 0

    def claim(self) -> int | None:
        """Atomically take the oldest queued capture. Returns its id, or None."""
        with self.sf() as db:
            for cid in db.scalars(
                select(Capture.id)
                .where(Capture.status == CaptureStatus.queued)
                .order_by(Capture.id)
                .limit(10)
            ):
                now = utcnow()
                res = db.execute(
                    update(Capture)
                    .where(Capture.id == cid, Capture.status == CaptureStatus.queued)
                    .values(
                        status=CaptureStatus.processing,
                        worker=self.name,
                        heartbeat_at=now,
                        started_at=now,
                        progress=0.0,
                        error=None,
                        cancel_requested=False,
                    )
                    .execution_options(synchronize_session=False)
                )
                if res.rowcount == 1:
                    self._touch_engagement(db, cid)
                    db.commit()
                    return cid
                db.rollback()
        return None

    def run_once(self) -> bool:
        """Claim and process one capture. Returns False if the queue was empty."""
        cid = self.claim()
        if cid is None:
            return False
        self.process(cid)
        return True

    # ── one job ───────────────────────────────────────────────────────────
    def process(self, cid: int) -> None:
        with self.sf() as db:
            cap = db.get(Capture, cid)
            eid, path = cap.engagement_id, self.storage.capture_file(cap.engagement_id, cid, cap.file_name)

        state = {"cancel": False, "last_check": 0.0, "last_progress": 0.0}
        hb_stop = threading.Event()

        def heartbeat():
            while not hb_stop.wait(HEARTBEAT_S):
                with self.sf() as db:
                    db.execute(
                        update(Capture)
                        .where(Capture.id == cid)
                        .values(heartbeat_at=utcnow())
                        .execution_options(synchronize_session=False)
                    )
                    db.commit()

        def should_cancel() -> bool:
            if self._stop.is_set():
                return True
            now = time.monotonic()
            if now - state["last_check"] >= PROGRESS_EVERY_S:
                state["last_check"] = now
                with self.sf() as db:
                    state["cancel"] = bool(
                        db.scalar(select(Capture.cancel_requested).where(Capture.id == cid))
                    )
            return state["cancel"]

        def progress(fed: int, total: int, _packets: int) -> None:
            now = time.monotonic()
            if total and now - state["last_progress"] >= PROGRESS_EVERY_S:
                state["last_progress"] = now
                with self.sf() as db:
                    db.execute(
                        update(Capture)
                        .where(Capture.id == cid)
                        .values(progress=min(0.99, fed / total), heartbeat_at=utcnow())
                        .execution_options(synchronize_session=False)
                    )
                    self._touch_engagement(db, cid)
                    db.commit()

        hb = threading.Thread(target=heartbeat, daemon=True)
        hb.start()
        try:
            result = analyze_capture(
                path,
                tshark_path=self.settings.tshark_path,
                workers=self.settings.analysis_workers,
                progress=progress,
                should_cancel=should_cancel,
                files_dir=self.storage.files_dir(eid),
            )
            error = None
        except CaptureError as exc:
            result, error = None, str(exc)
        except Exception as exc:  # noqa: BLE001 - recorded on the capture, shown to the user
            log.exception("analysis of capture %s failed", cid)
            result, error = None, f"Analysis failed unexpectedly: {exc.__class__.__name__}"
        finally:
            hb_stop.set()
            hb.join()

        with self.sf() as db:
            cap = db.get(Capture, cid)
            if cap is None:  # deleted while running
                return
            if self._stop.is_set():
                self._requeue(db, cap)  # shutting down: someone will pick it up again
            elif state["cancel"] or cap.cancel_requested:
                cap.status, cap.progress, cap.error = CaptureStatus.cancelled, 0.0, None
            elif error is not None:
                cap.status, cap.error = CaptureStatus.failed, error
            else:
                self._write_result(eid, cid, result)
                cap.status, cap.progress, cap.error = CaptureStatus.done, 1.0, None
                cap.summary = summarize(result)
                cap.engine_version = __version__
                self._merge_assets(db, cap, result)
            cap.finished_at = utcnow() if cap.status != CaptureStatus.queued else None
            cap.worker = None
            self._touch_engagement(db, cid)
            db.commit()

    @staticmethod
    def _merge_assets(db: Session, cap: Capture, result: AnalysisResult) -> None:
        """Fold the capture's hosts into the asset inventory, in the same transaction as 'done'.

        A failure here must not lose the analysis: it's logged and retried at the next start.
        """
        try:
            with db.begin_nested():
                asset_merge.ingest_capture(db, cap, result)
        except Exception:  # noqa: BLE001
            log.exception("merging capture %s into assets failed", cap.id)
            cap.assets_merged_at = None

    def _write_result(self, eid: int, cid: int, result: AnalysisResult) -> None:
        dest = self.storage.result_path(eid, cid)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        with gzip.open(tmp, "wb", compresslevel=6) as fh:
            fh.write(result.model_dump_json().encode())
        tmp.replace(dest)  # atomic: readers never see half a file

    @staticmethod
    def _requeue(db: Session, cap: Capture) -> None:
        cap.status, cap.progress, cap.worker, cap.heartbeat_at, cap.started_at = (
            CaptureStatus.queued,
            0.0,
            None,
            None,
            None,
        )

    @staticmethod
    def _touch_engagement(db: Session, cid: int) -> None:
        eid = db.scalar(select(Capture.engagement_id).where(Capture.id == cid))
        eng = db.get(Engagement, eid) if eid else None
        if eng is not None:
            eng.touch()


def result_file(storage: Storage, cap: Capture) -> Path:
    return storage.result_path(cap.engagement_id, cap.id)
