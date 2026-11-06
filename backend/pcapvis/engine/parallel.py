"""Parallel analysis: split by host pair, aggregate partitions in worker processes, merge.

1. The capture is split into N partition files by host pair (fast, sequential I/O).
2. N workers (tshark + decode + aggregate) run fully independently, one per partition.
3. Their aggregators are merged. Because the Aggregator is order-independent (see aggregate.py),
   the result equals a single-process analysis of the same capture.
"""

import os
import pickle  # noqa: S403 - results come from our own worker processes
import shutil
import signal
import subprocess  # noqa: S404
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path

from pcapvis.engine.aggregate import Aggregator
from pcapvis.engine.runner import CaptureError, ProgressFn, RunStats
from pcapvis.engine.split import split
from pcapvis.engine.tshark_env import TsharkEnv

POLL_S = 0.2


class _Stop(Exception):
    pass


def analyze_parallel(
    path: Path,
    env: TsharkEnv,
    tshark_path: str,
    workers: int,
    *,
    partitions: int | None = None,
    max_packets: int | None = None,
    progress: ProgressFn | None = None,
    should_cancel: Callable[[], bool] | None = None,
    stats: RunStats,
    scratch_dir: Path | None = None,
) -> Aggregator:
    stats.bytes_total = os.path.getsize(path)
    work = Path(tempfile.mkdtemp(prefix="pcapvis-split-", dir=scratch_dir))
    try:
        env_path = work / "env.pickle"
        env_path.write_bytes(pickle.dumps(env, protocol=5))

        # ── 1. split ─────────────────────────────────────────────────────────
        # More partitions than workers keeps each tshark's memory bounded (it grows with packets).
        n_parts = max(workers, partitions or 0)
        part_paths = [work / f"part{i}.cap" for i in range(n_parts)]
        part_files = [open(p, "wb") for p in part_paths]  # noqa: SIM115 - closed in finally below
        routed = 0

        class Counting:
            def __init__(self, f):
                self.f = f

            def read(self, n=-1):
                data = self.f.read(n)
                stats.bytes_fed += len(data)
                return data

        def on_packet(_i: int) -> None:
            nonlocal routed
            routed += 1
            if should_cancel and routed % 5000 == 0 and should_cancel():
                stats.stopped_early = True
                raise _Stop
            if max_packets and routed >= max_packets:
                raise _Stop

        try:
            with open(path, "rb") as fh:
                split(Counting(fh), [f.write for f in part_files], on_packet=on_packet)
        except _Stop:
            pass
        finally:
            for f in part_files:
                f.close()
        if stats.stopped_early:
            return Aggregator(env)

        # ── 2. workers: a pool of `workers` processes over the partitions ───────
        sizes = [p.stat().st_size for p in part_paths]
        procs: dict[int, subprocess.Popen] = {}
        outputs: dict[int, bytes] = {}
        errors: list[str] = []
        threads: list[threading.Thread] = []
        pending = sorted(range(n_parts), key=lambda i: -sizes[i])  # biggest first: better packing

        def launch(i: int) -> None:
            with open(part_paths[i], "rb") as stdin:
                procs[i] = subprocess.Popen(  # noqa: S603
                    [sys.executable, "-m", "pcapvis.engine.worker", str(env_path), tshark_path],
                    stdin=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            def collect():
                outputs[i] = procs[i].stdout.read()

            def collect_err():
                text = procs[i].stderr.read().decode("utf-8", "replace").strip()
                if text:
                    errors.append(text[-2000:])

            for target in (collect, collect_err):
                t = threading.Thread(target=target, daemon=True)
                t.start()
                threads.append(t)

        finished: set[int] = set()
        while len(finished) < n_parts:
            running = [i for i in procs if i not in finished]
            while pending and len(running) < workers and not stats.stopped_early:
                launch(pending[0])
                running.append(pending.pop(0))
            for i in running:
                if procs[i].poll() is not None:
                    finished.add(i)
                    if progress:
                        done = sum(sizes[j] for j in finished)
                        progress(int(stats.bytes_total * done / max(sum(sizes), 1)), stats.bytes_total, 0)
            if stats.stopped_early and not [i for i in procs if i not in finished]:
                break  # cancelled: don't start the remaining partitions
            if len(finished) == n_parts:
                break
            if should_cancel and not stats.stopped_early and should_cancel():
                stats.stopped_early = True
                for i, p in procs.items():
                    if i not in finished and p.poll() is None:
                        p.send_signal(signal.SIGTERM)  # workers return what they have so far
            time.sleep(POLL_S)
        for t in threads:
            t.join()

        # ── 3. merge ─────────────────────────────────────────────────────────
        merged: Aggregator | None = None
        tshark_failed: list[str] = []
        for i in sorted(outputs):
            data = outputs[i]
            if procs[i].returncode != 0 or not data:
                raise CaptureError("analysis worker failed: " + ("; ".join(errors) or "no output"))
            agg, tshark_rc, tshark_errors = pickle.loads(data)  # noqa: S301
            stats.stderr.extend(e for e in tshark_errors if e not in stats.stderr)
            if tshark_rc not in (0, None, -9) and sizes[i] > 64:
                tshark_failed.extend(tshark_errors or [f"tshark exit code {tshark_rc}"])
            if merged is None:
                merged = agg
            else:
                merged.merge(agg)
        if merged is None:  # cancelled before any worker started
            merged = Aggregator()
        merged.env = env
        if merged.packets == 0 and tshark_failed:
            raise CaptureError("tshark could not read this capture: " + "; ".join(tshark_failed))
        stats.packets = merged.packets
        if progress:
            progress(stats.bytes_total, stats.bytes_total, stats.packets)
        return merged
    finally:
        shutil.rmtree(work, ignore_errors=True)
