"""Run tshark over a capture and stream decoded packets.

The capture is fed through stdin rather than passed as a path: tshark's AppArmor profile on
Ubuntu/Debian only lets it open files under /tmp, while stdin works for any file the app can read.
Feeding stdin from a thread also gives byte-accurate progress.
"""

import os
import subprocess  # noqa: S404
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import orjson

from pcapvis.engine.fields import ek_name

CHUNK = 1 << 20


class CaptureError(Exception):
    """tshark couldn't read the capture (message is safe to show)."""


@dataclass
class RunStats:
    bytes_total: int = 0
    bytes_fed: int = 0
    packets: int = 0
    stderr: list[str] = field(default_factory=list)
    stopped_early: bool = False


ProgressFn = Callable[[int, int, int], None]  # (bytes_fed, bytes_total, packets)


def stream_packets(
    path: Path,
    fields: list[str],
    tshark_path: str = "tshark",
    *,
    max_packets: int | None = None,
    progress: ProgressFn | None = None,
    should_cancel: Callable[[], bool] | None = None,
    stats: RunStats | None = None,
) -> Iterator[dict[str, list[str]]]:
    """Yield one ``{ek_field_name: [values...]}`` dict per packet."""
    stats = stats if stats is not None else RunStats()
    stats.bytes_total = os.path.getsize(path)
    # Sequence analysis off: dissect every segment as captured. With it on, tshark skips the payload of
    # segments it considers out-of-order, which hides credentials and PLC commands in SPAN captures with
    # reordering. Retransmissions are de-duplicated by the aggregator instead (see Aggregator.add).
    args = [tshark_path, "-r", "-", "-n", "-T", "ek", "-l", "-o", "tcp.analyze_sequence_numbers:FALSE"]
    if max_packets:
        args += ["-c", str(max_packets)]
    for f in fields:
        args += ["-e", f]

    proc = subprocess.Popen(  # noqa: S603
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=CHUNK
    )

    def feed():
        try:
            with open(path, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    proc.stdin.write(chunk)
                    stats.bytes_fed += len(chunk)
        except (BrokenPipeError, ValueError, OSError):
            pass  # tshark stopped reading (-c limit, cancel, or error)
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def drain_stderr():
        for line in proc.stderr:
            text = line.decode("utf-8", "replace").strip()
            if text and len(stats.stderr) < 50:
                stats.stderr.append(text)

    feeder = threading.Thread(target=feed, daemon=True)
    err_reader = threading.Thread(target=drain_stderr, daemon=True)
    feeder.start()
    err_reader.start()

    try:
        for line in proc.stdout:
            if line.startswith(b'{"index"'):
                continue
            try:
                doc = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            layers = doc.get("layers")
            if layers is None:
                continue
            stats.packets += 1
            yield layers
            if progress and stats.packets % 5000 == 0:
                progress(stats.bytes_fed, stats.bytes_total, stats.packets)
            if should_cancel and stats.packets % 1000 == 0 and should_cancel():
                stats.stopped_early = True
                break
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        feeder.join(timeout=5)
        err_reader.join(timeout=5)

    # A valid but empty capture is fine; an unreadable one makes tshark exit non-zero.
    if stats.packets == 0 and not stats.stopped_early and proc.returncode not in (0, -9):
        detail = "; ".join(stats.stderr) or f"exit code {proc.returncode}"
        raise CaptureError(f"tshark could not read this capture: {detail}")
    if progress:
        progress(stats.bytes_fed, stats.bytes_total, stats.packets)


def ek_fields_map(fields: list[str]) -> dict[str, str]:
    """Map EK key → original field name."""
    return {ek_name(f): f for f in fields}
