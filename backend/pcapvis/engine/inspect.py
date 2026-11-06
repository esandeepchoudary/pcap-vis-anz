"""On-demand packet inspection with tshark: list packets matching a display filter, decode one (M7).

Like the analysis engine, the capture is fed through stdin (tshark's AppArmor profile blocks most paths).
Filters are passed as one argument (no shell) and validated by tshark itself; run time and output are capped.
"""

import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

LIST_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "_ws.col.def_src",
    "_ws.col.def_dst",
    "_ws.col.protocol",
    "frame.len",
    "_ws.col.info",
)
MAX_FILTER = 500
MAX_DETAIL_BYTES = 512 * 1024
CHUNK = 1 << 20


class InspectError(Exception):
    """Bad filter or unreadable capture (message is safe to show)."""


@dataclass
class PacketRow:
    number: int
    time: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str


def _feed(proc: subprocess.Popen, path: Path) -> None:
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(CHUNK):
                proc.stdin.write(chunk)
    except (BrokenPipeError, OSError):
        pass  # tshark stopped reading (we killed it after enough output)
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass


def _run(tshark: str, path: Path, args: list[str], *, max_lines: int | None, max_bytes: int, timeout: float):
    exe = shutil.which(tshark) or tshark
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [exe, "-r", "-", "-n", *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    feeder = threading.Thread(target=_feed, args=(proc, path), daemon=True)
    feeder.start()
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    out, lines, truncated = bytearray(), 0, False
    try:
        for line in proc.stdout:
            if (max_lines is not None and lines >= max_lines) or len(out) + len(line) > max_bytes:
                truncated = True
                proc.kill()
                break
            out += line
            lines += 1
        err = proc.stderr.read().decode("utf-8", "replace")
        code = proc.wait()
    finally:
        timer.cancel()
    timed_out = code == -9 and not truncated
    if timed_out:
        raise InspectError("Inspection took too long; narrow the filter.")
    if code not in (0, -9) and not out:
        msg = err.strip().splitlines()[0] if err.strip() else f"tshark failed ({code})."
        raise InspectError(msg.removeprefix("tshark: ")[:300])
    return out.decode("utf-8", "replace"), truncated


def check_filter(display_filter: str) -> str:
    f = display_filter.strip()
    if len(f) > MAX_FILTER or any(c in f for c in "\x00\r\n"):
        raise InspectError("Filter is too long or has line breaks.")
    return f


def list_packets(tshark: str, path: Path, display_filter: str, *, limit: int = 500, timeout: float = 60):
    f = check_filter(display_filter)
    args = (["-Y", f] if f else []) + ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for field in LIST_FIELDS:
        args += ["-e", field]
    text, truncated = _run(tshark, path, args, max_lines=limit, max_bytes=8 * 1024 * 1024, timeout=timeout)
    rows = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < len(LIST_FIELDS) or not parts[0].isdigit():
            continue
        try:
            rows.append(
                PacketRow(
                    int(parts[0]),
                    float(parts[1] or 0),
                    parts[2],
                    parts[3],
                    parts[4],
                    int(parts[5] or 0),
                    "\t".join(parts[6:]).strip()[:500],
                )
            )
        except ValueError:
            continue
    return rows, truncated


def packet_detail(tshark: str, path: Path, number: int, *, timeout: float = 60) -> str:
    """Full decode (and hex dump) of one frame. Stops reading the capture right after it."""
    if number < 1:
        raise InspectError("Packet numbers start at 1.")
    args = ["-c", str(number), "-Y", f"frame.number=={number}", "-V", "-x"]
    text, truncated = _run(tshark, path, args, max_lines=None, max_bytes=MAX_DETAIL_BYTES, timeout=timeout)
    if not text.strip():
        raise InspectError(f"No packet {number} in this capture.")
    return text + ("\n… (truncated)" if truncated else "")
