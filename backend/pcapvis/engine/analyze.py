"""Analyse one capture file: tshark → packets → aggregate → result."""

import os
from collections.abc import Callable
from pathlib import Path

from pcapvis.engine.aggregate import Aggregator
from pcapvis.engine.files import TRIGGER_PROTOCOLS, extract_files
from pcapvis.engine.model import AnalysisResult, ArpClaim, CaptureSummary, FileTransfer, VlanStat
from pcapvis.engine.packet import decode
from pcapvis.engine.parallel import analyze_parallel
from pcapvis.engine.rules import run_rules
from pcapvis.engine.runner import ProgressFn, RunStats, stream_packets
from pcapvis.engine.split import capture_format
from pcapvis.engine.tshark_env import load_env
from pcapvis.tshark import check_tshark

DEFAULT_MAX_PACKETS = 5_000_000
PARALLEL_MIN_BYTES = 32 * 1024 * 1024  # below this, one tshark is fast enough and small enough
PARTITION_TARGET_BYTES = 64 * 1024 * 1024  # tshark memory grows ~1.5 KB/packet; keep partitions modest
MAX_WORKERS = 8


def choose_plan(path: Path, requested_workers: int | None) -> tuple[int, int]:
    """Return (workers, partitions). (1, 1) means a single tshark over the whole file."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        splittable = capture_format(fh.read(4)) in ("pcap", "pcapng")
    if not splittable:
        return 1, 1
    if requested_workers is not None:
        workers = max(1, requested_workers)
    elif size < PARALLEL_MIN_BYTES:
        return 1, 1
    else:
        # Half the hardware threads ≈ physical cores; tshark gains little from hyper-threads.
        workers = max(1, min((os.cpu_count() or 2) // 2, MAX_WORKERS))
    partitions = max(workers, -(-size // PARTITION_TARGET_BYTES))
    return workers, (partitions if workers > 1 or partitions > 1 else 1)


def analyze_capture(
    path: Path | str,
    *,
    tshark_path: str = "tshark",
    max_packets: int = DEFAULT_MAX_PACKETS,
    progress: ProgressFn | None = None,
    should_cancel: Callable[[], bool] | None = None,
    extract_objects: bool = True,
    files_dir: Path | None = None,
    workers: int | None = None,
) -> AnalysisResult:
    """Analyse a capture. ``workers`` = number of tshark processes (None = automatic by file size)."""
    path = Path(path)
    env = load_env(tshark_path)
    stats = RunStats()
    agg = Aggregator(env)
    n_workers, n_parts = choose_plan(path, workers)
    kw = dict(max_packets=max_packets, progress=progress, should_cancel=should_cancel, stats=stats)
    if n_parts > 1:
        agg = analyze_parallel(path, env, tshark_path, n_workers, partitions=n_parts, **kw)
    else:
        for layers in stream_packets(path, env.fields, tshark_path, **kw):
            agg.add(decode(layers))
    hosts, flows = agg.finish()

    files: list[FileTransfer] = []
    if extract_objects and not stats.stopped_early and agg.app_protocols_seen & TRIGGER_PROTOCOLS:
        urls = {uri.rsplit("/", 1)[-1].split("?")[0]: uri for uri in agg.notes.request_uris}
        for f in extract_files(path, tshark_path, files_dir):
            files.append(
                FileTransfer(
                    protocol=f.protocol,
                    filename=f.filename,
                    size=f.size,
                    sha256=f.sha256,
                    mime=f.mime,
                    interesting=f.interesting,
                    source_url=urls.get(f.filename),
                    stored_path=f.stored_path,
                )
            )

    warnings = list(stats.stderr)
    if env.missing_fields:
        warnings.append("This tshark lacks some fields (older Wireshark?): " + ", ".join(env.missing_fields))
    summary = CaptureSummary(
        file_name=path.name,
        file_size=stats.bytes_total,
        packets=agg.packets,
        bytes=agg.bytes,
        first_seen=agg.first_ts,
        last_seen=agg.last_ts,
        link_types=[k for k, _ in agg.link_types.most_common()],
        malformed_packets=agg.malformed,
        truncated=agg.packets >= max_packets or stats.stopped_early,
        tshark_version=check_tshark(tshark_path).version,
        warnings=warnings,
    )
    result = AnalysisResult(
        capture=summary,
        hosts=hosts,
        flows=flows,
        ot_commands=agg.ot_commands,
        ot_commands_truncated=agg.ot_truncated,
        credentials=agg.credentials,
        files=files,
        vlan_stats=[
            VlanStat(vlan=v, packets=n, broadcast=agg.vlan_broadcast.get(v, 0))
            for v, n in sorted(agg.vlan_packets.items(), key=lambda kv: (kv[0] is None, kv[0] or 0))
        ],
        arp_claims=[
            ArpClaim(vlan=vlan, ip=ip, macs=sorted(macs))
            for (vlan, ip), macs in sorted(agg.arp_claims.items(), key=lambda kv: (str(kv[0][0]), kv[0][1]))
        ],
    )
    result.anomalies = run_rules(result)
    return result
