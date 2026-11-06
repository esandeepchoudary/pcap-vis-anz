"""Analyse one capture file: tshark → packets → aggregate → result."""

from collections.abc import Callable
from pathlib import Path

from pcapvis.engine.aggregate import Aggregator
from pcapvis.engine.files import TRIGGER_PROTOCOLS, extract_files
from pcapvis.engine.model import AnalysisResult, CaptureSummary, FileTransfer
from pcapvis.engine.packet import decode
from pcapvis.engine.runner import ProgressFn, RunStats, stream_packets
from pcapvis.engine.tshark_env import load_env
from pcapvis.tshark import check_tshark

DEFAULT_MAX_PACKETS = 5_000_000


def analyze_capture(
    path: Path | str,
    *,
    tshark_path: str = "tshark",
    max_packets: int = DEFAULT_MAX_PACKETS,
    progress: ProgressFn | None = None,
    should_cancel: Callable[[], bool] | None = None,
    extract_objects: bool = True,
    files_dir: Path | None = None,
) -> AnalysisResult:
    path = Path(path)
    env = load_env(tshark_path)
    stats = RunStats()
    agg = Aggregator(env)
    for layers in stream_packets(
        path,
        env.fields,
        tshark_path,
        max_packets=max_packets,
        progress=progress,
        should_cancel=should_cancel,
        stats=stats,
    ):
        agg.add(decode(layers))
    hosts, flows = agg.finish()

    files: list[FileTransfer] = []
    if extract_objects and not stats.stopped_early and agg.app_protocols_seen & TRIGGER_PROTOCOLS:
        urls = {uri.rsplit("/", 1)[-1].split("?")[0]: uri for uri in agg.notes.request_uri.values()}
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
    return AnalysisResult(
        capture=summary,
        hosts=hosts,
        flows=flows,
        ot_commands=agg.ot_commands,
        ot_commands_truncated=agg.ot_truncated,
        credentials=sorted(agg.credentials.values(), key=lambda c: c.first_seen),
        files=files,
    )
