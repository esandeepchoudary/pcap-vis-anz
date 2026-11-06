"""Worker process for parallel analysis: tshark + decode + aggregate one host-pair partition.

Run as ``python -m pcapvis.engine.worker <env.pickle> <tshark>``. The partition (a valid pcap/pcapng
stream) arrives on stdin and is handed straight to tshark; the pickled Aggregator goes to stdout.
"""

import pickle  # noqa: S403 - parent and worker are the same trusted program
import signal
import subprocess  # noqa: S404
import sys
import threading

import orjson

from pcapvis.engine.aggregate import Aggregator
from pcapvis.engine.packet import decode


def main(env_path: str, tshark_path: str) -> int:
    with open(env_path, "rb") as fh:
        env = pickle.load(fh)  # noqa: S301
    args = [tshark_path, "-r", "-", "-n", "-T", "ek", "-o", "tcp.analyze_sequence_numbers:FALSE"]
    for f in env.fields:
        args += ["-e", f]
    # tshark reads our stdin directly: no copying through Python.
    proc = subprocess.Popen(args, stdin=sys.stdin.buffer, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603
    errors: list[str] = []

    def drain():
        for line in proc.stderr:
            if len(errors) < 50:
                errors.append(line.decode("utf-8", "replace").strip())

    t = threading.Thread(target=drain, daemon=True)
    t.start()

    # SIGTERM = "stop now": end tshark and still return what was aggregated so far (cancel support).
    def stop(_sig, _frame):
        if proc.poll() is None:
            proc.kill()

    signal.signal(signal.SIGTERM, stop)
    agg = Aggregator(env)
    for line in proc.stdout:
        if line.startswith(b'{"index"'):
            continue
        try:
            layers = orjson.loads(line).get("layers")
        except orjson.JSONDecodeError:
            continue
        if layers is not None:
            agg.add(decode(layers))
    proc.wait()
    t.join(timeout=5)
    agg.env = None  # the parent has it
    sys.stdout.buffer.write(pickle.dumps((agg, proc.returncode, [e for e in errors if e]), protocol=5))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
