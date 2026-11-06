"""Detect tshark (Wireshark's CLI dissector) and check it meets the minimum version."""
import platform
import re
import shutil
import subprocess  # noqa: S404 - we only run the configured tshark binary with fixed args
from dataclasses import asdict, dataclass

_VERSION_RE = re.compile(r"TShark \(Wireshark\) (\d+)\.(\d+)\.(\d+)")

INSTALL_HINTS = {
    "Linux": "Debian/Ubuntu/Kali: sudo apt install tshark   ·   Fedora/RHEL: sudo dnf install wireshark-cli",
    "Darwin": "macOS: brew install wireshark",
    "Windows": "Windows: install Wireshark from https://www.wireshark.org/download.html "
    "(or: winget install WiresharkFoundation.Wireshark) and add it to PATH",
}
CONTAINER_HINT = "Or run the container image, which includes tshark: docker run -p 8080:8080 pcapvis"


@dataclass(frozen=True)
class TsharkStatus:
    ok: bool
    path: str | None
    version: str | None
    min_version: str
    message: str

    def as_dict(self) -> dict:
        return asdict(self)


def parse_version(text: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.search(text)
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def install_hint() -> str:
    return f"{INSTALL_HINTS.get(platform.system(), INSTALL_HINTS['Linux'])}\n{CONTAINER_HINT}"


def check_tshark(tshark_path: str = "tshark", min_version: str = "4.0.0") -> TsharkStatus:
    path = shutil.which(tshark_path)
    if not path:
        return TsharkStatus(False, None, None, min_version, f"tshark not found ('{tshark_path}').")
    try:
        out = subprocess.run(  # noqa: S603
            [path, "--version"], capture_output=True, text=True, timeout=15, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        return TsharkStatus(False, path, None, min_version, f"Could not run tshark: {exc}")
    found = parse_version(out)
    if not found:
        return TsharkStatus(False, path, None, min_version, "Could not read the tshark version.")
    version = ".".join(map(str, found))
    if found < _version_tuple(min_version):
        return TsharkStatus(
            False, path, version, min_version, f"tshark {version} is too old; {min_version}+ is required."
        )
    return TsharkStatus(True, path, version, min_version, f"tshark {version}")
