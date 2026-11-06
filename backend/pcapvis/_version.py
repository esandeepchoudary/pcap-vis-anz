"""App version. The repo-root VERSION file is the single source of truth."""

from importlib import metadata
from pathlib import Path


def _find_version() -> str:
    # Source checkout / container: walk up from this file to find VERSION.
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "VERSION"
        if candidate.is_file():
            return candidate.read_text().strip()
    # Installed wheel: version was baked into package metadata at build time.
    try:
        return metadata.version("pcapvis")
    except metadata.PackageNotFoundError:
        return "0.0.0"


__version__ = _find_version()
