"""Where engagement data lives on disk.

<data_dir>/engagements/<id>/
    captures/<capture id>/<original file name>   original pcaps, untouched (evidence)
    results/<capture id>.json.gz                  analysis result
    files/<sha256>                                files extracted from traffic
"""

import re
import shutil
from pathlib import Path

_UNSAFE = re.compile(r"[^A-Za-z0-9._ -]+")


def safe_filename(name: str) -> str:
    """Keep a readable original name without any path components or odd characters."""
    base = Path(name.replace("\\", "/")).name.strip()
    base = _UNSAFE.sub("_", base).strip(" .")
    return (base or "capture")[:200]


class Storage:
    def __init__(self, data_dir: Path):
        self.root = Path(data_dir) / "engagements"

    def engagement_dir(self, eid: int) -> Path:
        return self.root / str(int(eid))

    def capture_dir(self, eid: int, cid: int) -> Path:
        return self.engagement_dir(eid) / "captures" / str(int(cid))

    def capture_file(self, eid: int, cid: int, file_name: str) -> Path:
        return self.capture_dir(eid, cid) / safe_filename(file_name)

    def result_path(self, eid: int, cid: int) -> Path:
        return self.engagement_dir(eid) / "results" / f"{int(cid)}.json.gz"

    def files_dir(self, eid: int) -> Path:
        return self.engagement_dir(eid) / "files"

    def delete_engagement(self, eid: int) -> None:
        shutil.rmtree(self.engagement_dir(eid), ignore_errors=True)

    def delete_capture(self, eid: int, cid: int) -> None:
        shutil.rmtree(self.capture_dir(eid, cid), ignore_errors=True)
        self.result_path(eid, cid).unlink(missing_ok=True)
