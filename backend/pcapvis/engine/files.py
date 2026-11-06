"""Extract transferred files with Wireshark's object export (HTTP, SMB, FTP-data, TFTP, IMF)."""

import hashlib
import os
import shutil
import subprocess  # noqa: S404
import tempfile
from dataclasses import dataclass
from pathlib import Path

EXPORT_TYPES = ("http", "smb", "ftp-data", "tftp", "imf")
# Protocols in frame.protocols that mean an export pass is worth running.
TRIGGER_PROTOCOLS = {"http", "smb", "smb2", "ftp-data", "tftp", "imf"}
MAX_FILES = 500

MAGIC = (
    (b"MZ", "application/x-msdownload"),
    (b"\x7fELF", "application/x-elf"),
    (b"PK\x03\x04", "application/zip"),
    (b"%PDF", "application/pdf"),
    (b"Rar!", "application/x-rar"),
    (b"7z\xbc\xaf", "application/x-7z-compressed"),
    (b"\x1f\x8b", "application/gzip"),
    (b"\xd0\xcf\x11\xe0", "application/x-ole-storage"),
    (b"\x89PNG", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"<?xml", "application/xml"),
    (b"{", "application/json"),
    (b"<!DOCTYPE html", "text/html"),
    (b"<html", "text/html"),
)
# Extensions consultants care about: executables, scripts, archives, documents, PLC/HMI projects.
INTERESTING_EXT = {
    "exe",
    "dll",
    "msi",
    "scr",
    "ps1",
    "bat",
    "cmd",
    "vbs",
    "js",
    "jar",
    "apk",
    "elf",
    "sh",
    "bin",
    "img",
    "zip",
    "7z",
    "rar",
    "gz",
    "tar",
    "cab",
    "iso",
    "doc",
    "docx",
    "docm",
    "xls",
    "xlsx",
    "xlsm",
    "ppt",
    "pptx",
    "pdf",
    "rtf",
    "s7p",
    "ap11",
    "ap13",
    "ap14",
    "ap15",
    "ap16",
    "ap17",
    "ap18",
    "ap19",
    "zap15",
    "zap16",
    "zap17",
    "acd",
    "l5x",
    "l5k",
    "rss",
    "rsp",
    "mer",
    "apa",
    "gxw",
    "gx3",
    "cxp",
    "stu",
    "sta",
    "xef",
    "zef",
    "project",
    "pro",
    "ccwsln",
    "wsp",
    "cfg",
    "conf",
    "hex",
    "fw",
    "upd",
}
INTERESTING_MIME = {
    "application/x-msdownload",
    "application/x-elf",
    "application/zip",
    "application/x-rar",
    "application/x-7z-compressed",
    "application/x-ole-storage",
    "application/pdf",
}


@dataclass
class ExtractedFile:
    protocol: str
    filename: str
    size: int
    sha256: str
    mime: str
    interesting: bool
    stored_path: str | None = None


def sniff_mime(head: bytes) -> str:
    stripped = head.lstrip()
    for magic, mime in MAGIC:
        if head.startswith(magic) or stripped.startswith(magic):
            return mime
    try:
        head.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def extract_files(
    path: Path, tshark_path: str = "tshark", store_dir: Path | None = None
) -> list[ExtractedFile]:
    """Run one tshark export pass; hash every object; optionally keep them in store_dir/<sha256>."""
    out: list[ExtractedFile] = []
    # tshark may only write under /tmp (AppArmor), so export there and move afterwards.
    with tempfile.TemporaryDirectory(prefix="pcapvis-objects-") as tmp:
        args = [tshark_path, "-r", "-", "-n", "-q"]
        for t in EXPORT_TYPES:
            os.makedirs(os.path.join(tmp, t))
            args += ["--export-objects", f"{t},{os.path.join(tmp, t)}"]
        with open(path, "rb") as fh:
            subprocess.run(args, stdin=fh, capture_output=True, timeout=3600, check=False)  # noqa: S603
        for proto in EXPORT_TYPES:
            d = Path(tmp) / proto
            for f in sorted(d.iterdir()):
                if len(out) >= MAX_FILES or not f.is_file():
                    continue
                data = f.read_bytes()
                if not data:
                    continue
                sha = hashlib.sha256(data).hexdigest()
                mime = sniff_mime(data[:64])
                ext = f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
                stored = None
                if store_dir is not None:
                    store_dir.mkdir(parents=True, exist_ok=True)
                    target = store_dir / sha
                    if not target.exists():
                        shutil.move(str(f), target)
                    stored = str(target)
                out.append(
                    ExtractedFile(
                        protocol=proto.upper(),
                        filename=f.name,
                        size=len(data),
                        sha256=sha,
                        mime=mime,
                        interesting=ext in INTERESTING_EXT or mime in INTERESTING_MIME,
                        stored_path=stored,
                    )
                )
    # Same file seen twice (e.g. retransmitted download): keep one per (protocol, hash, name).
    seen, unique = set(), []
    for f in out:
        key = (f.protocol, f.sha256, f.filename)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
