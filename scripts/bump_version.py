#!/usr/bin/env python3
"""Increment the project version in VERSION and add a CHANGELOG.md entry.

Usage:
    python scripts/bump_version.py patch "Fix OT map label clipping"
    python scripts/bump_version.py minor "Add OT asset editor"
    python scripts/bump_version.py major "Change session file format"

patch = bug fixes / small tweaks, minor = new features (backward compatible),
major = breaking changes (e.g. session/project file format, /upload schema).
"""
import argparse
import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"
CHANGELOG_FILE = ROOT / "CHANGELOG.md"
MARKER = "<!-- next-entry -->"
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse(version):
    m = _SEMVER.match(version.strip())
    if not m:
        raise ValueError(f"Not a MAJOR.MINOR.PATCH version: {version!r}")
    return tuple(int(x) for x in m.groups())


def bump(version, part):
    major, minor, patch = parse(version)
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"Unknown bump part: {part!r}")


def add_changelog_entry(text, new_version, summary, date):
    entry = f"{MARKER}\n\n## v{new_version} -- {date}\n\n- {summary}\n"
    if MARKER not in text:
        raise ValueError(f"{CHANGELOG_FILE.name} is missing the {MARKER} marker")
    return text.replace(f"{MARKER}\n", entry, 1)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("part", choices=["major", "minor", "patch"])
    ap.add_argument("summary", help="One-line description of the change for CHANGELOG.md")
    args = ap.parse_args(argv)

    old = VERSION_FILE.read_text().strip()
    new = bump(old, args.part)
    today = datetime.date.today().isoformat()

    CHANGELOG_FILE.write_text(add_changelog_entry(CHANGELOG_FILE.read_text(), new, args.summary, today))
    VERSION_FILE.write_text(new + "\n")
    print(f"{old} -> {new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
