#!/usr/bin/env python3
"""Exit non-zero unless VERSION is strictly greater than the base version.

Usage: python scripts/check_version_bump.py <base_version> [<head_version>]
(head defaults to the VERSION file). Used by CI on pull requests.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bump_version import VERSION_FILE, parse  # noqa: E402


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    base = argv[0].strip()
    head = argv[1].strip() if len(argv) > 1 else VERSION_FILE.read_text().strip()
    if parse(head) > parse(base):
        print(f"OK: version bumped {base} -> {head}")
        return 0
    print(f"ERROR: VERSION is {head}, which is not higher than {base} on the base branch.\n"
          f'Run: python scripts/bump_version.py <major|minor|patch> "summary"')
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
