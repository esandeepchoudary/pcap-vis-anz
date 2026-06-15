# Application Logic Review

Date: 2026-06-15

## Findings

### High: Purdue cross-zone highlighting is broken in the main graph

- Location: `static/js/app.js:2436`
- Issue: `renderGraph()` builds `_pLevel` with `purdueLevel(n.host_type)`, but `purdueLevel()` expects a full node object.
- Impact: Every node gets Purdue level `-1` in this path, so cross-zone edge classes and colors are not applied in the main graph.
- Suggested fix: Use `n.purdue_level ?? purdueLevel(n)` when building `_pLevel`.

### Medium: OT Log can keep stale filter buttons after loading a capture with zero OT commands

- Location: `static/js/app.js:6891`
- Issue: `renderOtLog()` returns early for empty command lists without clearing `#otlog-filter-protos` or `#otlog-filter-dirs`.
- Impact: Filter buttons from a previous dataset can remain visible even though the current capture has no OT commands.
- Suggested fix: Clear both filter bars before the early return, or rebuild them into the empty state.

### Medium: Concurrent uploads can invalidate captured file downloads globally

- Location: `app.py:3527`
- Issue: `/upload` clears the shared `_file_body_cache` at the start of every upload.
- Impact: If another upload starts, existing `/download/<sha256>` links from a prior result can return 404 or be replaced.
- Suggested fix: Scope cached file bodies per upload/session, for example by keying downloads with an upload id plus hash.

### Medium: Timed-out parse tasks continue running in the worker pool

- Location: `app.py:3564`
- Issue: `future.result(timeout=...)` reports a timeout or failure to the request, but the submitted worker task can continue running.
- Impact: Repeated slow or stuck parses can occupy all four shared workers after requests have already returned.
- Suggested fix: Attempt `future.cancel()` for pending work and consider per-request process isolation for hard cancellation of active parses.

### Low: IPv6 extension headers are not parsed

- Location: `app.py:2316`, `app.py:2320`
- Issue: The parser reads the IPv6 `next header` field once and uses a fixed 40-byte IPv6 header offset.
- Impact: TCP/UDP ports and protocol labels are missed when IPv6 packets include extension headers such as hop-by-hop, routing, destination options, or fragments.
- Suggested fix: Traverse supported IPv6 extension headers before transport parsing, with bounds checks and a small hop limit.

## Verification

- `python -m pytest tests/ -q`: 336 passed, 4 warnings. This required elevated execution because Scapy imports inspect local network interfaces.
- `node --check static/js/app.js`: passed.
- `python -m pytest tests/test_frontend_findings_static.py -q`: 4 passed.
