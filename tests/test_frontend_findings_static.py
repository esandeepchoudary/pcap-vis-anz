from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_findings_ui_markup_and_styles_exist():
    html = read("templates/index.html")
    css = read("static/css/style.css")

    assert 'data-view="findings"' in html
    assert 'id="findings-view"' in html
    assert 'id="text-modal"' in html
    assert "#findings-view" in css
    assert ".text-modal" in css


def test_findings_frontend_contract_is_wired():
    js = read("static/js/app.js")

    assert "function deriveFindings(data)" in js
    assert "function renderFindingsWorkspace()" in js
    assert "Curated Findings" in js
    assert "findings: findings || []" in js
    assert "initializeFindings(data)" in js


def test_blocking_prompt_calls_are_not_reintroduced():
    assert "prompt(" not in read("static/js/app.js")


def test_inline_event_handlers_are_not_reintroduced():
    js = read("static/js/app.js")

    assert "onclick=" not in js


def test_agents_instructions_are_available():
    agents = read("AGENTS.md")

    assert "## Branching" in agents
    assert "python -m pytest tests/ -q" in agents
    assert "Commit and push" in agents


# ── Fix 1: Purdue cross-zone highlighting uses full node object ────────────────

def test_purdue_level_lookup_uses_full_node_not_host_type_string():
    """renderGraph() must call purdueLevel(n) not purdueLevel(n.host_type)."""
    js = read("static/js/app.js")
    # The bad pattern that was the bug — must not appear
    assert "purdueLevel(n.host_type)" not in js, (
        "renderGraph() should not pass n.host_type (string) to purdueLevel(); "
        "use n.purdue_level ?? purdueLevel(n) instead"
    )
    # The correct pattern must be present
    assert "n.purdue_level ?? purdueLevel(n)" in js, (
        "renderGraph() should prefer the backend purdue_level with JS fallback"
    )


# ── Fix 2: OT Log empty path clears stale filter bars ────────────────────────

def test_otlog_empty_path_clears_filter_bars():
    """The empty-command early return in renderOtLog() must clear both filter bars."""
    js = read("static/js/app.js")
    # Find the renderOtLog function body up to and including the early return
    start = js.find("function renderOtLog(")
    assert start != -1, "renderOtLog not found in app.js"
    # The early-return block (before the non-empty path)
    early_return = js.find("return;", start)
    assert early_return != -1
    early_block = js[start:early_return]
    assert 'protoBar.innerHTML = ""' in early_block, (
        "renderOtLog() empty branch must clear protoBar before returning"
    )
    assert 'dirBar.innerHTML = ""' in early_block, (
        "renderOtLog() empty branch must clear dirBar before returning"
    )


def test_graph_payload_is_normalized_before_global_assignment():
    """Partial session/upload JSON should get safe defaults before helpers read graphData."""
    js = read("static/js/app.js")

    assert "function normalizeGraphPayload(data)" in js
    assert "data = normalizeGraphPayload(data);" in js

    normalizer_start = js.find("function normalizeGraphPayload(data)")
    load_start = js.find("function loadGraph(data)")
    assert normalizer_start != -1
    assert load_start != -1
    normalizer = js[normalizer_start:load_start]

    for field in (
        "nodes",
        "edges",
        "anomalies",
        "credentials",
        "files",
        "ot_commands",
        "warnings",
    ):
        assert f"payload.{field}" in normalizer
        assert f"Array.isArray(payload.{field})" in normalizer

    assert "payload.stats =" in normalizer
    assert "payload.packets =" in normalizer
    for stat_field in ("protocols", "host_types", "vlans", "ip_versions"):
        assert f"stats.{stat_field}" in normalizer
        assert f"Array.isArray(stats.{stat_field})" in normalizer


def test_stats_consumers_use_safe_fallbacks():
    """Filter, legend, and table code must not directly dereference graphData.stats fields."""
    js = read("static/js/app.js")

    for unsafe in (
        "graphData.stats.protocols",
        "graphData.stats.host_types",
        "graphData.stats.vlans",
        "graphData.stats.ip_versions",
        "data.stats.host_types",
    ):
        assert unsafe not in js

    assert "const stats = graphData.stats || {};" in js
    assert "const stats = data.stats || {};" in js


def test_upload_error_parsing_reads_response_body_once():
    """Fetch Response bodies are single-use; upload errors need text preserved for diagnostics."""
    js = read("static/js/app.js")

    assert "await resp.json()" not in js
    assert "const raw = await resp.text();" in js
    assert "raw ? JSON.parse(raw) : {}" in js
    assert "Server returned non-JSON" in js
