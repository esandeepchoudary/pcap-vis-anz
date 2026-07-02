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
