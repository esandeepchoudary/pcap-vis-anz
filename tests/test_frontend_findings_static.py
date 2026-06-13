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


def test_agents_instructions_are_available():
    agents = read("AGENTS.md")

    assert "## Branching" in agents
    assert "python -m pytest tests/ -q" in agents
    assert "Commit and push" in agents
