"""Tests for project versioning: VERSION file, bump script, CI check, /version route."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import bump_version  # noqa: E402
import check_version_bump  # noqa: E402
import app as app_module  # noqa: E402


def test_version_file_is_semver():
    with open(os.path.join(ROOT, "VERSION")) as fh:
        assert bump_version.parse(fh.read())


@pytest.mark.parametrize("part,expected", [
    ("patch", "1.2.4"), ("minor", "1.3.0"), ("major", "2.0.0"),
])
def test_bump(part, expected):
    assert bump_version.bump("1.2.3", part) == expected


@pytest.mark.parametrize("bad", ["1.2", "v1.2.3", "1.2.3-beta", ""])
def test_parse_rejects_non_semver(bad):
    with pytest.raises(ValueError):
        bump_version.parse(bad)


def test_changelog_entry_inserted_below_marker():
    text = "# Changelog\n\n<!-- next-entry -->\n\n## v0.1.0 -- 2026-01-01\n"
    out = bump_version.add_changelog_entry(text, "0.2.0", "Add thing", "2026-02-02")
    assert out.index("<!-- next-entry -->") < out.index("## v0.2.0") < out.index("## v0.1.0")
    assert "- Add thing" in out
    assert out.count("<!-- next-entry -->") == 1


def test_changelog_requires_marker():
    with pytest.raises(ValueError):
        bump_version.add_changelog_entry("# Changelog\n", "0.2.0", "x", "2026-02-02")


def test_main_updates_files(tmp_path, monkeypatch):
    vf = tmp_path / "VERSION"
    cf = tmp_path / "CHANGELOG.md"
    vf.write_text("0.1.0\n")
    cf.write_text("# Changelog\n\n<!-- next-entry -->\n")
    monkeypatch.setattr(bump_version, "VERSION_FILE", vf)
    monkeypatch.setattr(bump_version, "CHANGELOG_FILE", cf)
    assert bump_version.main(["minor", "New feature"]) == 0
    assert vf.read_text() == "0.2.0\n"
    assert "## v0.2.0" in cf.read_text()


@pytest.mark.parametrize("base,head,rc", [
    ("0.1.0", "0.1.1", 0), ("0.1.0", "0.2.0", 0), ("0.9.9", "1.0.0", 0),
    ("0.1.0", "0.1.0", 1), ("0.2.0", "0.1.9", 1),
    ("0.10.0", "0.9.0", 1),  # numeric, not string, comparison
])
def test_check_version_bump(base, head, rc):
    assert check_version_bump.main([base, head]) == rc


def test_version_route_and_header():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        r = c.get("/version")
        assert r.status_code == 200
        assert r.get_json()["version"] == app_module.__version__
        page = c.get("/").get_data(as_text=True)
        assert f'id="app-version" title="App version">v{app_module.__version__}<' in page
