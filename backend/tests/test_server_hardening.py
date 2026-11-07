"""Team-server hardening (M9): readiness probe, deployment warnings, backups."""

import zipfile

import pytest
from fastapi.testclient import TestClient

from pcapvis import cli
from pcapvis.app import create_app
from pcapvis.config import deployment_warnings, get_settings
from tests.test_captures_api import H, engagement


def test_health_checks_the_database(make_settings):
    app = create_app(make_settings(mode="laptop"))
    with TestClient(app) as c:
        assert c.get("/api/health").json() == {"status": "ok"}

        def broken():
            raise RuntimeError("db down")

        app.state.session_factory = broken
        r = c.get("/api/health")
        assert r.status_code == 503 and r.json()["detail"] == "Database unreachable."


def test_deployment_warnings(make_settings):
    assert deployment_warnings(make_settings(mode="laptop")) == []
    w = deployment_warnings(make_settings(mode="server", admin_password="short-pass-1"))
    assert any("COOKIE_SECURE" in x for x in w) and any("short" in x for x in w)
    ok = deployment_warnings(make_settings(mode="server", cookie_secure=True, admin_password="x" * 20))
    assert all("COOKIE_SECURE" not in x and "short" not in x for x in ok)


def test_startup_logs_warnings(make_settings, caplog):
    with caplog.at_level("WARNING", logger="pcapvis"):
        create_app(
            make_settings(mode="server", admin_username="admin", admin_password="correct horse battery")
        )
    assert any("COOKIE_SECURE" in r.message for r in caplog.records)


@pytest.fixture(autouse=True)
def fresh_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_check_prints_warnings(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("PCAPVIS_MODE", "server")
    monkeypatch.setenv("PCAPVIS_DATA_DIR", str(tmp_path))
    cli.main(["check"])
    assert "WARN PCAPVIS_COOKIE_SECURE is off" in capsys.readouterr().out


def test_export_all_backs_up_every_engagement(make_settings, monkeypatch, tmp_path, capsys):
    settings = make_settings(mode="laptop")
    app = create_app(settings)
    with TestClient(app) as c:
        engagement(c, "Plant A")
        engagement(c, "Plant / B")
        c.post("/api/engagements", json={"name": "x"}, headers=H)
    monkeypatch.setenv("PCAPVIS_DATA_DIR", str(settings.data_dir))
    if settings.database_url:
        monkeypatch.setenv("PCAPVIS_DATABASE_URL", settings.database_url)
    get_settings.cache_clear()
    out = tmp_path / "backup"
    assert cli.main(["export-all", str(out), "--no-captures"]) == 0
    files = sorted(p.name for p in out.iterdir())
    assert files == ["0001-Plant_A.pcapvis", "0002-Plant___B.pcapvis", "0003-x.pcapvis"]
    with zipfile.ZipFile(out / files[0]) as z:
        assert "manifest.json" in z.namelist()
    assert "Exported 3 engagement(s)" in capsys.readouterr().out
