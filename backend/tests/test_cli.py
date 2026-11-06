import json

import pytest

from pcapvis import cli

PW = "correct horse battery"


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    from pcapvis.config import get_settings

    monkeypatch.setenv("PCAPVIS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PCAPVIS_MODE", "server")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_version_flag(capsys):
    from pcapvis import __version__

    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_create_user_and_duplicate(monkeypatch, capsys):
    monkeypatch.setenv("PCAPVIS_NEW_USER_PASSWORD", PW)
    assert cli.main(["create-user", "alice", "--role", "admin"]) == 0
    assert "Created admin 'alice'" in capsys.readouterr().out
    assert cli.main(["create-user", "alice"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_create_user_weak_password(monkeypatch, capsys):
    monkeypatch.setenv("PCAPVIS_NEW_USER_PASSWORD", "short")
    assert cli.main(["create-user", "bob"]) == 1
    assert "at least" in capsys.readouterr().err


def test_check_reports_missing_tshark(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PCAPVIS_TSHARK_PATH", str(tmp_path / "no-tshark"))
    assert cli.main(["check"]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "Install it" in out


def test_serve_refuses_without_tshark(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PCAPVIS_TSHARK_PATH", str(tmp_path / "no-tshark"))
    assert cli.main(["serve", "--port", "1"]) == 1
    assert "Cannot start pcapvis" in capsys.readouterr().err


def test_db_upgrade(tmp_path, capsys):
    assert cli.main(["db-upgrade"]) == 0
    assert (tmp_path / "data" / "pcapvis.db").is_file()


def test_openapi_output(capsys):
    assert cli.main(["openapi"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert {"/api/health", "/api/system", "/api/auth/login", "/api/users"} <= set(schema["paths"])
