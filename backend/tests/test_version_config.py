from pathlib import Path

import pcapvis
from pcapvis.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_version_matches_repo_version_file():
    assert pcapvis.__version__ == (REPO_ROOT / "VERSION").read_text().strip()


def test_default_database_is_sqlite_in_data_dir(tmp_path):
    s = Settings(data_dir=tmp_path / "d")
    assert s.resolved_database_url == f"sqlite:///{(tmp_path / 'd' / 'pcapvis.db').resolve()}"


def test_explicit_database_url_wins(tmp_path):
    s = Settings(data_dir=tmp_path, database_url="postgresql+psycopg://u:p@db/pcapvis")
    assert s.resolved_database_url == "postgresql+psycopg://u:p@db/pcapvis"


def test_auth_required_only_in_server_mode():
    assert Settings(mode="laptop").auth_required is False
    assert Settings(mode="server").auth_required is True


def test_env_vars_configure_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("PCAPVIS_MODE", "server")
    monkeypatch.setenv("PCAPVIS_PORT", "9123")
    monkeypatch.setenv("PCAPVIS_REQUIRE_TSHARK", "false")
    s = Settings()
    assert (s.mode, s.port, s.require_tshark) == ("server", 9123, False)


def test_invalid_mode_rejected():
    import pydantic
    import pytest

    with pytest.raises(pydantic.ValidationError):
        Settings(mode="cloud")
