"""Test fixtures.

By default every test gets a fresh SQLite database. Set PCAPVIS_TEST_DATABASE_URL to a
PostgreSQL URL to run the same suite against PostgreSQL; the schema is wiped before each test.
"""

import os

import pytest
from sqlalchemy import create_engine, text

from pcapvis.config import Settings
from pcapvis.db import models
from pcapvis.db.migrate import upgrade_to_head
from pcapvis.db.session import make_engine, make_session_factory

TEST_DB_URL = os.environ.get("PCAPVIS_TEST_DATABASE_URL")


def _reset_postgres(url: str) -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


def _settings(tmp_path, **kw) -> Settings:
    if TEST_DB_URL:
        _reset_postgres(TEST_DB_URL)
        kw.setdefault("database_url", TEST_DB_URL)
    kw.setdefault("require_tshark", False)
    kw.setdefault("frontend_dist", None)
    return Settings(data_dir=tmp_path / "data", **kw)


@pytest.fixture
def make_settings(tmp_path):
    """Factory for Settings that honours PCAPVIS_TEST_DATABASE_URL."""
    return lambda **kw: _settings(tmp_path, **kw)


@pytest.fixture
def settings(make_settings) -> Settings:
    return make_settings(mode="laptop")


@pytest.fixture
def server_settings(make_settings) -> Settings:
    return make_settings(mode="server")


@pytest.fixture
def db(settings):
    upgrade_to_head(settings.resolved_database_url)
    engine = make_engine(settings.resolved_database_url)
    factory = make_session_factory(engine)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.fixture
def eng(db):
    e = models.Engagement(name="Plant")
    db.add(e)
    db.commit()
    return e


@pytest.fixture
def user(db):
    u = models.User(username="alice", role="consultant")
    db.add(u)
    db.commit()
    return u
