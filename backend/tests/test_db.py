import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from pcapvis.db.migrate import alembic_config, upgrade_to_head
from pcapvis.db.models import Role, User
from pcapvis.db.session import make_engine


def test_migrations_create_tables(settings):
    upgrade_to_head(settings.resolved_database_url)
    engine = make_engine(settings.resolved_database_url)
    assert {"users", "auth_sessions", "alembic_version"} <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_migrations_are_idempotent(settings):
    upgrade_to_head(settings.resolved_database_url)
    upgrade_to_head(settings.resolved_database_url)  # second run is a no-op, not an error


def test_migrations_downgrade_to_base(settings):
    from alembic import command

    url = settings.resolved_database_url
    upgrade_to_head(url)
    command.downgrade(alembic_config(url), "base")
    engine = make_engine(url)
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    engine.dispose()


def test_models_match_migrations(settings):
    """Autogenerate must find nothing to change: models and migrations are in sync."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from pcapvis.db.base import Base

    upgrade_to_head(settings.resolved_database_url)
    engine = make_engine(settings.resolved_database_url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    engine.dispose()
    assert diff == []


@pytest.mark.skipif(bool(__import__("os").environ.get("PCAPVIS_TEST_DATABASE_URL")), reason="SQLite only")
def test_sqlite_pragmas(db):
    assert db.execute(text("PRAGMA journal_mode")).scalar() == "wal"
    assert db.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_username_unique(db):
    db.add(User(username="alice", role=Role.viewer))
    db.commit()
    db.add(User(username="alice", role=Role.viewer))
    with pytest.raises(IntegrityError):
        db.commit()


def test_role_ordering():
    assert Role.admin.at_least(Role.lead)
    assert Role.lead.at_least(Role.consultant)
    assert Role.consultant.at_least(Role.viewer)
    assert not Role.viewer.at_least(Role.consultant)
    assert Role.consultant.at_least(Role.consultant)


def test_data_dir_created(tmp_path):
    url = f"sqlite:///{tmp_path / 'nested' / 'deeper' / 'x.db'}"
    upgrade_to_head(url)
    assert (tmp_path / "nested" / "deeper" / "x.db").is_file()


def test_datetimes_come_back_timezone_aware(db):
    from pcapvis.db.base import utcnow

    u = User(username="tz", role=Role.viewer, created_at=utcnow())
    db.add(u)
    db.commit()
    db.expire_all()
    assert db.get(User, u.id).created_at.tzinfo is not None


def test_naive_datetime_rejected(db):
    from datetime import datetime

    from sqlalchemy.exc import StatementError

    db.add(User(username="naive", role=Role.viewer, created_at=datetime(2026, 1, 1)))  # noqa: DTZ001
    with pytest.raises(StatementError, match="Naive datetime"):
        db.commit()
