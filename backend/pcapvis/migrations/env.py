from alembic import context
from sqlalchemy import create_engine, pool

from pcapvis.db import models  # noqa: F401 - registers tables on Base.metadata
from pcapvis.db.base import Base
from pcapvis.db.session import make_engine

config = context.config
target_metadata = Base.metadata


def render_item(type_, obj, autogen_context):
    """Render our UTCDateTime as a plain timezone-aware DateTime so migrations don't import app code."""
    from pcapvis.db.base import UTCDateTime

    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = config.get_main_option("sqlalchemy.url")
    # SQLite: reuse the app engine (WAL + FK pragmas). Others: no pooling for a one-off run.
    connectable = (
        make_engine(url) if url.startswith("sqlite") else create_engine(url, poolclass=pool.NullPool)
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite needs batch mode for ALTER TABLE
            render_item=render_item,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
