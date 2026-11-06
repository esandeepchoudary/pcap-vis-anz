"""Run Alembic migrations programmatically (on startup and from the CLI)."""
from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def alembic_config(database_url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    # Escape % so passwords containing it survive ConfigParser interpolation.
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return cfg


def upgrade_to_head(database_url: str) -> None:
    command.upgrade(alembic_config(database_url), "head")
