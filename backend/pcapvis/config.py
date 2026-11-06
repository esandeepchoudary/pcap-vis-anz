"""Runtime settings, read from environment variables prefixed with PCAPVIS_."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

Mode = Literal["laptop", "server"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PCAPVIS_", env_file=".env", extra="ignore")

    # laptop: single user, no login, SQLite. server: accounts and roles, usually PostgreSQL.
    mode: Mode = "laptop"
    data_dir: Path = Path("./pcapvis-data")
    # Defaults to SQLite inside data_dir. Server example: postgresql+psycopg://user:pw@db/pcapvis
    database_url: str | None = None

    host: str = "127.0.0.1"
    port: int = 8000

    tshark_path: str = "tshark"
    tshark_min_version: str = "4.0.0"
    # Refuse to start when tshark is missing or too old. Only disable for frontend-only dev or tests.
    require_tshark: bool = True

    # Built React app. None = auto-detect (../frontend/dist in a checkout, /app/frontend in the image).
    frontend_dist: Path | None = None

    session_ttl_hours: int = 12
    # Set true when served over HTTPS so the session cookie is only sent on TLS.
    cookie_secure: bool = False

    # Server mode first run: create this admin if no users exist yet.
    admin_username: str | None = None
    admin_password: str | None = None

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'pcapvis.db').resolve()}"

    @property
    def auth_required(self) -> bool:
        return self.mode == "server"


@lru_cache
def get_settings() -> Settings:
    return Settings()
