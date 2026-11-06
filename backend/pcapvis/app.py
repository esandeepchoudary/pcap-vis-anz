"""FastAPI application factory."""

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from pcapvis import __version__
from pcapvis.api import routes_auth, routes_system, routes_users
from pcapvis.auth import service as auth
from pcapvis.config import Settings, get_settings
from pcapvis.db.migrate import upgrade_to_head
from pcapvis.db.session import make_engine, make_session_factory
from pcapvis.tshark import check_tshark, install_hint

log = logging.getLogger("pcapvis")

# Unsafe methods must carry this header. Browsers can't add custom headers to cross-site
# requests without a CORS preflight, which this API never allows, so this blocks CSRF.
CSRF_HEADER = "x-pcapvis-client"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    ),
}


class StartupError(RuntimeError):
    """Raised when the app can't start safely (message is shown to the operator)."""


def _find_frontend_dist(settings: Settings) -> Path | None:
    if settings.frontend_dist is not None:
        return settings.frontend_dist if (settings.frontend_dist / "index.html").is_file() else None
    for candidate in (
        Path(__file__).resolve().parents[2] / "frontend" / "dist",  # source checkout
        Path("/app/frontend"),  # container image
    ):
        if (candidate / "index.html").is_file():
            return candidate
    return None


def _bootstrap_users(settings: Settings, session_factory) -> None:
    with session_factory() as db:
        if not settings.auth_required:
            auth.ensure_local_user(db)
            return
        if auth.count_active_admins(db) == 0:
            if settings.admin_username and settings.admin_password:
                auth.create_user(
                    db, settings.admin_username, settings.admin_password, auth.Role.admin, "Administrator"
                )
                log.warning("Created initial admin user '%s'.", settings.admin_username)
            else:
                log.warning(
                    "Server mode has no admin yet. Create one with: pcapvis create-user <name> --role admin"
                )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    tshark_status = check_tshark(settings.tshark_path, settings.tshark_min_version)
    if settings.require_tshark and not tshark_status.ok:
        raise StartupError(f"{tshark_status.message}\n\nInstall it:\n{install_hint()}")

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    upgrade_to_head(settings.resolved_database_url)
    engine = make_engine(settings.resolved_database_url)
    session_factory = make_session_factory(engine)
    _bootstrap_users(settings, session_factory)

    app = FastAPI(
        title="PCAP Network Visualizer",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.tshark = tshark_status
    app.state.login_throttle = auth.LoginThrottle()

    @app.middleware("http")
    async def csrf_and_headers(request: Request, call_next):
        if (
            request.method in UNSAFE_METHODS
            and request.url.path.startswith("/api/")
            and request.headers.get(CSRF_HEADER) != "1"
        ):
            return JSONResponse({"detail": "Missing X-PcapVis-Client header."}, status_code=403)
        response: Response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.include_router(routes_system.router)
    app.include_router(routes_auth.router)
    app.include_router(routes_users.router)

    @app.api_route(
        "/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False
    )
    def api_not_found(rest: str):
        return JSONResponse({"detail": "Not found."}, status_code=404)

    dist = _find_frontend_dist(settings)
    if dist is not None:
        if (dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
        index_html = dist / "index.html"
        dist_root = dist.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            # Serve real top-level files (favicon etc.); everything else is a client-side route.
            candidate = (dist / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(dist_root):
                return FileResponse(candidate)
            return FileResponse(index_html, headers={"Cache-Control": "no-cache"})
    else:

        @app.get("/", include_in_schema=False)
        def no_frontend():
            return JSONResponse(
                {"detail": "Frontend not built. Run: cd frontend && npm run build"}, status_code=503
            )

    return app
