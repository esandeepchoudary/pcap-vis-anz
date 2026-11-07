"""FastAPI application factory."""

import logging
import math
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from pcapvis import __version__
from pcapvis.api import (
    routes_assets,
    routes_auth,
    routes_captures,
    routes_engagements,
    routes_findings,
    routes_forensics,
    routes_links,
    routes_reports,
    routes_system,
    routes_users,
    routes_zones,
)
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
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), serial=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    ),
}


# JSON bodies are small (the largest is a bulk edit of 10k ids); uploads and imports are multipart and
# enforce their own streaming limits. Cap everything else so a huge body can't exhaust memory.
MAX_JSON_BODY = 2 * 1024 * 1024


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


# Python 3.13 renamed some HTTP status phrases, which FastAPI uses as default response descriptions.
# Pin them so the generated frontend types are identical whichever Python generates them.
_PHRASE_VARIANTS = {
    "Content Too Large": "Content too large",
    "Request Entity Too Large": "Content too large",
    "Range Not Satisfiable": "Range not satisfiable",
    "Requested Range Not Satisfiable": "Range not satisfiable",
    "Unprocessable Content": "Unprocessable content",
    "Unprocessable Entity": "Unprocessable content",
}


def _finite(v):
    if isinstance(v, float) and not math.isfinite(v):
        return str(v)
    if isinstance(v, list):
        return [_finite(x) for x in v]
    if isinstance(v, dict):
        return {k: _finite(x) for k, x in v.items()}
    return v


def _stable_openapi(app: FastAPI) -> None:
    generate = app.openapi

    def openapi() -> dict:
        if app.openapi_schema is None:
            schema = generate()
            for ops in schema.get("paths", {}).values():
                for op in ops.values():
                    for resp in op.get("responses", {}).values():
                        if resp.get("description") in _PHRASE_VARIANTS:
                            resp["description"] = _PHRASE_VARIANTS[resp["description"]]
        return app.openapi_schema

    app.openapi = openapi


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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runner = None
        if settings.run_jobs_in_app:
            from pcapvis.jobs.runner import JobRunner

            runner = JobRunner(settings, session_factory)
            runner.start()
        app.state.job_runner = runner
        yield
        if runner is not None:
            runner.stop()

    app = FastAPI(
        lifespan=lifespan,
        title="PCAP Network Visualizer",
        version=__version__,
        # The API description is public by nature, so a team server doesn't hand it to signed-out visitors.
        docs_url=None if settings.auth_required else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.auth_required else "/api/openapi.json",
    )
    _stable_openapi(app)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        # Same body as FastAPI's default, but NaN/Infinity inputs (which Python's JSON parser accepts) are
        # echoed back as text: the default handler crashed trying to serialise them.
        return JSONResponse({"detail": _finite(jsonable_encoder(exc.errors()))}, status_code=422)

    @app.exception_handler(UnicodeEncodeError)
    async def unstorable_text(request: Request, exc: UnicodeEncodeError):
        # JSON allows lone surrogates ("\ud800"); no database can store them.
        log.info("rejected unstorable text on %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "Text contains invalid Unicode characters."}, status_code=400)

    from pcapvis.config import deployment_warnings

    for warning in deployment_warnings(settings):
        log.warning(warning)
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
        if request.method in UNSAFE_METHODS and not request.headers.get("content-type", "").startswith(
            "multipart/form-data"
        ):
            length = request.headers.get("content-length")
            if length is None and request.headers.get("transfer-encoding"):
                return JSONResponse({"detail": "Send a Content-Length."}, status_code=411)
            if length is not None and (not length.isdigit() or int(length) > MAX_JSON_BODY):
                return JSONResponse({"detail": "Request body too large."}, status_code=413)
        response: Response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if settings.cookie_secure:  # served over HTTPS: tell browsers to stay on it
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    app.include_router(routes_system.router)
    app.include_router(routes_auth.router)
    app.include_router(routes_users.router)
    app.include_router(routes_engagements.router)
    app.include_router(routes_captures.router)
    app.include_router(routes_assets.router)
    app.include_router(routes_links.router)
    app.include_router(routes_zones.router)
    app.include_router(routes_forensics.router)
    app.include_router(routes_findings.router)
    app.include_router(routes_reports.router)

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
