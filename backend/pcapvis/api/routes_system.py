from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text

from pcapvis import __version__
from pcapvis.api.deps import get_settings_dep
from pcapvis.api.schemas import ErrorOut, Health, SystemInfo, TsharkInfo
from pcapvis.config import Settings

router = APIRouter(prefix="/api", tags=["system"])


@router.get(
    "/health",
    response_model=Health,
    responses={503: {"model": ErrorOut, "description": "Database unreachable"}},
)
def health(request: Request) -> Health:
    """Readiness probe for container health checks: the app is up and its database answers. No auth."""
    try:
        with request.app.state.session_factory() as db:
            db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - any database failure means "not ready"
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Database unreachable.") from exc
    return Health()


@router.get("/system", response_model=SystemInfo)
def system(request: Request, settings: Settings = Depends(get_settings_dep)) -> SystemInfo:
    """Version, deployment mode, and tshark status. No auth: the login page needs it."""
    return SystemInfo(
        version=__version__,
        mode=settings.mode,
        auth_required=settings.auth_required,
        tshark=TsharkInfo(**request.app.state.tshark.as_dict()),
    )
