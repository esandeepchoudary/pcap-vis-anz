from fastapi import APIRouter, Depends, Request

from pcapvis import __version__
from pcapvis.api.deps import get_settings_dep
from pcapvis.api.schemas import Health, SystemInfo, TsharkInfo
from pcapvis.config import Settings

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health", response_model=Health)
def health() -> Health:
    """Liveness probe for container health checks. No auth."""
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
