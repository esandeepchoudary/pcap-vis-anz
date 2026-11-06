"""Report downloads: asset register (XLSX), Purdue diagram (draw.io, SVG), report (DOCX, HTML) (M8)."""

import re

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from pcapvis.api.routes_engagements import as_viewer
from pcapvis.engagements import audit
from pcapvis.reports import gather
from pcapvis.reports.diagram import drawio, svg
from pcapvis.reports.document import to_docx, to_html
from pcapvis.reports.xlsx import asset_register

router = APIRouter(prefix="/api", tags=["reports"])
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
FILE = {200: {"content": {"application/octet-stream": {}}, "description": "The file"}}


def _name(eng, suffix: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_-]+", "_", eng.name).strip("_")[:60] or "engagement"
    return f"{base}-{suffix}"


def _send(ctx, kind: str, build, media: str, suffix: str) -> Response:
    eng, _r, user, db = ctx
    body = build(gather(db, eng))
    audit.record(db, user, "report.download", engagement_id=eng.id, target=kind)
    db.commit()
    return Response(
        content=body if isinstance(body, bytes) else body.encode(),
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{_name(eng, suffix)}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/engagements/{engagement_id}/reports/assets.xlsx", responses=FILE, response_class=Response)
def xlsx(ctx=Depends(as_viewer)):
    return _send(ctx, "asset register", asset_register, XLSX, "asset-register.xlsx")


@router.get("/engagements/{engagement_id}/reports/purdue.drawio", responses=FILE, response_class=Response)
def purdue_drawio(ctx=Depends(as_viewer)):
    return _send(ctx, "Purdue diagram (draw.io)", drawio, "application/xml", "purdue.drawio")


@router.get("/engagements/{engagement_id}/reports/purdue.svg", responses=FILE, response_class=Response)
def purdue_svg(ctx=Depends(as_viewer)):
    return _send(ctx, "Purdue diagram (SVG)", svg, "image/svg+xml", "purdue.svg")


@router.get("/engagements/{engagement_id}/reports/report.docx", responses=FILE, response_class=Response)
def report_docx(ctx=Depends(as_viewer)):
    return _send(ctx, "report (DOCX)", to_docx, DOCX, "report.docx")


@router.get("/engagements/{engagement_id}/reports/report.html", responses=FILE, response_class=Response)
def report_html(ctx=Depends(as_viewer)):
    return _send(ctx, "report (HTML)", to_html, "text/html; charset=utf-8", "report.html")
