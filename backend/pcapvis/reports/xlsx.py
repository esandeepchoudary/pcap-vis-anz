"""Asset register workbook. Text cells are always written as text, so traffic-supplied strings that start
with '=' can never become formulas, and characters Excel can't store are removed."""

import io

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE, Cell
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from pcapvis.assets import fields as F
from pcapvis.reports import ReportData, level_name, ts

HEADER_FILL = PatternFill("solid", fgColor="1F3A68")
HEADER_FONT = Font(bold=True, color="FFFFFF")


def _value(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, (list, tuple)):
        v = "; ".join(str(x) for x in v)
    return ILLEGAL_CHARACTERS_RE.sub("", str(v))[:32_000]


def _text_cell(ws, v):
    """Strings become Cells pinned to text (never a formula). Built here because looking a row up after
    ws.append() rescans the whole sheet, which made big registers quadratic."""
    if not isinstance(v, str):
        return v
    cell = Cell(ws, value=v)
    cell.data_type = "s"
    return cell


def _sheet(wb: Workbook, title: str, header: list[str], rows: list[list]) -> None:
    ws = wb.create_sheet(title)
    ws.append(header)
    for c in ws[1]:
        c.fill, c.font, c.alignment = HEADER_FILL, HEADER_FONT, Alignment(vertical="top")
    for row in rows:
        ws.append([_text_cell(ws, _value(v)) for v in row])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for i, h in enumerate(header, start=1):
        width = max(
            [len(h)] + [len(str(r[i - 1])) for r in rows[:200] if i - 1 < len(r) and r[i - 1] is not None]
        )
        ws.column_dimensions[get_column_letter(i)].width = min(60, max(10, width + 2))


def asset_register(data: ReportData) -> bytes:
    wb = Workbook()
    wb.remove(wb.active)
    cols = list(F.FIELDS)
    _sheet(
        wb,
        "Assets",
        [
            "Asset ID",
            *(F.FIELDS[c].label for c in cols),
            "Purdue level name",
            "IP addresses",
            "MAC addresses",
            "MAC vendor",
            "Protocols",
            "First seen",
            "Last seen",
            "Captures",
            "Set by hand",
            "Origin",
        ],
        [
            [
                a.id,
                *(a.values.get(c) for c in cols),
                level_name(a.level),
                a.ips,
                a.macs,
                a.mac_vendor,
                a.protocols,
                ts(a.first_seen),
                ts(a.last_seen),
                a.captures,
                a.overridden,
                a.origin,
            ]
            for a in data.assets
        ],
    )
    _sheet(
        wb,
        "Zones",
        ["Zone", "Defined", "Purdue level", "Target SL", "Assets", "Description"],
        [
            [z.name, z.defined, z.purdue_level, z.security_level, len(z.asset_ids), z.description]
            for z in data.zones
        ],
    )
    zname = {z.id: z.name for z in data.zones if z.id}
    _sheet(
        wb,
        "Conduits",
        ["Zone A", "Zone B", "Name", "Allowed protocols", "Description"],
        [
            [zname.get(c.zone_a_id), zname.get(c.zone_b_id), c.name, c.allowed or "any", c.description]
            for c in data.conduits
        ],
    )
    label = lambda i: data.asset(i).label if data.asset(i) else i  # noqa: E731
    _sheet(
        wb,
        "Zone violations",
        ["From", "From zone", "To", "To zone", "Problem", "Protocols", "Flows", "OT writes"],
        [
            [
                label(v.src),
                v.src_zone,
                label(v.dst),
                v.dst_zone,
                v.kind.replace("_", " "),
                v.protocols,
                v.flows,
                v.ot_writes,
            ]
            for v in data.violations
        ],
    )
    _sheet(
        wb,
        "Findings",
        [
            "Severity",
            "Title",
            "Status",
            "In report",
            "Source",
            "ATT&CK",
            "Assets",
            "Description",
            "Recommendation",
            "Notes",
            "Occurrences",
        ],
        [
            [
                f.severity,
                f.title,
                f.status.replace("_", " "),
                f.include_in_report,
                f.source,
                f.attack,
                [label(i) for i in f.asset_ids],
                f.description,
                f.recommendation,
                f.notes,
                f.count,
            ]
            for f in data.findings
        ],
    )
    _sheet(
        wb,
        "OT commands",
        ["From", "To", "Protocol", "Function", "Kind", "Count", "First seen", "Last seen", "Detail"],
        [
            [
                label(o.src_asset_id),
                label(o.dst_asset_id),
                o.protocol,
                o.function,
                o.kind,
                o.count,
                ts(o.first_seen),
                ts(o.last_seen),
                o.sample,
            ]
            for o in data.ot_ops
        ],
    )
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
