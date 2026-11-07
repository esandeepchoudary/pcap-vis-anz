"""Import asset edits from a spreadsheet: the client filled in the register we exported.

Accepts the app's own exports (CSV with field-name headers, XLSX with label headers) and anything shaped
like them. Rows match assets by asset ID, else by an IP address. Only editable fields are read; a blank
cell leaves the asset as it is (so a half-filled sheet can't wipe detected values). ``plan`` returns the
changes without applying them, so the consultant sees a preview first.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.assets import fields as F
from pcapvis.assets import service
from pcapvis.db.models import Asset, User

MAX_BYTES = 10 * 1024 * 1024
MAX_UNZIPPED = 100 * 1024 * 1024
MAX_ROWS = 20_000
MAX_COLS = 100
_LEVEL = re.compile(r"-?\d+(?:\.\d+)?")


class ImportError_(ValueError):  # noqa: N801 - avoid shadowing the builtin
    """The file can't be read (message is safe to show)."""


@dataclass
class Change:
    asset_id: int
    label: str
    field: str
    old: Any
    new: Any


@dataclass
class Plan:
    rows: int = 0
    matched: int = 0
    unmatched: list[str] = field(default_factory=list)  # "row 7: no asset with ID 99"
    errors: list[str] = field(default_factory=list)  # "row 3, Purdue level: must be one of …"
    changes: list[Change] = field(default_factory=list)


def _norm(h: Any) -> str:
    return re.sub(r"[\s_]+", " ", str(h or "")).strip().lower()


HEADERS: dict[str, str] = {}
for _name, _spec in F.FIELDS.items():
    HEADERS[_norm(_name)] = _name
    HEADERS[_norm(_spec.label)] = _name
HEADERS.update({"asset id": "@id", "id": "@id", "ip addresses": "@ips", "ip address": "@ips", "ip": "@ips"})


def read_rows(name: str, data: bytes) -> list[dict[str, Any]]:
    """Rows of the first sheet as {field or @id/@ips: raw value}. Unknown columns are ignored."""
    if len(data) > MAX_BYTES:
        raise ImportError_(f"The file is larger than {MAX_BYTES // 2**20} MB.")
    if data[:2] == b"PK" or name.lower().endswith((".xlsx", ".xlsm")):
        table = _xlsx(data)
    else:
        table = _csv(data)
    if not table:
        raise ImportError_("The file is empty.")
    header = [HEADERS.get(_norm(h)) for h in table[0][:MAX_COLS]]
    if "@id" not in header and "@ips" not in header:
        raise ImportError_(
            "No 'asset_id' or 'IP addresses' column: export the register from this engagement and edit that."
        )
    if not any(h and not h.startswith("@") for h in header):
        raise ImportError_("No editable columns (Name, Type, Purdue level, Zone, …) found.")
    rows = []
    for raw in table[1 : MAX_ROWS + 1]:
        row = {h: raw[i] for i, h in enumerate(header) if h and i < len(raw)}
        if any(v not in (None, "") for v in row.values()):
            rows.append(row)
    if len(table) - 1 > MAX_ROWS:
        raise ImportError_(f"At most {MAX_ROWS:,} rows per import.")
    return rows


def _csv(data: bytes) -> list[list[str]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")  # Excel on Windows saves CSV in the ANSI code page
    return [r for r in csv.reader(io.StringIO(text))]


def _xlsx(data: bytes) -> list[list[Any]]:
    from openpyxl import load_workbook  # parses with defusedxml (no XXE, no entity expansion)

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if sum(i.file_size for i in z.infolist()) > MAX_UNZIPPED:
                raise ImportError_("The workbook is too large once unpacked.")
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)  # cached values, never formulas
    except ImportError_:
        raise
    except Exception as exc:  # noqa: BLE001 - any parse failure is the user's file
        raise ImportError_("Not a readable .xlsx workbook.") from exc
    try:
        ws = wb["Assets"] if "Assets" in wb.sheetnames else wb.worksheets[0]
        out = []
        for i, row in enumerate(ws.iter_rows(values_only=True, max_col=MAX_COLS)):
            if i > MAX_ROWS + 1:
                out.append(())  # just enough to trip the row limit
                break
            out.append(list(row))
        return out
    except Exception as exc:  # noqa: BLE001 - rows are parsed lazily in read-only mode
        raise ImportError_("Not a readable .xlsx workbook.") from exc
    finally:
        wb.close()


def _value(field_name: str, raw: Any) -> Any:
    """Cell → field value (validated). None means "blank: leave as is"."""
    if raw is None:
        return None
    if isinstance(raw, float) and raw.is_integer():
        raw = int(raw)
    s = str(raw).strip()
    if s == "":
        return None
    if len(s) > 1 and s[0] == "'" and s[1] in "=+-@\t\r":  # our CSV export's formula guard
        s = s[1:]
    spec = F.FIELDS[field_name]
    if spec.kind == "level":
        m = _LEVEL.search(s.replace("L", "", 1) if s[:1] in "Ll" else s)
        if not m:
            raise F.FieldError(f"{spec.label} must be a number such as 1 or 3.5.")
        v: Any = float(m.group())
    elif spec.kind == "tags":
        v = [t.strip() for t in re.split(r"[;,]", s) if t.strip()]
    elif spec.kind == "choice":
        v = s.lower()
    else:
        v = s
    return F.validate(field_name, v)


def plan(db: Session, eid: int, rows: list[dict[str, Any]]) -> Plan:
    assets = list(db.scalars(select(Asset).where(Asset.engagement_id == eid)))
    by_id = {a.id: a for a in assets}
    by_ip: dict[str, Asset] = {}
    for a in sorted(assets, key=lambda a: a.id):
        for ip in a.ips or []:
            by_ip.setdefault(ip, a)
    p = Plan(rows=len(rows))
    seen: set[int] = set()
    for n, row in enumerate(rows, start=2):  # row 1 is the header
        a = None
        rid = row.get("@id")
        if rid not in (None, ""):
            try:
                a = by_id.get(int(float(str(rid).strip())))
            except ValueError:
                a = None
            if a is None:
                p.unmatched.append(f"row {n}: no asset with ID {str(rid)[:20]}")
                continue
        else:
            ips = re.split(r"[\s,;]+", str(row.get("@ips") or "").strip())
            a = next((by_ip[ip] for ip in ips if ip in by_ip), None)
            if a is None:
                p.unmatched.append(f"row {n}: no asset with address {' '.join(ips)[:60]}")
                continue
        if a.id in seen:
            p.unmatched.append(f"row {n}: asset {a.id} appears twice; only the first row is used")
            continue
        seen.add(a.id)
        p.matched += 1
        current = F.effective_all(a.auto or {}, a.overrides or {})
        for f in F.FIELDS:
            if f not in row:
                continue
            try:
                v = _value(f, row[f])
            except F.FieldError as exc:
                p.errors.append(f"row {n}, {F.FIELDS[f].label}: {exc}")
                continue
            if v is None or v == current[f] or (f == "purdue_level" and float(v) == float(current[f])):
                continue
            p.changes.append(Change(a.id, service.label(a), f, current[f], v))
    return p


def apply(db: Session, eid: int, p: Plan, user: User | None, reason: str) -> int:
    """Apply a plan's changes as manual values (with history). Returns assets changed. Caller commits."""
    per_asset: dict[int, dict[str, Any]] = {}
    for c in p.changes:
        per_asset.setdefault(c.asset_id, {})[c.field] = c.new
    n = 0
    for aid, values in per_asset.items():
        a = db.get(Asset, aid)
        if a is None or a.engagement_id != eid:
            continue
        for _attempt in range(3):
            try:
                if service.edit(db, a, user, set_=values, reset=[], reason=reason, expected_version=None):
                    n += 1
                break
            except service.EditConflict:
                db.refresh(a)
    return n
