"""The assessment report as HTML (self-contained, prints to PDF) and DOCX, from one content outline.

Untrusted text: HTML output escapes everything (and contains no scripts); python-docx escapes XML itself.
"""

import html
import io
from collections import Counter
from dataclasses import dataclass

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

from pcapvis.reports import ReportData, done_captures, level_name, ts

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_COLOURS = {"critical": "B42318", "high": "C4320A", "medium": "B54708", "low": "175CD3", "info": "475467"}
MAX_REGISTER = 2000
MAX_VIOLATIONS = 100


@dataclass
class Table:
    header: list[str]
    rows: list[list[str]]


@dataclass
class Block:
    kind: str  # h1 | h2 | p | table | finding | kv
    text: str = ""
    table: Table | None = None
    meta: dict | None = None


def outline(d: ReportData) -> list[Block]:
    eng = d.engagement
    caps = done_captures(d)
    fs = d.reported_findings
    sev = Counter(f.severity for f in fs)
    label = lambda i: d.asset(i).label if d.asset(i) else f"asset {i}"  # noqa: E731
    ot_links = [lk for lk in d.links if lk.is_ot]
    writes = sum(o.count for o in d.ot_ops if o.kind == "write")
    levels = Counter(level_name(a.level) for a in d.assets)
    b: list[Block] = [
        Block(
            "kv",
            meta={
                "Client": eng.client or "—",
                "Site": eng.site or "—",
                "Generated": d.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
                "Tool": f"PCAP Visualizer v{d.app_version}",
            },
        ),
        Block("h1", "Executive summary"),
        Block(
            "p",
            f"{len(caps)} packet capture(s) were analysed passively ({sum((c.summary or {}).get('packets', 0) for c in caps):,} packets). "
            f"{len(d.assets)} assets were identified, {len(ot_links)} asset pairs communicate over OT protocols, and "
            f"{writes:,} OT write commands were observed.",
        ),
        Block(
            "p",
            "Findings included in this report: "
            + (", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s]) or "none")
            + ".",
        ),
    ]
    if d.violations:
        b.append(
            Block(
                "p",
                f"{len(d.violations)} connection(s) cross zone boundaries without an approved conduit or with a protocol the conduit does not allow.",
            )
        )
    if eng.description:
        b.append(Block("p", eng.description))
    b += [
        Block("h1", "Scope"),
        Block(
            "table",
            table=Table(
                ["Capture", "Capture point", "Packets", "From", "To"],
                [
                    [
                        c.file_name,
                        c.capture_point.name if c.capture_point else "—",
                        f"{(c.summary or {}).get('packets', 0):,}",
                        ts((c.summary or {}).get("first_seen")),
                        ts((c.summary or {}).get("last_seen")),
                    ]
                    for c in caps
                ],
            ),
        ),
    ]
    b.append(Block("h1", "Findings"))
    if not fs:
        b.append(Block("p", "No findings are included in this report."))
    for f in fs:
        b.append(
            Block(
                "finding",
                f.title,
                meta={
                    "severity": f.severity,
                    "status": f.status.replace("_", " "),
                    "description": f.description,
                    "assets": ", ".join(label(i) for i in f.asset_ids[:20]) or "—",
                    "evidence": f.evidence[:5],
                    "attack": ", ".join(f.attack),
                    "recommendation": f.recommendation,
                    "notes": f.notes,
                },
            )
        )
    b.append(Block("h1", "Segmentation"))
    zones = [z for z in d.zones]
    if zones:
        b.append(
            Block(
                "table",
                table=Table(
                    ["Zone", "Purdue level", "Target SL", "Assets"],
                    [
                        [
                            z.name + ("" if z.defined else " (undefined)"),
                            level_name(z.purdue_level) if z.purdue_level is not None else "—",
                            f"SL {z.security_level}" if z.security_level else "—",
                            str(len(z.asset_ids)),
                        ]
                        for z in zones
                    ],
                ),
            )
        )
        zname = {z.id: z.name for z in zones if z.id}
        if d.conduits:
            b.append(Block("h2", "Conduits"))
            b.append(
                Block(
                    "table",
                    table=Table(
                        ["Between", "Allowed protocols"],
                        [
                            [
                                f"{zname.get(c.zone_a_id)} ↔ {zname.get(c.zone_b_id)}",
                                ", ".join(c.allowed) or "any",
                            ]
                            for c in d.conduits
                        ],
                    ),
                )
            )
        if d.violations:
            b.append(Block("h2", "Traffic outside approved conduits"))
            b.append(
                Block(
                    "table",
                    table=Table(
                        ["From", "To", "Problem", "Protocols"],
                        [
                            [
                                f"{label(v.src)} ({v.src_zone})",
                                f"{label(v.dst)} ({v.dst_zone})",
                                v.kind.replace("_", " "),
                                ", ".join(v.protocols),
                            ]
                            for v in d.violations[:MAX_VIOLATIONS]
                        ],
                    ),
                )
            )
    else:
        b.append(Block("p", "No zones were defined for this engagement."))
    b += [
        Block("h1", "Asset inventory"),
        Block(
            "table", table=Table(["Purdue level", "Assets"], [[k, str(v)] for k, v in sorted(levels.items())])
        ),
        Block("h2", "Asset register"),
        Block(
            "table",
            table=Table(
                ["Name", "Type", "Level", "Zone", "Vendor / model", "Addresses"],
                [
                    [
                        a.label,
                        a.values.get("asset_type") or "—",
                        level_name(a.level),
                        a.values.get("zone") or "—",
                        " ".join(v for v in (a.values.get("vendor"), a.values.get("model")) if v) or "—",
                        ", ".join(a.ips[:3]),
                    ]
                    for a in d.assets[:MAX_REGISTER]
                ],
            ),
        ),
    ]
    if len(d.assets) > MAX_REGISTER:
        b.append(
            Block(
                "p",
                f"The first {MAX_REGISTER} assets are listed; the complete register is in the XLSX export.",
            )
        )
    return b


def title(d: ReportData) -> str:
    return f"OT network assessment – {d.engagement.name}"


CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;color:#101828;max-width:960px;margin:32px auto;padding:0 24px;line-height:1.45}
h1{font-size:22px;border-bottom:2px solid #1f3a68;padding-bottom:4px;margin-top:32px}h2{font-size:16px;margin-top:20px}
.title{font-size:28px;font-weight:700;margin:0}table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}
th{background:#1f3a68;color:#fff;text-align:left}th,td{border:1px solid #d0d5dd;padding:4px 6px;vertical-align:top}
.kv td:first-child{font-weight:600;width:140px}.finding{border:1px solid #d0d5dd;border-left:6px solid;border-radius:4px;padding:8px 12px;margin:10px 0;break-inside:avoid}
.sev{font-weight:700;text-transform:uppercase;font-size:11px}.muted{color:#667085;font-size:12px}
@media print{body{margin:0}h1{break-after:avoid}tr{break-inside:avoid}}
"""


def to_html(d: ReportData) -> str:
    e = html.escape
    out = [
        f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>{e(title(d))}</title><style>{CSS}</style></head><body>',
        f'<p class="title">{e(title(d))}</p>',
    ]
    for blk in outline(d):
        if blk.kind == "kv":
            out.append(
                '<table class="kv">'
                + "".join(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in blk.meta.items())
                + "</table>"
            )
        elif blk.kind in ("h1", "h2"):
            out.append(f"<{blk.kind}>{e(blk.text)}</{blk.kind}>")
        elif blk.kind == "p":
            out.append(f"<p>{e(blk.text)}</p>")
        elif blk.kind == "table":
            t = blk.table
            out.append(
                "<table><thead><tr>"
                + "".join(f"<th>{e(h)}</th>" for h in t.header)
                + "</tr></thead><tbody>"
                + "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in t.rows)
                + "</tbody></table>"
            )
        elif blk.kind == "finding":
            m = blk.meta
            colour = SEV_COLOURS[m["severity"]]
            parts = [
                f'<div class="finding" style="border-left-color:#{colour}"><span class="sev" style="color:#{colour}">{e(m["severity"])}</span> '
                f'<strong>{e(blk.text)}</strong> <span class="muted">· {e(m["status"])}</span>',
                f"<p>{e(m['description'])}</p>" if m["description"] else "",
                f'<p class="muted">Affected: {e(m["assets"])}{(" · ATT&amp;CK for ICS: " + e(m["attack"])) if m["attack"] else ""}</p>',
            ]
            if m["evidence"]:
                parts.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in m["evidence"]) + "</ul>")
            if m["recommendation"]:
                parts.append(f"<p><strong>Recommendation:</strong> {e(m['recommendation'])}</p>")
            if m["notes"]:
                parts.append(f'<p class="muted">Analyst notes: {e(m["notes"])}</p>')
            out.append("".join(parts) + "</div>")
    out.append("</body></html>")
    return "".join(out)


def _clean(s: str) -> str:
    # XML 1.0 can't hold most control characters; python-docx would raise on them.
    return "".join(ch for ch in s if ch in "\t\n\r" or ord(ch) >= 0x20)


def to_docx(d: ReportData) -> bytes:
    doc = Document()
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)
    t = doc.add_heading(_clean(title(d)), level=0)
    t.alignment = WD_ALIGN_PARAGRAPH.LEFT
    for blk in outline(d):
        if blk.kind == "kv":
            table = doc.add_table(rows=0, cols=2)
            table.style = "Light List Accent 1"
            for k, v in blk.meta.items():
                row = table.add_row().cells
                row[0].text, row[1].text = _clean(k), _clean(v)
        elif blk.kind == "h1":
            doc.add_heading(_clean(blk.text), level=1)
        elif blk.kind == "h2":
            doc.add_heading(_clean(blk.text), level=2)
        elif blk.kind == "p":
            doc.add_paragraph(_clean(blk.text))
        elif blk.kind == "table":
            tb = blk.table
            table = doc.add_table(rows=1, cols=len(tb.header))
            table.style = "Light Grid Accent 1"
            for cell, h in zip(table.rows[0].cells, tb.header, strict=True):
                cell.text = _clean(h)
            for r in tb.rows:
                for cell, v in zip(table.add_row().cells, r, strict=True):
                    cell.text = _clean(str(v))
        elif blk.kind == "finding":
            m = blk.meta
            p = doc.add_paragraph()
            run = p.add_run(m["severity"].upper() + "  ")
            run.bold = True
            run.font.color.rgb = RGBColor.from_string(SEV_COLOURS[m["severity"]])
            p.add_run(_clean(blk.text)).bold = True
            p.add_run(f"  ({_clean(m['status'])})")
            if m["description"]:
                doc.add_paragraph(_clean(m["description"]))
            doc.add_paragraph(
                _clean(
                    f"Affected: {m['assets']}" + (f" · ATT&CK for ICS: {m['attack']}" if m["attack"] else "")
                )
            )
            for x in m["evidence"]:
                doc.add_paragraph(_clean(x), style="List Bullet")
            if m["recommendation"]:
                rp = doc.add_paragraph()
                rp.add_run("Recommendation: ").bold = True
                rp.add_run(_clean(m["recommendation"]))
            if m["notes"]:
                doc.add_paragraph(_clean(f"Analyst notes: {m['notes']}"))
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
