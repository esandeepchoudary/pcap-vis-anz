"""Purdue diagram as draw.io (editable in diagrams.net) and SVG.

Layout mirrors the app's Purdue map: a lane per level (top: enterprise), a box per zone, assets in a grid.
Labels are plain text: draw.io gets ``html=0`` so a hostile hostname can't inject markup, and every
attribute/text is XML-escaped.
"""

from dataclasses import dataclass
from xml.sax.saxutils import escape as _escape
from xml.sax.saxutils import quoteattr as _quoteattr

from pcapvis.reports import AssetRow, ReportData, level_name, xml_safe


def escape(s: str) -> str:
    return _escape(xml_safe(s))


def quoteattr(s: str) -> str:
    return _quoteattr(xml_safe(s))


LANES = (6, 5, 4, 3.5, 3, 2, 1, 0, -1)
ALWAYS = {5, 4, 3.5, 3, 2, 1, 0}
NODE_W, NODE_H, GAP, ZONE_HEAD, ZONE_GAP, LANE_PAD, LABEL_W, MAX_COLS = 170, 44, 10, 24, 20, 14, 170, 4
LANE_COLOURS = {
    0: "#fdf0e8",
    1: "#fdf0e8",
    2: "#fdf6e3",
    3: "#eef3fd",
    3.5: "#eef3fd",
    4: "#eef5fb",
    5: "#eef5fb",
}


@dataclass
class Box:
    x: float
    y: float
    w: float
    h: float
    label: str


def layout(data: ReportData):
    assets = [a for a in data.assets if a.is_private or a.origin == "manual"]
    used = {a.level for a in assets}
    lanes, zones, nodes = [], [], {}
    y, width = 0.0, 900.0
    for level in LANES:
        if level not in ALWAYS and level not in used:
            continue
        members = [a for a in assets if a.level == level]
        names = sorted({a.values.get("zone") for a in members if a.values.get("zone")})
        names.append(None)
        x, lane_h = float(LABEL_W), 90.0
        for zone in names:
            zm = sorted((a for a in members if a.values.get("zone") == zone), key=lambda a: (a.label, a.id))
            if zone is None and not zm and len(names) > 1:
                continue
            cols = max(1, min(MAX_COLS, len(zm)))
            rows = max(1, -(-len(zm) // cols))
            w, h = cols * (NODE_W + GAP) + GAP, ZONE_HEAD + rows * (NODE_H + GAP) + GAP
            zones.append(Box(x, y + LANE_PAD, w, h, zone or "No zone"))
            for i, a in enumerate(zm):
                nodes[a.id] = (
                    Box(
                        x + GAP + (i % cols) * (NODE_W + GAP),
                        y + LANE_PAD + ZONE_HEAD + (i // cols) * (NODE_H + GAP),
                        NODE_W,
                        NODE_H,
                        a.label,
                    ),
                    a,
                )
            x += w + ZONE_GAP
            lane_h = max(lane_h, h + 2 * LANE_PAD)
        width = max(width, x)
        lanes.append((level, y, lane_h))
        y += lane_h
    return (
        [Box(0, ly, width, lh, level_name(lv)) for lv, ly, lh in lanes],
        [lv for lv, _y, _h in lanes],
        zones,
        nodes,
        width,
        y,
    )


def _sub(a: AssetRow) -> str:
    return " · ".join(
        v for v in (a.values.get("asset_type"), a.ips[0] if a.ips and a.values.get("name") else None) if v
    )


def drawio(data: ReportData) -> str:
    lanes, levels, zones, nodes, _w, _h = layout(data)
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for i, (lane, lv) in enumerate(zip(lanes, levels, strict=True)):
        colour = LANE_COLOURS.get(lv, "#f3f4f6")
        cells.append(
            f'<mxCell id="lane{i}" value={quoteattr(lane.label)} style="rounded=0;whiteSpace=wrap;html=0;fillColor={colour};'
            f'strokeColor=#c7ccd6;align=left;verticalAlign=middle;spacingLeft=8;fontStyle=1;" vertex="1" parent="1">'
            f'<mxGeometry x="{lane.x}" y="{lane.y}" width="{lane.w}" height="{lane.h}" as="geometry"/></mxCell>'
        )
    for i, z in enumerate(zones):
        cells.append(
            f'<mxCell id="zone{i}" value={quoteattr(z.label)} style="rounded=1;whiteSpace=wrap;html=0;fillColor=none;'
            f'strokeColor=#5b6b85;dashed={1 if z.label == "No zone" else 0};verticalAlign=top;align=left;spacingLeft=6;fontSize=10;fontStyle=1;" '
            f'vertex="1" parent="1"><mxGeometry x="{z.x}" y="{z.y}" width="{z.w}" height="{z.h}" as="geometry"/></mxCell>'
        )
    for aid, (b, a) in nodes.items():
        label = b.label + ("\n" + _sub(a) if _sub(a) else "")
        cells.append(
            f'<mxCell id="a{aid}" value={quoteattr(label)} style="rounded=1;whiteSpace=wrap;html=0;fillColor=#ffffff;'
            f'strokeColor=#2f5bd3;fontSize=10;" vertex="1" parent="1"><mxGeometry x="{b.x}" y="{b.y}" width="{b.w}" height="{b.h}" as="geometry"/></mxCell>'
        )
    for i, link in enumerate(lk for lk in data.links if lk.is_ot and lk.src in nodes and lk.dst in nodes):
        colour = "#d92d20" if link.ot_writes else "#2f5bd3"
        label = ", ".join(p.protocol for p in link.protocols[:3])
        cells.append(
            f'<mxCell id="e{i}" value={quoteattr(label)} style="endArrow=block;html=0;strokeColor={colour};fontSize=9;" edge="1" '
            f'parent="1" source="a{link.src}" target="a{link.dst}"><mxGeometry relative="1" as="geometry"/></mxCell>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<mxfile host="pcapvis"><diagram id="purdue" name='
        + quoteattr(f"Purdue map – {data.engagement.name}")
        + f'><mxGraphModel grid="1" gridSize="10"><root>{"".join(cells)}</root></mxGraphModel></diagram></mxfile>\n'
    )


def svg(data: ReportData) -> str:
    lanes, levels, zones, nodes, w, h = layout(data)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="Segoe UI, Arial, sans-serif">',
        f"<title>{escape('Purdue map – ' + data.engagement.name)}</title>",
        '<defs><marker id="arr" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker></defs>',
    ]
    for lane, lv in zip(lanes, levels, strict=True):
        out.append(
            f'<rect x="{lane.x}" y="{lane.y}" width="{lane.w}" height="{lane.h}" fill="{LANE_COLOURS.get(lv, "#f3f4f6")}" stroke="#c7ccd6"/>'
            f'<text x="10" y="{lane.y + lane.h / 2}" font-size="12" font-weight="700" fill="#364152">{escape(lane.label)}</text>'
        )
    for z in zones:
        dash = ' stroke-dasharray="5 4"' if z.label == "No zone" else ""
        out.append(
            f'<rect x="{z.x}" y="{z.y}" width="{z.w}" height="{z.h}" rx="6" fill="none" stroke="#5b6b85"{dash}/>'
            f'<text x="{z.x + 6}" y="{z.y + 15}" font-size="10" font-weight="700" fill="#5b6b85">{escape(z.label.upper())}</text>'
        )
    centre = {aid: (b.x + b.w / 2, b.y + b.h / 2) for aid, (b, _a) in nodes.items()}
    for link in data.links:
        if link.is_ot and link.src in centre and link.dst in centre:
            (x1, y1), (x2, y2) = centre[link.src], centre[link.dst]
            colour = "#d92d20" if link.ot_writes else "#2f5bd3"
            out.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{colour}" stroke-width="1.5" marker-end="url(#arr)" opacity="0.8"/>'
            )
    for _aid, (b, a) in nodes.items():
        out.append(
            f'<rect x="{b.x}" y="{b.y}" width="{b.w}" height="{b.h}" rx="4" fill="#ffffff" stroke="#2f5bd3"/>'
            f'<text x="{b.x + 8}" y="{b.y + 18}" font-size="11" font-weight="600" fill="#111827">{escape(b.label[:28])}</text>'
            f'<text x="{b.x + 8}" y="{b.y + 34}" font-size="10" fill="#6b7280">{escape(_sub(a)[:32])}</text>'
        )
    out.append("</svg>")
    return "\n".join(out)
