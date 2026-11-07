"""Asset-to-asset traffic merged across captures (shared by the Purdue map and zone checks)."""

from collections import defaultdict

from pydantic import TypeAdapter
from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.api.schemas import LinkOut
from pcapvis.db.models import AssetLink
from pcapvis.engine import knowledge as K

_LINKS = TypeAdapter(list[LinkOut])
COUNTS = ("flows", "packets", "bytes", "ot_reads", "ot_writes", "ot_errors")


def aggregate_links(db: Session, eid: int) -> list[LinkOut]:
    """All asset-to-asset traffic of an engagement, merged across captures.

    Hot path (Purdue map, dashboard, zone checks, reports): reads plain columns rather than ORM objects and
    builds plain dicts, validated in one pass by pydantic's core (faster than constructing models in Python).
    """
    t = AssetLink
    rows = db.execute(
        select(
            t.src_asset_id,
            t.dst_asset_id,
            t.protocol,
            t.ports,
            t.flows,
            t.packets,
            t.bytes,
            t.ot_reads,
            t.ot_writes,
            t.ot_errors,
            t.first_seen,
            t.last_seen,
            t.capture_id,
        ).where(t.engagement_id == eid)
    )
    # per (src, dst, protocol): [ports set, flows, packets, bytes, reads, writes, errors, first, last, caps]
    per_proto: dict[tuple[int, int, str], list] = {}
    for s, d, proto, ports, fl, pk, by, rd, wr, er, first, last, cap in rows:
        p = per_proto.get((s, d, proto))
        if p is None:
            per_proto[(s, d, proto)] = [set(ports or ()), fl, pk, by, rd, wr, er, first, last, {cap}]
            continue
        p[0].update(ports or ())
        p[1] += fl
        p[2] += pk
        p[3] += by
        p[4] += rd
        p[5] += wr
        p[6] += er
        if first is not None and (p[7] is None or first < p[7]):
            p[7] = first
        if last is not None and (p[8] is None or last > p[8]):
            p[8] = last
        p[9].add(cap)
    pairs: dict[tuple[int, int], list[tuple[str, list]]] = defaultdict(list)
    for (s, d, proto), p in per_proto.items():
        pairs[(s, d)].append((proto, p))
    ot = K.OT_PROTOCOLS
    out = []
    for (s, d), protos in sorted(pairs.items()):
        protos.sort(key=lambda x: (-x[1][2], x[0]))
        tot = [0] * 6
        firsts, lasts, caps, plist, is_ot = [], [], set(), [], False
        for n, p in protos:
            counts = p[1:7]
            for i, v in enumerate(counts):
                tot[i] += v
            if p[7] is not None:
                firsts.append(p[7])
            if p[8] is not None:
                lasts.append(p[8])
            caps |= p[9]
            is_ot = is_ot or n in ot
            plist.append(
                {"protocol": n, "ports": sorted(p[0])[:20], **dict(zip(COUNTS, counts, strict=True))}
            )
        out.append(
            {
                "src": s,
                "dst": d,
                "protocols": plist,
                "is_ot": is_ot or tot[3] + tot[4] > 0,
                **dict(zip(COUNTS, tot, strict=True)),
                "first_seen": min(firsts, default=None),
                "last_seen": max(lasts, default=None),
                "captures": sorted(caps),
            }
        )
    return _LINKS.validate_python(out)
