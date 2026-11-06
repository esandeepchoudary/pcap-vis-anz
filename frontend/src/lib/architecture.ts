import type { Violation, Zone } from '../api/client'

export const ZONE_W = 230
export const ZONE_H = 120
const GAP_X = 70
const GAP_Y = 90
const ORDER = [6, 5, 4, 3.5, 3, 2, 1, 0]

/** Saved positions win; other zones are placed in rows by Purdue level (top: enterprise), then by name. */
export function zonePositions(zones: Zone[], levelOf: (z: Zone) => number | null): Map<string, { x: number; y: number }> {
  const out = new Map<string, { x: number; y: number }>()
  const rows = new Map<number, Zone[]>()
  for (const z of zones) {
    if (z.x != null && z.y != null) {
      out.set(z.name, { x: z.x, y: z.y })
      continue
    }
    const lvl = levelOf(z)
    const row = lvl == null ? ORDER.length : Math.max(0, ORDER.indexOf(lvl))
    rows.set(row, [...(rows.get(row) ?? []), z])
  }
  for (const [row, list] of rows) {
    list.sort((a, b) => a.name.localeCompare(b.name))
    list.forEach((z, i) => out.set(z.name, { x: i * (ZONE_W + GAP_X), y: row * (ZONE_H + GAP_Y) }))
  }
  return out
}

/** Violations folded per zone pair (unordered), for drawing one edge per pair. */
export function violationPairs(vs: Violation[]): { a: string; b: string; count: number; writes: number; protocols: string[] }[] {
  const m = new Map<string, { a: string; b: string; count: number; writes: number; protocols: Set<string> }>()
  for (const v of vs) {
    const [a, b] = [v.src_zone, v.dst_zone].sort()
    const k = `${a}\u0000${b}`
    const cur = m.get(k) ?? { a, b, count: 0, writes: 0, protocols: new Set<string>() }
    cur.count++
    cur.writes += v.ot_writes
    for (const p of v.protocols) cur.protocols.add(p)
    m.set(k, cur)
  }
  return [...m.values()].map((x) => ({ ...x, protocols: [...x.protocols].sort() }))
}
