import { describe, expect, it } from 'vitest'
import type { Asset, Link } from '../api/client'
import { NODE_H, NODE_W, bypassesDmz, dropTarget, layoutPurdue, levelMatrix } from './purdue'

const base: Asset = {
  id: 0, origin: 'observed', version: 1, ips: [], macs: [], name: null, asset_type: null, purdue_level: -1, zone: null,
  criticality: null, vendor: null, model: null, firmware: null, serial: null, location: null, owner: null, tags: [],
  notes: null, overridden: [], type_confidence: null, mac_vendor: null, is_private: true, protocols: [], ot_role: 'unknown',
  os_hint: null, packets: 0, bytes: 0, first_seen: null, last_seen: null, capture_count: 1, updated_at: '',
}
const asset = (id: number, level: number, zone: string | null = null, name?: string): Asset =>
  ({ ...base, id, purdue_level: level, zone, name: name ?? null, ips: [`10.0.0.${id}`] })

describe('layoutPurdue', () => {
  it('always shows the standard lanes top to bottom, and external/unclassified only when used', () => {
    expect(layoutPurdue([]).lanes.map((l) => l.level)).toEqual([5, 4, 3.5, 3, 2, 1, 0])
    expect(layoutPurdue([asset(1, 6), asset(2, -1)]).lanes.map((l) => l.level)).toEqual([6, 5, 4, 3.5, 3, 2, 1, 0, -1])
  })

  it('puts each zone in its own box, named zones first and "No zone" last', () => {
    const l = layoutPurdue([asset(1, 1, 'Line B'), asset(2, 1), asset(3, 1, 'Line A'), asset(4, 2)])
    expect(l.zones.filter((z) => z.level === 1).map((z) => z.zone)).toEqual(['Line A', 'Line B', null])
    const empty = l.zones.find((z) => z.level === 3)!
    expect(empty.zone).toBeNull() // empty lanes still get a drop box
  })

  it('places every asset inside its zone box without overlaps', () => {
    const assets = Array.from({ length: 23 }, (_, i) => asset(i + 1, i % 3, i % 2 ? 'Cell' : null, `dev-${i}`))
    const l = layoutPurdue(assets)
    const rects = assets.map((a) => ({ a, ...l.positions.get(a.id)! }))
    for (const r of rects) {
      const box = l.zones.find((z) => z.level === r.a.purdue_level && z.zone === r.a.zone)!
      expect(r.x).toBeGreaterThanOrEqual(box.x)
      expect(r.x + NODE_W).toBeLessThanOrEqual(box.x + box.w)
      expect(r.y + NODE_H).toBeLessThanOrEqual(box.y + box.h)
    }
    for (let i = 0; i < rects.length; i++) {
      for (let j = i + 1; j < rects.length; j++) {
        const [p, q] = [rects[i], rects[j]]
        const overlap = p.x < q.x + NODE_W && q.x < p.x + NODE_W && p.y < q.y + NODE_H && q.y < p.y + NODE_H
        expect(overlap).toBe(false)
      }
    }
  })

  it('is deterministic and sorts by name', () => {
    const a = [asset(2, 1, null, 'plc-10'), asset(1, 1, null, 'plc-2')]
    const l1 = layoutPurdue(a)
    expect(l1.positions.get(1)!.x).toBeLessThan(l1.positions.get(2)!.x) // natural sort: plc-2 before plc-10
    expect(layoutPurdue([...a].reverse()).positions).toEqual(l1.positions)
  })

  it('shows zones created on the map before any asset is in them', () => {
    const l = layoutPurdue([], [{ level: 2, zone: 'New cell' }])
    expect(l.zones.some((z) => z.level === 2 && z.zone === 'New cell')).toBe(true)
  })
})

describe('dropTarget', () => {
  const l = layoutPurdue([asset(1, 1, 'Cell A'), asset(2, 2)])
  it('finds the zone box under the point', () => {
    const box = l.zones.find((z) => z.zone === 'Cell A')!
    expect(dropTarget(l, box.x + 5, box.y + 5)).toEqual({ level: 1, zone: 'Cell A' })
  })
  it('falls back to the lane (level only) between boxes', () => {
    const lane = l.lanes.find((x) => x.level === 4)!
    expect(dropTarget(l, 5, lane.y + lane.h / 2)).toEqual({ level: 4 })
  })
  it('returns null outside the map', () => {
    expect(dropTarget(l, 5, l.height + 50)).toBeNull()
  })
})

describe('bypassesDmz', () => {
  it.each([
    [4, 1, true], [1, 4, true], [6, 2, true], [4, 3, true], [5, 0, true],
    [3, 1, false], [4, 3.5, false], [3.5, 2, false], [4, 5, false], [-1, 1, false], [4, -1, false],
  ])('%s ↔ %s → %s', (a, b, expected) => expect(bypassesDmz(a, b)).toBe(expected))
})

it('levelMatrix counts pairs, OT links and writes per level pair', () => {
  const assets = new Map([asset(1, 3), asset(2, 1), asset(3, 4)].map((a) => [a.id, a]))
  const link = (src: number, dst: number, is_ot: boolean, ot_writes = 0) =>
    ({ src, dst, is_ot, ot_writes, protocols: [], flows: 1, packets: 1, bytes: 1, ot_reads: 0, ot_errors: 0, first_seen: 0, last_seen: 0, captures: [1] }) as Link
  const m = levelMatrix([link(1, 2, true, 3), link(3, 2, false), link(9, 2, true)], assets)
  expect(m.get('3|1')).toMatchObject({ writes: 3, ot: 1 })
  expect(m.get('4|1')!.links).toHaveLength(1)
  expect(m.size).toBe(2) // links to unknown assets are skipped
})
