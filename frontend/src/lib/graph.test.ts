import { describe, expect, it } from 'vitest'
import type { Asset, Finding } from '../api/client'
import {
  G_NODE_H, G_NODE_W, MULTI_VLAN, UNTAGGED, activeIn, forceLayout, isCrossVlan, nodeRadius, subnetLayout, subnetOf, suspiciousPairs,
  timeBounds, vlanLayout, vlanOf, vlanStats,
} from './graph'

const asset = (id: number, ip: string, extra: Partial<Asset> = {}): Asset => ({
  id, origin: 'observed', version: 1, ips: ip ? [ip] : [], macs: [], name: null, asset_type: null, purdue_level: 1, zone: null,
  criticality: null, vendor: null, model: null, firmware: null, serial: null, location: null, owner: null, tags: [], notes: null,
  overridden: [], type_confidence: null, mac_vendor: null, is_private: true, protocols: [], vlans: [], ot_role: 'unknown', os_hint: null,
  packets: 0, bytes: 0, first_seen: null, last_seen: null, capture_count: 1, updated_at: '', ...extra,
})

it('groups assets by subnet', () => {
  expect(subnetOf(asset(1, '10.0.2.51'))).toBe('10.0.2.0/24')
  expect(subnetOf(asset(2, '8.8.8.8', { is_private: false }))).toBe('External')
  expect(subnetOf(asset(3, 'fe80::1'))).toBe('IPv6 / other')
  expect(subnetOf(asset(4, ''))).toBe('No address')
})

it('places every asset inside its subnet box without overlaps, busiest subnet first', () => {
  const assets = [
    ...Array.from({ length: 12 }, (_, i) => asset(i + 1, `10.0.1.${i + 1}`)),
    asset(50, '10.0.2.50'), asset(51, '10.0.2.51'), asset(99, '8.8.8.8', { is_private: false }),
  ]
  const degree = new Map([[50, 9], [51, 9]])
  const { groups, positions } = subnetLayout(assets, degree, (k) => (k === '10.0.2.0/24' ? [20] : []))
  expect(groups.map((g) => g.key)).toEqual(['10.0.2.0/24', '10.0.1.0/24', 'External'])
  expect(groups[0].label).toBe('10.0.2.0/24 · VLAN 20 · 2')
  const rects = assets.map((a) => ({ a, ...positions.get(a.id)! }))
  for (const r of rects) {
    const g = groups.find((x) => x.key === subnetOf(r.a))!
    expect(r.x >= g.x && r.x + G_NODE_W <= g.x + g.w && r.y >= g.y && r.y + G_NODE_H <= g.y + g.h).toBe(true)
  }
  for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) {
    const [p, q] = [rects[i], rects[j]]
    expect(p.x < q.x + G_NODE_W && q.x < p.x + G_NODE_W && p.y < q.y + G_NODE_H && q.y < p.y + G_NODE_H).toBe(false)
  }
})

describe('forceLayout', () => {
  const items = [
    ...Array.from({ length: 8 }, (_, i) => ({ id: i + 1, group: '10.0.1.0/24', radius: 16 })),
    ...Array.from({ length: 6 }, (_, i) => ({ id: i + 20, group: '10.0.2.0/24', radius: 20 })),
    { id: 99, group: 'External', radius: 14 },
  ]
  const links = [
    ...Array.from({ length: 7 }, (_, i) => ({ src: 1, dst: i + 2, weight: 1 })),
    ...Array.from({ length: 5 }, (_, i) => ({ src: 20, dst: i + 21, weight: 1 })),
    { src: 1, dst: 20, weight: 1 }, { src: 5, dst: 99, weight: 1 },
  ]
  const pos = forceLayout(items, links)
  const d = (a: number, b: number) => Math.hypot(pos.get(a)!.x - pos.get(b)!.x, pos.get(a)!.y - pos.get(b)!.y)

  it('is deterministic and finite', () => {
    expect(forceLayout([...items].reverse(), links)).toEqual(pos)
    for (const p of pos.values()) expect(Number.isFinite(p.x) && Number.isFinite(p.y)).toBe(true)
  })
  it('keeps nodes apart', () => {
    for (const a of items) for (const b of items) if (a.id < b.id) expect(d(a.id, b.id)).toBeGreaterThan(a.radius + b.radius)
  })
  it('keeps subnets together', () => {
    const avg = (pairs: [number, number][]) => pairs.reduce((n, [a, b]) => n + d(a, b), 0) / pairs.length
    const within = avg([[2, 3], [4, 6], [21, 22], [23, 24]])
    const across = avg([[2, 21], [3, 22], [6, 24], [7, 25]])
    expect(within).toBeLessThan(across)
  })
})

it('nodeRadius grows with traffic within bounds', () => {
  expect(nodeRadius(0, 1000)).toBe(14)
  expect(nodeRadius(1000, 1000)).toBe(30)
  expect(nodeRadius(30, 1000)).toBeGreaterThan(14)
})

it('suspiciousPairs links assets named by open findings only', () => {
  const f = (asset_ids: number[], status: Finding['status'] = 'open') => ({ asset_ids, status }) as Finding
  const s = suspiciousPairs([f([1, 2]), f([3, 4], 'false_positive'), f([5])])
  expect([...s].sort()).toEqual(['1-2', '2-1'])
})

describe('VLANs', () => {
  const v = (id: number, vlans: number[]) => asset(id, `10.0.0.${id}`, { vlans })
  const list = [v(1, [10]), v(2, [10]), v(3, [20]), v(4, [10, 20]), v(5, [])]
  it('names the group an asset belongs to', () => {
    expect(list.map(vlanOf)).toEqual(['VLAN 10', 'VLAN 10', 'VLAN 20', MULTI_VLAN, UNTAGGED])
  })
  it('counts traffic crossing VLANs only when both ends are tagged and share none', () => {
    expect(isCrossVlan(list[0], list[2])).toBe(true)
    expect(isCrossVlan(list[0], list[1])).toBe(false)
    expect(isCrossVlan(list[3], list[2])).toBe(false) // the trunk is on 20 too
    expect(isCrossVlan(list[0], list[4])).toBe(false) // untagged: unknown
    const s = vlanStats(list, [{ src: 1, dst: 3 }, { src: 1, dst: 2 }, { src: 3, dst: 1 }, { src: 4, dst: 3 }, { src: 9, dst: 1 }])
    expect(s).toMatchObject({ vlans: [10, 20], crossLinks: 2, untagged: 1, multi: 1 })
    expect(Object.fromEntries(s.matrix)).toEqual({ '10-20': 2, '10-10': 1 })
  })
  it('lays out one box per VLAN, trunks and untagged last', () => {
    const g = vlanLayout(list, new Map())
    expect(g.groups.map((x) => x.key)).toEqual(['VLAN 10', 'VLAN 20', MULTI_VLAN, UNTAGGED])
    expect(g.groups[0].label).toBe('VLAN 10 · 2')
    expect(g.positions.size).toBe(5)
  })
})

describe('timeline', () => {
  it('spans the links that have times', () => {
    expect(timeBounds([{ first_seen: 5, last_seen: 9 }, { first_seen: 2, last_seen: 4 }, { first_seen: null, last_seen: null }])).toEqual([2, 9])
    expect(timeBounds([{ first_seen: 3, last_seen: 3 }])).toBeNull()
    expect(timeBounds([])).toBeNull()
  })
  it('keeps connections active at some point in the window', () => {
    const l = { first_seen: 10, last_seen: 20 }
    expect(activeIn(l, 0, 9)).toBe(false)
    expect(activeIn(l, 0, 10)).toBe(true)
    expect(activeIn(l, 15, 16)).toBe(true)
    expect(activeIn(l, 21, 30)).toBe(false)
    expect(activeIn({ first_seen: null, last_seen: null }, 21, 30)).toBe(true)
  })
})
