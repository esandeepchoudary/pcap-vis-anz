import { expect, it } from 'vitest'
import type { Asset } from '../api/client'
import { G_NODE_H, G_NODE_W, subnetLayout, subnetOf } from './graph'

const asset = (id: number, ip: string, extra: Partial<Asset> = {}): Asset => ({
  id, origin: 'observed', version: 1, ips: ip ? [ip] : [], macs: [], name: null, asset_type: null, purdue_level: 1, zone: null,
  criticality: null, vendor: null, model: null, firmware: null, serial: null, location: null, owner: null, tags: [], notes: null,
  overridden: [], type_confidence: null, mac_vendor: null, is_private: true, protocols: [], ot_role: 'unknown', os_hint: null,
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
