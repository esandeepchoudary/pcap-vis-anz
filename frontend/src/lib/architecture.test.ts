import { describe, expect, it } from 'vitest'
import type { Violation, Zone } from '../api/client'
import { violationPairs, zonePositions } from './architecture'

const z = (name: string, extra: Partial<Zone> = {}): Zone =>
  ({ id: 1, name, defined: true, purdue_level: null, security_level: null, description: '', x: null, y: null, asset_ids: [], ...extra })

describe('zonePositions', () => {
  it('keeps saved positions and lays out the rest in rows by level, enterprise on top', () => {
    const pos = zonePositions([z('Cell', { purdue_level: 1 }), z('DMZ', { purdue_level: 3.5 }), z('Moved', { x: 5, y: 6 }), z('Loose')],
      (zone) => zone.purdue_level)
    expect(pos.get('Moved')).toEqual({ x: 5, y: 6 })
    expect(pos.get('DMZ')!.y).toBeLessThan(pos.get('Cell')!.y)
    expect(pos.get('Loose')!.y).toBeGreaterThan(pos.get('Cell')!.y) // no level: bottom row
  })
  it('places zones of one level side by side, by name', () => {
    const pos = zonePositions([z('B', { purdue_level: 2 }), z('A', { purdue_level: 2 })], (zone) => zone.purdue_level)
    expect(pos.get('A')!.x).toBeLessThan(pos.get('B')!.x)
    expect(pos.get('A')!.y).toBe(pos.get('B')!.y)
  })
})

it('violationPairs folds both directions into one pair', () => {
  const v = (src_zone: string, dst_zone: string, protocols: string[], ot_writes = 0): Violation =>
    ({ kind: 'no_conduit', src: 1, dst: 2, src_zone, dst_zone, conduit_id: null, protocols, flows: 1, packets: 1, ot_writes, first_seen: 0, last_seen: 0 })
  expect(violationPairs([v('A', 'B', ['HTTP']), v('B', 'A', ['Modbus'], 2)])).toEqual([
    { a: 'A', b: 'B', count: 2, writes: 2, protocols: ['HTTP', 'Modbus'] },
  ])
})
