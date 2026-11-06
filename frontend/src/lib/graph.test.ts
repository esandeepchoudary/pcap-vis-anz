import { expect, it } from 'vitest'
import { ringLayout } from './graph'

it('puts the busiest node in the middle and the rest on rings without collisions', () => {
  const ids = Array.from({ length: 20 }, (_, i) => i + 1)
  const degree = new Map(ids.map((id) => [id, id === 7 ? 50 : 1]))
  const pos = ringLayout(ids, degree)
  expect(pos.get(7)).toEqual({ x: 0, y: 0 })
  const keys = new Set([...pos.values()].map((p) => `${p.x},${p.y}`))
  expect(keys.size).toBe(20)
  expect(ringLayout([...ids].reverse(), degree)).toEqual(pos) // order-independent
})
