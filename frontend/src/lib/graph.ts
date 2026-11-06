/**
 * Deterministic graph layout: the busiest nodes in the middle, the rest on concentric rings.
 * Good enough for a few hundred assets without a physics simulation (and stable between renders).
 */
export function ringLayout(ids: number[], degree: Map<number, number>, spacing = 150): Map<number, { x: number; y: number }> {
  const sorted = [...ids].sort((a, b) => (degree.get(b) ?? 0) - (degree.get(a) ?? 0) || a - b)
  const out = new Map<number, { x: number; y: number }>()
  let i = 0
  let ring = 0
  while (i < sorted.length) {
    const capacity = ring === 0 ? 1 : ring * 8
    const members = sorted.slice(i, i + capacity)
    members.forEach((id, k) => {
      const angle = (2 * Math.PI * k) / members.length - Math.PI / 2
      out.set(id, { x: Math.round(Math.cos(angle) * ring * spacing) + 0, y: Math.round(Math.sin(angle) * ring * spacing) + 0 }) // + 0 turns -0 into 0
    })
    i += capacity
    ring++
  }
  return out
}
