import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationNodeDatum } from 'd3-force'
import type { Asset, Finding, Link } from '../api/client'
import { assetLabel } from './assets'

export const G_NODE_W = 150
export const G_NODE_H = 36
const GAP_X = 36 // room for connections between assets of one subnet to be seen
const GAP_Y = 34
const HEAD = 34
const PAD = 10
const BOX_GAP = 70
const MAX_COLS = 3
const ROW_WIDTH = 1500

export type Group = { key: string; label: string; x: number; y: number; w: number; h: number }
export type GraphLayout = { groups: Group[]; positions: Map<number, { x: number; y: number }> }

/** The network an asset sits on: its first private IPv4 /24, else "external" / "IPv6" / "no address". */
export function subnetOf(a: Asset): string {
  const v4 = a.ips.filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip))
  const priv = v4.find((ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip))
  if (priv) return priv.split('.').slice(0, 3).join('.') + '.0/24'
  if (!a.is_private) return 'External'
  if (a.ips.length) return 'IPv6 / other'
  return 'No address'
}

/**
 * Subnet boxes with their assets in a small grid, boxes placed left to right in rows (busiest subnet
 * first). Deterministic and overlap-free by construction, unlike a free-form layout.
 */
export function subnetLayout(assets: Asset[], degree: Map<number, number>, vlansOf: (key: string) => number[] = () => []): GraphLayout {
  return groupLayout(assets, degree, subnetOf, (k) => (k === 'External' ? 2 : k.includes('/24') ? 0 : 1),
    (key, n) => { const vlans = vlansOf(key); return `${key}${vlans.length ? ` · VLAN ${vlans.join(', ')}` : ''} · ${n}` })
}

/** Boxes of assets grouped by VLAN tag: one per VLAN, then hosts on several VLANs (trunks, routers), then untagged. */
export function vlanLayout(assets: Asset[], degree: Map<number, number>): GraphLayout {
  return groupLayout(assets, degree, vlanOf, (k) => (k === MULTI_VLAN ? 1 : k === UNTAGGED ? 2 : 0), (key, n) => `${key} · ${n}`)
}

/** Grid of group boxes; ``rank`` puts special groups last, then busiest first. Overlap-free by construction. */
function groupLayout(
  assets: Asset[], degree: Map<number, number>, keyOf: (a: Asset) => string, rank: (key: string) => number,
  label: (key: string, n: number) => string,
): GraphLayout {
  const groups = new Map<string, Asset[]>()
  for (const a of assets) groups.set(keyOf(a), [...(groups.get(keyOf(a)) ?? []), a])
  const weight = (list: Asset[]) => list.reduce((n, a) => n + (degree.get(a.id) ?? 0), 0)
  const ordered = [...groups.entries()].sort((x, y) => {
    const special = rank
    return special(x[0]) - special(y[0]) || weight(y[1]) - weight(x[1]) || x[0].localeCompare(y[0], undefined, { numeric: true })
  })
  const out: Group[] = []
  const positions = new Map<number, { x: number; y: number }>()
  let x = 0
  let y = 0
  let rowH = 0
  for (const [key, list] of ordered) {
    list.sort((p, q) => (degree.get(q.id) ?? 0) - (degree.get(p.id) ?? 0) || assetLabel(p).localeCompare(assetLabel(q), undefined, { numeric: true }))
    const cols = Math.min(MAX_COLS, Math.max(1, Math.ceil(Math.sqrt(list.length))))
    const rows = Math.ceil(list.length / cols)
    const w = PAD * 2 + cols * G_NODE_W + (cols - 1) * GAP_X
    const h = HEAD + PAD + rows * G_NODE_H + (rows - 1) * GAP_Y
    if (x > 0 && x + w > ROW_WIDTH) { x = 0; y += rowH + BOX_GAP; rowH = 0 }
    out.push({ key, label: label(key, list.length), x, y, w, h })
    list.forEach((a, i) => positions.set(a.id, { x: x + PAD + (i % cols) * (G_NODE_W + GAP_X), y: y + HEAD + Math.floor(i / cols) * (G_NODE_H + GAP_Y) }))
    x += w + BOX_GAP
    rowH = Math.max(rowH, h)
  }
  return { groups: out, positions }
}

// ── Force layout (default graph view) ────────────────────────────────────────


export type ForceItem = { id: number; group: string; radius: number }
type SimNode = SimulationNodeDatum & ForceItem

/** Circle radius from traffic volume: busy devices stand out (14–30 px), like the v1 graph. */
export function nodeRadius(packets: number, maxPackets: number): number {
  return Math.round(14 + 16 * (Math.log1p(packets) / Math.log1p(Math.max(1, maxPackets))))
}

/**
 * Force-directed layout that still keeps each subnet together: links pull talkers together, nodes repel and never
 * overlap, and a gentle pull draws each subnet towards its own anchor (external hosts on the outside).
 * Deterministic: d3 seeds its initial placement and randomness, and we run a fixed number of ticks.
 */
export function forceLayout(items: ForceItem[], links: { src: number; dst: number; weight: number }[]): Map<number, { x: number; y: number }> {
  const nodes: SimNode[] = [...items].sort((a, b) => a.id - b.id).map((n) => ({ ...n }))
  const groups = [...new Set(nodes.map((n) => n.group))].sort((a, b) => (a === 'External') === (b === 'External') ? a.localeCompare(b, undefined, { numeric: true }) : a === 'External' ? 1 : -1)
  const internal = groups.filter((g) => g !== 'External')
  const spread = 180 + 60 * Math.sqrt(nodes.length)
  const anchor = new Map<string, { x: number; y: number }>()
  internal.forEach((g, i) => {
    const a = internal.length === 1 ? 0 : (2 * Math.PI * i) / internal.length
    const r = internal.length === 1 ? 0 : spread * 0.55
    anchor.set(g, { x: Math.cos(a) * r, y: Math.sin(a) * r })
  })
  anchor.set('External', { x: spread * 1.4, y: 0 })
  const ids = new Set(nodes.map((n) => n.id))
  const simLinks = links.filter((l) => ids.has(l.src) && ids.has(l.dst) && l.src !== l.dst)
    .map((l) => ({ source: l.src, target: l.dst, weight: l.weight }))
  const sim = forceSimulation(nodes)
    .force('link', forceLink<SimNode, (typeof simLinks)[number]>(simLinks).id((d) => d.id).distance(110).strength(0.25))
    .force('charge', forceManyBody().strength(-260).distanceMax(600))
    .force('collide', forceCollide<SimNode>().radius((d) => d.radius + 34).iterations(2))
    .force('x', forceX<SimNode>((d) => anchor.get(d.group)!.x).strength(0.08))
    .force('y', forceY<SimNode>((d) => anchor.get(d.group)!.y).strength(0.08))
    .stop()
  for (let i = 0; i < 400; i++) sim.tick()
  return new Map(nodes.map((n) => [n.id, { x: Math.round(n.x ?? 0), y: Math.round(n.y ?? 0) }]))
}

/** Asset pairs named together by an open finding: their connection is drawn as suspicious. */
export function suspiciousPairs(findings: Finding[]): Set<string> {
  const out = new Set<string>()
  for (const f of findings) {
    if (f.status === 'false_positive' || f.status === 'resolved' || f.asset_ids.length < 2) continue
    for (const a of f.asset_ids) for (const b of f.asset_ids) if (a !== b) out.add(`${a}-${b}`)
  }
  return out
}

export const linkKey = (l: Pick<Link, 'src' | 'dst'>) => `${l.src}-${l.dst}`

// ── VLANs ────────────────────────────────────────────────────────────────────

export const UNTAGGED = 'Untagged'
export const MULTI_VLAN = 'Several VLANs'

export function vlanOf(a: Pick<Asset, 'vlans'>): string {
  if (!a.vlans.length) return UNTAGGED
  return a.vlans.length === 1 ? `VLAN ${a.vlans[0]}` : MULTI_VLAN
}

/** Both ends tagged and sharing no VLAN: the traffic was routed between segments. */
export function isCrossVlan(a: Pick<Asset, 'vlans'>, b: Pick<Asset, 'vlans'>): boolean {
  return a.vlans.length > 0 && b.vlans.length > 0 && !a.vlans.some((v) => b.vlans.includes(v))
}

export type VlanStats = {
  vlans: number[]
  crossLinks: number
  untagged: number
  multi: number
  /** connections between single-VLAN assets, keyed "low-high" VLAN pair (same VLAN: "v-v") */
  matrix: Map<string, number>
}

export function vlanStats(assets: Asset[], links: Pick<Link, 'src' | 'dst'>[]): VlanStats {
  const byId = new Map(assets.map((a) => [a.id, a]))
  const vlans = [...new Set(assets.flatMap((a) => a.vlans))].sort((x, y) => x - y)
  const matrix = new Map<string, number>()
  let crossLinks = 0
  for (const l of links) {
    const a = byId.get(l.src)
    const b = byId.get(l.dst)
    if (!a || !b) continue
    if (isCrossVlan(a, b)) crossLinks++
    if (a.vlans.length === 1 && b.vlans.length === 1) {
      const [x, y] = [a.vlans[0], b.vlans[0]].sort((p, q) => p - q)
      matrix.set(`${x}-${y}`, (matrix.get(`${x}-${y}`) ?? 0) + 1)
    }
  }
  return {
    vlans, crossLinks, matrix,
    untagged: assets.filter((a) => !a.vlans.length).length,
    multi: assets.filter((a) => a.vlans.length > 1).length,
  }
}

// ── Timeline ─────────────────────────────────────────────────────────────────

/** Earliest first-seen and latest last-seen over the links, or null when there's no usable span. */
export function timeBounds(links: Pick<Link, 'first_seen' | 'last_seen'>[]): [number, number] | null {
  let lo = Infinity
  let hi = -Infinity
  for (const l of links) {
    if (l.first_seen != null) lo = Math.min(lo, l.first_seen)
    if (l.last_seen != null) hi = Math.max(hi, l.last_seen)
  }
  return Number.isFinite(lo) && Number.isFinite(hi) && hi > lo ? [lo, hi] : null
}

/** The connection was active at some point in [from, to]. Links without times always count. */
export function activeIn(l: Pick<Link, 'first_seen' | 'last_seen'>, from: number, to: number): boolean {
  return (l.first_seen == null || l.first_seen <= to) && (l.last_seen == null || l.last_seen >= from)
}
