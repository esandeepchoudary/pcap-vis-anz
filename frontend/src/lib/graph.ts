import type { Asset } from '../api/client'
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
  const groups = new Map<string, Asset[]>()
  for (const a of assets) groups.set(subnetOf(a), [...(groups.get(subnetOf(a)) ?? []), a])
  const weight = (list: Asset[]) => list.reduce((n, a) => n + (degree.get(a.id) ?? 0), 0)
  const ordered = [...groups.entries()].sort((x, y) => {
    const special = (k: string) => (k === 'External' ? 2 : k.includes('/24') ? 0 : 1)
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
    const vlans = vlansOf(key)
    out.push({ key, label: `${key}${vlans.length ? ` · VLAN ${vlans.join(', ')}` : ''} · ${list.length}`, x, y, w, h })
    list.forEach((a, i) => positions.set(a.id, { x: x + PAD + (i % cols) * (G_NODE_W + GAP_X), y: y + HEAD + Math.floor(i / cols) * (G_NODE_H + GAP_Y) }))
    x += w + BOX_GAP
    rowH = Math.max(rowH, h)
  }
  return { groups: out, positions }
}
