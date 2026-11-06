import type { Asset, Link } from '../api/client'
import { assetLabel } from './assets'

/** Lanes top to bottom. Standard levels always show (so you can drop into them); others only when used. */
export const LANES: { level: number; always: boolean }[] = [
  { level: 6, always: false },
  { level: 5, always: true },
  { level: 4, always: true },
  { level: 3.5, always: true },
  { level: 3, always: true },
  { level: 2, always: true },
  { level: 1, always: true },
  { level: 0, always: true },
  { level: -1, always: false },
]

export const NODE_W = 176
export const NODE_H = 46
const GAP = 10
const ZONE_HEAD = 26
const ZONE_GAP = 20
const LANE_PAD = 14
const LABEL_W = 150
const MAX_COLS = 4
const MIN_LANE_H = 92
const MIN_W = 900

export type Rect = { x: number; y: number; w: number; h: number }
export type ZoneBox = Rect & { level: number; zone: string | null; key: string }
export type LaneBox = Rect & { level: number }
export type Layout = {
  lanes: LaneBox[]
  zones: ZoneBox[]
  positions: Map<number, { x: number; y: number }>
  width: number
  height: number
}

export const zoneKey = (level: number, zone: string | null) => `${level}|${zone ?? ''}`

/**
 * Deterministic Purdue layout: one lane per level, one box per zone inside it (plus "No zone"),
 * assets in a grid inside their zone box, sorted by name.
 */
export function layoutPurdue(assets: Asset[], extraZones: { level: number; zone: string }[] = []): Layout {
  const byZone = new Map<string, Asset[]>()
  for (const a of assets) {
    const k = zoneKey(a.purdue_level, a.zone)
    byZone.set(k, [...(byZone.get(k) ?? []), a])
  }
  for (const z of extraZones) if (!byZone.has(zoneKey(z.level, z.zone))) byZone.set(zoneKey(z.level, z.zone), [])
  const used = new Set(assets.map((a) => a.purdue_level))
  for (const z of extraZones) used.add(z.level)

  const lanes: LaneBox[] = []
  const zones: ZoneBox[] = []
  const positions = new Map<number, { x: number; y: number }>()
  let y = 0
  let width = MIN_W
  for (const { level, always } of LANES) {
    if (!always && !used.has(level)) continue
    const keys = [...byZone.keys()].filter((k) => Number(k.split('|')[0]) === level)
    // Named zones alphabetically, "No zone" last; an empty lane still gets a "No zone" drop box.
    const names = keys.map((k) => k.slice(k.indexOf('|') + 1) || null)
      .sort((a, b) => (a === null ? 1 : b === null ? -1 : a.localeCompare(b)))
    if (!names.includes(null)) names.push(null)
    let x = LABEL_W
    let laneH = MIN_LANE_H
    for (const zone of names) {
      const members = (byZone.get(zoneKey(level, zone)) ?? []).slice()
        .sort((a, b) => assetLabel(a).localeCompare(assetLabel(b), undefined, { numeric: true }) || a.id - b.id)
      const cols = Math.max(1, Math.min(MAX_COLS, members.length))
      const rows = Math.max(1, Math.ceil(members.length / cols))
      const w = cols * (NODE_W + GAP) + GAP
      const h = ZONE_HEAD + rows * (NODE_H + GAP) + GAP
      const box: ZoneBox = { x, y: y + LANE_PAD, w, h, level, zone, key: zoneKey(level, zone) }
      zones.push(box)
      members.forEach((a, i) => {
        positions.set(a.id, {
          x: box.x + GAP + (i % cols) * (NODE_W + GAP),
          y: box.y + ZONE_HEAD + Math.floor(i / cols) * (NODE_H + GAP),
        })
      })
      x += w + ZONE_GAP
      laneH = Math.max(laneH, h + 2 * LANE_PAD)
    }
    width = Math.max(width, x)
    lanes.push({ x: 0, y, w: 0, h: laneH, level })
    y += laneH
  }
  for (const l of lanes) l.w = width
  return { lanes, zones, positions, width, height: y }
}

/** Where a dragged node's centre landed: a zone box, else just a lane, else nowhere. */
export function dropTarget(layout: Layout, cx: number, cy: number): { level: number; zone?: string | null } | null {
  const inside = (r: Rect) => cx >= r.x && cx <= r.x + r.w && cy >= r.y && cy <= r.y + r.h
  const zone = layout.zones.find(inside)
  if (zone) return { level: zone.level, zone: zone.zone }
  const lane = layout.lanes.find((l) => cy >= l.y && cy <= l.y + l.h)
  return lane ? { level: lane.level } : null
}

/**
 * Traffic that bypasses the industrial DMZ: business/enterprise/external (L4 and up) talking directly
 * to site operations or below (L3 and down). Unclassified assets are never flagged.
 */
export function bypassesDmz(a: number, b: number): boolean {
  if (a < 0 || b < 0) return false
  return (a >= 4 && b <= 3) || (b >= 4 && a <= 3)
}

export type MatrixCell = { links: Link[]; writes: number; ot: number }

/** Links between levels: rows = client level, columns = server level. */
export function levelMatrix(links: Link[], assets: Map<number, Asset>): Map<string, MatrixCell> {
  const m = new Map<string, MatrixCell>()
  for (const l of links) {
    const s = assets.get(l.src)
    const d = assets.get(l.dst)
    if (!s || !d) continue
    const k = `${s.purdue_level}|${d.purdue_level}`
    const cell = m.get(k) ?? { links: [], writes: 0, ot: 0 }
    cell.links.push(l)
    cell.writes += l.ot_writes
    if (l.is_ot) cell.ot++
    m.set(k, cell)
  }
  return m
}
