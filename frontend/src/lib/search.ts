import type { Asset, Engagement, Finding, Zone } from '../api/client'
import { assetLabel } from './assets'

export type SearchHit =
  | { kind: 'asset'; id: number; label: string; sub: string; score: number }
  | { kind: 'finding'; key: string; label: string; sub: string; score: number }
  | { kind: 'zone'; id: number; label: string; sub: string; score: number }
  | { kind: 'engagement'; id: number; label: string; sub: string; score: number }

export const MAX_HITS = 12

/** Lowercase terms; every term must appear somewhere in an item for it to match. */
export function terms(q: string): string[] {
  return q.toLowerCase().split(/\s+/).filter(Boolean)
}

/**
 * Score one item against the terms: null when a term is missing. ``strong`` are the fields a person types
 * exactly (name, IP, MAC): an exact or prefix match there ranks first.
 */
export function score(t: string[], strong: (string | null | undefined)[], weak: (string | null | undefined)[]): number | null {
  const s = strong.filter(Boolean).map((x) => x!.toLowerCase())
  const all = [...s, ...weak.filter(Boolean).map((x) => x!.toLowerCase())].join('\n')
  let total = 0
  for (const term of t) {
    if (!all.includes(term)) return null
    if (s.some((x) => x === term)) total += 100
    else if (s.some((x) => x.startsWith(term))) total += 40
    else if (s.some((x) => x.includes(term))) total += 15
    else total += 5
  }
  return total
}

const rank = (a: SearchHit, b: SearchHit) => b.score - a.score || a.label.localeCompare(b.label, undefined, { numeric: true })

export function searchEngagement(q: string, data: { assets?: Asset[]; findings?: Finding[]; zones?: Zone[] }): SearchHit[] {
  const t = terms(q)
  if (!t.length) return []
  const out: SearchHit[] = []
  for (const a of data.assets ?? []) {
    const s = score(t, [a.name, ...a.ips, ...a.macs], [a.asset_type, a.vendor, a.model, a.firmware, a.serial, a.zone, a.location,
      a.owner, a.notes, a.mac_vendor, a.os_hint, ...a.tags, ...a.protocols, ...a.vlans.map((v) => `vlan ${v}`)])
    if (s !== null) {
      out.push({ kind: 'asset', id: a.id, label: assetLabel(a), score: s + 2,
        sub: [a.name ? a.ips[0] : null, a.asset_type, a.vendor].filter(Boolean).join(' · ') })
    }
  }
  for (const f of data.findings ?? []) {
    const s = score(t, [f.title, f.rule], [f.description, f.src, f.dst, f.category, f.severity, f.status, ...f.attack, ...f.evidence])
    if (s !== null) out.push({ kind: 'finding', key: f.key, label: f.title, score: s + 1, sub: [f.severity, f.src && f.dst ? `${f.src} → ${f.dst}` : f.src ?? f.dst].filter(Boolean).join(' · ') })
  }
  for (const z of data.zones ?? []) {
    const s = score(t, [z.name], [z.description])
    if (s !== null) out.push({ kind: 'zone', id: z.id, label: z.name, score: s, sub: `Zone · ${z.asset_ids.length} assets` })
  }
  return out.sort(rank).slice(0, MAX_HITS)
}

export function searchEngagements(q: string, engagements: Engagement[]): SearchHit[] {
  const t = terms(q)
  if (!t.length) return []
  const out: SearchHit[] = []
  for (const e of engagements) {
    const s = score(t, [e.name], [e.client, e.site, e.description])
    if (s !== null) out.push({ kind: 'engagement', id: e.id, label: e.name, score: s, sub: [e.client, e.site].filter(Boolean).join(' · ') })
  }
  return out.sort(rank).slice(0, MAX_HITS)
}
