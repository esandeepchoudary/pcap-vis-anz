import type { Asset, AssetChange, AssetFields, EditableField, FieldValue } from '../api/client'
import { purdueLabel } from './format'

export const CRITICALITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 } as const

/** A short label for an asset: its name, else its first address. */
export function assetLabel(a: Pick<Asset, 'name' | 'ips' | 'macs' | 'id'>): string {
  return a.name || a.ips[0] || a.macs[0] || `Asset ${a.id}`
}

export function formatValue(field: EditableField, v: FieldValue | undefined): string {
  if (v === null || v === undefined || v === '') return '—'
  if (field === 'purdue_level') return purdueLabel(Number(v))
  if (Array.isArray(v)) return v.length ? v.join(', ') : '—'
  return String(v)
}

export function levelName(fields: AssetFields | undefined, level: number): string {
  return fields?.purdue_names[String(level)] ?? purdueLabel(level)
}

/** Text the grid search matches against. */
export function searchText(a: Asset): string {
  return [a.name, a.asset_type, a.zone, a.vendor, a.model, a.location, a.owner, a.mac_vendor, a.notes,
    ...a.ips, ...a.macs, ...a.protocols, ...a.tags].filter(Boolean).join(' ').toLowerCase()
}

export function parseList(text: string): string[] {
  return text.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)
}

export function parseTags(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter(Boolean)
}

/** One line describing a history entry. */
export function describeChange(c: AssetChange, fields: AssetFields | undefined): string {
  const label = fields?.fields.find((f) => f.name === c.field)?.label ?? c.field ?? ''
  const v = (x: FieldValue) => (c.field ? formatValue(c.field, x) : '')
  switch (c.kind) {
    case 'created': return c.actor.startsWith('capture ') ? `First seen in ${c.actor.slice(8)}` : 'Added'
    case 'override': return `${label}: ${v(c.old)} → ${v(c.new)}`
    case 'reset': return `${label} reset to detected value ${v(c.new)} (was ${v(c.old)})`
    case 'auto': return `${label} detected: ${v(c.old)} → ${v(c.new)}`
    case 'merge': return `Merged in ${(c.old as string[] | null)?.join(', ') ?? 'other assets'}`
    case 'split': return c.new ? `Split off from another asset: ${(c.new as string[]).join(', ')}` : `Addresses moved to a new asset: ${((c.old as string[] | null) ?? []).join(', ')}`
    default: return `${label}: ${v(c.new)}`
  }
}

/** What a device revealed about itself, grouped by the protocol it came from (labels mirror the backend). */
const IDENTITY_SOURCES: [string, string][] = [
  ['enip_', 'EtherNet/IP identity'], ['modbus_', 'Modbus device identification'], ['s7_', 'S7 identification (SZL)'],
  ['pn_', 'PROFINET DCP'], ['snmp_', 'SNMP'], ['bacnet_', 'BACnet'], ['cdp_', 'CDP'], ['lldp_', 'LLDP'], ['dhcp_', 'DHCP'],
]

export function identityGroups(identity: Record<string, string>): [string, [string, string][]][] {
  const groups = new Map<string, [string, string][]>()
  for (const [k, v] of Object.entries(identity).sort()) {
    const hit = IDENTITY_SOURCES.find(([prefix]) => k.startsWith(prefix))
    const source = hit ? hit[1] : 'Other'
    const label = (hit ? k.slice(hit[0].length) : k).replaceAll('_', ' ')
    groups.set(source, [...(groups.get(source) ?? []), [label.charAt(0).toUpperCase() + label.slice(1), v]])
  }
  return [...groups.entries()]
}
