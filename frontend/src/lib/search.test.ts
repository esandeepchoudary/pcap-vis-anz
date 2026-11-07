import { describe, expect, it } from 'vitest'
import type { Asset, Engagement, Finding, Zone } from '../api/client'
import { MAX_HITS, score, searchEngagement, searchEngagements, terms } from './search'

const asset = (id: number, ip: string, extra: Partial<Asset> = {}): Asset => ({
  id, origin: 'observed', version: 1, ips: [ip], macs: [`00:1b:1b:00:00:${id.toString(16).padStart(2, '0')}`], name: null, asset_type: null,
  purdue_level: 1, zone: null, criticality: null, vendor: null, model: null, firmware: null, serial: null, location: null, owner: null,
  tags: [], notes: null, overridden: [], type_confidence: null, mac_vendor: null, is_private: true, protocols: [], vlans: [],
  ot_role: 'unknown', os_hint: null, packets: 0, bytes: 0, first_seen: null, last_seen: null, capture_count: 1, updated_at: '', ...extra,
})
const assets = [
  asset(1, '10.50.0.10', { name: 'PLC-A1', asset_type: 'PLC', vendor: 'Siemens', vlans: [500], tags: ['line 2'] }),
  asset(2, '10.50.0.11', { asset_type: 'PLC', vendor: 'Siemens' }),
  asset(3, '10.10.0.117', { name: 'WS-017', asset_type: 'Windows Host' }),
  asset(10, '10.50.0.100', { asset_type: 'HMI' }),
]
const findings = [{ key: 'k1', rule: 'ot_s7_code_download', title: 'PLC program download', description: 'blocks to 10.50.0.10',
  severity: 'critical', src: '10.30.0.21', dst: '10.50.0.10', category: 'ot', status: 'open', attack: ['T0843'], evidence: [] }] as unknown as Finding[]
const zones = [{ id: 4, name: 'Cell A', description: 'Filtration', asset_ids: [1, 2] }] as unknown as Zone[]

describe('search', () => {
  it('needs every term and ignores case and spacing', () => {
    expect(terms('  Siemens   PLC ')).toEqual(['siemens', 'plc'])
    expect(score(['siemens', 'plc'], ['PLC-A1'], ['Siemens'])).not.toBeNull()
    expect(score(['siemens', 'rockwell'], ['PLC-A1'], ['Siemens'])).toBeNull()
  })

  it('ranks an exact address above partial matches', () => {
    const hits = searchEngagement('10.50.0.10', { assets, findings, zones })
    expect(hits[0]).toMatchObject({ kind: 'asset', id: 1, label: 'PLC-A1' })
    expect(hits.map((h) => h.kind)).toEqual(['asset', 'asset', 'finding']) // 10.50.0.100 by prefix, then the finding naming it
  })

  it('finds assets by vendor, tag, VLAN and protocol words', () => {
    expect(searchEngagement('siemens', { assets }).map((h) => h.kind === 'asset' && h.id).sort()).toEqual([1, 2])
    expect(searchEngagement('line 2', { assets }).map((h) => h.label)).toEqual(['PLC-A1'])
    expect(searchEngagement('vlan 500', { assets }).map((h) => h.label)).toEqual(['PLC-A1'])
  })

  it('finds findings by rule or ATT&CK id, and zones by name', () => {
    expect(searchEngagement('T0843', { findings })[0]).toMatchObject({ kind: 'finding', key: 'k1' })
    expect(searchEngagement('cell', { zones })[0]).toMatchObject({ kind: 'zone', id: 4, sub: 'Zone · 2 assets' })
  })

  it('caps results and returns nothing for an empty query', () => {
    const many = Array.from({ length: 40 }, (_, i) => asset(100 + i, `10.0.0.${i}`))
    expect(searchEngagement('10.0', { assets: many })).toHaveLength(MAX_HITS)
    expect(searchEngagement('   ', { assets })).toEqual([])
  })

  it('searches engagements by name, client and site', () => {
    const engs = [{ id: 1, name: 'Riverside WTP', client: 'Riverside Water', site: 'North' }, { id: 2, name: 'Acme', client: 'Acme', site: 'Plant 3' }] as unknown as Engagement[]
    expect(searchEngagements('plant', engs).map((h) => h.kind === 'engagement' && h.id)).toEqual([2])
    expect(searchEngagements('river', engs)[0]).toMatchObject({ kind: 'engagement', id: 1, sub: 'Riverside Water · North' })
  })
})
