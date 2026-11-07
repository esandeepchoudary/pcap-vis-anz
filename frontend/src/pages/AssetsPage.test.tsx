import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { Asset, AssetChange, AssetDetail, AssetFields, Engagement, FieldValue } from '../api/client'
import { Inspector } from '../components/Inspector'
import { InspectorContext, type Selection } from '../inspector/context'
import { describeChange, formatValue, parseList, parseTags } from '../lib/assets'
import { engagement, json, mockApi, renderWithProviders } from '../test/utils'
import { AssetsPage } from './AssetsPage'
import { EngagementLayout } from './EngagementLayout'

const fields: AssetFields = {
  fields: [
    { name: 'name', label: 'Name', kind: 'text', max_len: 200, auto: true },
    { name: 'asset_type', label: 'Type', kind: 'text', max_len: 100, auto: true },
    { name: 'purdue_level', label: 'Purdue level', kind: 'level', max_len: 200, auto: true },
    { name: 'zone', label: 'Zone', kind: 'text', max_len: 100, auto: false },
    { name: 'criticality', label: 'Criticality', kind: 'choice', max_len: 200, auto: false },
    { name: 'vendor', label: 'Vendor', kind: 'text', max_len: 200, auto: true },
    { name: 'tags', label: 'Tags', kind: 'tags', max_len: 200, auto: false },
    { name: 'notes', label: 'Notes', kind: 'longtext', max_len: 10000, auto: false },
  ],
  purdue_levels: [-1, 0, 1, 2, 3, 3.5, 4, 5, 6],
  purdue_names: { '-1': 'Unclassified', '1': 'Level 1 – Basic control', '2': 'Level 2 – Supervisory control', '3': 'Level 3 – Site operations' },
  criticalities: ['low', 'medium', 'high', 'critical'],
  asset_types: ['Firewall', 'HMI', 'PLC'],
}

const base: Asset = {
  id: 1, origin: 'observed', version: 1, ips: ['10.0.2.51'], macs: ['00:0c:29:00:00:51'], name: null, asset_type: 'PLC',
  purdue_level: 1, zone: null, criticality: null, vendor: 'Siemens', model: 'S7-1500', firmware: null, serial: null,
  location: null, owner: null, tags: [], notes: null, overridden: [], type_confidence: 'high', mac_vendor: 'Siemens AG',
  is_private: true, protocols: ['S7comm'], vlans: [], ot_role: 'outstation', os_hint: null, packets: 10, bytes: 1000,
  first_seen: 1700000000, last_seen: 1700000050, capture_count: 1, updated_at: '2026-11-06T10:00:00Z',
}
const assets: Asset[] = [
  base,
  { ...base, id: 2, ips: ['10.0.2.10'], macs: ['00:0c:29:00:00:10'], name: 'eng-ws-01', asset_type: 'Engineering Workstation',
    purdue_level: 3, zone: 'Cell 2', overridden: ['zone'], vendor: null, model: null, protocols: ['S7comm', 'HTTP'], tags: ['jump'] },
  { ...base, id: 3, ips: ['8.8.8.8'], macs: [], asset_type: 'Internet Host', purdue_level: 6, is_private: false, vendor: null, model: null },
]

const detail: AssetDetail = {
  ...base,
  auto: { asset_type: 'PLC', purdue_level: 1, vendor: 'Siemens' },
  auto_sources: { vendor: 'S7 identification (SZL)', asset_type: 'classification' },
  overrides: {}, services: [{ transport: 'tcp', port: 102, protocol: 'S7comm', packets: 10, clients: 1 }], vlans: [20],
  identity: { s7_order_number: '6ES7 516-3AN01-0AB0', s7_firmware: 'V2.9.4', snmp_sys_location: 'Cabinet 12' }, hostnames: [], tls_sni: [], modbus_unit_ids: [], dnp3_addresses: [], ttl: null,
  type_evidence: [{ kind: 'serves', detail: 'Serves S7comm on tcp/102', weight: 5 }], purdue_evidence: [],
  sightings: [{ capture_id: 11, file_name: 'line2.pcap', capture_point: 'Core SPAN', ip: '10.0.2.51', mac: '00:0c:29:00:00:51',
    first_seen: 1700000000, last_seen: 1700000050, packets: 10, host_type: 'PLC', purdue_level: 1 }],
}

const history: AssetChange[] = [
  { id: 3, at: '2026-11-06T10:05:00Z', actor: 'alice', kind: 'override', field: 'purdue_level', old: 1, new: 2, reason: 'Walkdown' },
  { id: 2, at: '2026-11-06T10:02:00Z', actor: 'capture b.pcap', kind: 'auto', field: 'asset_type', old: 'HMI', new: 'PLC', reason: '' },
  { id: 1, at: '2026-11-06T10:00:00Z', actor: 'capture a.pcap', kind: 'created', field: null, old: null, new: null, reason: '' },
]

function Harness() {
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="assets" element={<AssetsPage />} /></Route></Routes>
      <Inspector />
    </InspectorContext.Provider>
  )
}

function setup(extra: Record<string, unknown> = {}, eng: Engagement = engagement) {
  const api = mockApi({
    'GET /api/engagements/7': eng,
    'GET /api/engagements/7/assets': assets,
    'GET /api/asset-fields': fields,
    'GET /api/engagements/7/assets/1': detail,
    'GET /api/engagements/7/assets/1/history': history,
    ...extra,
  })
  renderWithProviders(<Harness />, { route: '/e/7/assets' })
  return api
}

const rows = () => within(screen.getByRole('table', { name: 'Assets' })).getAllByRole('row').slice(1)

describe('Asset inventory', () => {
  it('lists internal assets by level, hides external ones until asked, marks manual values', async () => {
    setup()
    await screen.findByText('eng-ws-01')
    expect(rows()).toHaveLength(2)
    expect(rows()[0]).toHaveTextContent('10.0.2.51')
    expect(rows()[1]).toHaveTextContent('Cell 2')
    expect(within(rows()[1]).getByLabelText('set manually')).toBeInTheDocument()
    expect(screen.getByText(/3 assets · 1 edited by hand/)).toBeInTheDocument()
    await userEvent.click(screen.getByLabelText('Show 1 external'))
    expect(rows()).toHaveLength(3)
    expect(rows()[2]).toHaveTextContent('External')
  })

  it('searches and filters', async () => {
    setup()
    await screen.findByText('eng-ws-01')
    await userEvent.type(screen.getByLabelText('Search assets'), 'jump')
    expect(rows()).toHaveLength(1)
    await userEvent.clear(screen.getByLabelText('Search assets'))
    await userEvent.selectOptions(screen.getByLabelText('Filter by Purdue level'), '1')
    expect(rows()).toHaveLength(1)
    expect(rows()[0]).toHaveTextContent('PLC')
    await userEvent.selectOptions(screen.getByLabelText('Filter by Purdue level'), 'all')
    await userEvent.click(screen.getByLabelText('Edited only'))
    expect(rows()).toHaveLength(1)
    expect(rows()[0]).toHaveTextContent('eng-ws-01')
  })

  it('sorts by a column', async () => {
    setup()
    await screen.findByText('eng-ws-01')
    await userEvent.click(screen.getByRole('button', { name: 'Level' })) // flips to descending
    expect(rows()[0]).toHaveTextContent('eng-ws-01')
  })

  it('opens an asset and saves an edit with its version and reason', async () => {
    const saved = { ...detail, version: 2, purdue_level: 2, overridden: ['purdue_level' as const],
      overrides: { purdue_level: { value: 2, reason: 'Walkdown', by: 'local', at: '2026-11-06T10:05:00Z' } } }
    const api = setup({ 'PATCH /api/engagements/7/assets/1': saved })
    await userEvent.click(await screen.findByText('10.0.2.51'))
    const form = await screen.findByRole('form', { name: 'Asset fields' })
    expect(within(form).getByText('From S7 identification (SZL)')).toBeInTheDocument() // vendor's source
    await userEvent.selectOptions(within(form).getByLabelText('Purdue level'), '2')
    await userEvent.type(within(form).getByLabelText('Zone'), 'Cell 1')
    await userEvent.type(within(form).getByLabelText('Reason (recorded in history)'), 'Walkdown')
    await userEvent.click(within(form).getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(api.calls.some((c) => c.method === 'PATCH')).toBe(true))
    const call = api.calls.find((c) => c.method === 'PATCH')!
    expect(call.body).toEqual({ version: 1, set: { purdue_level: 2, zone: 'Cell 1' }, reset: [], reason: 'Walkdown' })
    expect(await within(form).findByText('Why: Walkdown')).toBeInTheDocument()
    expect(within(form).getByText('Detected: L1')).toBeInTheDocument()
  })

  it('resets a manual value back to the detected one', async () => {
    const edited = { ...detail, overridden: ['purdue_level' as const], purdue_level: 2,
      overrides: { purdue_level: { value: 2, reason: 'x', by: 'bob', at: '2026-11-06T10:05:00Z' } } }
    const api = setup({ 'GET /api/engagements/7/assets/1': edited, 'PATCH /api/engagements/7/assets/1': detail })
    await userEvent.click(await screen.findByText('10.0.2.51'))
    await userEvent.click(await screen.findByLabelText('Reset Purdue level to automatic'))
    expect(screen.getByText('reset on save')).toBeInTheDocument()
    expect(screen.getByLabelText('Purdue level')).toHaveValue('1')
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(api.calls.find((c) => c.method === 'PATCH')?.body).toEqual({ version: 1, set: {}, reset: ['purdue_level'], reason: '' }))
  })

  it('explains a conflicting edit instead of overwriting', async () => {
    setup({ 'PATCH /api/engagements/7/assets/1': () => json(409, { detail: 'Someone else changed this asset…' }) })
    await userEvent.click(await screen.findByText('10.0.2.51'))
    await userEvent.type(await screen.findByLabelText('Zone'), 'X')
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByText(/Someone else changed this asset while you were editing/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Discard mine' }))
    expect(screen.getByLabelText('Zone')).toHaveValue('')
  })

  it('shows evidence, sightings and history', async () => {
    setup()
    await userEvent.click(await screen.findByText('10.0.2.51'))
    await userEvent.click(await screen.findByRole('tab', { name: 'Evidence' }))
    expect(screen.getByText('Serves S7comm on tcp/102')).toBeInTheDocument()
    expect(screen.getByLabelText('Identity from S7 identification (SZL)')).toHaveTextContent('Order number6ES7 516-3AN01-0AB0')
    expect(screen.getByLabelText('Identity from SNMP')).toHaveTextContent('Sys locationCabinet 12')
    expect(within(screen.getByLabelText('Sightings')).getByRole('link', { name: 'line2.pcap' })).toHaveAttribute('href', '/e/7/captures/11')
    await userEvent.click(screen.getByRole('tab', { name: 'History' }))
    const list = await screen.findByLabelText('Change history')
    expect(list).toHaveTextContent('Purdue level: L1 → L2')
    expect(list).toHaveTextContent('“Walkdown”')
    expect(list).toHaveTextContent('Type detected: HMI → PLC')
    expect(list).toHaveTextContent('First seen in a.pcap')
  })

  it('describes merges and splits in history', () => {
    const c = (kind: AssetChange['kind'], old: FieldValue, nw: FieldValue): AssetChange => ({ id: 1, at: '', actor: 'a', kind, field: null, old, new: nw, reason: '' })
    expect(describeChange(c('merge', ['plc (10.0.0.51)'], ['10.0.0.51']), fields)).toBe('Merged in plc (10.0.0.51)')
    expect(describeChange(c('split', ['10.0.0.52'], null), fields)).toBe('Addresses moved to a new asset: 10.0.0.52')
    expect(describeChange(c('split', null, ['10.0.0.52']), fields)).toBe('Split off from another asset: 10.0.0.52')
  })

  it('bulk-edits the selected assets', async () => {
    const api = setup({ 'POST /api/engagements/7/assets/bulk': { assets: 2, changes: 2 } })
    await screen.findByText('eng-ws-01')
    await userEvent.click(screen.getByLabelText('Select all shown'))
    const bar = screen.getByRole('region', { name: 'Bulk edit' })
    expect(bar).toHaveTextContent('2 selected')
    await userEvent.selectOptions(within(bar).getByLabelText('Field to change'), 'zone')
    await userEvent.type(within(bar).getByLabelText('New value'), 'Cell 9')
    await userEvent.type(within(bar).getByLabelText('Reason'), 'Same cabinet')
    await userEvent.click(within(bar).getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(api.calls.find((c) => c.method === 'POST')?.body).toEqual({
      asset_ids: [1, 2], set: { zone: 'Cell 9' }, reset: [], reason: 'Same cabinet',
    }))
    await waitFor(() => expect(screen.queryByRole('region', { name: 'Bulk edit' })).not.toBeInTheDocument())
  })

  it('merges selected assets into the one picked to keep', async () => {
    const api = setup({ 'POST /api/engagements/7/assets/2/merge': { ...detail, id: 2 } })
    await screen.findByText('eng-ws-01')
    await userEvent.click(screen.getByLabelText('Select all shown'))
    await userEvent.click(screen.getByRole('button', { name: 'Merge 2 into one…' }))
    const bar = screen.getByRole('region', { name: 'Merge assets' })
    await userEvent.selectOptions(within(bar).getByLabelText('Asset to keep'), '2')
    await userEvent.type(within(bar).getByLabelText('Merge reason'), 'Same box, two NICs')
    await userEvent.click(within(bar).getByRole('button', { name: 'Merge' }))
    await waitFor(() => expect(api.calls.find((c) => c.path.endsWith('/merge'))?.body).toEqual({
      version: 1, source_ids: [1], reason: 'Same box, two NICs',
    }))
    await waitFor(() => expect(screen.queryByRole('region', { name: 'Merge assets' })).not.toBeInTheDocument())
  })

  it('splits addresses off into a new asset and opens it', async () => {
    const twoIps = { ...detail, ips: ['10.0.2.51', '10.0.2.52'] }
    const created = { ...detail, id: 9, ips: ['10.0.2.52'], name: null }
    const api = setup({
      'GET /api/engagements/7/assets/1': twoIps,
      'POST /api/engagements/7/assets/1/split': { original: detail, created },
      'GET /api/engagements/7/assets/9': created,
    })
    await userEvent.click(await screen.findByText('10.0.2.51'))
    await userEvent.click(await screen.findByRole('tab', { name: 'Evidence' }))
    await userEvent.click(screen.getByRole('button', { name: 'Split addresses…' }))
    const split = screen.getByRole('button', { name: 'Split' })
    expect(split).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: '10.0.2.52' }))
    await userEvent.click(split)
    await waitFor(() => expect(api.calls.find((c) => c.path.endsWith('/split'))?.body).toEqual({ version: 1, ips: ['10.0.2.52'], reason: '' }))
    await waitFor(() => expect(api.calls.some((c) => c.path === '/api/engagements/7/assets/9')).toBe(true)) // the new asset opens
  })

  it('viewers can read but not edit', async () => {
    setup({}, { ...engagement, my_role: 'viewer' })
    await screen.findByText('eng-ws-01')
    expect(screen.queryByLabelText('Select all shown')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add asset/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Export CSV/ })).toHaveAttribute('href', '/api/engagements/7/assets/export')
    await userEvent.click(screen.getByText('10.0.2.51'))
    expect(await screen.findByLabelText('Zone')).toBeDisabled()
  })

  it('adds an asset by hand and opens it', async () => {
    const api = setup({ 'POST /api/engagements/7/assets': () => json(201, detail) })
    await screen.findByText('eng-ws-01')
    await userEvent.click(screen.getByRole('button', { name: /Add asset/ }))
    const form = screen.getByRole('form', { name: 'Add asset' })
    await userEvent.type(within(form).getByLabelText('Name'), 'FW-1')
    await userEvent.type(within(form).getByLabelText('IP addresses'), '10.0.0.254, 10.0.1.254')
    await userEvent.selectOptions(within(form).getByLabelText('Purdue level'), '3.5')
    await userEvent.click(within(form).getByRole('button', { name: 'Add asset' }))
    await waitFor(() => expect(api.calls.find((c) => c.method === 'POST')?.body).toEqual({
      ips: ['10.0.0.254', '10.0.1.254'], macs: [], values: { name: 'FW-1', purdue_level: 3.5 }, reason: '',
    }))
    expect(await screen.findByRole('form', { name: 'Asset fields' })).toBeInTheDocument()
  })

  it('shows an empty state with a link to captures', async () => {
    setup({ 'GET /api/engagements/7/assets': [] })
    expect(await screen.findByText('No assets yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Add captures' })).toHaveAttribute('href', '/e/7/captures')
  })
})

describe('asset helpers', () => {
  it('formats values and parses lists', () => {
    expect(formatValue('purdue_level', 3.5)).toBe('L3.5')
    expect(formatValue('purdue_level', -1)).toBe('Unclassified')
    expect(formatValue('purdue_level', 6)).toBe('External')
    expect(formatValue('tags', [])).toBe('—')
    expect(formatValue('name', null)).toBe('—')
    expect(parseList('10.0.0.1, 10.0.0.2 10.0.0.3')).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.3'])
    expect(parseTags('a b, c ,,')).toEqual(['a b', 'c'])
  })

  it('describes history entries', () => {
    expect(describeChange(history[0], fields)).toBe('Purdue level: L1 → L2')
    expect(describeChange({ ...history[0], kind: 'reset', old: 2, new: 1 }, fields)).toBe('Purdue level reset to detected value L1 (was L2)')
    expect(describeChange({ ...history[2], actor: 'alice' }, fields)).toBe('Added')
  })
})
