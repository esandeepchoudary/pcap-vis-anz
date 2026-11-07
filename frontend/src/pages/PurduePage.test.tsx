import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { Asset, Link, OtOperation } from '../api/client'
import { Inspector } from '../components/Inspector'
import { InspectorContext, type Selection } from '../inspector/context'
import { engagement, mockApi, renderWithProviders } from '../test/utils'
import { EngagementLayout } from './EngagementLayout'
import { PurduePage } from './PurduePage'

const base: Asset = {
  id: 0, origin: 'observed', version: 1, ips: [], macs: [], name: null, asset_type: null, purdue_level: -1, zone: null,
  criticality: null, vendor: null, model: null, firmware: null, serial: null, location: null, owner: null, tags: [],
  notes: null, overridden: [], type_confidence: null, mac_vendor: null, is_private: true, protocols: [], vlans: [], ot_role: 'unknown',
  os_hint: null, packets: 0, bytes: 0, first_seen: null, last_seen: null, capture_count: 1, updated_at: '',
}
const assets: Asset[] = [
  { ...base, id: 1, name: 'eng-ws-01', ips: ['10.0.2.10'], asset_type: 'Engineering Workstation', purdue_level: 3 },
  { ...base, id: 2, ips: ['10.0.2.51'], asset_type: 'PLC', purdue_level: 1, zone: 'Line 2' },
  { ...base, id: 3, name: 'erp', ips: ['10.0.1.80'], asset_type: 'Web Server', purdue_level: 4 },
]
const link = (src: number, dst: number, extra: Partial<Link> = {}): Link => ({
  src, dst, protocols: [{ protocol: 'S7comm', ports: ['tcp/102'], flows: 1, packets: 20, bytes: 2000, ot_reads: 1, ot_writes: 2, ot_errors: 0 }],
  is_ot: true, flows: 1, packets: 20, bytes: 2000, ot_reads: 1, ot_writes: 2, ot_errors: 0, first_seen: 1700000000, last_seen: 1700000060,
  captures: [11], ...extra,
})
const links: Link[] = [
  link(1, 2),
  link(3, 2, { is_ot: false, ot_writes: 0, ot_reads: 0, protocols: [{ protocol: 'HTTP', ports: ['tcp/80'], flows: 1, packets: 5, bytes: 500, ot_reads: 0, ot_writes: 0, ot_errors: 0 }] }),
]
const ops: OtOperation[] = [
  { src: 1, dst: 2, protocol: 'S7comm', function: 'Request download', function_code: 26, kind: 'write', count: 2, first_seen: 1700000010, last_seen: 1700000020, sample: 'Block OB1', captures: [11] },
  { src: 1, dst: 2, protocol: 'S7comm', function: 'Read Var', function_code: 4, kind: 'read', count: 9, first_seen: 1700000010, last_seen: 1700000030, sample: '', captures: [11] },
]

function Harness() {
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="purdue" element={<PurduePage />} /></Route></Routes>
      <Inspector />
    </InspectorContext.Provider>
  )
}

function setup(extra: Record<string, unknown> = {}) {
  mockApi({
    'GET /api/engagements/7': engagement,
    'GET /api/engagements/7/assets': assets,
    'GET /api/engagements/7/links': links,
    'GET /api/engagements/7/ot-operations': ops,
    'GET /api/asset-fields': { fields: [], purdue_levels: [-1, 0, 1, 2, 3, 3.5, 4, 5, 6], purdue_names: {}, criticalities: [], asset_types: [] },
    ...extra,
  })
  renderWithProviders(<Harness />, { route: '/e/7/purdue' })
}

describe('Purdue page', () => {
  it('renders the map with assets in their lanes', async () => {
    setup()
    expect(await screen.findByText('3 assets · 1 OT connections · 2 OT writes')).toBeInTheDocument()
    const map = screen.getByLabelText('Purdue map')
    await waitFor(() => expect(within(map).getByText('eng-ws-01')).toBeInTheDocument())
    expect(within(map).getByText('Line 2')).toBeInTheDocument()
    expect(within(map).getByText('L3')).toBeInTheDocument() // lane label (falls back to the short name)
  })

  it('level matrix flags DMZ bypass and lists the pairs in a cell', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: 'Level matrix' }))
    expect(screen.getByRole('status')).toHaveTextContent('1 asset pair(s) bypass the industrial DMZ')
    const cell = screen.getByRole('button', { name: 'L4 to L1: 1 pairs' })
    expect(cell.closest('td')).toHaveClass('dmz')
    expect(screen.getByRole('button', { name: 'L3 to L1: 1 pairs' }).closest('td')).toHaveClass('writes')
    await userEvent.click(cell)
    expect(within(screen.getByRole('table', { name: 'Links' })).getByText('erp')).toBeInTheDocument()
  })

  it('OT matrix shows writes between masters and devices, and opens the connection', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: 'OT matrix' }))
    const cell = within(screen.getByRole('table', { name: 'OT matrix' })).getByRole('button', { name: 'eng-ws-01 to 10.0.2.51' })
    expect(cell).toHaveTextContent('W2')
    await userEvent.click(cell)
    const details = await screen.findByLabelText('Connection details')
    expect(details).toHaveTextContent('S7comm')
    expect(within(details).getByLabelText('OT commands on this connection')).toHaveTextContent('Request download')
  })

  it('OT command log filters by kind and search', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: /OT commands/ }))
    const table = screen.getByRole('table', { name: 'OT commands' })
    expect(within(table).getAllByRole('row')).toHaveLength(3)
    await userEvent.selectOptions(screen.getByLabelText('Filter by kind'), 'write')
    expect(within(table).getAllByRole('row')).toHaveLength(2)
    expect(table).toHaveTextContent('Block OB1')
    await userEvent.selectOptions(screen.getByLabelText('Filter by kind'), 'all')
    await userEvent.type(screen.getByLabelText('Search OT commands'), 'read var')
    expect(within(table).getAllByRole('row')).toHaveLength(2)
  })

  it('shows an empty state without assets', async () => {
    setup({ 'GET /api/engagements/7/assets': [] })
    expect(await screen.findByText('No assets yet')).toBeInTheDocument()
  })
})
