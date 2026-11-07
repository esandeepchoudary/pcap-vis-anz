import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { Asset, Conduit, Network, Violation, Zone } from '../api/client'
import { InspectorContext, type Selection } from '../inspector/context'
import { engagement, json, mockApi, renderWithProviders } from '../test/utils'
import { ArchitecturePage } from './ArchitecturePage'
import { EngagementLayout } from './EngagementLayout'

const base: Omit<Asset, 'id' | 'ips' | 'asset_type' | 'purdue_level'> = {
  origin: 'observed', version: 1, macs: [], name: null, zone: null, criticality: null, vendor: null, model: null,
  firmware: null, serial: null, location: null, owner: null, tags: [], notes: null, overridden: [], type_confidence: null,
  mac_vendor: null, is_private: true, protocols: [], vlans: [], ot_role: 'unknown', os_hint: null, packets: 0, bytes: 0,
  first_seen: null, last_seen: null, capture_count: 1, updated_at: '',
}
const assets: Asset[] = [
  { ...base, id: 1, name: 'eng-ws', ips: ['10.0.2.10'], asset_type: 'Engineering Workstation', purdue_level: 3, zone: 'Control' },
  { ...base, id: 2, ips: ['10.0.2.51'], asset_type: 'PLC', purdue_level: 1, zone: 'Cell 1' },
  { ...base, id: 3, name: 'fw-1', ips: ['10.0.2.1'], asset_type: 'Firewall', purdue_level: 3, zone: 'Control' },
]
const zones: Zone[] = [
  { id: 1, name: 'Control', defined: true, purdue_level: 3, security_level: 2, description: '', x: null, y: null, asset_ids: [1, 3] },
  { id: 2, name: 'Cell 1', defined: true, purdue_level: 1, security_level: null, description: '', x: null, y: null, asset_ids: [2] },
  { id: null, name: 'Loose', defined: false, purdue_level: null, security_level: null, description: '', x: null, y: null, asset_ids: [] },
]
const conduits: Conduit[] = []
const violations: Violation[] = [
  { kind: 'no_conduit', src: 1, dst: 2, src_zone: 'Control', dst_zone: 'Cell 1', conduit_id: null, protocols: ['S7comm'],
    flows: 3, packets: 30, ot_writes: 2, first_seen: 1, last_seen: 2 },
]
const networks: Network[] = [{ cidr: '10.0.2.0/24', vlans: [20], asset_ids: [1, 2, 3], gateways: [3], zones: ['Cell 1', 'Control'], purdue_levels: [1, 3] }]

function Harness() {
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="architecture" element={<ArchitecturePage />} /></Route></Routes>
    </InspectorContext.Provider>
  )
}

function setup(extra: Record<string, unknown> = {}) {
  const api = mockApi({
    'GET /api/engagements/7': engagement,
    'GET /api/engagements/7/assets': assets,
    'GET /api/engagements/7/zones': zones,
    'GET /api/engagements/7/conduits': conduits,
    'GET /api/engagements/7/violations': violations,
    'GET /api/engagements/7/networks': networks,
    ...extra,
  })
  renderWithProviders(<Harness />, { route: '/e/7/architecture' })
  return api
}

describe('Architecture page', () => {
  it('draws zones with their level, SL-T, assets and gateways', async () => {
    setup()
    expect(await screen.findByText('3 zones · 0 conduits · 1 unapproved cross-zone connections')).toBeInTheDocument()
    const diagram = screen.getByLabelText('Architecture diagram')
    await waitFor(() => expect(within(diagram).getByText('L3 · SL-T 2 · 2 assets')).toBeInTheDocument())
    expect(within(diagram).getByText('Firewall: fw-1')).toBeInTheDocument()
    expect(within(diagram).getByText('Not defined yet')).toBeInTheDocument()
  })

  it('defines a zone used on assets and adds a conduit', async () => {
    const api = setup({
      'POST /api/engagements/7/zones': () => json(201, zones[0]),
      'POST /api/engagements/7/conduits': () => json(201, { id: 9, zone_a_id: 1, zone_b_id: 2, name: '', allowed: [], description: '' }),
    })
    await userEvent.click(await screen.findByRole('tab', { name: 'Zones & conduits' }))
    await userEvent.click(screen.getByRole('button', { name: 'Define' }))
    await waitFor(() => expect(api.calls.find((c) => c.path.endsWith('/zones') && c.method === 'POST')?.body).toEqual({ name: 'Loose', description: '' }))
    await userEvent.selectOptions(screen.getByLabelText('Conduit from'), 'Control')
    await userEvent.selectOptions(screen.getByLabelText('Conduit to'), 'Cell 1')
    await userEvent.click(screen.getByRole('button', { name: 'Add conduit' }))
    await waitFor(() => expect(api.calls.find((c) => c.path.endsWith('/conduits') && c.method === 'POST')?.body)
      .toEqual({ name: '', description: '', zone_a_id: 1, zone_b_id: 2, allowed: [] }))
  })

  it('lists violations and approves one as a conduit with its protocols', async () => {
    const api = setup({ 'POST /api/engagements/7/conduits': () => json(201, { id: 9, zone_a_id: 1, zone_b_id: 2, name: '', allowed: ['S7comm'], description: '' }) })
    await userEvent.click(await screen.findByRole('tab', { name: /Violations/ }))
    const table = screen.getByRole('table', { name: 'Violations' })
    expect(table).toHaveTextContent('no conduit')
    expect(table).toHaveTextContent('S7comm')
    await userEvent.click(within(table).getByRole('button', { name: 'Approve as conduit' }))
    await waitFor(() => expect(api.calls.find((c) => c.method === 'POST')?.body).toMatchObject({ zone_a_id: 1, zone_b_id: 2, allowed: ['S7comm'] }))
  })

  it('adds a disallowed protocol to the existing conduit', async () => {
    const api = setup({
      'GET /api/engagements/7/conduits': [{ id: 9, zone_a_id: 1, zone_b_id: 2, name: '', allowed: ['S7comm'], description: '' }],
      'GET /api/engagements/7/violations': [{ ...violations[0], kind: 'protocol_not_allowed', conduit_id: 9, protocols: ['Modbus'] }],
      'PATCH /api/engagements/7/conduits/9': { id: 9, zone_a_id: 1, zone_b_id: 2, name: '', allowed: ['S7comm', 'Modbus'], description: '' },
    })
    await userEvent.click(await screen.findByRole('tab', { name: /Violations/ }))
    await userEvent.click(await screen.findByRole('button', { name: 'Allow Modbus' }))
    await waitFor(() => expect(api.calls.find((c) => c.method === 'PATCH')?.body).toEqual({ allowed: ['S7comm', 'Modbus'] }))
  })

  it('shows inferred networks with gateways', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: 'Networks' }))
    const t = screen.getByRole('table', { name: 'Networks' })
    expect(t).toHaveTextContent('10.0.2.0/24')
    expect(within(t).getByRole('button', { name: 'fw-1' })).toBeInTheDocument()
  })

  it('viewers see zones read-only', async () => {
    mockApi({
      'GET /api/engagements/7': { ...engagement, my_role: 'viewer' }, 'GET /api/engagements/7/assets': assets,
      'GET /api/engagements/7/zones': zones, 'GET /api/engagements/7/conduits': conduits,
      'GET /api/engagements/7/violations': violations, 'GET /api/engagements/7/networks': networks,
    })
    renderWithProviders(<Harness />, { route: '/e/7/architecture' })
    await userEvent.click(await screen.findByRole('tab', { name: 'Zones & conduits' }))
    expect(screen.queryByRole('button', { name: 'Define' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('New zone name')).not.toBeInTheDocument()
  })
})
