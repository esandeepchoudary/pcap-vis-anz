import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { Asset, Capture } from '../api/client'
import { InspectorContext, type Selection } from '../inspector/context'
import { doneCapture, engagement, json, mockApi, renderWithProviders, result } from '../test/utils'
import { EngagementLayout } from './EngagementLayout'
import { FlowsPage } from './FlowsPage'

const asset = (id: number, ip: string, name: string | null): Asset => ({
  id, origin: 'observed', version: 1, ips: [ip], macs: [], name, asset_type: 'PLC', purdue_level: 1, zone: null, criticality: null,
  vendor: null, model: null, firmware: null, serial: null, location: null, owner: null, tags: [], notes: null, overridden: [],
  type_confidence: null, mac_vendor: null, is_private: true, protocols: [], ot_role: 'unknown', os_hint: null, packets: 0, bytes: 0,
  first_seen: null, last_seen: null, capture_count: 1, updated_at: '',
})
const assets = [asset(1, '10.0.2.10', 'eng-ws-01'), asset(2, '10.0.2.51', null)]
const second: Capture = { ...doneCapture, id: 12, file_name: 'friday.pcap' }
const r = {
  ...result,
  hosts: result.hosts.map((h, i) => (i === 0 ? { ...h, dns_queries: ['updates.vendor.example', 'time.example'] } : h)),
  flows: [
    { id: 1, transport: 'tcp', client: '10.0.2.10', client_port: 50000, server: '10.0.2.51', server_port: 102, protocol: 'S7comm',
      detected_protocols: [], direction_basis: 'handshake' as const, packets_c2s: 8, packets_s2c: 8, bytes_c2s: 900, bytes_s2c: 900,
      first_seen: 1700000000, last_seen: 1700000050, vlans: [], syn_seen: true, resets: 0, ot_reads: 1, ot_writes: 2, ot_errors: 0,
      function_counts: {}, notes: {}, c2s_times: [] },
    { id: 2, transport: 'udp', client: '10.0.2.10', client_port: 5353, server: '10.0.1.53', server_port: 53, protocol: 'DNS',
      detected_protocols: [], direction_basis: 'port' as const, packets_c2s: 1, packets_s2c: 1, bytes_c2s: 80, bytes_s2c: 120,
      first_seen: 1700000001, last_seen: 1700000001, vlans: [], syn_seen: false, resets: 0, ot_reads: 0, ot_writes: 0, ot_errors: 0,
      function_counts: {}, notes: {}, c2s_times: [] },
  ],
  vlan_stats: [{ vlan: 20, packets: 100, broadcast: 30 }, { vlan: null, packets: 10, broadcast: 0 }],
}

function Harness() {
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="flows" element={<FlowsPage />} /></Route></Routes>
    </InspectorContext.Provider>
  )
}

function setup(extra: Record<string, unknown> = {}, eng = engagement) {
  const api = mockApi({
    'GET /api/engagements/7': eng,
    'GET /api/engagements/7/captures': [doneCapture, second],
    'GET /api/engagements/7/assets': assets,
    'GET /api/engagements/7/links': [],
    'GET /api/engagements/7/captures/11/result': r,
    'GET /api/engagements/7/captures/12/result': r,
    ...extra,
  })
  renderWithProviders(<Harness />, { route: '/e/7/flows' })
  return api
}

describe('Flows page', () => {
  it('lists flows largest first and filters them', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: 'Flows' }))
    const table = await screen.findByRole('table', { name: 'Flows' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('S7comm')
    expect(rows[0]).toHaveTextContent('1/2')
    await userEvent.type(screen.getByLabelText('Filter flows'), 'dns')
    expect(within(table).getAllByRole('row')).toHaveLength(2)
  })

  it('shows DNS names with who asked, and VLANs with broadcast share', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: 'DNS' }))
    expect(await screen.findByRole('table', { name: 'DNS queries' })).toHaveTextContent('updates.vendor.example')
    await userEvent.click(screen.getByRole('tab', { name: 'VLANs' }))
    const vlans = await screen.findByRole('table', { name: 'VLANs' })
    expect(vlans).toHaveTextContent('30%high')
    expect(within(vlans).getByRole('button', { name: 'eng-ws-01' })).toBeInTheDocument()
  })

  it('compares two captures', async () => {
    setup({ 'GET /api/engagements/7/diff': { new_assets: [2], gone_assets: [], new_links: [{ src: 1, dst: 2, protocol: 'S7comm', packets: 16 }], gone_links: [] } })
    await userEvent.click(await screen.findByRole('tab', { name: 'Diff' }))
    expect(await screen.findByLabelText('New assets')).toHaveTextContent('10.0.2.51')
    expect(screen.getByLabelText('New connections')).toHaveTextContent('eng-ws-01 → 10.0.2.51 S7comm')
  })

  it('packet inspector: filter, pick a packet, see its decode', async () => {
    const api = setup({
      'GET /api/engagements/7/captures/12/packets': { packets: [{ number: 5, time: 1700000000, src: '10.0.2.10', dst: '10.0.2.51', protocol: 'S7COMM', length: 80, info: 'Job Request' }], truncated: false },
      'GET /api/engagements/7/captures/12/packets/5': { number: 5, text: 'Frame 5: 80 bytes on wire' },
    })
    await userEvent.click(await screen.findByRole('tab', { name: 'Packets' }))
    await userEvent.type(screen.getByLabelText('Display filter'), 's7comm')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(api.calls.some((c) => c.path.endsWith('/packets'))).toBe(true))
    await userEvent.click(await screen.findByText('Job Request'))
    expect(await screen.findByText('Frame 5: 80 bytes on wire')).toBeInTheDocument()
  })

  it('shows tshark filter errors', async () => {
    setup({ 'GET /api/engagements/7/captures/12/packets': () => json(400, { detail: '"bogus" is not a valid protocol or protocol field.' }) })
    await userEvent.click(await screen.findByRole('tab', { name: 'Packets' }))
    expect(await screen.findByText(/is not a valid protocol/)).toBeInTheDocument()
  })

  it('viewers cannot open the packet inspector', async () => {
    setup({}, { ...engagement, my_role: 'viewer' })
    await userEvent.click(await screen.findByRole('tab', { name: 'Packets' }))
    expect(screen.getByText(/needs the editor role/)).toBeInTheDocument()
  })
})
