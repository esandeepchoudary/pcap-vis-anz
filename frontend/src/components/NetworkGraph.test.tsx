import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import type { Asset, Finding, Link } from '../api/client'
import { InspectorContext, type Selection } from '../inspector/context'
import { engagement, mockApi, renderWithProviders } from '../test/utils'
import { NetworkGraph } from './NetworkGraph'

const asset = (id: number, ip: string, asset_type: string, extra: Partial<Asset> = {}): Asset => ({
  id, origin: 'observed', version: 1, ips: [ip], macs: [], name: null, asset_type, purdue_level: 1, zone: null, criticality: null,
  vendor: null, model: null, firmware: null, serial: null, location: null, owner: null, tags: [], notes: null, overridden: [],
  type_confidence: null, mac_vendor: null, is_private: true, protocols: [], vlans: [], ot_role: 'unknown', os_hint: null, packets: 0, bytes: 0,
  first_seen: null, last_seen: null, capture_count: 1, updated_at: '', ...extra,
})
const assets = [
  asset(1, '10.0.2.10', 'Engineering Workstation', { name: 'eng-ws' }),
  asset(2, '10.0.2.51', 'PLC'),
  asset(3, '10.0.1.80', 'Web Server', { name: 'erp' }),
  asset(4, '203.0.113.66', 'Security Tool', { is_private: false }),
]
const link = (src: number, dst: number, protocol: string, extra: Partial<Link> = {}): Link => ({
  src, dst, protocols: [{ protocol, ports: [], flows: 1, packets: 10, bytes: 100, ot_reads: 0, ot_writes: 0, ot_errors: 0 }],
  is_ot: false, flows: 1, packets: 10, bytes: 100, ot_reads: 0, ot_writes: 0, ot_errors: 0, first_seen: 0, last_seen: 1, captures: [1], ...extra,
})
const links = [
  link(1, 2, 'S7comm', { is_ot: true, ot_writes: 3, packets: 400 }),
  link(1, 3, 'HTTPS'),
  link(4, 3, 'HTTP'),
]
const finding = (asset_ids: number[], category: string, severity: Finding['severity']) =>
  ({ key: `${category}-${asset_ids.join()}`, asset_ids, category, severity, status: 'open', rule: category }) as unknown as Finding

function Harness({ list = assets, conns = links }: { list?: Asset[]; conns?: Link[] }) {
  const [selection, select] = useState<Selection>(null)
  return <InspectorContext.Provider value={{ selection, select }}><NetworkGraph eng={engagement} assets={list} links={conns} /></InspectorContext.Provider>
}

function setup(list?: Asset[], conns?: Link[]) {
  mockApi({ 'GET /api/engagements/7/findings': [finding([1, 2], 'ot', 'critical'), finding([4, 3], 'credentials', 'high')] })
  renderWithProviders(<Harness list={list} conns={conns} />)
}

const graph = () => screen.getByLabelText('Network graph')

describe('Network graph', () => {
  it('draws every asset with its device icon, finding badge and credential key', async () => {
    setup()
    await waitFor(() => expect(within(graph()).getByText('eng-ws')).toBeInTheDocument())
    expect(graph().querySelectorAll('.fgx')).toHaveLength(4)
    expect(graph().querySelector('.fgx-circle.cat-control')).not.toBeNull() // the PLC
    expect(graph().querySelector('.fgx-circle.cat-security')).not.toBeNull() // the scanner
    expect(graph().querySelector('.fgx-circle.write-target')).not.toBeNull() // the PLC receives writes
    await waitFor(() => expect(within(graph()).getAllByLabelText('cleartext credentials')).toHaveLength(2))
    expect(graph().querySelector('.sev-bg-critical')).not.toBeNull()
  })

  it('filters by protocol and hides external hosts on request', async () => {
    setup()
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(4))
    await userEvent.click(screen.getByRole('button', { name: 'HTTP' }))
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(3)) // the scanner only spoke HTTP
    await userEvent.click(screen.getByRole('button', { name: 'Show all' }))
    await userEvent.click(screen.getByLabelText('External hosts'))
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(3))
  })

  it('isolates an asset on double-click', async () => {
    setup()
    await waitFor(() => expect(within(graph()).getByText('erp')).toBeInTheDocument())
    fireEvent.doubleClick(within(graph()).getByText('erp').closest('.react-flow__node')!)
    expect(await screen.findByRole('status')).toHaveTextContent('Showing erp and who it talks to')
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(3)) // erp, eng-ws, scanner
    await userEvent.click(screen.getByRole('button', { name: 'Show everything' }))
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(4))
  })

  it('switches to the subnet layout', async () => {
    setup()
    await userEvent.click(screen.getByRole('button', { name: 'By subnet' }))
    await waitFor(() => expect(within(graph()).getByText(/10\.0\.2\.0\/24/)).toBeInTheDocument())
  })

  it('groups by VLAN, marks traffic between VLANs and shows the VLAN matrix', async () => {
    const tagged = [
      { ...assets[0], vlans: [20] }, { ...assets[1], vlans: [10] }, { ...assets[2], vlans: [20] }, { ...assets[3], vlans: [] },
    ]
    setup(tagged)
    await userEvent.click(screen.getByRole('button', { name: 'By VLAN' }))
    await waitFor(() => expect(within(graph()).getByText('VLAN 20 · 2')).toBeInTheDocument())
    expect(within(graph()).getByText('VLAN 10 · 1')).toBeInTheDocument()
    expect(within(graph()).getByText('Untagged · 1')).toBeInTheDocument()
    expect(screen.getByLabelText('VLAN summary')).toHaveTextContent('2 VLANs1 connections between VLANs') // eng-ws → PLC
    await waitFor(() => expect(graph().querySelectorAll('.pm-edge-crossvlan')).toHaveLength(1))
    const matrix = screen.getByRole('table', { name: 'VLAN matrix' })
    expect(within(matrix).getAllByRole('cell').filter((c) => c.className === 'cross').map((c) => c.textContent)).toEqual(['1', '1'])
  })

  it('offers no VLAN layout without VLAN tags', async () => {
    setup()
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(4))
    expect(screen.queryByRole('button', { name: 'By VLAN' })).toBeNull()
  })

  it('narrows the graph to a time window and replays it', async () => {
    const timed = [
      link(1, 2, 'S7comm', { first_seen: 0, last_seen: 10 }),
      link(1, 3, 'HTTPS', { first_seen: 50, last_seen: 60 }),
      link(4, 3, 'HTTP', { first_seen: 90, last_seen: 100 }),
    ]
    setup(assets, timed)
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(4))
    const timeline = screen.getByRole('group', { name: 'Timeline' })
    expect(timeline).toHaveTextContent('3 of 3 connections')
    fireEvent.change(within(timeline).getByLabelText('Window end'), { target: { value: '200' } }) // up to t=20
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(2)) // eng-ws and the PLC
    expect(timeline).toHaveTextContent('1 of 3 connections')
    fireEvent.change(within(timeline).getByLabelText('Window start'), { target: { value: '400' } }) // 40..20 → clamps to 20..20
    await userEvent.click(within(timeline).getByRole('button', { name: 'Whole capture' }))
    await waitFor(() => expect(graph().querySelectorAll('.fgx')).toHaveLength(4))
    expect(within(timeline).queryByRole('button', { name: 'Whole capture' })).toBeNull()
    await userEvent.selectOptions(within(timeline).getByLabelText('Playback speed'), '8')
    await userEvent.click(within(timeline).getByRole('button', { name: 'Play' })) // at the end: restarts from the start
    await waitFor(() => expect(within(timeline).getByRole('button', { name: 'Pause' })).toBeInTheDocument())
    await waitFor(() => expect(timeline).toHaveTextContent('3 of 3 connections'), { timeout: 4000 })
    await waitFor(() => expect(within(timeline).getByRole('button', { name: 'Play' })).toBeInTheDocument()) // stopped at the end
  }, 10_000)
})
