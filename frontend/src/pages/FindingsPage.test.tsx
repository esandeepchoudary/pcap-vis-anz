import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { Finding } from '../api/client'
import { Inspector } from '../components/Inspector'
import { InspectorContext, type Selection } from '../inspector/context'
import { engagement, json, mockApi, renderWithProviders } from '../test/utils'
import { EngagementLayout } from './EngagementLayout'
import { FindingsPage } from './FindingsPage'
import { ReportPage } from './ReportPage'

const rule: Finding = {
  key: 'a1', source: 'rule', rule: 'ot_s7_code_download', category: 'ot', title: 'PLC program download (S7comm)',
  description: 'Program blocks were downloaded', severity: 'critical', detected_severity: 'critical', attack: ['T0843'],
  evidence: ['Block OB1'], asset_ids: [], src: '10.0.2.10', dst: '10.0.2.51', count: 3, first_seen: 1700000000, last_seen: 1700000100,
  captures: [11], status: 'open', notes: '', recommendation: '', include_in_report: true, updated_by: '', updated_at: null,
}
const fp: Finding = { ...rule, key: 'b2', title: 'Port scan', severity: 'low', detected_severity: 'low', status: 'false_positive', include_in_report: false, attack: [] }

function Harness() {
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}>
        <Route path="findings" element={<FindingsPage />} /><Route path="report" element={<ReportPage />} />
      </Route></Routes>
      <Inspector />
    </InspectorContext.Provider>
  )
}

function setup(extra: Record<string, unknown> = {}, route = '/e/7/findings', eng = engagement) {
  const api = mockApi({
    'GET /api/engagements/7': eng, 'GET /api/engagements/7/findings': [rule, fp], 'GET /api/engagements/7/assets': [], ...extra,
  })
  renderWithProviders(<Harness />, { route })
  return api
}

describe('Findings', () => {
  it('lists findings and filters by status and search', async () => {
    setup()
    expect(await screen.findByText('2 findings across all captures · 1 in the report')).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Filter by status'), 'false_positive')
    expect(within(screen.getByRole('table', { name: 'Findings' })).getAllByRole('row')).toHaveLength(2)
    await userEvent.selectOptions(screen.getByLabelText('Filter by status'), 'all')
    await userEvent.type(screen.getByLabelText('Search findings'), 't0843')
    expect(within(screen.getByRole('table', { name: 'Findings' })).getAllByRole('row')).toHaveLength(2)
  })

  it('triages a finding in the inspector', async () => {
    const api = setup({ 'PATCH /api/engagements/7/findings/a1': { ...rule, status: 'confirmed' } })
    await userEvent.click(await screen.findByText('PLC program download (S7comm)'))
    const panel = await screen.findByLabelText('Finding details')
    expect(within(panel).getByLabelText('Finding evidence')).toHaveTextContent('Block OB1')
    await userEvent.selectOptions(within(panel).getByLabelText('Status'), 'confirmed')
    await waitFor(() => expect(api.calls.find((c) => c.method === 'PATCH')?.body).toEqual({ clear_severity_override: false, status: 'confirmed' }))
  })

  it('adds a manual finding', async () => {
    const api = setup({ 'POST /api/engagements/7/findings': () => json(201, { ...rule, key: 'manual-x', source: 'manual', title: 'Flat network' }) })
    await userEvent.click(await screen.findByRole('button', { name: /Add finding/ }))
    const form = screen.getByRole('form', { name: 'Add finding' })
    await userEvent.type(within(form).getByLabelText('Title'), 'Flat network')
    await userEvent.selectOptions(within(form).getByLabelText('Severity'), 'high')
    await userEvent.click(within(form).getByRole('button', { name: 'Add finding' }))
    await waitFor(() => expect(api.calls.find((c) => c.method === 'POST')?.body).toEqual({
      description: '', recommendation: '', asset_ids: [], title: 'Flat network', severity: 'high',
    }))
  })

  it('keeps an unsaved recommendation when the finding refreshes', async () => {
    let status: Finding['status'] = 'open'
    setup({
      'GET /api/engagements/7/findings': () => json(200, [{ ...rule, status, updated_at: status === 'open' ? null : '2026-11-06T10:00:00Z' }, fp]),
      'PATCH /api/engagements/7/findings/a1': () => { status = 'confirmed'; return json(200, { ...rule, status }) },
    })
    await userEvent.click(await screen.findByText('PLC program download (S7comm)'))
    const panel = await screen.findByLabelText('Finding details')
    await userEvent.type(within(panel).getByLabelText('Recommendation'), 'Restrict downloads')
    await userEvent.selectOptions(within(panel).getByLabelText('Status'), 'confirmed')
    await waitFor(() => expect(within(panel).getByLabelText('Status')).toHaveValue('confirmed'))
    expect(within(panel).getByLabelText('Recommendation')).toHaveValue('Restrict downloads')
    expect(within(panel).getByRole('button', { name: 'Save notes' })).toBeInTheDocument()
  })

  it('viewers cannot triage', async () => {
    setup({}, '/e/7/findings', { ...engagement, my_role: 'viewer' })
    expect(screen.queryByRole('button', { name: /Add finding/ })).not.toBeInTheDocument()
    await userEvent.click(await screen.findByText('PLC program download (S7comm)'))
    expect(await screen.findByLabelText('Status')).toBeDisabled()
  })
})

it('report page offers every deliverable and says what the report will contain', async () => {
  setup({}, '/e/7/report')
  await waitFor(() => expect(screen.getByLabelText('Report contents')).toHaveTextContent('1 finding will be in the report'))
  expect(screen.getByRole('link', { name: /Word/ })).toHaveAttribute('href', '/api/engagements/7/reports/report.docx')
  expect(screen.getByRole('link', { name: /HTML/ })).toHaveAttribute('href', '/api/engagements/7/reports/report.html')
  expect(screen.getByRole('link', { name: /Excel/ })).toHaveAttribute('href', '/api/engagements/7/reports/assets.xlsx')
  expect(screen.getAllByRole('link', { name: /draw.io/ }).map((l) => l.getAttribute('href'))).toEqual([
    '/api/engagements/7/reports/purdue.drawio', '/api/engagements/7/reports/architecture.drawio',
  ])
  expect(screen.getAllByRole('link', { name: /SVG/ }).map((l) => l.getAttribute('href'))).toEqual([
    '/api/engagements/7/reports/purdue.svg', '/api/engagements/7/reports/architecture.svg',
  ])
  await userEvent.click(screen.getByLabelText('Include original captures'))
  expect(screen.getByRole('link', { name: /.pcapvis/ })).toHaveAttribute('href', '/api/engagements/7/export?captures=true&files=true')
})
