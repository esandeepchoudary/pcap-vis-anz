import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import type { Capture } from '../api/client'
import { doneCapture, engagement, FakeXhr, mockApi, renderWithProviders } from '../test/utils'
import { CapturesPage } from './CapturesPage'
import { EngagementLayout } from './EngagementLayout'

const points = [{ id: 2, name: 'Core SPAN', description: 'Gi0/24', created_at: '2026-11-06T10:00:00Z' }]
const running: Capture = { ...doneCapture, id: 12, file_name: 'live.pcap', status: 'processing', progress: 0.42, summary: null }
const failed: Capture = { ...doneCapture, id: 13, file_name: 'bad.pcap', status: 'failed', error: 'tshark could not read this capture', summary: null }

function setup(role: 'lead' | 'viewer' = 'lead', captures: Capture[] = [doneCapture, running, failed]) {
  const api = mockApi({
    'GET /api/engagements/7': { ...engagement, my_role: role },
    'GET /api/engagements/7/captures': captures,
    'GET /api/engagements/7/capture-points': points,
    'POST /api/engagements/7/captures/12/cancel': { ...running },
    'POST /api/engagements/7/captures/13/reanalyze': { ...failed, status: 'queued' },
    'POST /api/engagements/7/capture-points': points[0],
  })
  renderWithProviders(
    <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="captures" element={<CapturesPage />} /></Route></Routes>,
    { route: '/e/7/captures' },
  )
  return api
}

describe('Captures page', () => {
  it('shows each capture with status, progress, summary and findings', async () => {
    setup()
    const table = await screen.findByRole('table')
    const rows = within(table).getAllByRole('row')
    expect(rows).toHaveLength(4)
    expect(within(rows[1]).getByRole('link', { name: 'line2.pcap' })).toHaveAttribute('href', '/e/7/captures/11')
    expect(within(rows[1]).getByText('Done')).toBeInTheDocument()
    expect(within(rows[1]).getByText('2 critical')).toBeInTheDocument()
    expect(within(rows[1]).getByText('401')).toBeInTheDocument()
    expect(within(rows[2]).getByText('Analysing')).toBeInTheDocument()
    expect(within(rows[2]).getByRole('progressbar')).toHaveAttribute('aria-valuenow', '42')
    expect(within(rows[3]).getByText('tshark could not read this capture')).toBeInTheDocument()
  })

  it('cancels a running analysis and re-analyses a failed one', async () => {
    const { calls } = setup()
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel live.pcap' }))
    await userEvent.click(screen.getByRole('button', { name: 'Re-analyse bad.pcap' }))
    await waitFor(() => expect(calls.filter((c) => c.method === 'POST').map((c) => c.path)).toEqual([
      '/api/engagements/7/captures/12/cancel', '/api/engagements/7/captures/13/reanalyze']))
  })

  it('deleting needs a second click', async () => {
    const { calls } = mockApi({
      'GET /api/engagements/7': engagement, 'GET /api/engagements/7/captures': [doneCapture],
      'GET /api/engagements/7/capture-points': points, 'DELETE /api/engagements/7/captures/11': new Response(null, { status: 204 }),
    })
    renderWithProviders(
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="captures" element={<CapturesPage />} /></Route></Routes>,
      { route: '/e/7/captures' },
    )
    const del = await screen.findByLabelText('Delete line2.pcap')
    await userEvent.click(del)
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Delete?' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE')).toBe(true))
  })

  it('uploads with the chosen capture point and reports duplicates', async () => {
    setup('lead', [])
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    FakeXhr.respond = { status: 201, body: [{ capture: doneCapture, duplicate: true }] }
    await screen.findByRole('option', { name: 'Core SPAN' })
    await userEvent.selectOptions(screen.getByLabelText('Capture point for upload'), 'Core SPAN')
    await userEvent.upload(screen.getByTestId('file-input'), new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'line2.pcap'))
    expect(await screen.findByText('line2.pcap was already uploaded; skipped.')).toBeInTheDocument()
    const form = FakeXhr.last?.body as FormData
    expect(FakeXhr.last?.url).toBe('/api/engagements/7/captures')
    expect(form.get('capture_point_id')).toBe('2')
    expect((form.get('files') as File).name).toBe('line2.pcap')
  })

  it('the file picker only offers capture files', async () => {
    setup('lead', [])
    expect(await screen.findByTestId('file-input')).toHaveAttribute('accept', '.pcap,.pcapng,.cap,.gz')
  })

  it('shows upload errors from the server', async () => {
    setup('lead', [])
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    FakeXhr.respond = { status: 400, body: { detail: 'notes.pcap: not a pcap, pcapng or gzipped capture.' } }
    // A .pcap name gets past the browser's file filter; the server checks the actual content.
    await userEvent.upload(await screen.findByTestId('file-input'), new File(['hello'], 'notes.pcap'))
    expect(await screen.findByRole('alert')).toHaveTextContent('not a pcap')
  })

  it('adds a capture point', async () => {
    const { calls } = setup('lead', [])
    const section = await screen.findByRole('region', { name: 'Capture points' })
    await userEvent.click(within(section).getByRole('button', { name: /Add/ }))
    await userEvent.type(within(section).getByLabelText('Capture point name'), 'Cell A TAP')
    await userEvent.click(within(section).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ name: 'Cell A TAP', description: '' }))
  })

  it('viewers see captures but no upload or actions', async () => {
    setup('viewer')
    await screen.findByRole('table')
    expect(screen.queryByRole('region', { name: 'Add captures' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/Capture point for line2/)).not.toBeInTheDocument()
    expect(screen.getByLabelText('Download line2.pcap')).toBeInTheDocument()
  })

  it('explains when the engagement is not accessible', async () => {
    mockApi({})  // every call 404s
    renderWithProviders(
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="captures" element={<CapturesPage />} /></Route></Routes>,
      { route: '/e/99/captures' },
    )
    expect(await screen.findByRole('alert')).toHaveTextContent("doesn't exist or you don't have access")
  })
})
