import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { Inspector } from '../components/Inspector'
import { InspectorContext, type Selection } from '../inspector/context'
import { doneCapture, engagement, mockApi, renderWithProviders, result } from '../test/utils'
import { CaptureReport } from './CaptureReport'
import { EngagementLayout } from './EngagementLayout'

function Harness() {
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="captures/:cid" element={<CaptureReport />} /></Route></Routes>
      <Inspector />
    </InspectorContext.Provider>
  )
}

function setup(capture = doneCapture) {
  mockApi({
    'GET /api/engagements/7': engagement,
    'GET /api/engagements/7/captures': [capture],
    'GET /api/engagements/7/captures/11/result': result,
  })
  renderWithProviders(<Harness />, { route: '/e/7/captures/11' })
}

describe('Capture report', () => {
  it('shows summary tiles and findings with ATT&CK ids, critical first', async () => {
    setup()
    const tiles = await screen.findByLabelText('Capture summary')
    expect(within(tiles).getByText('401')).toBeInTheDocument()
    expect(within(tiles).getByText('1m 0s')).toBeInTheDocument()
    const findings = screen.getAllByRole('article')
    expect(findings[0]).toHaveTextContent('PLC program download (S7comm)')
    expect(findings[0]).toHaveTextContent('T0843')
    expect(findings[0]).toHaveTextContent('Block OB1')
  })

  it('filters findings by severity', async () => {
    setup()
    await screen.findAllByRole('article')
    await userEvent.selectOptions(screen.getByLabelText('Filter findings by severity'), 'low')
    expect(screen.getAllByRole('article')).toHaveLength(1)
    expect(screen.getByText('1 finding')).toBeInTheDocument()
  })

  it('selecting a host shows its evidence in the inspector', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: /Hosts/ }))
    await userEvent.click(screen.getByRole('row', { name: /10.0.2.10/ }))
    const details = screen.getByLabelText('Host 10.0.2.10')
    expect(within(details).getByText('Engineering Workstation')).toBeInTheDocument()
    expect(within(details).getByText('Downloads PLC program blocks to 10.0.2.51 over S7comm')).toBeInTheDocument()
    expect(within(details).getByText('Purdue L3')).toBeInTheDocument()
    await userEvent.click(within(details).getByRole('button', { name: 'Close host details' }))
    expect(screen.getByText('Nothing selected')).toBeInTheDocument()
  })

  it('filters hosts', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: /Hosts/ }))
    await userEvent.type(screen.getByLabelText('Filter hosts'), 'plc')
    expect(screen.queryByRole('row', { name: /10.0.2.10/ })).not.toBeInTheDocument()
    expect(screen.getByRole('row', { name: /10.0.2.51/ })).toBeInTheDocument()
  })

  it('groups OT commands, writes first', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: /OT commands/ }))
    const rows = within(screen.getByRole('table', { name: 'OT commands' })).getAllByRole('row')
    expect(rows[1]).toHaveTextContent('Request download')
    expect(rows[1]).toHaveTextContent('write')
  })

  it('hides credential secrets until revealed', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: /Credentials/ }))
    const secret = screen.getByText('Summer2024!')
    expect(secret).toHaveClass('masked')
    await userEvent.click(screen.getByRole('button', { name: /Reveal secrets/ }))
    expect(screen.getByText('Summer2024!')).not.toHaveClass('masked')
  })

  it('lists files with a safe download link', async () => {
    setup()
    await userEvent.click(await screen.findByRole('tab', { name: /Files/ }))
    expect(screen.getByText('review')).toBeInTheDocument()
    expect(screen.getByLabelText('Download update.exe')).toHaveAttribute('href', `/api/engagements/7/files/${'b'.repeat(64)}?name=update.exe`)
  })

  it('shows progress while the capture is still being analysed', async () => {
    setup({ ...doneCapture, status: 'processing', progress: 0.3, summary: null })
    expect(await screen.findByText('Analysing… 30%')).toBeInTheDocument()
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })
})
