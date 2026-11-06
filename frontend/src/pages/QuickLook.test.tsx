import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { doneCapture, engagement, FakeXhr, renderWithProviders } from '../test/utils'
import { QuickLook } from './QuickLook'

describe('Quick look', () => {
  it('uploads one file and opens its report', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    FakeXhr.respond = { status: 201, body: { engagement: { ...engagement, id: 9, is_quicklook: true }, capture: { ...doneCapture, id: 21 } } }
    renderWithProviders(
      <Routes><Route path="/quicklook" element={<QuickLook />} /><Route path="/e/:eid/captures/:cid" element={<div>report page</div>} /></Routes>,
      { route: '/quicklook' },
    )
    await userEvent.upload(screen.getByTestId('file-input'), new File(['x'], 'walk.pcap'))
    expect(await screen.findByText('report page')).toBeInTheDocument()
    expect(FakeXhr.last?.url).toBe('/api/quicklook')
    const form = FakeXhr.last!.body as FormData
    expect((form.get('file') as File).name).toBe('walk.pcap')
  })
})
