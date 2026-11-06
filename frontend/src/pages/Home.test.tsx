import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { adminUser, engagement, FakeXhr, json, laptopSystem, localUser, mockApi, renderWithProviders, serverSystem } from '../test/utils'
import { Home } from './Home'

function renderHome(system = laptopSystem, user = localUser, route = '/') {
  return renderWithProviders(
    <Routes>
      <Route path="/" element={<Home system={system} user={user} />} />
      <Route path="/e/:eid/*" element={<div>opened engagement</div>} />
    </Routes>,
    { route },
  )
}

describe('Home (engagements)', () => {
  it('lists engagements with client, site, counts and role', async () => {
    mockApi({ 'GET /api/engagements': (req: Request) => json(200, new URL(req.url).searchParams.get('quicklook') === 'true' ? [] : [engagement]) })
    renderHome()
    const list = await screen.findByLabelText('Engagement list')
    const card = within(list).getByRole('link', { name: /ACME Plant 3/ })
    expect(card).toHaveAttribute('href', '/e/7/overview')
    expect(card).toHaveTextContent('ACME · Plant 3')
    expect(card).toHaveTextContent('1 capture')
    expect(card).toHaveTextContent('lead')
  })

  it('shows an empty state and system status', async () => {
    mockApi({ 'GET /api/engagements': [] })
    renderHome()
    expect(await screen.findByText('No engagements yet')).toBeInTheDocument()
    expect(screen.getByText('tshark 4.6.4')).toBeInTheDocument()
  })

  it('creates an engagement and opens it', async () => {
    const { calls } = mockApi({ 'GET /api/engagements': [], 'POST /api/engagements': engagement })
    renderHome()
    await userEvent.click(await screen.findByRole('button', { name: /New engagement/ }))
    const form = screen.getByRole('form', { name: 'New engagement' })
    await userEvent.type(within(form).getByLabelText('Name'), 'ACME Plant 3')
    await userEvent.type(within(form).getByLabelText('Client'), 'ACME')
    await userEvent.click(within(form).getByRole('button', { name: 'Create engagement' }))
    expect(await screen.findByText('opened engagement')).toBeInTheDocument()
    expect(calls.find((c) => c.method === 'POST')?.body).toMatchObject({ name: 'ACME Plant 3', client: 'ACME' })
  })

  it.each(['consultant', 'viewer'] as const)('%s cannot create or import in server mode', async (role) => {
    mockApi({ 'GET /api/engagements': [] })
    renderHome(serverSystem, { ...adminUser, role })
    await screen.findByText('No engagements yet')
    expect(screen.queryByRole('button', { name: /New engagement/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Import/ })).not.toBeInTheDocument()
    expect(screen.getByText(/Ask a lead to add you/)).toBeInTheDocument()
  })

  it('imports a .pcapvis bundle and opens it', async () => {
    mockApi({ 'GET /api/engagements': [] })
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    FakeXhr.respond = { status: 201, body: engagement }
    renderHome()
    await userEvent.upload(await screen.findByTestId('import-input'), new File(['PK'], 'acme.pcapvis'))
    expect(await screen.findByText('opened engagement')).toBeInTheDocument()
    expect(FakeXhr.last?.url).toBe('/api/engagements/import')
    expect(FakeXhr.last?.headers['X-PcapVis-Client']).toBe('1')
  })

  it('shows the server message when an import is rejected', async () => {
    mockApi({ 'GET /api/engagements': [] })
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    FakeXhr.respond = { status: 400, body: { detail: 'Unexpected entry in bundle' } }
    renderHome()
    await userEvent.upload(await screen.findByTestId('import-input'), new File(['PK'], 'evil.pcapvis'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Import failed: Unexpected entry in bundle')
  })

  it('lists personal Quick looks separately', async () => {
    const ql = { ...engagement, id: 9, name: 'walkdown.pcap', is_quicklook: true }
    mockApi({ 'GET /api/engagements': (req: Request) => json(200, new URL(req.url).searchParams.get('quicklook') === 'true' ? [ql] : []) })
    renderHome()
    const section = await screen.findByRole('region', { name: 'Your Quick looks' })
    expect(within(section).getByRole('link', { name: 'walkdown.pcap' })).toHaveAttribute('href', '/e/9/captures')
  })
})
