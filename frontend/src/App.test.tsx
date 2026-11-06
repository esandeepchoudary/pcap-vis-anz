import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import App from './App'
import { STAGES } from './stages'
import {
  adminUser, json, laptopSystem, localUser, mockApi, renderWithProviders, serverSystem,
} from './test/utils'

describe('App: laptop mode', () => {
  it('opens straight into the workbench without sign-in', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />)
    expect(await screen.findByRole('heading', { name: 'Welcome' })).toBeInTheDocument()
    expect(within(screen.getByRole('banner')).getByText('v9.8.7')).toBeInTheDocument()
    expect(screen.getByText('Laptop mode')).toBeInTheDocument()
    expect(screen.queryByLabelText('Sign in')).not.toBeInTheDocument()
  })

  it('shows every workflow stage in the rail, in order', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />)
    const rail = await screen.findByRole('navigation', { name: 'Workflow stages' })
    const labels = within(rail).getAllByRole('link').map((a) => a.textContent)
    expect(labels).toEqual(STAGES.map((s) => s.label))
    expect(within(rail).queryByText('Users')).not.toBeInTheDocument() // no user admin in laptop mode
  })

  it('navigates to a stage and marks it active', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />)
    const rail = await screen.findByRole('navigation', { name: 'Workflow stages' })
    await userEvent.click(within(rail).getByRole('link', { name: /Assets/ }))
    expect(await screen.findByRole('heading', { name: 'Asset inventory' })).toBeInTheDocument()
    expect(screen.getByText('Arrives in M3')).toBeInTheDocument()
    expect(within(rail).getByRole('link', { name: /Assets/ })).toHaveClass('active')
    expect(within(rail).getByRole('link', { name: /Overview/ })).not.toHaveClass('active')
  })

  it('redirects unknown routes to the overview', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />, { route: '/no/such/page' })
    expect(await screen.findByRole('heading', { name: 'Welcome' })).toBeInTheDocument()
  })

  it('hides account and admin routes in laptop mode', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />, { route: '/admin/users' })
    expect(await screen.findByRole('heading', { name: 'Welcome' })).toBeInTheDocument()
  })

  it('warns prominently when tshark is unavailable', async () => {
    const broken = { ...laptopSystem, tshark: { ...laptopSystem.tshark, ok: false, version: null, path: null, message: 'tshark not found.' } }
    mockApi({ 'GET /api/system': broken, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />)
    expect(await screen.findByRole('alert')).toHaveTextContent('tshark not found.')
    expect(screen.getByText('unavailable')).toBeInTheDocument()
  })

  it('shows a clear error when the server is unreachable', async () => {
    mockApi({ 'GET /api/system': new Response('down', { status: 502 }) })
    renderWithProviders(<App />)
    expect(await screen.findByRole('alert')).toHaveTextContent("Can't reach the PCAP Visualizer server")
  })
})

describe('App: server mode', () => {
  it('shows the sign-in page when not signed in', async () => {
    mockApi({ 'GET /api/system': serverSystem, 'GET /api/auth/me': json(401, { detail: 'Not signed in.' }) })
    renderWithProviders(<App />)
    expect(await screen.findByRole('form', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
  })

  it('signs in and enters the workbench', async () => {
    const { calls } = mockApi({
      'GET /api/system': serverSystem,
      'GET /api/auth/me': json(401, { detail: 'Not signed in.' }),
      'POST /api/auth/login': adminUser,
    })
    renderWithProviders(<App />)
    await userEvent.type(await screen.findByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { name: 'Welcome' })).toBeInTheDocument()
    const login = calls.find((c) => c.path === '/api/auth/login')!
    expect(login.body).toEqual({ username: 'admin', password: 'correct horse battery' })
    expect(login.headers.get('X-PcapVis-Client')).toBe('1')
  })

  it('shows the server error on a failed sign-in and stays on the form', async () => {
    mockApi({
      'GET /api/system': serverSystem,
      'GET /api/auth/me': json(401, { detail: 'Not signed in.' }),
      'POST /api/auth/login': json(401, { detail: 'Wrong username or password.' }),
    })
    renderWithProviders(<App />)
    await userEvent.type(await screen.findByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'nope nope nope')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Wrong username or password.')
    expect(screen.getByRole('form', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('shows throttling message', async () => {
    mockApi({
      'GET /api/system': serverSystem,
      'GET /api/auth/me': json(401, { detail: 'Not signed in.' }),
      'POST /api/auth/login': json(429, { detail: 'Too many failed sign-in attempts. Try again in 15 minutes.' }),
    })
    renderWithProviders(<App />)
    await userEvent.type(await screen.findByLabelText('Username'), 'admin')
    await userEvent.type(screen.getByLabelText('Password'), 'x')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Too many failed sign-in attempts')
  })

  it('admins see the Users link; others do not', async () => {
    mockApi({ 'GET /api/system': serverSystem, 'GET /api/auth/me': adminUser })
    const { unmount } = renderWithProviders(<App />)
    expect(await screen.findByRole('link', { name: /Users/ })).toBeInTheDocument()
    unmount()
    mockApi({ 'GET /api/system': serverSystem, 'GET /api/auth/me': { ...adminUser, role: 'consultant' } })
    renderWithProviders(<App />)
    await screen.findByRole('heading', { name: 'Welcome' })
    expect(screen.queryByRole('link', { name: /Users/ })).not.toBeInTheDocument()
  })

  it('non-admins cannot reach the users page by URL', async () => {
    mockApi({ 'GET /api/system': serverSystem, 'GET /api/auth/me': { ...adminUser, role: 'viewer' } })
    renderWithProviders(<App />, { route: '/admin/users' })
    expect(await screen.findByRole('heading', { name: 'Welcome' })).toBeInTheDocument()
  })

  it('signs out from the user menu', async () => {
    let signedIn = true
    const { calls } = mockApi({
      'GET /api/system': serverSystem,
      'GET /api/auth/me': () => (signedIn ? json(200, adminUser) : json(401, { detail: 'Not signed in.' })),
      'POST /api/auth/logout': () => { signedIn = false; return new Response(null, { status: 204 }) },
    })
    renderWithProviders(<App />)
    await userEvent.click(await screen.findByRole('button', { name: /Ada Admin/ }))
    await userEvent.click(screen.getByRole('menuitem', { name: /Sign out/ }))
    expect(await screen.findByRole('form', { name: 'Sign in' })).toBeInTheDocument()
    expect(calls.some((c) => c.method === 'POST' && c.path === '/api/auth/logout')).toBe(true)
  })

  it('user menu closes on Escape', async () => {
    mockApi({ 'GET /api/system': serverSystem, 'GET /api/auth/me': adminUser })
    renderWithProviders(<App />)
    await userEvent.click(await screen.findByRole('button', { name: /Ada Admin/ }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).not.toBeInTheDocument())
  })
})

describe('Header', () => {
  it('toggles the theme from the header button', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />)
    await userEvent.click(await screen.findByRole('button', { name: 'Switch to dark theme' }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(screen.getByRole('button', { name: 'Switch to light theme' })).toBeInTheDocument()
  })

  it('inspector collapses and remembers it', async () => {
    mockApi({ 'GET /api/system': laptopSystem, 'GET /api/auth/me': localUser })
    renderWithProviders(<App />)
    await userEvent.click(await screen.findByRole('button', { name: 'Collapse inspector' }))
    expect(screen.queryByText('Nothing selected')).not.toBeInTheDocument()
    expect(localStorage.getItem('pcapvis.inspector.collapsed')).toBe('1')
  })
})
