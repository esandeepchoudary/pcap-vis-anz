import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import type { SystemInfo, User } from '../api/client'
import { ThemeProvider } from '../theme/theme'

export const laptopSystem: SystemInfo = {
  version: '9.8.7', mode: 'laptop', auth_required: false,
  tshark: { ok: true, path: '/usr/bin/tshark', version: '4.6.4', min_version: '4.0.0', message: 'tshark 4.6.4' },
}
export const serverSystem: SystemInfo = { ...laptopSystem, mode: 'server', auth_required: true }

export const adminUser: User = {
  id: 1, username: 'admin', display_name: 'Ada Admin', role: 'admin', is_active: true,
  created_at: '2026-11-06T10:00:00Z', last_login_at: null,
}
export const localUser: User = { ...adminUser, id: 9, username: 'local', display_name: 'Local user' }

type Handler = (req: Request) => Response | Promise<Response>
export type Recorded = { method: string; path: string; headers: Headers; body: unknown }

export function json(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}

/** Stub fetch with a route table keyed by "METHOD /path". Records every request. */
export function mockApi(routes: Record<string, Handler | Response | unknown>) {
  const calls: Recorded[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(new URL(String(input), 'http://test'), init)
    const url = new URL(req.url)
    const text = req.method === 'GET' ? '' : await req.clone().text()
    calls.push({ method: req.method, path: url.pathname, headers: req.headers, body: text ? JSON.parse(text) : undefined })
    const key = `${req.method} ${url.pathname}`
    const route = routes[key]
    if (route === undefined) return json(404, { detail: `unmocked ${key}` })
    if (typeof route === 'function') return (route as Handler)(req)
    if (route instanceof Response) return route.clone()
    return json(200, route)
  })
  vi.stubGlobal('fetch', fetchMock)
  return { calls, fetchMock }
}

export function renderWithProviders(ui: ReactElement, { route = '/' } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}
