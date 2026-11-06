import { describe, expect, it } from 'vitest'
import { mockApi, json } from '../test/utils'
import { api, ApiError, CSRF_HEADERS, unwrap } from './client'

describe('api client', () => {
  it('sends the CSRF header on unsafe requests', async () => {
    const { calls } = mockApi({ 'POST /api/auth/logout': new Response(null, { status: 204 }) })
    await api.POST('/api/auth/logout')
    expect(calls[0].headers.get('X-PcapVis-Client')).toBe(CSRF_HEADERS['X-PcapVis-Client'])
  })

  it('unwrap returns data on success', async () => {
    mockApi({ 'GET /api/health': { status: 'ok' } })
    expect(unwrap(await api.GET('/api/health'))).toEqual({ status: 'ok' })
  })

  it('unwrap throws ApiError with the backend detail message', async () => {
    mockApi({ 'GET /api/auth/me': json(401, { detail: 'Not signed in.' }) })
    const err = await api.GET('/api/auth/me').then(unwrap).catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(401)
    expect(err.message).toBe('Not signed in.')
  })

  it('unwrap reads validation (422) error lists', async () => {
    mockApi({ 'POST /api/auth/login': json(422, { detail: [{ msg: 'String should have at least 1 character' }] }) })
    const err = await api.POST('/api/auth/login', { body: { username: '', password: '' } }).then(unwrap).catch((e) => e)
    expect(err.message).toBe('String should have at least 1 character')
  })

  it('unwrap falls back to a generic message', async () => {
    mockApi({ 'GET /api/health': new Response('boom', { status: 500 }) })
    const err = await api.GET('/api/health').then(unwrap).catch((e) => e)
    expect(err.message).toBe('Request failed (500)')
  })
})
