import createClient from 'openapi-fetch'
import type { components, paths } from './schema'

export type SystemInfo = components['schemas']['SystemInfo']
export type User = components['schemas']['UserOut']
export type Role = User['role']
export type UserCreate = components['schemas']['UserCreate']
export type UserUpdate = components['schemas']['UserUpdate']

/** Every unsafe request carries this header; the backend rejects ones without it (CSRF guard). */
export const CSRF_HEADERS = { 'X-PcapVis-Client': '1' } as const

export const api = createClient<paths>({
  // Absolute origin: same server in the browser, and valid for Request() in tests.
  baseUrl: globalThis.location?.origin ?? '',
  credentials: 'same-origin',
  headers: CSRF_HEADERS,
  // Resolve fetch at call time so tests can stub globalThis.fetch.
  fetch: (req) => globalThis.fetch(req),
})

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

/** Turn an openapi-fetch result into data-or-throw, with the backend's `detail` as the message. */
export function unwrap<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.error !== undefined || !result.response.ok) {
    throw new ApiError(result.response.status, errorMessage(result.error, result.response.status))
  }
  return result.data as T
}

function errorMessage(error: unknown, status: number): string {
  if (error && typeof error === 'object' && 'detail' in error) {
    const detail = (error as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg)
  }
  return `Request failed (${status})`
}
