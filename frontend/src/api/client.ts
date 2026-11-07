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

export function errorMessage(error: unknown, status: number): string {
  if (error && typeof error === 'object' && 'detail' in error) {
    const detail = (error as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg)
  }
  return `Request failed (${status})`
}

type S = components['schemas']
export type Engagement = S['EngagementOut']
export type EngagementCreate = S['EngagementCreate']
export type EngagementUpdate = S['EngagementUpdate']
export type MemberRole = Engagement['my_role']
export type Member = S['MemberOut']
export type DirectoryUser = S['DirectoryUser']
export type CapturePoint = S['CapturePointOut']
export type Capture = S['CaptureOut']
export type AuditEvent = S['AuditEventOut']
export type AnalysisResult = S['AnalysisResult']
export type Host = S['Host']
export type Flow = S['Flow']
export type Anomaly = S['Anomaly']
export type OtCommand = S['OtCommand']
export type Credential = S['Credential']
export type FileTransfer = S['FileTransfer']
export type Evidence = S['Evidence']
export type UploadResult = { capture: Capture; duplicate: boolean }
export type QuickLookResult = { engagement: Engagement; capture: Capture }

/**
 * Multipart upload with progress (fetch can't report upload progress).
 * Resolves with the parsed JSON body; rejects with ApiError carrying the server's message.
 */
export function uploadForm<T>(
  url: string,
  form: FormData,
  onProgress?: (fraction: number) => void,
  signal?: AbortSignal,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', url)
    xhr.withCredentials = true
    xhr.setRequestHeader('X-PcapVis-Client', CSRF_HEADERS['X-PcapVis-Client'])
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total)
    }
    xhr.onload = () => {
      let body: unknown = null
      try {
        body = xhr.responseText ? JSON.parse(xhr.responseText) : null
      } catch {
        /* non-JSON error page */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as T)
      else reject(new ApiError(xhr.status, errorMessage(body, xhr.status)))
    }
    xhr.onerror = () => reject(new ApiError(0, 'Network error during upload.'))
    xhr.onabort = () => reject(new ApiError(0, 'Upload cancelled.'))
    signal?.addEventListener('abort', () => xhr.abort())
    xhr.send(form)
  })
}

export type Asset = S['AssetOut']
export type AssetDetail = S['AssetDetail']
export type AssetChange = S['AssetChangeOut']
export type AssetFields = S['AssetFieldsOut']
export type AssetField = S['AssetFieldOut']
export type EditableField = AssetField['name']
export type AssetEdit = S['AssetEdit']
export type AssetBulkEdit = S['AssetBulkEdit']
export type AssetCreate = S['AssetCreate']
export type FieldValue = string | number | string[] | null
export type Link = S['LinkOut']
export type OtOperation = S['OtOperationOut']
export type Zone = S['ZoneOut']
export type Conduit = S['ConduitOut']
export type Violation = S['ViolationOut']
export type Network = S['NetworkOut']
export type ZoneIn = S['ZoneIn']
export type ZoneUpdate = S['ZoneUpdate']
export type Dashboard = S['DashboardOut']
export type DiffResult = S['DiffOut']
export type PacketList = S['PacketListOut']
export type Finding = S['FindingOut']
export type FindingUpdate = S['FindingUpdate']
export type FindingCreate = S['FindingCreate']
export type MergeReport = S['MergeReportOut']
