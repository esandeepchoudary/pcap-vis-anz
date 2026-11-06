import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import type { AnalysisResult, Capture, Engagement, SystemInfo, User } from '../api/client'
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


export const engagement: Engagement = {
  id: 7, name: 'ACME Plant 3', client: 'ACME', site: 'Plant 3', description: 'SPAN on core', status: 'active',
  is_quicklook: false, created_at: '2026-11-06T10:00:00Z', updated_at: '2026-11-06T10:00:00Z', revision: 3,
  my_role: 'lead', capture_count: 1, member_count: 1,
}

export const doneCapture: Capture = {
  id: 11, engagement_id: 7, capture_point_id: 2, capture_point: 'Core SPAN', file_name: 'line2.pcap', size: 2048,
  sha256: 'a'.repeat(64), status: 'done', progress: 1, error: null, uploaded_by: 'local',
  uploaded_at: '2026-11-06T10:00:00Z', started_at: null, finished_at: '2026-11-06T10:01:00Z',
  summary: { packets: 401, hosts: 29, findings: { critical: 2, high: 3, medium: 0, low: 1, info: 0 }, ot_writes: 4, credentials: 2 },
}

export const result: AnalysisResult = {
  capture: { file_name: 'line2.pcap', file_size: 2048, packets: 401, bytes: 9000, first_seen: 1700000000, last_seen: 1700000060,
    link_types: ['eth'], malformed_packets: 0, truncated: false, tshark_version: '4.6.4', warnings: [] },
  hosts: [
    { ip: '10.0.2.10', ip_version: 4, is_private: true, is_multicast: false, is_broadcast: false, mac: '00:0c:29:aa:bb:c0',
      macs: ['00:0c:29:aa:bb:c0'], mac_vendor: 'VMware, Inc.', mac_is_gateway: false, hostname: 'eng-ws-01',
      hostnames: [{ name: 'eng-ws-01', source: 'dhcp' }], dns_queries: [], protocols: ['Modbus', 'S7comm'], services: [],
      os_hint: 'Windows', ttl: 128, vlans: [20], vlan_outer: [], vlan_pcps: [], vlan_untagged: false, vlan_qinq: false,
      packets_sent: 25, packets_recv: 24, bytes_sent: 1900, bytes_recv: 2000, first_seen: 1700000000, last_seen: 1700000050,
      tls_sni: [], tls_ja3: [], tls_ja4: [], ot_role: 'master', modbus_unit_ids: [], dnp3_addresses: [], identity: {},
      host_type: 'Engineering Workstation', host_type_confidence: 'high',
      host_type_evidence: [{ kind: 's7_download', detail: 'Downloads PLC program blocks to 10.0.2.51 over S7comm', weight: 10 }],
      purdue_level: 3, purdue_evidence: [{ kind: 'host_type', detail: 'Engineering Workstation → Level 3', weight: 1 }] },
    { ip: '10.0.2.51', ip_version: 4, is_private: true, is_multicast: false, is_broadcast: false, mac: null, macs: [],
      mac_vendor: null, mac_is_gateway: false, hostname: null, hostnames: [], dns_queries: [], protocols: ['S7comm'],
      services: [{ transport: 'tcp', port: 102, protocol: 'S7comm', packets: 16, clients: 1 }], os_hint: null, ttl: null,
      vlans: [], vlan_outer: [], vlan_pcps: [], vlan_untagged: true, vlan_qinq: false, packets_sent: 8, packets_recv: 8,
      bytes_sent: 900, bytes_recv: 900, first_seen: 1700000000, last_seen: 1700000050, tls_sni: [], tls_ja3: [], tls_ja4: [],
      ot_role: 'outstation', modbus_unit_ids: [], dnp3_addresses: [], identity: { enip_vendor: 'Siemens' },
      host_type: 'PLC', host_type_confidence: 'high', host_type_evidence: [], purdue_level: 1, purdue_evidence: [] },
  ],
  flows: [],
  ot_commands: [
    { time: 1700000010, flow_id: 1, src: '10.0.2.10', dst: '10.0.2.51', protocol: 'S7comm', function_code: 26,
      function: 'Request download', kind: 'write', is_request: true, unit: null, address: null, quantity: null, detail: 'Block OB1' },
    { time: 1700000011, flow_id: 1, src: '10.0.2.10', dst: '10.0.2.51', protocol: 'S7comm', function_code: 4,
      function: 'Read Var', kind: 'read', is_request: true, unit: null, address: null, quantity: null, detail: '' },
  ],
  ot_commands_truncated: false,
  credentials: [{ protocol: 'FTP', kind: 'password', client: '10.0.1.10', server: '10.0.1.80', server_port: 21,
    username: 'ftpadmin', secret: 'Summer2024!', flow_id: 3, first_seen: 1700000020, count: 1 }],
  files: [{ protocol: 'HTTP', filename: 'update.exe', size: 304, sha256: 'b'.repeat(64), mime: 'application/x-msdownload',
    interesting: true, source_url: 'hmi/update.exe', stored_path: null }],
  anomalies: [
    { id: 'a1', rule: 'ot_s7_code_download', category: 'ot', severity: 'critical', title: 'PLC program download (S7comm)',
      description: '10.0.2.10 downloaded program blocks to PLC 10.0.2.51', src: '10.0.2.10', dst: '10.0.2.51', flow_ids: [1],
      first_seen: 1700000010, last_seen: 1700000010, count: 1, evidence: ['Block OB1'], attack: ['T0843'] },
    { id: 'a2', rule: 'vlan_native_leak', category: 'vlan', severity: 'low', title: 'Tagged and untagged frames from one host',
      description: '10.0.1.80 sends both', src: '10.0.1.80', dst: null, flow_ids: [], first_seen: null, last_seen: null,
      count: 1, evidence: [], attack: [] },
  ],
  vlan_stats: [], arp_claims: [],
}

/** Minimal XMLHttpRequest stand-in for upload tests. Configure via FakeXhr.respond. */
export class FakeXhr {
  static respond: { status: number; body: unknown } = { status: 201, body: [] }
  static last: FakeXhr | null = null
  method = ''
  url = ''
  headers: Record<string, string> = {}
  body: unknown = null
  status = 0
  responseText = ''
  withCredentials = false
  upload: { onprogress: ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null } = { onprogress: null }
  onload: (() => void) | null = null
  onerror: (() => void) | null = null
  onabort: (() => void) | null = null
  open(method: string, url: string) { this.method = method; this.url = url }
  setRequestHeader(k: string, v: string) { this.headers[k] = v }
  abort() { this.onabort?.() }
  send(body: unknown) {
    this.body = body
    FakeXhr.last = this
    queueMicrotask(() => {
      this.upload.onprogress?.({ lengthComputable: true, loaded: 50, total: 100 })
      this.status = FakeXhr.respond.status
      this.responseText = JSON.stringify(FakeXhr.respond.body)
      this.onload?.()
    })
  }
}
