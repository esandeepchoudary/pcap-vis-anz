import { expect, it } from 'vitest'
import { deviceSpec } from './devices'

// Every type the backend's engine (knowledge.py + classification) can produce.
const ENGINE_TYPES = [
  'PLC', 'RTU', 'IED', 'Field Device', 'Smart Meter', 'HMI', 'SCADA Server', 'DCS', 'Historian', 'Engineering Workstation',
  'Web Server', 'DNS Server', 'DHCP Server', 'DHCP Client', 'Mail Server', 'Directory Server', 'Database Server', 'FTP Server',
  'SSH Server', 'Telnet Server', 'NTP Server', 'Log Server', 'Print Server', 'Cache Server', 'Search Server', 'News Server',
  'Container Host', 'Router', 'Network Device', 'VPN Gateway', 'CPE Device', 'Windows Host', 'Linux Host', 'Remote Desktop',
  'Mobile Device', 'Building Controller', 'IP Camera', 'IoT Gateway', 'IoT Sensor', 'Smart Home Hub', 'Smart Speaker',
  'Security Tool', 'Discovery', 'Internet Host',
]

it('has a specific icon and family for every type the engine produces', () => {
  for (const t of ENGINE_TYPES) expect(deviceSpec(t).category, t).not.toBe('unknown')
})

it('groups devices into the right families', () => {
  expect(deviceSpec('PLC').category).toBe('control')
  expect(deviceSpec('Engineering Workstation').category).toBe('supervisory')
  expect(deviceSpec('Firewall').category).toBe('network')
  expect(deviceSpec('Unknown Host').category).toBe('unknown')
  expect(deviceSpec(null, false).category).toBe('external')
})
