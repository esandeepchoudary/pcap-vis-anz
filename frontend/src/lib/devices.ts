import {
  ArrowRightToLine, BrickWall, Building, Cctv, ChartLine, CircleQuestionMark, Clock, Container, Cpu, Database, Factory,
  FolderOpen, Gauge, Globe, House, Layers, Mail, Monitor, MonitorCog, Network, Printer, Radar, RadioTower, Router,
  ScanSearch, ScreenShare, ScrollText, Search, Server, ShieldCheck, Signpost, Smartphone, Speaker, Terminal,
  Thermometer, Users, Wrench, Zap, type LucideIcon,
} from 'lucide-react'

/** Broad device families: they decide the colour, so a map reads at a glance. */
export type DeviceCategory = 'control' | 'supervisory' | 'server' | 'network' | 'endpoint' | 'iot' | 'security' | 'external' | 'unknown'

export const CATEGORY_LABELS: Record<DeviceCategory, string> = {
  control: 'OT control (PLC, RTU, IED, field)',
  supervisory: 'OT supervisory (HMI, SCADA, EWS)',
  server: 'IT server',
  network: 'Network / boundary',
  endpoint: 'Workstation / endpoint',
  iot: 'IoT / building',
  security: 'Security / scanner',
  external: 'External',
  unknown: 'Unknown',
}

type Spec = { icon: LucideIcon; category: DeviceCategory }

/** Every type the engine produces, plus the ones consultants commonly add by hand. */
const TYPES: Record<string, Spec> = {
  // OT control level
  PLC: { icon: Cpu, category: 'control' },
  RTU: { icon: RadioTower, category: 'control' },
  IED: { icon: Zap, category: 'control' },
  'Field Device': { icon: Gauge, category: 'control' },
  'Smart Meter': { icon: Gauge, category: 'control' },
  // OT supervisory
  HMI: { icon: MonitorCog, category: 'supervisory' },
  'SCADA Server': { icon: Factory, category: 'supervisory' },
  DCS: { icon: Factory, category: 'supervisory' },
  Historian: { icon: ChartLine, category: 'supervisory' },
  'Engineering Workstation': { icon: Wrench, category: 'supervisory' },
  // IT servers
  'Web Server': { icon: Globe, category: 'server' },
  'DNS Server': { icon: Signpost, category: 'server' },
  'DHCP Server': { icon: Network, category: 'server' },
  'Mail Server': { icon: Mail, category: 'server' },
  'Directory Server': { icon: Users, category: 'server' },
  'Database Server': { icon: Database, category: 'server' },
  'FTP Server': { icon: FolderOpen, category: 'server' },
  'SSH Server': { icon: Terminal, category: 'server' },
  'Telnet Server': { icon: Terminal, category: 'server' },
  'NTP Server': { icon: Clock, category: 'server' },
  'Log Server': { icon: ScrollText, category: 'server' },
  'Print Server': { icon: Printer, category: 'server' },
  'Cache Server': { icon: Layers, category: 'server' },
  'Search Server': { icon: Search, category: 'server' },
  'News Server': { icon: Server, category: 'server' },
  'Container Host': { icon: Container, category: 'server' },
  // Network and boundary
  Router: { icon: Router, category: 'network' },
  'Network Device': { icon: Network, category: 'network' },
  Switch: { icon: Network, category: 'network' },
  Firewall: { icon: BrickWall, category: 'network' },
  'Data Diode': { icon: ArrowRightToLine, category: 'network' },
  'VPN Gateway': { icon: ShieldCheck, category: 'network' },
  'CPE Device': { icon: Router, category: 'network' },
  // Endpoints
  'Windows Host': { icon: Monitor, category: 'endpoint' },
  'Linux Host': { icon: Terminal, category: 'endpoint' },
  'DHCP Client': { icon: Monitor, category: 'endpoint' },
  'Remote Desktop': { icon: ScreenShare, category: 'endpoint' },
  'Mobile Device': { icon: Smartphone, category: 'endpoint' },
  // IoT and building
  'Building Controller': { icon: Building, category: 'iot' },
  'IP Camera': { icon: Cctv, category: 'iot' },
  'IoT Gateway': { icon: Router, category: 'iot' },
  'IoT Sensor': { icon: Thermometer, category: 'iot' },
  'Smart Home Hub': { icon: House, category: 'iot' },
  'Smart Speaker': { icon: Speaker, category: 'iot' },
  // Other
  'Security Tool': { icon: ScanSearch, category: 'security' },
  Discovery: { icon: Radar, category: 'network' },
  'Internet Host': { icon: Globe, category: 'external' },
}

const UNKNOWN: Spec = { icon: CircleQuestionMark, category: 'unknown' }

export function deviceSpec(type: string | null | undefined, isPrivate = true): Spec {
  const spec = (type && TYPES[type]) || UNKNOWN
  if (!isPrivate && spec.category === 'unknown') return { icon: Globe, category: 'external' }
  return spec
}

export const KNOWN_DEVICE_TYPES = Object.keys(TYPES)
