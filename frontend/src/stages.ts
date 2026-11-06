import {
  ArrowLeftRight, Boxes, FileText, Layers, LayoutDashboard, Network, ShieldAlert, Upload, type LucideIcon,
} from 'lucide-react'

export type Stage = {
  id: string
  /** URL segment under /e/:eid/ */
  segment: string
  label: string
  title: string
  icon: LucideIcon
  milestone: string
  summary: string
  plans: string[]
}

/** Workflow stages shown in the left rail, in engagement order. */
export const STAGES: Stage[] = [
  {
    id: 'overview', segment: 'overview', label: 'Overview', title: 'Overview', icon: LayoutDashboard, milestone: 'M2',
    summary: 'Engagement summary, members, export and activity.', plans: [],
  },
  {
    id: 'captures', segment: 'captures', label: 'Captures', title: 'Captures', icon: Upload, milestone: 'M2',
    summary: 'Add pcaps to an engagement, tag where each was captured, and track parsing progress.',
    plans: ['Upload with background parsing, progress and cancel', 'Capture points (switch, SPAN, segment)', 'Quick look without an engagement', '.pcapvis engagement export and import'],
  },
  {
    id: 'assets', segment: 'assets', label: 'Assets', title: 'Asset inventory', icon: Boxes, milestone: 'M3',
    summary: 'Every device seen on the wire, editable, with evidence and change history.',
    plans: [],
  },
  {
    id: 'purdue', segment: 'purdue', label: 'Purdue', title: 'Purdue map', icon: Layers, milestone: 'M4',
    summary: 'Assets by Purdue level and zone, editable by drag, dropdown, or bulk assignment.',
    plans: [],
  },
  {
    id: 'architecture', segment: 'architecture', label: 'Architecture', title: 'Network architecture', icon: Network, milestone: 'M6',
    summary: 'Zones, conduits, and a layered network architecture diagram.',
    plans: ['IEC 62443 zones and conduits with violation detection', 'Subnets, VLANs and gateways', 'Manual firewalls and data diodes'],
  },
  {
    id: 'flows', segment: 'flows', label: 'Flows', title: 'Flows & network', icon: ArrowLeftRight, milestone: 'M7',
    summary: 'Network graph, flow table, DNS, VLANs, baseline diff, and packet inspector.',
    plans: ['Graph and flow table', 'DNS and VLAN views', 'Baseline diff', 'Packet inspector'],
  },
  {
    id: 'findings', segment: 'findings', label: 'Findings', title: 'Findings', icon: ShieldAlert, milestone: 'M8',
    summary: 'Anomalies and analyst findings with triage, evidence, and report inclusion.',
    plans: ['Findings from rules and manual entries', 'Status, severity, notes', 'Evidence bundles'],
  },
  {
    id: 'report', segment: 'report', label: 'Report', title: 'Report & exports', icon: FileText, milestone: 'M8',
    summary: 'Client-ready deliverables.',
    plans: ['Asset register (XLSX)', 'Editable diagrams (SVG, draw.io)', 'DOCX/PDF report', 'One-click engagement bundle'],
  },
]
