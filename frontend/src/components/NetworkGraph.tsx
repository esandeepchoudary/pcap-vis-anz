import {
  Background, BackgroundVariant, Controls, Handle, MiniMap, Position, ReactFlow, applyNodeChanges,
  type Edge, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { KeyRound } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { Asset, Engagement, Finding, Link } from '../api/client'
import { useFindings } from '../api/findings'
import { useInspector } from '../inspector/context'
import { assetLabel } from '../lib/assets'
import { CATEGORY_LABELS, deviceSpec, type DeviceCategory } from '../lib/devices'
import { G_NODE_H, G_NODE_W, forceLayout, linkKey, nodeRadius, subnetLayout, subnetOf, suspiciousPairs } from '../lib/graph'
import { purdueLabel } from '../lib/format'
import { SEVERITIES } from '../lib/severity'
import { DeviceIcon } from './DeviceIcon'

type Layout = 'force' | 'subnet'
const LABEL_W = 132
type AssetData = { asset: Asset; r: number; dim: boolean; risk: Finding['severity'] | null; findings: number; credentials: boolean; writeTarget: boolean; compact: boolean }

function ForceNode({ data, selected }: NodeProps<Node<AssetData>>) {
  const { asset: a, r } = data
  const { category } = deviceSpec(a.asset_type, a.is_private)
  return (
    <div className={`fgx${data.dim ? ' dim' : ''}${selected ? ' selected' : ''}`} style={{ width: LABEL_W }}
      title={`${assetLabel(a)} · ${a.ips.join(', ')} · ${a.asset_type ?? 'Unknown'} · ${purdueLabel(a.purdue_level)}`}>
      <div className={`fgx-circle cat-${category}${data.writeTarget ? ' write-target' : ''}`} style={{ width: r * 2, height: r * 2 }}>
        <DeviceIcon type={a.asset_type} isPrivate={a.is_private} size={Math.round(r * 0.95)} label={false} />
        {data.risk && <span className={`fgx-badge sev-bg-${data.risk}`} aria-label={`${data.findings} findings`}>{data.findings}</span>}
        {data.credentials && <span className="fgx-key" aria-label="cleartext credentials"><KeyRound size={10} /></span>}
      </div>
      <div className="fgx-label">{assetLabel(a)}</div>
      {!data.compact && a.name && a.ips[0] && <div className="fgx-sub">{a.ips[0]}</div>}
      <Handle type="target" position={Position.Top} className="fgx-handle" style={{ top: r }} isConnectable={false} />
      <Handle type="source" position={Position.Bottom} className="fgx-handle" style={{ top: r, bottom: 'auto' }} isConnectable={false} />
    </div>
  )
}

function CardNode({ data, selected }: NodeProps<Node<AssetData>>) {
  const a = data.asset
  return (
    <div className={`fg-node${selected ? ' selected' : ''}${data.dim ? ' dim' : ''}`} title={`${assetLabel(a)} · ${a.ips.join(', ')}`}>
      <Handle type="target" position={Position.Top} className="pm-handle" isConnectable={false} />
      <div className="pm-asset-name"><DeviceIcon type={a.asset_type} isPrivate={a.is_private} size={13} label={false} /> {assetLabel(a)}
        {data.risk && <span className={`fgx-inline sev-bg-${data.risk}`}>{data.findings}</span>}</div>
      <div className="pm-asset-sub">{a.asset_type ?? 'Unknown'} · {purdueLabel(a.purdue_level)}</div>
      <Handle type="source" position={Position.Bottom} className="pm-handle" isConnectable={false} />
    </div>
  )
}

function SubnetNode({ data }: NodeProps<Node<{ label: string }>>) {
  return <div className="fg-subnet"><span>{data.label}</span></div>
}
const nodeTypes = { asset: ForceNode, card: CardNode, subnet: SubnetNode }

export function NetworkGraph({ eng, assets, links }: { eng: Engagement; assets: Asset[]; links: Link[] }) {
  const { selection, select } = useInspector()
  const findings = useFindings(eng.id)
  const [layout, setLayout] = useState<Layout>('force')
  const [otOnly, setOtOnly] = useState(false)
  const [showExternal, setShowExternal] = useState(true)
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [isolate, setIsolate] = useState<number | null>(null)
  const [hover, setHover] = useState<number | null>(null)
  const [legendOpen, setLegendOpen] = useState(() => localStorage.getItem('pcapvis.graph.legend') === 'open')
  const byId = useMemo(() => new Map(assets.map((a) => [a.id, a])), [assets])

  const allProtocols = useMemo(() => [...new Set(links.flatMap((l) => l.protocols.map((p) => p.protocol)))].sort(), [links])
  const shown = useMemo(() => {
    const visible = (id: number) => { const a = byId.get(id); return !!a && (showExternal || a.is_private || a.origin === 'manual') }
    let out = links.filter((l) => (!otOnly || l.is_ot) && visible(l.src) && visible(l.dst)
      && l.protocols.some((p) => !hidden.has(p.protocol)))
    if (isolate != null) out = out.filter((l) => l.src === isolate || l.dst === isolate)
    return out
  }, [links, byId, otOnly, showExternal, hidden, isolate])

  const risk = useMemo(() => {
    const m = new Map<number, { worst: Finding['severity']; n: number }>()
    for (const f of findings.data ?? []) {
      if (f.status === 'false_positive' || f.status === 'resolved') continue
      for (const id of f.asset_ids) {
        const cur = m.get(id)
        const worse = !cur || SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(cur.worst)
        m.set(id, { worst: worse ? f.severity : cur!.worst, n: (cur?.n ?? 0) + 1 })
      }
    }
    return m
  }, [findings.data])
  // Hosts named in an open credentials finding (cleartext logins, default or reused passwords).
  const credentialAssets = useMemo(() => new Set((findings.data ?? [])
    .filter((f) => f.category === 'credentials' && f.status !== 'false_positive' && f.status !== 'resolved')
    .flatMap((f) => f.asset_ids)), [findings.data])
  const suspicious = useMemo(() => suspiciousPairs(findings.data ?? []), [findings.data])

  const focus = hover ?? (selection?.kind === 'asset' && selection.eid === eng.id ? selection.id : null)
  const neighbours = useMemo(() => {
    const n = new Set<number>()
    if (focus != null) for (const l of shown) if (l.src === focus || l.dst === focus) { n.add(l.src); n.add(l.dst) }
    return n
  }, [shown, focus])

  const built = useMemo(() => {
    const ids = [...new Set(shown.flatMap((l) => [l.src, l.dst]))].filter((id) => byId.has(id))
    const members = ids.map((id) => byId.get(id)!)
    const traffic = new Map<number, number>()
    for (const l of shown) for (const id of [l.src, l.dst]) traffic.set(id, (traffic.get(id) ?? 0) + l.packets)
    const maxT = Math.max(1, ...traffic.values())
    const writeTargets = new Set(shown.filter((l) => l.ot_writes > 0).map((l) => l.dst))
    const nodes: Node[] = []
    const data = (a: Asset, r: number): AssetData => ({
      asset: a, r, dim: false, risk: risk.get(a.id)?.worst ?? null, findings: risk.get(a.id)?.n ?? 0,
      credentials: credentialAssets.has(a.id), writeTarget: writeTargets.has(a.id), compact: members.length > 60,
    })
    if (layout === 'force') {
      const radius = new Map(members.map((a) => [a.id, nodeRadius(traffic.get(a.id) ?? 0, maxT)]))
      const pos = forceLayout(members.map((a) => ({ id: a.id, group: subnetOf(a), radius: radius.get(a.id)! })),
        shown.map((l) => ({ src: l.src, dst: l.dst, weight: l.packets })))
      for (const a of members) {
        const r = radius.get(a.id)!
        const p = pos.get(a.id)!
        nodes.push({ id: String(a.id), type: 'asset', position: { x: p.x - LABEL_W / 2, y: p.y - r }, data: data(a, r), zIndex: 2 })
      }
    } else {
      const degree = new Map<number, number>()
      for (const l of shown) for (const id of [l.src, l.dst]) degree.set(id, (degree.get(id) ?? 0) + 1)
      const g = subnetLayout(members, degree)
      for (const box of g.groups) {
        nodes.push({ id: `g-${box.key}`, type: 'subnet', position: { x: box.x, y: box.y }, data: { label: box.label },
          draggable: false, selectable: false, focusable: false, zIndex: 0, style: { width: box.w, height: box.h } })
      }
      for (const a of members) {
        nodes.push({ id: String(a.id), type: 'card', position: g.positions.get(a.id)!, data: data(a, 0), zIndex: 2,
          style: { width: G_NODE_W, height: G_NODE_H } })
      }
    }
    return nodes
  }, [shown, byId, layout, risk, credentialAssets])

  // Positions are local state so nodes can be dragged; a new layout (filters, data) starts fresh.
  const [nodes, setNodes] = useState<Node[]>(built)
  const [source, setSource] = useState(built)
  if (source !== built) { setSource(built); setNodes(built) }
  const viewNodes = useMemo(() => nodes.map((n) => n.type === 'subnet' ? n
    : { ...n, data: { ...(n.data as AssetData), dim: focus != null && !neighbours.has(Number(n.id)) } }), [nodes, focus, neighbours])

  const edges: Edge[] = useMemo(() => shown.map((l) => {
    const on = focus == null || l.src === focus || l.dst === focus
    const sus = suspicious.has(linkKey(l))
    const protos = l.protocols.map((p) => p.protocol).filter((p) => !hidden.has(p))
    return {
      id: linkKey(l), source: String(l.src), target: String(l.dst), type: 'straight', data: { link: l },
      className: `pm-edge pm-edge-${l.ot_writes ? 'write' : l.is_ot ? 'ot' : 'it'}${sus ? ' pm-edge-suspicious' : ''}${on ? '' : ' faded'}`,
      style: { strokeWidth: Math.min(5, 1 + Math.log10(Math.max(1, l.packets)) * 1.2) },
      label: focus != null && on ? protos.slice(0, 3).join(', ') : undefined,
      labelStyle: { fontSize: 11, fontWeight: 600 },
      labelShowBg: true,
      labelBgPadding: [4, 2] as [number, number],
      labelBgBorderRadius: 4,
      zIndex: on && focus != null ? 3 : 1,
    }
  }), [shown, focus, suspicious, hidden])

  const categories = useMemo(() => {
    const seen = new Map<DeviceCategory, string>()
    for (const n of built) if (n.type !== 'subnet') {
      const a = (n.data as AssetData).asset
      const { category } = deviceSpec(a.asset_type, a.is_private)
      if (!seen.has(category)) seen.set(category, a.asset_type ?? '')
    }
    return [...seen.entries()]
  }, [built])

  if (!links.length) return <p className="muted">No traffic between assets yet.</p>
  const toggleProto = (p: string) => setHidden((h) => { const n = new Set(h); if (n.has(p)) n.delete(p); else n.add(p); return n })
  const isolated = isolate != null ? byId.get(isolate) : null
  return (
    <div className="stack" style={{ gap: 'var(--space-2)' }}>
      <div className="row" style={{ gap: 'var(--space-3)' }}>
        <div className="seg" role="group" aria-label="Graph layout">
          <button type="button" className={layout === 'force' ? 'active' : ''} aria-pressed={layout === 'force'} onClick={() => setLayout('force')}>Topology</button>
          <button type="button" className={layout === 'subnet' ? 'active' : ''} aria-pressed={layout === 'subnet'} onClick={() => setLayout('subnet')}>By subnet</button>
        </div>
        <label className="row"><input type="checkbox" checked={otOnly} onChange={(e) => setOtOnly(e.target.checked)} /> OT traffic only</label>
        <label className="row"><input type="checkbox" checked={showExternal} onChange={(e) => setShowExternal(e.target.checked)} /> External hosts</label>
        <span className="muted">{built.filter((n) => n.type !== 'subnet').length} assets · {edges.length} connections · hover to trace, double-click to isolate, drag to arrange</span>
      </div>
      {allProtocols.length > 1 && (
        <div className="chips proto-chips" role="group" aria-label="Protocols">
          {allProtocols.map((p) => (
            <button key={p} type="button" className={`chip${hidden.has(p) ? ' off' : ''}`} aria-pressed={!hidden.has(p)} onClick={() => toggleProto(p)}>{p}</button>
          ))}
          {hidden.size > 0 && <button type="button" className="chip" onClick={() => setHidden(new Set())}>Show all</button>}
        </div>
      )}
      {isolated && (
        <div className="alert alert-ok" role="status">Showing {assetLabel(isolated)} and who it talks to.
          <button type="button" className="link-btn" style={{ marginLeft: 8 }} onClick={() => setIsolate(null)}>Show everything</button></div>
      )}
      <div className="purdue-canvas graph-canvas" aria-label="Network graph">
        <ReactFlow nodes={viewNodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.05}
          nodesConnectable={false} proOptions={{ hideAttribution: true }}
          onNodesChange={(ch: NodeChange[]) => setNodes((ns) => applyNodeChanges(ch, ns))}
          onNodeMouseEnter={(_e, n) => { if (n.type !== 'subnet') setHover(Number(n.id)) }}
          onNodeMouseLeave={() => setHover(null)}
          onNodeClick={(_e, n) => { if (n.type !== 'subnet') select({ kind: 'asset', eid: eng.id, id: Number(n.id) }) }}
          onNodeDoubleClick={(_e, n) => { if (n.type !== 'subnet') setIsolate((cur) => (cur === Number(n.id) ? null : Number(n.id))) }}
          onEdgeClick={(_e, e) => { const l = (e.data as { link: Link }).link; select({ kind: 'link', eid: eng.id, src: l.src, dst: l.dst }) }}>
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable style={{ width: 150, height: 100 }} nodeClassName={(n) => (n.type === 'subnet' ? 'pm-mini-bg' : 'pm-mini-asset')} />
        </ReactFlow>
        <details className="graph-legend" aria-label="Legend" open={legendOpen} onToggle={(e) => { const o = (e.target as HTMLDetailsElement).open; setLegendOpen(o); localStorage.setItem('pcapvis.graph.legend', o ? 'open' : 'closed') }}>
          <summary>Legend</summary>
          {categories.map(([cat, sample]) => (
            <div key={cat}><DeviceIcon type={sample} isPrivate={cat !== 'external'} size={13} label={false} /> {CATEGORY_LABELS[cat]}</div>
          ))}
          <hr />
          <div><i className="pm-key pm-key-ot" /> OT</div>
          <div><i className="pm-key pm-key-write" /> OT writes</div>
          <div><i className="pm-key pm-key-suspicious" /> named in a finding</div>
          <div><i className="pm-key pm-key-it" /> other</div>
          <div className="muted">Size = traffic · badge = open findings · key = credentials</div>
        </details>
      </div>
    </div>
  )
}
