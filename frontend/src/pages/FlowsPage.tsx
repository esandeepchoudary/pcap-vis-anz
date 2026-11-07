import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { AnalysisResult, Asset, Capture, Engagement, Link } from '../api/client'
import { useAssets } from '../api/assets'
import { useCaptureResult, useCaptures } from '../api/engagements'
import { useDiff, usePacket, usePackets } from '../api/forensics'
import { useLinks } from '../api/purdue'
import { AssetButton } from '../components/LinkDetails'
import { ErrorNote, Tabs } from '../components/ui'
import { useInspector } from '../inspector/context'
import { assetLabel } from '../lib/assets'
import { formatBytes, formatDateTime, formatDuration, formatNumber, purdueLabel } from '../lib/format'
import { G_NODE_H, G_NODE_W, subnetLayout } from '../lib/graph'
import './purdue.css'
import './flows.css'

type Tab = 'graph' | 'flows' | 'dns' | 'vlans' | 'diff' | 'packets'

function CapturePicker({ captures, value, onChange, label = 'Capture' }: { captures: Capture[]; value: number | null; onChange: (id: number) => void; label?: string }) {
  return (
    <select className="select" aria-label={label} value={value ?? ''} onChange={(e) => onChange(Number(e.target.value))}>
      <option value="" disabled>Choose a capture…</option>
      {captures.map((c) => <option key={c.id} value={c.id}>{c.file_name}{c.capture_point ? ` (${c.capture_point})` : ''}</option>)}
    </select>
  )
}

type GraphData = { asset: Asset; dim: boolean }

function GraphNode({ data, selected }: NodeProps<Node<GraphData>>) {
  const a = data.asset
  return (
    <div className={`fg-node level-edge-${String(a.purdue_level).replace('.', '_').replace('-', 'm')}${selected ? ' selected' : ''}${data.dim ? ' dim' : ''}`}
      title={`${assetLabel(a)} · ${a.ips.join(', ')} · ${a.asset_type ?? 'Unknown'}`}>
      <Handle type="target" position={Position.Top} className="pm-handle" isConnectable={false} />
      <div className="pm-asset-name">{assetLabel(a)}</div>
      <div className="pm-asset-sub">{a.asset_type ?? 'Unknown'} · {purdueLabel(a.purdue_level)}</div>
      <Handle type="source" position={Position.Bottom} className="pm-handle" isConnectable={false} />
    </div>
  )
}

function SubnetNode({ data }: NodeProps<Node<{ label: string }>>) {
  return <div className="fg-subnet"><span>{data.label}</span></div>
}
const nodeTypes = { asset: GraphNode, subnet: SubnetNode }

function Graph({ eng, assets, links }: { eng: Engagement; assets: Asset[]; links: Link[] }) {
  const { selection, select } = useInspector()
  const [otOnly, setOtOnly] = useState(false)
  const [showExternal, setShowExternal] = useState(false)
  const [hover, setHover] = useState<number | null>(null)
  const byId = useMemo(() => new Map(assets.map((a) => [a.id, a])), [assets])
  const visible = (id: number) => { const a = byId.get(id); return !!a && (showExternal || a.is_private || a.origin === 'manual') }
  const shown = links.filter((l) => (!otOnly || l.is_ot) && visible(l.src) && visible(l.dst))
  const focus = hover ?? (selection?.kind === 'asset' && selection.eid === eng.id ? selection.id : null)
  const neighbours = useMemo(() => {
    const n = new Set<number>()
    if (focus != null) for (const l of shown) if (l.src === focus || l.dst === focus) { n.add(l.src); n.add(l.dst) }
    return n
  }, [shown, focus])
  const { nodes, edges } = useMemo(() => {
    const ids = new Set(shown.flatMap((l) => [l.src, l.dst]))
    const degree = new Map<number, number>()
    for (const l of shown) for (const id of [l.src, l.dst]) degree.set(id, (degree.get(id) ?? 0) + 1)
    const members = [...ids].map((id) => byId.get(id)!).filter(Boolean)
    const layout = subnetLayout(members, degree)
    const nodes: Node[] = [
      ...layout.groups.map((g): Node => ({ id: `g-${g.key}`, type: 'subnet', position: { x: g.x, y: g.y }, data: { label: g.label },
        draggable: false, selectable: false, focusable: false, zIndex: 0, style: { width: g.w, height: g.h } })),
      ...members.map((a): Node => ({ id: String(a.id), type: 'asset', position: layout.positions.get(a.id)!, zIndex: 2,
        data: { asset: a, dim: focus != null && !neighbours.has(a.id) }, style: { width: G_NODE_W, height: G_NODE_H } })),
    ]
    const edges: Edge[] = shown.map((l) => {
      const on = focus == null || l.src === focus || l.dst === focus
      return {
        id: `${l.src}-${l.dst}`, source: String(l.src), target: String(l.dst), data: { link: l }, zIndex: on && focus != null ? 3 : 1,
        className: `pm-edge pm-edge-${l.ot_writes ? 'write' : l.is_ot ? 'ot' : 'it'}${on ? '' : ' faded'}`,
        markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12 },
        style: { strokeWidth: Math.min(3, 1 + Math.log10(Math.max(1, l.packets)) / 2) },
      }
    })
    return { nodes, edges }
  }, [shown, byId, focus, neighbours])
  if (!links.length) return <p className="muted">No traffic between assets yet.</p>
  const external = assets.filter((a) => !a.is_private && a.origin === 'observed').length
  return (
    <div className="stack" style={{ gap: 'var(--space-3)' }}>
      <div className="row">
        <label className="row"><input type="checkbox" checked={otOnly} onChange={(e) => setOtOnly(e.target.checked)} /> OT traffic only</label>
        {external > 0 && <label className="row"><input type="checkbox" checked={showExternal} onChange={(e) => setShowExternal(e.target.checked)} /> Show {external} external</label>}
        <span className="muted">{nodes.filter((n) => n.type === 'asset').length} assets · {edges.length} connections, grouped by subnet. Hover an asset to see who it talks to.</span>
        <span className="spacer" />
        <span className="pm-legend"><i className="pm-key pm-key-ot" /> OT <i className="pm-key pm-key-write" /> writes <i className="pm-key pm-key-it" /> other</span>
      </div>
      <div className="purdue-canvas" aria-label="Network graph">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08 }} minZoom={0.05}
          nodesDraggable={false} nodesConnectable={false} proOptions={{ hideAttribution: true }}
          onNodeMouseEnter={(_e, n) => { if (n.type === 'asset') setHover(Number(n.id)) }}
          onNodeMouseLeave={() => setHover(null)}
          onNodeClick={(_e, n) => { if (n.type === 'asset') select({ kind: 'asset', eid: eng.id, id: Number(n.id) }) }}
          onEdgeClick={(_e, e) => { const l = (e.data as { link: Link }).link; select({ kind: 'link', eid: eng.id, src: l.src, dst: l.dst }) }}>
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  )
}

function hostName(r: AnalysisResult) {
  const m = new Map(r.hosts.map((h) => [h.ip, h.hostname]))
  return (ip: string) => m.get(ip) ?? null
}

function FlowsTable({ r, eid, assets }: { r: AnalysisResult; eid: number; assets: Asset[] }) {
  const { select } = useInspector()
  const [q, setQ] = useState('')
  const [limit, setLimit] = useState(200)
  const name = hostName(r)
  const assetOf = useMemo(() => {
    const m = new Map<string, Asset>()
    for (const a of assets) for (const ip of a.ips) m.set(ip, a)
    return m
  }, [assets])
  const who = (ip: string) => assetOf.get(ip)?.name ?? name(ip)
  const needle = q.trim().toLowerCase()
  const rows = r.flows.filter((f) => !needle || [f.client, f.server, f.protocol, String(f.server_port), who(f.client), who(f.server)]
    .some((v) => v?.toLowerCase().includes(needle))).sort((a, b) => (b.bytes_c2s + b.bytes_s2c) - (a.bytes_c2s + a.bytes_s2c))
  const open = (client: string, server: string) => {
    const s = assetOf.get(client)
    const d = assetOf.get(server)
    if (s && d && s.id !== d.id) select({ kind: 'link', eid, src: s.id, dst: d.id })
  }
  const Who = ({ ip, port }: { ip: string; port?: number }) => (
    <>{who(ip) ? <><strong>{who(ip)}</strong> <span className="muted mono">{ip}{port != null ? `:${port}` : ''}</span></>
      : <span className="mono">{ip}{port != null ? `:${port}` : ''}</span>}</>
  )
  return (
    <div className="stack">
      <div className="row">
        <input className="input" placeholder="Filter by address, name, protocol, port…" aria-label="Filter flows" value={q}
          onChange={(e) => { setQ(e.target.value); setLimit(200) }} style={{ width: 320 }} />
        <span className="muted">{formatNumber(rows.length)} of {formatNumber(r.flows.length)} flows, largest first. Click a row for the connection's details.</span>
      </div>
      <div className="table-wrap">
        <table className="table" aria-label="Flows">
          <thead><tr><th>Client</th><th>Server</th><th>Protocol</th><th className="num">Packets</th><th className="num">Bytes</th><th>Duration</th><th className="num" title="OT reads / writes">OT r/w</th></tr></thead>
          <tbody>{rows.slice(0, limit).map((f) => (
            <tr key={f.id} className="clickable" tabIndex={0} onClick={() => open(f.client, f.server)}
              onKeyDown={(e) => { if (e.key === 'Enter') open(f.client, f.server) }}>
              <td><Who ip={f.client} /></td>
              <td><Who ip={f.server} port={f.transport === 'tcp' || f.transport === 'udp' ? f.server_port : undefined} /></td>
              <td>{f.protocol}</td>
              <td className="num">{formatNumber(f.packets_c2s + f.packets_s2c)}</td>
              <td className="num">{formatBytes(f.bytes_c2s + f.bytes_s2c)}</td>
              <td>{formatDuration(f.last_seen - f.first_seen)}</td>
              <td className="num">{f.ot_reads || f.ot_writes ? <>{f.ot_reads}/<span className={f.ot_writes ? 'crit-critical' : ''}>{f.ot_writes}</span></> : '—'}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {rows.length > limit && <button type="button" className="btn" onClick={() => setLimit((l) => l + 200)}>Show more</button>}
    </div>
  )
}

function Dns({ r }: { r: AnalysisResult }) {
  const rows = useMemo(() => {
    const m = new Map<string, string[]>()
    for (const h of r.hosts) for (const q of h.dns_queries) m.set(q, [...(m.get(q) ?? []), h.ip])
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
  }, [r])
  if (!rows.length) return <p className="muted">No DNS queries in this capture.</p>
  return (
    <table className="table" aria-label="DNS queries">
      <thead><tr><th>Name queried</th><th className="num">Clients</th><th>Who asked</th></tr></thead>
      <tbody>{rows.map(([q, ips]) => <tr key={q}><td className="mono">{q}</td><td className="num">{ips.length}</td><td className="mono muted">{ips.slice(0, 8).join(', ')}{ips.length > 8 ? '…' : ''}</td></tr>)}</tbody>
    </table>
  )
}

function Vlans({ r, assets, eid }: { r: AnalysisResult; assets: Asset[]; eid: number }) {
  if (!r.vlan_stats.length) return <p className="muted">No VLAN information in this capture.</p>
  const ipVlans = new Map(r.hosts.map((h) => [h.ip, h.vlans]))
  return (
    <table className="table" aria-label="VLANs">
      <thead><tr><th>VLAN</th><th className="num">Frames</th><th className="num">Broadcast</th><th>Assets on it</th></tr></thead>
      <tbody>{r.vlan_stats.map((v) => {
        const on = assets.filter((a) => a.ips.some((ip) => v.vlan === null ? ipVlans.get(ip)?.length === 0 && ipVlans.has(ip) : ipVlans.get(ip)?.includes(v.vlan)))
        const pct = v.packets ? Math.round((v.broadcast / v.packets) * 100) : 0
        return (
          <tr key={String(v.vlan)}>
            <td>{v.vlan ?? 'untagged'}</td>
            <td className="num">{formatNumber(v.packets)}</td>
            <td className="num">{pct}%{pct >= 20 && <span className="badge badge-warn" style={{ marginLeft: 6 }}>high</span>}</td>
            <td>{on.slice(0, 12).map((a) => <AssetButton key={a.id} a={a} eid={eid} />).reduce<React.ReactNode[]>((acc, el, i) => (i ? [...acc, ', ', el] : [el]), [])}{on.length > 12 ? ` +${on.length - 12}` : ''}</td>
          </tr>
        )
      })}</tbody>
    </table>
  )
}

function Diff({ eng, captures, byId }: { eng: Engagement; captures: Capture[]; byId: Map<number, Asset> }) {
  const [base, setBase] = useState<number | null>(captures[0]?.id ?? null)
  const [compare, setCompare] = useState<number | null>(captures[captures.length - 1]?.id ?? null)
  const d = useDiff(eng.id, base, compare)
  if (captures.length < 2) return <p className="muted">Add a second capture to compare (for example, the same SPAN port on another day).</p>
  const list = (ids: number[]) => ids.length ? <ul className="evidence">{ids.map((id) => <li key={id}><AssetButton a={byId.get(id)} eid={eng.id} /> <span className="muted">{byId.get(id)?.asset_type}</span></li>)}</ul> : <p className="muted">None.</p>
  return (
    <div className="stack">
      <div className="row">
        <span>Baseline</span><CapturePicker captures={captures} value={base} onChange={setBase} label="Baseline capture" />
        <span>compared with</span><CapturePicker captures={captures} value={compare} onChange={setCompare} label="Compared capture" />
      </div>
      {base === compare && <p className="muted">Choose two different captures.</p>}
      {d.isError && <ErrorNote>{d.error.message}</ErrorNote>}
      {d.data && (
        <div className="grid-2" style={{ alignItems: 'start' }}>
          <section className="card" aria-label="New assets"><h2>New assets ({d.data.new_assets.length})</h2>{list(d.data.new_assets)}</section>
          <section className="card" aria-label="Gone assets"><h2>No longer seen ({d.data.gone_assets.length})</h2>{list(d.data.gone_assets)}</section>
          <section className="card" aria-label="New connections"><h2>New connections ({d.data.new_links.length})</h2>
            {d.data.new_links.length ? <ul className="evidence">{d.data.new_links.map((l) => <li key={`${l.src}-${l.dst}-${l.protocol}`}><AssetButton a={byId.get(l.src)} eid={eng.id} /> → <AssetButton a={byId.get(l.dst)} eid={eng.id} /> <strong>{l.protocol}</strong></li>)}</ul> : <p className="muted">None.</p>}
          </section>
          <section className="card" aria-label="Gone connections"><h2>Connections gone ({d.data.gone_links.length})</h2>
            {d.data.gone_links.length ? <ul className="evidence">{d.data.gone_links.map((l) => <li key={`${l.src}-${l.dst}-${l.protocol}`}><AssetButton a={byId.get(l.src)} eid={eng.id} /> → <AssetButton a={byId.get(l.dst)} eid={eng.id} /> <strong>{l.protocol}</strong></li>)}</ul> : <p className="muted">None.</p>}
          </section>
        </div>
      )}
    </div>
  )
}

function Packets({ eng, cid }: { eng: Engagement; cid: number | null }) {
  const [draft, setDraft] = useState('')
  const [filter, setFilter] = useState('')
  const [frame, setFrame] = useState<number | null>(null)
  const list = usePackets(eng.id, cid, filter)
  const detail = usePacket(eng.id, cid, frame)
  if (eng.my_role === 'viewer') return <p className="muted">The packet inspector shows raw packets (including unmasked secrets), so it needs the editor role.</p>
  return (
    <div className="packets">
      <form className="row" onSubmit={(e) => { e.preventDefault(); setFilter(draft); setFrame(null) }}>
        <input className="input mono" aria-label="Display filter" placeholder="Wireshark display filter, e.g. modbus.func_code == 6" value={draft}
          maxLength={500} onChange={(e) => setDraft(e.target.value)} style={{ flex: 1, minWidth: 320 }} />
        <button type="submit" className="btn btn-primary btn-sm">Apply</button>
      </form>
      {list.isError && <ErrorNote>{list.error.message}</ErrorNote>}
      {list.isFetching && <p className="muted">Running tshark…</p>}
      {list.data && (
        <div className="packets-split">
          <div className="table-wrap packets-list">
            <table className="table" aria-label="Packets">
              <thead><tr><th className="num">No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th></tr></thead>
              <tbody>{list.data.packets.map((p) => (
                <tr key={p.number} className={`clickable${frame === p.number ? ' selected' : ''}`} tabIndex={0}
                  onClick={() => setFrame(p.number)} onKeyDown={(e) => { if (e.key === 'Enter') setFrame(p.number) }}>
                  <td className="num">{p.number}</td><td className="muted" style={{ whiteSpace: 'nowrap' }}>{formatDateTime(p.time)}</td>
                  <td className="mono">{p.src}</td><td className="mono">{p.dst}</td><td>{p.protocol}</td><td className="packets-info">{p.info}</td>
                </tr>
              ))}</tbody>
            </table>
            {list.data.truncated && <p className="muted">Showing the first {list.data.packets.length} matches; narrow the filter to see more.</p>}
            {!list.data.packets.length && <p className="muted">No packets match.</p>}
          </div>
          <div className="packets-detail" aria-label="Packet details">
            {detail.isError && <ErrorNote>{detail.error.message}</ErrorNote>}
            {detail.data ? <pre>{detail.data.text}</pre> : <p className="muted">Select a packet to decode it.</p>}
          </div>
        </div>
      )}
    </div>
  )
}

export function FlowsPage() {
  const eng = useOutletContext<Engagement>()
  const captures = useCaptures(eng.id)
  const assets = useAssets(eng.id)
  const links = useLinks(eng.id)
  const done = (captures.data ?? []).filter((c) => c.status === 'done')
  const [tab, setTab] = useState<Tab>('graph')
  const [picked, setPicked] = useState<number | null>(null)
  const cid = picked ?? done[done.length - 1]?.id ?? null
  const cap = done.find((c) => c.id === cid)
  const result = useCaptureResult(eng.id, cid ?? 0, !!cap && ['flows', 'dns', 'vlans'].includes(tab), cap?.finished_at ?? '')
  const byId = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])
  const perCapture = ['flows', 'dns', 'vlans', 'packets'].includes(tab)
  return (
    <div className="page" style={{ maxWidth: 'none' }}>
      <div className="page-head"><div><h1>Flows &amp; network</h1><p>Who talks to whom, per capture detail, changes between captures, and raw packets.</p></div></div>
      {captures.isSuccess && !done.length && <p className="muted">No analysed captures yet.</p>}
      {done.length > 0 && (
        <>
          <Tabs<Tab> label="Network views" value={tab} onChange={setTab} tabs={[
            { id: 'graph', label: 'Graph' }, { id: 'flows', label: 'Flows' }, { id: 'dns', label: 'DNS' },
            { id: 'vlans', label: 'VLANs' }, { id: 'diff', label: 'Diff' }, { id: 'packets', label: 'Packets' },
          ]} />
          {perCapture && <div className="row" style={{ marginBottom: 'var(--space-3)' }}><CapturePicker captures={done} value={cid} onChange={setPicked} /></div>}
          {tab === 'graph' && assets.data && links.data && <Graph eng={eng} assets={assets.data} links={links.data} />}
          {result.isError && perCapture && <ErrorNote>{result.error.message}</ErrorNote>}
          {tab === 'flows' && result.data && <FlowsTable r={result.data} eid={eng.id} assets={assets.data ?? []} />}
          {tab === 'dns' && result.data && <Dns r={result.data} />}
          {tab === 'vlans' && result.data && <Vlans r={result.data} assets={assets.data ?? []} eid={eng.id} />}
          {tab === 'diff' && <Diff eng={eng} captures={done} byId={byId} />}
          {tab === 'packets' && <Packets key={cid} eng={eng} cid={cid} />}
        </>
      )}
    </div>
  )
}
