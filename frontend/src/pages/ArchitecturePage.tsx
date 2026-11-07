import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow, applyNodeChanges,
  type Connection, type Edge, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Network as NetworkIcon, ShieldAlert, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link as RouterLink, useOutletContext } from 'react-router-dom'
import type { Asset, Conduit, Engagement, Zone } from '../api/client'
import { useAssets } from '../api/assets'
import {
  useConduits, useCreateConduit, useCreateZone, useDeleteConduit, useDeleteZone, useNetworks, useUpdateConduit,
  useUpdateZone, useViolations, useZones,
} from '../api/zones'
import { AssetButton } from '../components/LinkDetails'
import { ConfirmButton, ErrorNote, Tabs } from '../components/ui'
import { useInspector } from '../inspector/context'
import { assetLabel } from '../lib/assets'
import { ZONE_H, ZONE_W, violationPairs, zonePositions } from '../lib/architecture'
import { formatNumber, purdueLabel } from '../lib/format'
import './architecture.css'
import './purdue.css' // shared canvas and legend styles

type Tab = 'diagram' | 'zones' | 'violations' | 'networks'
const GATEWAYS = new Set(['Firewall', 'Router', 'Data Diode', 'VPN Gateway'])
type ZoneData = { zone: Zone; level: number | null; gateways: Asset[]; violations: number }

function ZoneNode({ data, selected }: NodeProps<Node<ZoneData>>) {
  const z = data.zone
  return (
    <div className={`az-zone${z.defined ? '' : ' undefined'}${selected ? ' selected' : ''}${data.violations ? ' has-violations' : ''}`}>
      <Handle type="target" position={Position.Top} className="az-handle" />
      <div className="az-zone-name">{z.name}</div>
      <div className="az-zone-meta">
        {data.level != null ? purdueLabel(data.level) : 'no level'}{z.security_level ? ` · SL-T ${z.security_level}` : ''} · {z.asset_ids.length} asset{z.asset_ids.length === 1 ? '' : 's'}
      </div>
      {data.gateways.length > 0 && <div className="az-zone-gw">{data.gateways.map((g) => `${g.asset_type}: ${assetLabel(g)}`).join(' · ')}</div>}
      {!z.defined && <div className="az-zone-hint">Not defined yet</div>}
      <Handle type="source" position={Position.Bottom} className="az-handle" />
    </div>
  )
}
const nodeTypes = { zone: ZoneNode }

function levelOf(z: Zone, byId: Map<number, Asset>): number | null {
  if (z.purdue_level != null) return z.purdue_level
  const levels = z.asset_ids.map((id) => byId.get(id)?.purdue_level).filter((l): l is number => l != null && l >= 0)
  if (!levels.length) return null
  // The level most of its assets sit at.
  const counts = new Map<number, number>()
  for (const l of levels) counts.set(l, (counts.get(l) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])[0][0]
}

function Diagram({ eng, zones, conduits, byId, canEdit }: { eng: Engagement; zones: Zone[]; conduits: Conduit[]; byId: Map<number, Asset>; canEdit: boolean }) {
  const violations = useViolations(eng.id)
  const update = useUpdateZone(eng.id)
  const createConduit = useCreateConduit(eng.id)
  const [showViolations, setShowViolations] = useState(true)
  const pairs = useMemo(() => violationPairs(violations.data ?? []), [violations.data])
  const built = useMemo(() => {
    const pos = zonePositions(zones, (z) => levelOf(z, byId))
    return zones.map((z): Node => ({
      id: z.name, type: 'zone', position: pos.get(z.name)!, draggable: canEdit && z.defined,
      style: { width: ZONE_W, height: ZONE_H },
      data: {
        zone: z, level: levelOf(z, byId),
        gateways: z.asset_ids.map((id) => byId.get(id)).filter((a): a is Asset => !!a && GATEWAYS.has(a.asset_type ?? '')),
        violations: pairs.filter((p) => p.a === z.name || p.b === z.name).length,
      },
    }))
  }, [zones, byId, canEdit, pairs])
  const [nodes, setNodes] = useState<Node[]>(built)
  const [source, setSource] = useState(built)
  if (source !== built) { setSource(built); setNodes(built) }
  const nameOf = new Map(zones.filter((z) => z.id != null).map((z) => [z.id!, z.name]))
  const edges: Edge[] = [
    ...conduits.filter((c) => nameOf.has(c.zone_a_id) && nameOf.has(c.zone_b_id)).map((c): Edge => ({
      id: `c-${c.id}`, source: nameOf.get(c.zone_a_id)!, target: nameOf.get(c.zone_b_id)!, className: 'az-conduit',
      label: c.name ? `${c.name}: ${c.allowed.join(', ') || 'any'}` : c.allowed.join(', ') || 'any protocol',
    })),
    ...(showViolations ? pairs : []).map((p): Edge => ({
      id: `v-${p.a}-${p.b}`, source: p.a, target: p.b, className: `az-violation${p.writes ? ' writes' : ''}`,
      label: `${p.count} unapproved: ${p.protocols.slice(0, 3).join(', ')}${p.protocols.length > 3 ? '…' : ''}`,
      markerEnd: { type: MarkerType.ArrowClosed },
    })),
  ]
  const connect = (c: Connection) => {
    const a = zones.find((z) => z.name === c.source)
    const b = zones.find((z) => z.name === c.target)
    if (a?.id && b?.id && a.id !== b.id) createConduit.mutate({ zone_a_id: a.id, zone_b_id: b.id, allowed: [] })
  }
  return (
    <div className="stack" style={{ gap: 'var(--space-3)' }}>
      <div className="row">
        <label className="row"><input type="checkbox" checked={showViolations} onChange={(e) => setShowViolations(e.target.checked)} /> Show unapproved traffic</label>
        <span className="spacer" />
        <span className="pm-legend"><i className="pm-key az-key-conduit" /> conduit <i className="pm-key az-key-violation" /> traffic without a conduit</span>
      </div>
      {canEdit && <p className="muted" style={{ margin: 0, fontSize: 'var(--text-sm)' }}>Drag zones to arrange them (saved). Drag from a zone's bottom handle to another zone to add a conduit.</p>}
      {(createConduit.error ?? update.error) && <ErrorNote>{(createConduit.error ?? update.error)!.message}</ErrorNote>}
      <div className="purdue-canvas" aria-label="Architecture diagram">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView proOptions={{ hideAttribution: true }}
          onNodesChange={(ch: NodeChange[]) => setNodes((ns) => applyNodeChanges(ch, ns))}
          onNodeDragStop={(_e, n) => { const z = (n.data as ZoneData).zone; if (z.id) update.mutate({ id: z.id, x: n.position.x, y: n.position.y }) }}
          onConnect={canEdit ? connect : undefined} nodesConnectable={canEdit} minZoom={0.2}>
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  )
}

function ZoneRow({ eng, z, canEdit }: { eng: Engagement; z: Zone; canEdit: boolean }) {
  const update = useUpdateZone(eng.id)
  const del = useDeleteZone(eng.id)
  const create = useCreateZone(eng.id)
  const [name, setName] = useState(z.name)
  const err = update.error ?? del.error ?? create.error
  return (
    <tr>
      <td>
        {canEdit && z.defined ? (
          <input className="input" aria-label={`Zone name ${z.name}`} value={name} maxLength={100} onChange={(e) => setName(e.target.value)}
            onBlur={() => { if (name.trim() && name.trim() !== z.name) update.mutate({ id: z.id!, name }) }} />
        ) : <strong>{z.name}</strong>}
        {err && <ErrorNote>{err.message}</ErrorNote>}
      </td>
      <td>
        {canEdit && z.defined ? (
          <select className="select" aria-label={`Level of ${z.name}`} value={z.purdue_level == null ? '' : String(z.purdue_level)}
            onChange={(e) => update.mutate({ id: z.id!, purdue_level: e.target.value === '' ? null : Number(e.target.value) })}>
            <option value="">—</option>
            {[5, 4, 3.5, 3, 2, 1, 0].map((l) => <option key={l} value={String(l)}>{purdueLabel(l)}</option>)}
          </select>
        ) : z.purdue_level != null ? purdueLabel(z.purdue_level) : '—'}
      </td>
      <td>
        {canEdit && z.defined ? (
          <select className="select" aria-label={`Target security level of ${z.name}`} value={z.security_level ?? ''}
            onChange={(e) => update.mutate({ id: z.id!, security_level: e.target.value === '' ? null : (Number(e.target.value) as 1 | 2 | 3 | 4) })}>
            <option value="">—</option>{[1, 2, 3, 4].map((l) => <option key={l} value={l}>SL {l}</option>)}
          </select>
        ) : z.security_level ? `SL ${z.security_level}` : '—'}
      </td>
      <td className="num">{z.asset_ids.length}</td>
      <td>
        {canEdit && !z.defined && <button type="button" className="btn btn-sm" onClick={() => create.mutate({ name: z.name, description: '' })}>Define</button>}
        {canEdit && z.defined && <ConfirmButton className="btn btn-ghost btn-sm" onConfirm={() => del.mutate(z.id!)} confirmLabel="Delete?"><Trash2 size={14} aria-label={`Delete zone ${z.name}`} /></ConfirmButton>}
      </td>
    </tr>
  )
}

function ConduitRow({ eng, c, nameOf, canEdit }: { eng: Engagement; c: Conduit; nameOf: Map<number, string>; canEdit: boolean }) {
  const update = useUpdateConduit(eng.id)
  const del = useDeleteConduit(eng.id)
  const [allowed, setAllowed] = useState(c.allowed.join(', '))
  return (
    <tr>
      <td>
        <span title="A and B in rules">A: {nameOf.get(c.zone_a_id)} ↔ B: {nameOf.get(c.zone_b_id)}</span>
        {c.name && <div className="muted">{c.name}</div>}
      </td>
      <td>
        {canEdit ? (
          <input className="input" aria-label={`Allowed protocols ${nameOf.get(c.zone_a_id)} to ${nameOf.get(c.zone_b_id)}`} value={allowed}
            placeholder="any traffic" onChange={(e) => setAllowed(e.target.value)}
            onBlur={() => update.mutate({ id: c.id, allowed: allowed.split(',').map((s) => s.trim()).filter(Boolean) })} />
        ) : c.allowed.join(', ') || 'any'}
        {update.error && <ErrorNote>{update.error.message}</ErrorNote>}
      </td>
      <td>{canEdit && <ConfirmButton className="btn btn-ghost btn-sm" onConfirm={() => del.mutate(c.id)} confirmLabel="Delete?"><Trash2 size={14} aria-label="Delete conduit" /></ConfirmButton>}</td>
    </tr>
  )
}

function ZonesTab({ eng, zones, conduits, canEdit }: { eng: Engagement; zones: Zone[]; conduits: Conduit[]; canEdit: boolean }) {
  const create = useCreateZone(eng.id)
  const createConduit = useCreateConduit(eng.id)
  const [name, setName] = useState('')
  const defined = zones.filter((z) => z.defined)
  const [pair, setPair] = useState<{ a: string; b: string }>({ a: '', b: '' })
  const nameOf = new Map(defined.map((z) => [z.id!, z.name]))
  return (
    <div className="grid-2" style={{ alignItems: 'start' }}>
      <section className="card stack" aria-label="Zones">
        <h2 style={{ margin: 0 }}>Zones</h2>
        <p className="muted" style={{ margin: 0 }}>Assets join a zone through their Zone field (inventory, Purdue map, or bulk edit). Zones used on assets but not defined yet are listed so you can define them.</p>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>Name</th><th>Level</th><th>SL-T</th><th className="num">Assets</th><th /></tr></thead>
          <tbody>{zones.map((z) => <ZoneRow key={`${z.id}-${z.name}`} eng={eng} z={z} canEdit={canEdit} />)}</tbody>
        </table></div>
        {canEdit && (
          <form className="row" onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate({ name, description: '' }, { onSuccess: () => setName('') }) }}>
            <input className="input" aria-label="New zone name" placeholder="New zone" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
            <button type="submit" className="btn btn-sm btn-primary">Add zone</button>
          </form>
        )}
        {create.error && <ErrorNote>{create.error.message}</ErrorNote>}
      </section>
      <section className="card stack" aria-label="Conduits">
        <h2 style={{ margin: 0 }}>Conduits</h2>
        <p className="muted" style={{ margin: 0 }}>
          Approved paths between zones; other cross-zone traffic is flagged. List what each allows, separated by commas (empty allows anything):
          a protocol (<code>Modbus</code>), optionally a server port (<code>Modbus tcp/502</code>, <code>* tcp/443</code>) and a direction
          (<code>A→B</code>: zone A opens the connections; type <code>A-&gt;B</code>).
        </p>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>Between</th><th>Allowed</th><th /></tr></thead>
          <tbody>{conduits.map((c) => <ConduitRow key={c.id} eng={eng} c={c} nameOf={nameOf} canEdit={canEdit} />)}</tbody>
        </table></div>
        {canEdit && defined.length >= 2 && (
          <form className="row" onSubmit={(e) => {
            e.preventDefault()
            const a = defined.find((z) => z.name === pair.a)
            const b = defined.find((z) => z.name === pair.b)
            if (a && b) createConduit.mutate({ zone_a_id: a.id!, zone_b_id: b.id!, allowed: [] })
          }}>
            <select className="select" aria-label="Conduit from" value={pair.a} onChange={(e) => setPair({ ...pair, a: e.target.value })}>
              <option value="">Zone…</option>{defined.map((z) => <option key={z.name}>{z.name}</option>)}
            </select>
            <span>↔</span>
            <select className="select" aria-label="Conduit to" value={pair.b} onChange={(e) => setPair({ ...pair, b: e.target.value })}>
              <option value="">Zone…</option>{defined.map((z) => <option key={z.name}>{z.name}</option>)}
            </select>
            <button type="submit" className="btn btn-sm">Add conduit</button>
          </form>
        )}
        {createConduit.error && <ErrorNote>{createConduit.error.message}</ErrorNote>}
      </section>
    </div>
  )
}

function ViolationsTab({ eng, byId, zones, canEdit }: { eng: Engagement; byId: Map<number, Asset>; zones: Zone[]; canEdit: boolean }) {
  const v = useViolations(eng.id)
  const conduits = useConduits(eng.id)
  const create = useCreateConduit(eng.id)
  const update = useUpdateConduit(eng.id)
  const { select } = useInspector()
  if (v.isPending) return <p className="muted">Loading…</p>
  if (v.isError) return <ErrorNote>{v.error.message}</ErrorNote>
  if (!v.data.length) return <p className="muted">No cross-zone traffic outside the approved conduits. (Only assets with a zone are checked.)</p>
  const idOf = new Map(zones.filter((z) => z.id != null).map((z) => [z.name, z.id!]))
  // Approving covers everything seen between the two zones, not just this asset pair.
  const pairProtocols = (a: string, b: string) => [...new Set(v.data.filter((x) =>
    (x.src_zone === a && x.dst_zone === b) || (x.src_zone === b && x.dst_zone === a)).flatMap((x) => x.protocols))].sort()
  return (
    <div className="table-wrap">
      <table className="table" aria-label="Violations">
        <thead><tr><th>From</th><th>To</th><th>Problem</th><th>Protocols</th><th className="num">Flows</th><th className="num">OT writes</th><th /></tr></thead>
        <tbody>{v.data.map((x) => (
          <tr key={`${x.src}-${x.dst}-${x.kind}`}>
            <td><AssetButton a={byId.get(x.src)} eid={eng.id} /><div className="muted">{x.src_zone}</div></td>
            <td><AssetButton a={byId.get(x.dst)} eid={eng.id} /><div className="muted">{x.dst_zone}</div></td>
            <td><span className="badge badge-danger">{x.kind === 'no_conduit' ? 'no conduit' : 'not allowed'}</span></td>
            <td>{x.protocols.join(', ')}</td>
            <td className="num">{formatNumber(x.flows)}</td>
            <td className="num">{x.ot_writes || '—'}</td>
            <td className="row" style={{ flexWrap: 'nowrap' }}>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => select({ kind: 'link', eid: eng.id, src: x.src, dst: x.dst })}>Details</button>
              {canEdit && x.kind === 'no_conduit' && idOf.has(x.src_zone) && idOf.has(x.dst_zone) && (
                <button type="button" className="btn btn-sm" title="Create a conduit allowing the protocols seen between these zones"
                  onClick={() => create.mutate({ zone_a_id: idOf.get(x.src_zone)!, zone_b_id: idOf.get(x.dst_zone)!, allowed: pairProtocols(x.src_zone, x.dst_zone) })}>
                  Approve as conduit
                </button>
              )}
              {canEdit && x.kind === 'protocol_not_allowed' && x.conduit_id != null && (
                <button type="button" className="btn btn-sm" title="Add these protocols to the conduit"
                  onClick={() => {
                    const c = conduits.data?.find((y) => y.id === x.conduit_id)
                    if (c) update.mutate({ id: c.id, allowed: [...c.allowed, ...x.protocols.map((t) => t.replace(/\s*\((A→B|B→A)\)$/, ' $1'))] })
                  }}>
                  Allow {x.protocols.join(', ')}
                </button>
              )}
            </td>
          </tr>
        ))}</tbody>
      </table>
      {(create.error ?? update.error) && <ErrorNote>{(create.error ?? update.error)!.message}</ErrorNote>}
    </div>
  )
}

function NetworksTab({ eng, byId }: { eng: Engagement; byId: Map<number, Asset> }) {
  const n = useNetworks(eng.id)
  if (n.isPending) return <p className="muted">Loading…</p>
  if (n.isError) return <ErrorNote>{n.error.message}</ErrorNote>
  return (
    <div className="stack">
      <p className="muted" style={{ margin: 0 }}>Subnets inferred from asset addresses (private IPv4, grouped by /24), with the VLANs, gateways, zones and levels seen on them. Add firewalls or routers never seen on the wire as manual assets in the inventory.</p>
      <table className="table" aria-label="Networks">
        <thead><tr><th>Subnet</th><th>VLANs</th><th className="num">Assets</th><th>Gateways</th><th>Zones</th><th>Levels</th></tr></thead>
        <tbody>{n.data.map((x) => (
          <tr key={x.cidr}>
            <td className="mono">{x.cidr}</td>
            <td>{x.vlans.join(', ') || '—'}</td>
            <td className="num">{x.asset_ids.length}</td>
            <td>{x.gateways.map((id) => <AssetButton key={id} a={byId.get(id)} eid={eng.id} />)}{!x.gateways.length && <span className="muted">none known</span>}</td>
            <td>{x.zones.join(', ') || '—'}</td>
            <td>{x.purdue_levels.map(purdueLabel).join(', ')}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

export function ArchitecturePage() {
  const eng = useOutletContext<Engagement>()
  const canEdit = eng.my_role === 'lead' || eng.my_role === 'editor'
  const assets = useAssets(eng.id)
  const zones = useZones(eng.id)
  const conduits = useConduits(eng.id)
  const violations = useViolations(eng.id)
  const [tab, setTab] = useState<Tab>('diagram')
  const byId = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])
  const err = assets.error ?? zones.error ?? conduits.error
  return (
    <div className="page" style={{ maxWidth: 'none' }}>
      <div className="page-head">
        <div>
          <h1>Network architecture</h1>
          <p>{(zones.data ?? []).length} zones · {(conduits.data ?? []).length} conduits · {(violations.data ?? []).length} unapproved cross-zone connections</p>
        </div>
      </div>
      {err && <ErrorNote>{err.message}</ErrorNote>}
      {zones.isSuccess && zones.data.length === 0 && tab === 'diagram' && (
        <div className="empty card">
          <NetworkIcon size={36} strokeWidth={1.5} aria-hidden />
          <strong>No zones yet</strong>
          <span>Put assets in zones on the <RouterLink to={`/e/${eng.id}/purdue`}>Purdue map</RouterLink> or in the <RouterLink to={`/e/${eng.id}/assets`}>inventory</RouterLink>, or add zones under "Zones &amp; conduits".</span>
        </div>
      )}
      {zones.data && conduits.data && assets.data && (
        <>
          <Tabs<Tab> label="Architecture views" value={tab} onChange={setTab} tabs={[
            { id: 'diagram', label: 'Diagram' }, { id: 'zones', label: 'Zones & conduits' },
            { id: 'violations', label: 'Violations', count: violations.data?.length }, { id: 'networks', label: 'Networks' },
          ]} />
          {tab === 'diagram' && zones.data.length > 0 && <Diagram eng={eng} zones={zones.data} conduits={conduits.data} byId={byId} canEdit={canEdit} />}
          {tab === 'zones' && <ZonesTab eng={eng} zones={zones.data} conduits={conduits.data} canEdit={canEdit} />}
          {tab === 'violations' && <ViolationsTab eng={eng} byId={byId} zones={zones.data} canEdit={canEdit} />}
          {tab === 'networks' && <NetworksTab eng={eng} byId={byId} />}
        </>
      )}
      {violations.data && violations.data.length > 0 && tab === 'diagram' && (
        <div className="alert alert-warn" role="status" style={{ marginTop: 'var(--space-3)' }}>
          <ShieldAlert size={16} aria-hidden /> {violations.data.length} connection(s) cross zones without an approved conduit. See the Violations tab.
        </div>
      )}
    </div>
  )
}
