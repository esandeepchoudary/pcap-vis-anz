import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, applyNodeChanges,
  type Edge, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useQueryClient } from '@tanstack/react-query'
import { Pencil } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { Asset, AssetFields, Engagement, Link } from '../api/client'
import { akeys, useBulkEdit } from '../api/assets'
import { DeviceIcon } from '../components/DeviceIcon'
import { ErrorNote } from '../components/ui'
import { useInspector } from '../inspector/context'
import { assetLabel, levelName } from '../lib/assets'
import { purdueLabel } from '../lib/format'
import { NODE_H, NODE_W, dropTarget, layoutPurdue, bypassesDmz, type Layout } from '../lib/purdue'

type LaneData = { label: string; level: number }
type ZoneData = { label: string; empty: boolean }
type AssetData = { asset: Asset; dim: boolean }

function LaneNode({ data }: NodeProps<Node<LaneData>>) {
  return <div className={`pm-lane pm-lane-${String(data.level).replace('.', '_')}`}><span>{data.label}</span></div>
}

function ZoneNode({ data }: NodeProps<Node<ZoneData>>) {
  return <div className={`pm-zone${data.label === 'No zone' ? ' pm-zone-none' : ''}`}><span>{data.label}</span>{data.empty && <em>drop assets here</em>}</div>
}

function AssetNode({ data, selected }: NodeProps<Node<AssetData>>) {
  const a = data.asset
  return (
    <div className={`pm-asset${selected ? ' selected' : ''}${data.dim ? ' dim' : ''}${a.criticality ? ` crit-${a.criticality}` : ''}`}
      title={`${assetLabel(a)} · ${a.ips.join(', ')}`}>
      <Handle type="target" position={Position.Top} className="pm-handle" isConnectable={false} />
      <div className="pm-asset-name"><DeviceIcon type={a.asset_type} isPrivate={a.is_private} size={13} label={false} />{assetLabel(a)}{a.overridden.includes('purdue_level') && <Pencil size={10} aria-label="level set manually" />}</div>
      <div className="pm-asset-sub">{a.asset_type ?? 'Unknown'}{a.name && a.ips[0] ? ` · ${a.ips[0]}` : ''}</div>
      <Handle type="source" position={Position.Bottom} className="pm-handle" isConnectable={false} />
    </div>
  )
}

const nodeTypes = { lane: LaneNode, zone: ZoneNode, asset: AssetNode }

function buildNodes(layout: Layout, assets: Asset[], fields: AssetFields | undefined, needle: string, canEdit: boolean): Node[] {
  const nodes: Node[] = []
  for (const l of layout.lanes) {
    nodes.push({ id: `lane-${l.level}`, type: 'lane', position: { x: l.x, y: l.y }, data: { label: levelName(fields, l.level), level: l.level },
      draggable: false, selectable: false, focusable: false, zIndex: 0, style: { width: l.w, height: l.h } })
  }
  for (const z of layout.zones) {
    const count = assets.filter((a) => a.purdue_level === z.level && (a.zone ?? null) === z.zone).length
    nodes.push({ id: `zone-${z.key}`, type: 'zone', position: { x: z.x, y: z.y }, data: { label: z.zone ?? 'No zone', empty: count === 0 },
      draggable: false, selectable: false, focusable: false, zIndex: 1, style: { width: z.w, height: z.h } })
  }
  for (const a of assets) {
    const pos = layout.positions.get(a.id)
    if (!pos) continue
    const dim = !!needle && !`${assetLabel(a)} ${a.ips.join(' ')} ${a.asset_type ?? ''} ${a.vendor ?? ''}`.toLowerCase().includes(needle)
    nodes.push({ id: `a-${a.id}`, type: 'asset', position: pos, data: { asset: a, dim }, draggable: canEdit, zIndex: 2,
      style: { width: NODE_W, height: NODE_H } })
  }
  return nodes
}

function buildEdges(links: Link[], visible: Map<number, Asset>, otOnly: boolean, selectedLink: string | null): Edge[] {
  return links.filter((l) => (!otOnly || l.is_ot) && visible.has(l.src) && visible.has(l.dst)).map((l) => {
    const dmz = bypassesDmz(visible.get(l.src)!.purdue_level, visible.get(l.dst)!.purdue_level)
    const cls = l.ot_writes > 0 ? 'write' : dmz ? 'dmz' : l.is_ot ? 'ot' : 'it'
    const id = `l-${l.src}-${l.dst}`
    return {
      id, source: `a-${l.src}`, target: `a-${l.dst}`, zIndex: 3,
      className: `pm-edge pm-edge-${cls}${dmz ? ' pm-edge-bypass' : ''}${selectedLink === id ? ' selected' : ''}`,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      style: { strokeWidth: Math.min(4, 1 + Math.log10(Math.max(1, l.packets)) / 2) },
      data: { link: l },
      ariaLabel: `${assetLabel(visible.get(l.src)!)} to ${assetLabel(visible.get(l.dst)!)}`,
    }
  })
}

export function PurdueMap({ eng, assets, links, fields }: { eng: Engagement; assets: Asset[]; links: Link[]; fields: AssetFields | undefined }) {
  const canEdit = eng.my_role === 'lead' || eng.my_role === 'editor'
  const { selection, select } = useInspector()
  const qc = useQueryClient()
  const bulk = useBulkEdit(eng.id)
  const [otOnly, setOtOnly] = useState(true)
  const [showExternal, setShowExternal] = useState(false)
  const [needle, setNeedle] = useState('')
  const [extraZones, setExtraZones] = useState<{ level: number; zone: string }[]>([])
  const [newZone, setNewZone] = useState<{ name: string; level: string } | null>(null)
  const [status, setStatus] = useState<string | null>(null)

  const visibleAssets = useMemo(() => assets.filter((a) => showExternal || a.is_private || a.origin === 'manual'), [assets, showExternal])
  const visible = useMemo(() => new Map(visibleAssets.map((a) => [a.id, a])), [visibleAssets])
  const layout = useMemo(() => layoutPurdue(visibleAssets, extraZones), [visibleAssets, extraZones])
  const q = needle.trim().toLowerCase()
  const built = useMemo(() => buildNodes(layout, visibleAssets, fields, q, canEdit), [layout, visibleAssets, fields, q, canEdit])
  const [nodes, setNodes] = useState<Node[]>(built)
  const [source, setSource] = useState(built)
  if (source !== built) { // layout changed (data, filters): start from it again
    setSource(built)
    setNodes(built)
  }
  const selectedLink = selection?.kind === 'link' ? `l-${selection.src}-${selection.dst}` : null
  const edges = useMemo(() => buildEdges(links, visible, otOnly, selectedLink), [links, visible, otOnly, selectedLink])
  const external = assets.filter((a) => !a.is_private && a.origin === 'observed').length

  const onDragStop = (_e: unknown, node: Node, dragged: Node[]) => {
    const target = dropTarget(layout, node.position.x + NODE_W / 2, node.position.y + NODE_H / 2)
    const moved = dragged.filter((n) => n.type === 'asset').map((n) => (n.data as AssetData).asset)
      .filter((a) => target && (a.purdue_level !== target.level || (target.zone !== undefined && (a.zone ?? null) !== target.zone)))
    if (!target || moved.length === 0) {
      setNodes(built) // snap back
      return
    }
    const set: Record<string, unknown> = { purdue_level: target.level }
    if (target.zone !== undefined) set.zone = target.zone
    const ids = moved.map((a) => a.id)
    // Optimistic: move them in the cached inventory so the map re-lays out at once.
    qc.setQueryData<Asset[]>(akeys.all(eng.id), (old) => old?.map((a) => ids.includes(a.id)
      ? { ...a, purdue_level: target.level, zone: target.zone !== undefined ? target.zone : a.zone,
          overridden: [...new Set([...a.overridden, 'purdue_level' as const, ...(target.zone !== undefined ? ['zone' as const] : [])])] }
      : a))
    const where = `${purdueLabel(target.level)}${target.zone !== undefined ? ` · ${target.zone ?? 'no zone'}` : ''}`
    setStatus(`Moving ${moved.length === 1 ? assetLabel(moved[0]) : `${moved.length} assets`} to ${where}…`)
    bulk.mutate({ asset_ids: ids, set, reset: [], reason: 'Moved on the Purdue map' }, {
      onSuccess: () => setStatus(`Moved ${moved.length === 1 ? assetLabel(moved[0]) : `${moved.length} assets`} to ${where}. Change history keeps the previous value.`),
      onError: () => { setStatus(null); void qc.invalidateQueries({ queryKey: akeys.all(eng.id) }) },
    })
  }

  return (
    <div className="stack" style={{ gap: 'var(--space-3)' }}>
      <div className="row" style={{ gap: 'var(--space-3)' }}>
        <input className="input" placeholder="Highlight assets…" aria-label="Highlight assets" value={needle}
          onChange={(e) => setNeedle(e.target.value)} style={{ width: 240 }} />
        <label className="row"><input type="checkbox" checked={otOnly} onChange={(e) => setOtOnly(e.target.checked)} /> OT traffic only</label>
        {external > 0 && <label className="row"><input type="checkbox" checked={showExternal} onChange={(e) => setShowExternal(e.target.checked)} /> Show {external} external</label>}
        {canEdit && !newZone && <button type="button" className="btn btn-sm" onClick={() => setNewZone({ name: '', level: '1' })}>New zone…</button>}
        {newZone && (
          <form className="row" aria-label="New zone" onSubmit={(e) => {
            e.preventDefault()
            if (newZone.name.trim()) setExtraZones((z) => [...z, { level: Number(newZone.level), zone: newZone.name.trim() }])
            setNewZone(null)
          }}>
            <input className="input" aria-label="Zone name" placeholder="Zone name" value={newZone.name} maxLength={100} autoFocus
              onChange={(e) => setNewZone({ ...newZone, name: e.target.value })} style={{ width: 160 }} />
            <select className="select" aria-label="Zone level" value={newZone.level} onChange={(e) => setNewZone({ ...newZone, level: e.target.value })}>
              {[5, 4, 3.5, 3, 2, 1, 0].map((l) => <option key={l} value={String(l)}>{purdueLabel(l)}</option>)}
            </select>
            <button type="submit" className="btn btn-sm btn-primary">Add</button>
            <button type="button" className="btn btn-sm" onClick={() => setNewZone(null)}>Cancel</button>
          </form>
        )}
        <span className="spacer" />
        <span className="pm-legend" aria-label="Legend">
          <i className="pm-key pm-key-ot" /> OT <i className="pm-key pm-key-write" /> writes <i className="pm-key pm-key-dmz" /> bypasses DMZ <i className="pm-key pm-key-it" /> other
        </span>
      </div>
      {status && <div className="muted" role="status">{status}</div>}
      {bulk.isError && <ErrorNote>{bulk.error.message}</ErrorNote>}
      {canEdit && <p className="muted" style={{ margin: 0, fontSize: 'var(--text-sm)' }}>Drag assets between levels and zones. Shift-drag to select several.</p>}
      <div className="purdue-canvas" aria-label="Purdue map">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={(changes: NodeChange[]) => setNodes((ns) => applyNodeChanges(changes, ns))}
          onNodeDragStop={onDragStop}
          onNodeClick={(_e, n) => { if (n.type === 'asset') select({ kind: 'asset', eid: eng.id, id: (n.data as AssetData).asset.id }) }}
          onEdgeClick={(_e, edge) => { const l = (edge.data as { link: Link }).link; select({ kind: 'link', eid: eng.id, src: l.src, dst: l.dst }) }}
          nodesConnectable={false}
          nodesDraggable={canEdit}
          elementsSelectable
          selectionOnDrag={false}
          fitView
          fitViewOptions={{ padding: 0.05 }}
          minZoom={0.1}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
          <Controls showInteractive={false} />
          <MiniMap pannable zoomable nodeClassName={(n) => (n.type === 'asset' ? 'pm-mini-asset' : 'pm-mini-bg')} />
        </ReactFlow>
      </div>
    </div>
  )
}
