import { Layers } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link as RouterLink, useOutletContext } from 'react-router-dom'
import type { Asset, Engagement, Link, OtOperation } from '../api/client'
import { useAssetFields, useAssets } from '../api/assets'
import { useLinks, useOtOperations } from '../api/purdue'
import { AssetButton } from '../components/LinkDetails'
import { ErrorNote, Tabs } from '../components/ui'
import { useInspector } from '../inspector/context'
import { assetLabel, levelName } from '../lib/assets'
import { formatDateTime, formatNumber, purdueLabel } from '../lib/format'
import { LANES, levelMatrix, bypassesDmz } from '../lib/purdue'
import { PurdueMap } from './PurdueMap'
import './purdue.css'

type Tab = 'map' | 'levels' | 'ot' | 'log'

function LinkList({ links, assets, eid }: { links: Link[]; assets: Map<number, Asset>; eid: number }) {
  const { select } = useInspector()
  return (
    <table className="table" aria-label="Links">
      <thead><tr><th>From</th><th>To</th><th>Protocols</th><th className="num">Flows</th><th className="num">OT writes</th><th /></tr></thead>
      <tbody>{links.map((l) => (
        <tr key={`${l.src}-${l.dst}`}>
          <td><AssetButton a={assets.get(l.src)} eid={eid} /> <span className="muted">{purdueLabel(assets.get(l.src)?.purdue_level ?? -1)}</span></td>
          <td><AssetButton a={assets.get(l.dst)} eid={eid} /> <span className="muted">{purdueLabel(assets.get(l.dst)?.purdue_level ?? -1)}</span></td>
          <td>{l.protocols.map((p) => p.protocol).join(', ')}</td>
          <td className="num">{formatNumber(l.flows)}</td>
          <td className="num">{l.ot_writes ? <span className="badge badge-danger">{formatNumber(l.ot_writes)}</span> : '—'}</td>
          <td><button type="button" className="btn btn-ghost btn-sm" onClick={() => select({ kind: 'link', eid, src: l.src, dst: l.dst })}>Details</button></td>
        </tr>
      ))}</tbody>
    </table>
  )
}

function LevelMatrix({ links, assets, eid, fields }: { links: Link[]; assets: Map<number, Asset>; eid: number; fields: ReturnType<typeof useAssetFields>['data'] }) {
  const [otOnly, setOtOnly] = useState(false)
  const [cell, setCell] = useState<string | null>(null)
  const shown = otOnly ? links.filter((l) => l.is_ot) : links
  const m = useMemo(() => levelMatrix(shown, assets), [shown, assets])
  const used = new Set([...assets.values()].map((a) => a.purdue_level))
  const levels = LANES.filter((l) => l.always || used.has(l.level)).map((l) => l.level)
  const flagged = [...m.entries()].filter(([k]) => { const [a, b] = k.split('|').map(Number); return bypassesDmz(a, b) })
  return (
    <div className="stack">
      <div className="row">
        <p className="muted" style={{ margin: 0, flex: 1 }}>Asset pairs talking between levels (rows: client, columns: server). Highlighted cells bypass the industrial DMZ: the business network or the internet talking directly to site operations or control (L4+ ↔ L3 and below).</p>
        <label className="row"><input type="checkbox" checked={otOnly} onChange={(e) => setOtOnly(e.target.checked)} /> OT traffic only</label>
      </div>
      {flagged.length > 0 && (
        <div className="alert alert-warn" role="status">
          {flagged.reduce((n, [, c]) => n + c.links.length, 0)} asset pair(s) bypass the industrial DMZ (L4 and above talking directly to L3 and below).
        </div>
      )}
      <div className="table-wrap">
        <table className="matrix" aria-label="Level matrix">
          <thead><tr><th>From \ To</th>{levels.map((l) => <th key={l} title={levelName(fields, l)}>{purdueLabel(l)}</th>)}</tr></thead>
          <tbody>{levels.map((r) => (
            <tr key={r}>
              <th scope="row" title={levelName(fields, r)}>{purdueLabel(r)}</th>
              {levels.map((c) => {
                const k = `${r}|${c}`
                const v = m.get(k)
                return (
                  <td key={c} className={`${v && bypassesDmz(r, c) ? 'dmz' : ''}${v?.writes ? ' writes' : ''}${cell === k ? ' active' : ''}`}>
                    {v ? (
                      <button type="button" onClick={() => setCell(cell === k ? null : k)}
                        aria-label={`${purdueLabel(r)} to ${purdueLabel(c)}: ${v.links.length} pairs`}>
                        {v.links.length}{v.writes > 0 && <small> ✎{v.writes}</small>}
                      </button>
                    ) : <span className="muted">·</span>}
                  </td>
                )
              })}
            </tr>
          ))}</tbody>
        </table>
      </div>
      {cell && m.get(cell) && (
        <div className="card">
          <h2>{purdueLabel(Number(cell.split('|')[0]))} → {purdueLabel(Number(cell.split('|')[1]))}</h2>
          <LinkList links={m.get(cell)!.links} assets={assets} eid={eid} />
        </div>
      )}
    </div>
  )
}

function OtMatrix({ ops, links, assets, eid }: { ops: OtOperation[]; links: Link[]; assets: Map<number, Asset>; eid: number }) {
  const { select } = useInspector()
  const ot = links.filter((l) => l.is_ot)
  const byLabel = (a: number, b: number) => assetLabel(assets.get(a)!).localeCompare(assetLabel(assets.get(b)!), undefined, { numeric: true })
  const masters = [...new Set(ot.map((l) => l.src))].filter((i) => assets.has(i)).sort(byLabel)
  const devices = [...new Set(ot.map((l) => l.dst))].filter((i) => assets.has(i)).sort(byLabel)
  if (!ot.length) return <p className="muted">No OT traffic between assets yet.</p>
  const sum = new Map<string, { reads: number; writes: number; errors: number }>()
  for (const o of ops) {
    const k = `${o.src}|${o.dst}`
    const s = sum.get(k) ?? { reads: 0, writes: 0, errors: 0 }
    if (o.kind === 'write') s.writes += o.count; else if (o.kind === 'error') s.errors += o.count; else s.reads += o.count
    sum.set(k, s)
  }
  const linkSet = new Set(ot.map((l) => `${l.src}|${l.dst}`))
  return (
    <div className="stack">
      <p className="muted" style={{ margin: 0 }}>Who sends OT commands to whom. Rows: masters (HMIs, SCADA, engineering workstations); columns: devices. Red cells include writes.</p>
      <div className="table-wrap">
        <table className="matrix ot-matrix" aria-label="OT matrix">
          <thead><tr><th />{devices.map((d) => <th key={d} className="rot"><span><AssetButton a={assets.get(d)} eid={eid} /></span></th>)}</tr></thead>
          <tbody>{masters.map((m) => (
            <tr key={m}>
              <th scope="row"><AssetButton a={assets.get(m)} eid={eid} /></th>
              {devices.map((d) => {
                const k = `${m}|${d}`
                const s = sum.get(k)
                return (
                  <td key={d} className={s?.writes ? 'writes' : linkSet.has(k) ? 'has' : ''}>
                    {linkSet.has(k) ? (
                      <button type="button" onClick={() => select({ kind: 'link', eid, src: m, dst: d })}
                        aria-label={`${assetLabel(assets.get(m)!)} to ${assetLabel(assets.get(d)!)}`}
                        title={s ? `${s.reads} reads, ${s.writes} writes, ${s.errors} errors` : 'OT traffic'}>
                        {s ? (s.writes ? `W${s.writes}` : `R${s.reads}`) : '•'}
                      </button>
                    ) : ''}
                  </td>
                )
              })}
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  )
}

function OtLog({ ops, assets, eid }: { ops: OtOperation[]; assets: Map<number, Asset>; eid: number }) {
  const [kind, setKind] = useState('all')
  const [proto, setProto] = useState('all')
  const [q, setQ] = useState('')
  const protocols = [...new Set(ops.map((o) => o.protocol))].sort()
  const needle = q.trim().toLowerCase()
  const shown = ops.filter((o) => (kind === 'all' || o.kind === kind) && (proto === 'all' || o.protocol === proto)
    && (!needle || [o.function, o.sample, assetLabel(assets.get(o.src) ?? { id: o.src, name: null, ips: [], macs: [] }),
      assetLabel(assets.get(o.dst) ?? { id: o.dst, name: null, ips: [], macs: [] })].join(' ').toLowerCase().includes(needle)))
  if (!ops.length) return <p className="muted">No OT commands seen yet.</p>
  return (
    <div className="stack">
      <div className="row">
        <input className="input" placeholder="Search function, asset, detail…" aria-label="Search OT commands" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 280 }} />
        <select className="select" aria-label="Filter by kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="all">All kinds</option><option value="write">Writes</option><option value="error">Errors</option><option value="read">Reads</option><option value="other">Other</option>
        </select>
        <select className="select" aria-label="Filter by protocol" value={proto} onChange={(e) => setProto(e.target.value)}>
          <option value="all">All protocols</option>{protocols.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <span className="muted">{shown.length} of {ops.length}</span>
      </div>
      <div className="table-wrap">
        <table className="table" aria-label="OT commands">
          <thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Function</th><th>Kind</th><th className="num">Count</th><th>Last seen</th><th>Detail</th></tr></thead>
          <tbody>{shown.map((o) => (
            <tr key={`${o.src}-${o.dst}-${o.protocol}-${o.function}-${o.kind}-${o.function_code}`}>
              <td><AssetButton a={assets.get(o.src)} eid={eid} /></td>
              <td><AssetButton a={assets.get(o.dst)} eid={eid} /></td>
              <td>{o.protocol}</td>
              <td>{o.function}{o.function_code != null && <span className="muted"> ({o.function_code})</span>}</td>
              <td><span className={`badge ${o.kind === 'write' ? 'badge-danger' : o.kind === 'error' ? 'badge-warn' : ''}`}>{o.kind}</span></td>
              <td className="num">{formatNumber(o.count)}</td>
              <td className="muted" style={{ whiteSpace: 'nowrap' }}>{formatDateTime(o.last_seen)}</td>
              <td className="muted" style={{ maxWidth: 260 }}>{o.sample}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  )
}

export function PurduePage() {
  const eng = useOutletContext<Engagement>()
  const assets = useAssets(eng.id)
  const links = useLinks(eng.id)
  const ops = useOtOperations(eng.id)
  const fields = useAssetFields()
  const [tab, setTab] = useState<Tab>('map')
  const byId = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])
  const err = assets.error ?? links.error ?? ops.error
  const writes = (ops.data ?? []).filter((o) => o.kind === 'write').reduce((n, o) => n + o.count, 0)

  return (
    <div className="page" style={{ maxWidth: 'none' }}>
      <div className="page-head">
        <div>
          <h1>Purdue map</h1>
          <p>{byId.size} assets · {(links.data ?? []).filter((l) => l.is_ot).length} OT connections · {formatNumber(writes)} OT writes</p>
        </div>
      </div>
      {err && <ErrorNote>{err.message}</ErrorNote>}
      {assets.isSuccess && byId.size === 0 && (
        <div className="empty card">
          <Layers size={36} strokeWidth={1.5} aria-hidden />
          <strong>No assets yet</strong>
          <span>The map fills in as captures finish analysing. <RouterLink to={`/e/${eng.id}/captures`}>Add captures</RouterLink>.</span>
        </div>
      )}
      {assets.data && links.data && ops.data && byId.size > 0 && (
        <>
          <Tabs<Tab> label="Purdue views" value={tab} onChange={setTab} tabs={[
            { id: 'map', label: 'Map' }, { id: 'levels', label: 'Level matrix' },
            { id: 'ot', label: 'OT matrix' }, { id: 'log', label: 'OT commands', count: ops.data.length },
          ]} />
          {tab === 'map' && <PurdueMap eng={eng} assets={assets.data} links={links.data} fields={fields.data} />}
          {tab === 'levels' && <LevelMatrix links={links.data} assets={byId} eid={eng.id} fields={fields.data} />}
          {tab === 'ot' && <OtMatrix ops={ops.data} links={links.data} assets={byId} eid={eng.id} />}
          {tab === 'log' && <OtLog ops={ops.data} assets={byId} eid={eng.id} />}
        </>
      )}
    </div>
  )
}
