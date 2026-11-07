import { ArrowDown, ArrowUp, Boxes, Download, Pencil, Plus, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import type { Asset, AssetFields, EditableField, Engagement, FieldValue } from '../api/client'
import { assetExportUrl, useAssetFields, useAssets, useBulkEdit, useCreateAsset, useMergeAssets } from '../api/assets'
import { DeviceIcon } from '../components/DeviceIcon'
import { ErrorNote } from '../components/ui'
import { useInspector } from '../inspector/context'
import { CRITICALITY_ORDER, assetLabel, levelName, parseList, parseTags, searchText } from '../lib/assets'
import { formatDateTime, purdueLabel } from '../lib/format'
import './assets.css'

type SortKey = 'name' | 'asset_type' | 'purdue_level' | 'zone' | 'criticality' | 'vendor' | 'last_seen'
const PAGE = 200
const BULK_FIELDS: EditableField[] = ['purdue_level', 'asset_type', 'zone', 'criticality', 'location', 'owner', 'tags']

function sortValue(a: Asset, k: SortKey): string | number {
  switch (k) {
    case 'name': return assetLabel(a).toLowerCase()
    case 'purdue_level': return a.purdue_level < 0 ? 99 : a.purdue_level // unclassified last
    case 'criticality': return a.criticality ? CRITICALITY_ORDER[a.criticality] : 0
    case 'last_seen': return a.last_seen ?? 0
    default: return (a[k] ?? '').toLowerCase()
  }
}

function Edited({ a, field }: { a: Asset; field: EditableField }) {
  return a.overridden.includes(field)
    ? <Pencil size={11} className="edited-mark" aria-label="set manually"><title>Set manually</title></Pencil>
    : null
}

/** Several selected assets are one device: fold them into the one picked as the survivor. */
function MergeBar({ eid, selected, onDone }: { eid: number; selected: Asset[]; onDone: () => void }) {
  const [open, setOpen] = useState(false)
  const [target, setTarget] = useState<number | null>(null)
  const [reason, setReason] = useState('')
  const merge = useMergeAssets(eid)
  const survivor = selected.find((a) => a.id === target) ?? selected[0]
  if (!open) {
    return <button type="button" className="btn btn-sm" onClick={() => setOpen(true)}>Merge {selected.length} into one…</button>
  }
  return (
    <div className="bulk-bar" role="region" aria-label="Merge assets">
      <strong>Merge into</strong>
      <select className="select" aria-label="Asset to keep" value={survivor.id} onChange={(e) => setTarget(Number(e.target.value))}>
        {selected.map((a) => <option key={a.id} value={a.id}>{assetLabel(a)}{a.name && a.ips[0] ? ` (${a.ips[0]})` : ''}</option>)}
      </select>
      <span className="muted">Its manual values win; addresses, traffic, findings and history of the others move to it.</span>
      <input className="input" aria-label="Merge reason" placeholder="Reason (optional)" value={reason} maxLength={1000}
        onChange={(e) => setReason(e.target.value)} style={{ minWidth: 200 }} />
      <button type="button" className="btn btn-primary btn-sm" disabled={merge.isPending}
        onClick={() => merge.mutate(
          { target: survivor.id, version: survivor.version, source_ids: selected.filter((a) => a.id !== survivor.id).map((a) => a.id), reason },
          { onSuccess: () => { setOpen(false); setReason(''); onDone() } },
        )}>Merge</button>
      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>Cancel</button>
      {merge.isError && <ErrorNote>{merge.error.message}</ErrorNote>}
    </div>
  )
}

function BulkBar({ eid, ids, fields, onDone }: { eid: number; ids: number[]; fields: AssetFields; onDone: () => void }) {
  const [field, setField] = useState<EditableField>('purdue_level')
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const bulk = useBulkEdit(eid)
  const spec = fields.fields.find((f) => f.name === field)!
  const parsed = (): FieldValue => {
    if (spec.kind === 'level') return Number(value)
    if (spec.kind === 'tags') return parseTags(value)
    return value.trim() || null
  }
  const run = (reset: boolean) =>
    bulk.mutate(
      { asset_ids: ids, set: reset ? {} : { [field]: parsed() }, reset: reset ? [field] : [], reason },
      { onSuccess: () => { setValue(''); setReason(''); onDone() } },
    )
  return (
    <div className="bulk-bar" role="region" aria-label="Bulk edit">
      <strong>{ids.length} selected</strong>
      <select className="select" aria-label="Field to change" value={field}
        onChange={(e) => { setField(e.target.value as EditableField); setValue('') }}>
        {BULK_FIELDS.map((f) => <option key={f} value={f}>{fields.fields.find((x) => x.name === f)?.label}</option>)}
      </select>
      {spec.kind === 'level' ? (
        <select className="select" aria-label="New value" value={value} onChange={(e) => setValue(e.target.value)}>
          <option value="" disabled>Choose a level…</option>
          {fields.purdue_levels.map((l) => <option key={l} value={String(l)}>{levelName(fields, l)}</option>)}
        </select>
      ) : spec.kind === 'choice' ? (
        <select className="select" aria-label="New value" value={value} onChange={(e) => setValue(e.target.value)}>
          <option value="">Not set</option>
          {fields.criticalities.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      ) : (
        <input className="input" aria-label="New value" value={value} onChange={(e) => setValue(e.target.value)}
          list={field === 'asset_type' ? 'bulk-asset-types' : undefined}
          placeholder={spec.kind === 'tags' ? 'tags, comma-separated (replaces)' : 'New value'} />
      )}
      <datalist id="bulk-asset-types">{fields.asset_types.map((t) => <option key={t} value={t} />)}</datalist>
      <input className="input" aria-label="Reason" placeholder="Reason (optional)" value={reason} maxLength={1000}
        onChange={(e) => setReason(e.target.value)} style={{ minWidth: 200 }} />
      <button type="button" className="btn btn-primary btn-sm" disabled={bulk.isPending || (spec.kind === 'level' && value === '')}
        onClick={() => run(false)}>Apply</button>
      <button type="button" className="btn btn-sm" disabled={bulk.isPending} onClick={() => run(true)}
        title="Remove manual values for this field, going back to what traffic shows">Reset to detected</button>
      <button type="button" className="btn btn-ghost btn-sm" onClick={onDone} aria-label="Clear selection"><X size={14} /></button>
      {bulk.isError && <ErrorNote>{bulk.error.message}</ErrorNote>}
      {bulk.isSuccess && <span className="muted" role="status">Updated {bulk.data.assets} asset{bulk.data.assets === 1 ? '' : 's'}.</span>}
    </div>
  )
}

function AddAsset({ eid, fields, onCreated, onCancel }: {
  eid: number; fields: AssetFields; onCreated: (id: number) => void; onCancel: () => void
}) {
  const [name, setName] = useState('')
  const [ips, setIps] = useState('')
  const [macs, setMacs] = useState('')
  const [type, setType] = useState('')
  const [level, setLevel] = useState('-1')
  const [reason, setReason] = useState('')
  const create = useCreateAsset(eid)
  const submit = () => {
    const values: Partial<Record<EditableField, FieldValue>> = {}
    if (name.trim()) values.name = name.trim()
    if (type.trim()) values.asset_type = type.trim()
    if (level !== '-1') values.purdue_level = Number(level)
    create.mutate({ ips: parseList(ips), macs: parseList(macs), values, reason }, { onSuccess: (a) => onCreated(a.id) })
  }
  return (
    <form className="card stack" aria-label="Add asset" onSubmit={(e) => { e.preventDefault(); submit() }}>
      <div>
        <h2 style={{ marginBottom: 4 }}>Add an asset by hand</h2>
        <p className="muted" style={{ margin: 0 }}>For devices that never show up in captures, such as firewalls, data diodes or unmanaged switches. If a later capture sees the same address, it's merged into this asset.</p>
      </div>
      <div className="form-grid">
        <label className="field"><span>Name</span><input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} /></label>
        <label className="field"><span>IP addresses</span><input className="input" value={ips} onChange={(e) => setIps(e.target.value)} placeholder="10.0.0.1, 10.0.1.1" /></label>
        <label className="field"><span>MAC addresses</span><input className="input" value={macs} onChange={(e) => setMacs(e.target.value)} placeholder="00:0c:29:…" /></label>
        <label className="field"><span>Type</span><input className="input" value={type} onChange={(e) => setType(e.target.value)} list="add-asset-types" maxLength={100} /></label>
        <label className="field"><span>Purdue level</span>
          <select className="select" value={level} onChange={(e) => setLevel(e.target.value)}>
            {fields.purdue_levels.map((l) => <option key={l} value={String(l)}>{levelName(fields, l)}</option>)}
          </select>
        </label>
        <label className="field"><span>Reason</span><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. From site network drawing" maxLength={1000} /></label>
      </div>
      <datalist id="add-asset-types">{fields.asset_types.map((t) => <option key={t} value={t} />)}</datalist>
      {create.isError && <ErrorNote>{create.error.message}</ErrorNote>}
      <div className="row">
        <button type="submit" className="btn btn-primary" disabled={create.isPending}>Add asset</button>
        <button type="button" className="btn" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  )
}

export function AssetsPage() {
  const eng = useOutletContext<Engagement>()
  const assets = useAssets(eng.id)
  const fields = useAssetFields()
  const { selection, select } = useInspector()
  const canEdit = eng.my_role === 'lead' || eng.my_role === 'editor'
  const [q, setQ] = useState('')
  const [level, setLevel] = useState('all')
  const [type, setType] = useState('all')
  const [editedOnly, setEditedOnly] = useState(false)
  const [showExternal, setShowExternal] = useState(false)
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'purdue_level', dir: 1 })
  const [checked, setChecked] = useState<Set<number>>(new Set())
  const [limit, setLimit] = useState(PAGE)
  const [adding, setAdding] = useState(false)

  const all = useMemo(() => assets.data ?? [], [assets.data])
  const types = useMemo(() => [...new Set(all.map((a) => a.asset_type).filter((t): t is string => !!t))].sort(), [all])
  const external = all.filter((a) => !a.is_private && a.origin === 'observed').length
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const out = all.filter((a) =>
      (showExternal || a.is_private || a.origin === 'manual')
      && (level === 'all' || a.purdue_level === Number(level))
      && (type === 'all' || (type === '' ? !a.asset_type : a.asset_type === type))
      && (!editedOnly || a.overridden.length > 0)
      && (!needle || searchText(a).includes(needle)))
    return out.sort((x, y) => {
      const a = sortValue(x, sort.key)
      const b = sortValue(y, sort.key)
      return (a < b ? -1 : a > b ? 1 : 0) * sort.dir || x.id - y.id
    })
  }, [all, q, level, type, editedOnly, showExternal, sort])
  const visibleIds = rows.slice(0, limit).map((a) => a.id)
  const ids = [...checked].filter((id) => all.some((a) => a.id === id))
  const allChecked = visibleIds.length > 0 && visibleIds.every((id) => checked.has(id))

  const toggle = (id: number) => setChecked((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })
  const head = (key: SortKey, label: string) => (
    <th aria-sort={sort.key === key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="th-sort" onClick={() => setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 }))}>
        {label}{sort.key === key && (sort.dir === 1 ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
      </button>
    </th>
  )
  const edited = all.filter((a) => a.overridden.length > 0).length

  return (
    <div className="page" style={{ maxWidth: 'none' }}>
      <div className="page-head">
        <div>
          <h1>Asset inventory</h1>
          <p>{all.length} asset{all.length === 1 ? '' : 's'} · {edited} edited by hand · merged across all captures</p>
        </div>
        <div className="row">
          {canEdit && <button type="button" className="btn" onClick={() => setAdding(true)}><Plus size={14} /> Add asset</button>}
          <a className="btn" href={assetExportUrl(eng.id)} download><Download size={14} /> Export CSV</a>
        </div>
      </div>
      {assets.isError && <ErrorNote>{assets.error.message}</ErrorNote>}
      {fields.isError && <ErrorNote>{fields.error.message}</ErrorNote>}
      {adding && fields.data && (
        <AddAsset eid={eng.id} fields={fields.data} onCancel={() => setAdding(false)}
          onCreated={(id) => { setAdding(false); select({ kind: 'asset', eid: eng.id, id }) }} />
      )}
      {assets.isSuccess && all.length === 0 && !adding && (
        <div className="empty card">
          <Boxes size={36} strokeWidth={1.5} aria-hidden />
          <strong>No assets yet</strong>
          <span>Assets appear here as captures finish analysing. <Link to={`/e/${eng.id}/captures`}>Add captures</Link>{canEdit && ' or add an asset by hand'}.</span>
        </div>
      )}
      {all.length > 0 && (
        <div className="stack">
          <div className="row asset-toolbar">
            <input className="input" placeholder="Search name, address, vendor, protocol, tag…" aria-label="Search assets"
              value={q} onChange={(e) => { setQ(e.target.value); setLimit(PAGE) }} style={{ minWidth: 280, flex: 1, maxWidth: 420 }} />
            <select className="select" aria-label="Filter by Purdue level" value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="all">All levels</option>
              {(fields.data?.purdue_levels ?? []).map((l) => <option key={l} value={String(l)}>{levelName(fields.data, l)}</option>)}
            </select>
            <select className="select" aria-label="Filter by type" value={type} onChange={(e) => setType(e.target.value)}>
              <option value="all">All types</option>
              {types.map((t) => <option key={t} value={t}>{t}</option>)}
              <option value="">No type</option>
            </select>
            <label className="row"><input type="checkbox" checked={editedOnly} onChange={(e) => setEditedOnly(e.target.checked)} /> Edited only</label>
            {external > 0 && (
              <label className="row"><input type="checkbox" checked={showExternal} onChange={(e) => setShowExternal(e.target.checked)} /> Show {external} external</label>
            )}
            <span className="spacer" />
            <span className="muted" role="status">{rows.length} shown</span>
          </div>
          {canEdit && ids.length > 0 && fields.data && (
            <BulkBar eid={eng.id} ids={ids} fields={fields.data} onDone={() => setChecked(new Set())} />
          )}
          {canEdit && ids.length > 1 && (
            <MergeBar key={ids.join()} eid={eng.id} selected={(assets.data ?? []).filter((a) => checked.has(a.id))} onDone={() => setChecked(new Set())} />
          )}
          <div className="table-wrap">
            <table className="table asset-table" aria-label="Assets">
              <thead>
                <tr>
                  {canEdit && (
                    <th className="check">
                      <input type="checkbox" aria-label="Select all shown" checked={allChecked}
                        onChange={() => setChecked((s) => {
                          const n = new Set(s)
                          for (const id of visibleIds) if (allChecked) n.delete(id); else n.add(id)
                          return n
                        })} />
                    </th>
                  )}
                  {head('name', 'Asset')}
                  {head('asset_type', 'Type')}
                  {head('purdue_level', 'Level')}
                  {head('zone', 'Zone')}
                  {head('criticality', 'Criticality')}
                  {head('vendor', 'Vendor / model')}
                  <th>Protocols</th>
                  {head('last_seen', 'Last seen')}
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, limit).map((a) => {
                  const sel = selection?.kind === 'asset' && selection.id === a.id
                  const open = () => select({ kind: 'asset', eid: eng.id, id: a.id })
                  return (
                    <tr key={a.id} className={`clickable${sel ? ' selected' : ''}`} onClick={open} tabIndex={0}
                      onKeyDown={(e) => { if (e.key === 'Enter') open() }} aria-selected={sel}>
                      {canEdit && (
                        <td className="check" onClick={(e) => e.stopPropagation()}>
                          <input type="checkbox" aria-label={`Select ${assetLabel(a)}`} checked={checked.has(a.id)} onChange={() => toggle(a.id)} />
                        </td>
                      )}
                      <td>
                        <div className="asset-name">{a.name ?? <span className="mono">{a.ips[0] ?? a.macs[0]}</span>}<Edited a={a} field="name" />
                          {a.origin === 'manual' && <span className="badge" title="Added by hand">manual</span>}
                        </div>
                        <div className="muted mono asset-sub">{a.name ? [a.ips[0], a.macs[0]].filter(Boolean).join(' · ') : a.macs[0] ?? ''}{a.ips.length > 1 && ` +${a.ips.length - 1}`}</div>
                      </td>
                      <td><span className="type-cell"><DeviceIcon type={a.asset_type} isPrivate={a.is_private} size={15} label={false} />{a.asset_type ?? <span className="muted">—</span>}</span><Edited a={a} field="asset_type" />
                        {a.type_confidence === 'low' && <span className="muted" title="Low confidence"> ?</span>}</td>
                      <td title={levelName(fields.data, a.purdue_level)}>
                        <span className={`level level-${String(a.purdue_level).replace('.', '_')}`}>{purdueLabel(a.purdue_level)}</span>
                        <Edited a={a} field="purdue_level" />
                      </td>
                      <td>{a.zone ?? <span className="muted">—</span>}<Edited a={a} field="zone" /></td>
                      <td>{a.criticality ? <span className={`crit crit-${a.criticality}`}>{a.criticality}</span> : <span className="muted">—</span>}</td>
                      <td>{a.vendor ?? <span className="muted">—</span>}<Edited a={a} field="vendor" />
                        {a.model && <div className="muted asset-sub">{a.model}</div>}</td>
                      <td className="muted asset-protocols">{a.protocols.slice(0, 4).join(', ')}{a.protocols.length > 4 ? ` +${a.protocols.length - 4}` : ''}</td>
                      <td className="muted asset-seen" title={formatDateTime(a.last_seen)}>
                        {a.last_seen ? new Date(a.last_seen * 1000).toLocaleDateString() : a.capture_count === 0 ? 'not seen' : '—'}
                        {a.tags.length > 0 && <div className="chips">{a.tags.map((t) => <span key={t} className="badge">{t}</span>)}</div>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {rows.length > limit && (
            <button type="button" className="btn" onClick={() => setLimit((l) => l + PAGE)}>Show {Math.min(PAGE, rows.length - limit)} more</button>
          )}
          {rows.length === 0 && <p className="muted">No assets match these filters.</p>}
        </div>
      )}
    </div>
  )
}
