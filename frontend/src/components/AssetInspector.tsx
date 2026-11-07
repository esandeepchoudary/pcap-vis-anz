import { History, Pencil, RotateCcw, X } from 'lucide-react'
import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, type AssetDetail, type AssetField, type AssetFields, type EditableField, type FieldValue } from '../api/client'
import { useAsset, useAssetFields, useAssetHistory, useDeleteAsset, useEditAsset, useSplitAsset } from '../api/assets'
import { useEngagement } from '../api/engagements'
import { useInspector } from '../inspector/context'
import { assetLabel, describeChange, formatValue, identityGroups, levelName, parseTags } from '../lib/assets'
import { formatBytes, formatDateTime, formatNumber, relativeTime } from '../lib/format'
import { DeviceIcon } from './DeviceIcon'
import { ConfirmButton, ErrorNote, Tabs } from './ui'

type Tab = 'details' | 'evidence' | 'history'
type Raw = Partial<Record<EditableField, string>>

function toRaw(field: AssetField, v: FieldValue | undefined): string {
  if (v === null || v === undefined) return ''
  if (field.kind === 'tags') return (v as string[]).join(', ')
  return String(v)
}

function fromRaw(field: AssetField, raw: string): FieldValue {
  switch (field.kind) {
    case 'level': return Number(raw)
    case 'tags': return parseTags(raw)
    case 'longtext': return raw.trimEnd() || null
    default: return raw.trim() || null
  }
}

function same(a: FieldValue | undefined, b: FieldValue | undefined): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
}

const current = (d: AssetDetail, f: EditableField) => d[f] as FieldValue

function FieldControl({ field, value, onChange, fields, disabled }: {
  field: AssetField; value: string; onChange: (v: string) => void; fields: AssetFields; disabled: boolean
}) {
  const id = `asset-field-${field.name}`
  if (field.kind === 'level') {
    return (
      <select id={id} className="select" value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
        {fields.purdue_levels.map((l) => <option key={l} value={String(l)}>{levelName(fields, l)}</option>)}
      </select>
    )
  }
  if (field.kind === 'choice') {
    return (
      <select id={id} className="select" value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
        <option value="">Not set</option>
        {fields.criticalities.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
    )
  }
  if (field.kind === 'longtext') {
    return <textarea id={id} className="textarea" value={value} maxLength={field.max_len} disabled={disabled}
      onChange={(e) => onChange(e.target.value)} />
  }
  return (
    <input id={id} className="input" value={value} disabled={disabled} maxLength={field.kind === 'tags' ? 1000 : field.max_len}
      list={field.name === 'asset_type' ? 'asset-types' : undefined}
      placeholder={field.kind === 'tags' ? 'comma-separated' : undefined}
      onChange={(e) => onChange(e.target.value)} />
  )
}

function Details({ d, fields, canEdit, eid }: { d: AssetDetail; fields: AssetFields; canEdit: boolean; eid: number }) {
  const [raw, setRaw] = useState<Raw>({})
  const [resets, setResets] = useState<EditableField[]>([])
  const [reason, setReason] = useState('')
  const [base, setBase] = useState(d.version)
  const edit = useEditAsset(eid, d.id)
  const dirty = Object.keys(raw).length > 0 || resets.length > 0
  if (!dirty && base !== d.version) setBase(d.version) // nothing pending: follow the server
  const conflict = dirty && base !== d.version || (edit.error instanceof ApiError && edit.error.status === 409)

  const display = (f: AssetField): string => {
    if (resets.includes(f.name)) return toRaw(f, d.auto[f.name] ?? (f.kind === 'level' ? -1 : f.kind === 'tags' ? [] : null))
    return raw[f.name] ?? toRaw(f, current(d, f.name))
  }
  const change = (f: AssetField, v: string) => {
    setResets((r) => r.filter((x) => x !== f.name))
    setRaw((r) => ({ ...r, [f.name]: v }))
  }
  const discard = () => { setRaw({}); setResets([]); setReason(''); setBase(d.version); edit.reset() }
  const save = () => {
    const set: Partial<Record<EditableField, FieldValue>> = {}
    for (const f of fields.fields) {
      const v = raw[f.name]
      if (v === undefined) continue
      const parsed = fromRaw(f, v)
      if (!same(parsed, current(d, f.name))) set[f.name] = parsed
    }
    edit.mutate({ version: base, set, reset: resets, reason }, { onSuccess: () => { setRaw({}); setResets([]); setReason('') } })
  }

  return (
    <form className="asset-form" onSubmit={(e) => { e.preventDefault(); save() }} aria-label="Asset fields">
      <datalist id="asset-types">{fields.asset_types.map((t) => <option key={t} value={t} />)}</datalist>
      {fields.fields.map((f) => {
        const ov = d.overrides[f.name]
        const pendingReset = resets.includes(f.name)
        const autoValue = d.auto[f.name]
        return (
          <div className="asset-field" key={f.name}>
            <div className="asset-field-head">
              <label htmlFor={`asset-field-${f.name}`}>{f.label}</label>
              {ov && !pendingReset && (
                <span className="badge badge-accent" title={`Set by ${ov.by}${ov.at ? `, ${formatDateTime(ov.at)}` : ''}${ov.reason ? ` — ${ov.reason}` : ''}`}>
                  <Pencil size={10} aria-hidden /> manual
                </span>
              )}
              {pendingReset && <span className="badge">reset on save</span>}
              <span className="spacer" />
              {ov && !pendingReset && canEdit && (
                <button type="button" className="btn btn-ghost btn-sm" aria-label={`Reset ${f.label} to automatic`}
                  title="Go back to the value detected from traffic"
                  onClick={() => { setResets((r) => [...r, f.name]); setRaw((r) => { const n = { ...r }; delete n[f.name]; return n }) }}>
                  <RotateCcw size={12} />
                </button>
              )}
            </div>
            <FieldControl field={f} value={display(f)} onChange={(v) => change(f, v)} fields={fields} disabled={!canEdit} />
            {ov && !pendingReset && ov.reason && <div className="asset-hint">Why: {ov.reason}</div>}
            {f.auto && ov && !pendingReset && (
              <div className="asset-hint">Detected: {formatValue(f.name, autoValue)}{d.auto_sources[f.name] && ` (${d.auto_sources[f.name]})`}</div>
            )}
            {f.auto && !ov && d.auto_sources[f.name] && f.name !== 'asset_type' && (
              <div className="asset-hint">From {d.auto_sources[f.name]}</div>
            )}
          </div>
        )
      })}
      {canEdit && dirty && (
        <div className="asset-save">
          {conflict && (
            <div className="alert alert-warn" role="alert">
              <span>Someone else changed this asset while you were editing.{' '}
                <button type="button" className="link-btn" onClick={discard}>Discard mine</button>{' '}or{' '}
                <button type="button" className="link-btn" onClick={() => { setBase(d.version); edit.reset() }}>keep mine</button> and save again.
              </span>
            </div>
          )}
          <label className="field">
            <span>Reason (recorded in history)</span>
            <input className="input" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Confirmed with site engineer" />
          </label>
          {edit.isError && !conflict && <ErrorNote>{edit.error.message}</ErrorNote>}
          <div className="row">
            <button type="submit" className="btn btn-primary btn-sm" disabled={edit.isPending || conflict}>Save changes</button>
            <button type="button" className="btn btn-sm" onClick={discard}>Discard</button>
          </div>
        </div>
      )}
    </form>
  )
}

/** The matcher joined two devices: move some addresses (and their traffic) to a new asset. */
function SplitAddresses({ d, eid }: { d: AssetDetail; eid: number }) {
  const [open, setOpen] = useState(false)
  const [moving, setMoving] = useState<Set<string>>(new Set())
  const [reason, setReason] = useState('')
  const split = useSplitAsset(eid, d.id)
  const { select } = useInspector()
  if (!open) return <button type="button" className="btn btn-sm" onClick={() => setOpen(true)}>Split addresses…</button>
  const toggle = (ip: string) => setMoving((m) => { const n = new Set(m); if (n.has(ip)) n.delete(ip); else n.add(ip); return n })
  return (
    <fieldset className="split-box">
      <legend>Move to a new asset</legend>
      {d.ips.map((ip) => (
        <label key={ip} className="row mono"><input type="checkbox" checked={moving.has(ip)} onChange={() => toggle(ip)} /> {ip}</label>
      ))}
      <input className="input" aria-label="Split reason" placeholder="Reason (optional)" value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} />
      <div className="row">
        <button type="button" className="btn btn-primary btn-sm" disabled={!moving.size || moving.size >= d.ips.length || split.isPending}
          onClick={() => split.mutate({ version: d.version, ips: [...moving], reason },
            { onSuccess: (r) => { setOpen(false); select({ kind: 'asset', eid, id: r.created.id }) } })}>Split</button>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>Cancel</button>
      </div>
      {moving.size >= d.ips.length && <span className="muted">Leave at least one address here.</span>}
      {split.isError && <ErrorNote>{split.error.message}</ErrorNote>}
    </fieldset>
  )
}

function Evidence({ d, eid, canEdit }: { d: AssetDetail; eid: number; canEdit: boolean }) {
  const identity = identityGroups(d.identity)
  return (
    <div>
      <div className="inspector-section">
        <h3>Why this classification</h3>
        {d.type_confidence && <div className="row" style={{ marginBottom: 'var(--space-2)' }}>
          <strong>{d.auto.asset_type ?? 'Unknown'}</strong>
          <span className={`badge ${d.type_confidence === 'high' ? 'badge-ok' : d.type_confidence === 'medium' ? 'badge-warn' : ''}`}>{d.type_confidence} confidence</span>
        </div>}
        <ul className="evidence" aria-label="Evidence">
          {[...d.type_evidence, ...d.purdue_evidence].map((e, i) => <li key={i}>{e.detail}</li>)}
          {!d.type_evidence.length && !d.purdue_evidence.length && <li>No traffic evidence (added by hand or not seen yet).</li>}
        </ul>
      </div>
      <div className="inspector-section">
        <h3>Identity</h3>
        <dl className="kv">
          <dt>IP addresses</dt><dd className="mono">{d.ips.join(', ') || '—'}</dd>
          <dt>MAC addresses</dt><dd className="mono">{d.macs.join(', ') || '—'}</dd>
          <dt>MAC vendor</dt><dd>{d.mac_vendor ?? '—'}</dd>
          <dt>OS hint</dt><dd>{d.os_hint ?? '—'}{d.ttl != null && <span className="muted"> (TTL {d.ttl})</span>}</dd>
          <dt>VLANs</dt><dd>{d.vlans.join(', ') || '—'}</dd>
          {d.ot_role !== 'unknown' && <><dt>OT role</dt><dd>{d.ot_role}</dd></>}
          {d.modbus_unit_ids.length > 0 && <><dt>Modbus units</dt><dd>{d.modbus_unit_ids.join(', ')}</dd></>}
          {d.dnp3_addresses.length > 0 && <><dt>DNP3 addresses</dt><dd>{d.dnp3_addresses.join(', ')}</dd></>}
          {d.hostnames.length > 0 && <><dt>Names</dt><dd>{d.hostnames.map((n) => `${n.name} (${n.source})`).join(', ')}</dd></>}
        </dl>
        {canEdit && d.ips.length > 1 && <SplitAddresses key={d.id} d={d} eid={eid} />}
      </div>
      {identity.map(([source, entries]) => (
        <div className="inspector-section" key={source}>
          <h3>{source}</h3>
          <dl className="kv" aria-label={`Identity from ${source}`}>
            {entries.map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}
          </dl>
        </div>
      ))}
      {d.services.length > 0 && (
        <div className="inspector-section">
          <h3>Services</h3>
          <ul className="evidence">
            {d.services.map((s) => <li key={`${s.transport}/${s.port}/${s.protocol}`}>{s.protocol} on {s.transport}/{s.port} · {s.clients} client(s)</li>)}
          </ul>
        </div>
      )}
      <div className="inspector-section">
        <h3>Seen in</h3>
        {d.sightings.length === 0 && <p className="muted" style={{ margin: 0 }}>No capture shows this asset.</p>}
        <ul className="evidence" aria-label="Sightings">
          {d.sightings.map((s) => (
            <li key={`${s.capture_id}-${s.ip}`}>
              <Link to={`/e/${eid}/captures/${s.capture_id}`}>{s.file_name}</Link>
              {s.capture_point && <span className="muted"> · {s.capture_point}</span>}
              <div className="muted mono" style={{ fontSize: 'var(--text-xs)' }}>{s.ip}{s.mac ? ` · ${s.mac}` : ''} · {formatNumber(s.packets)} pkts</div>
            </li>
          ))}
        </ul>
      </div>
      <div className="inspector-section">
        <h3>Traffic</h3>
        <dl className="kv">
          <dt>Packets</dt><dd>{formatNumber(d.packets)} · {formatBytes(d.bytes)}</dd>
          <dt>First seen</dt><dd>{formatDateTime(d.first_seen)}</dd>
          <dt>Last seen</dt><dd>{formatDateTime(d.last_seen)}</dd>
          {d.protocols.length > 0 && <><dt>Protocols</dt><dd>{d.protocols.join(', ')}</dd></>}
        </dl>
      </div>
    </div>
  )
}

function HistoryList({ eid, id, fields }: { eid: number; id: number; fields: AssetFields }) {
  const h = useAssetHistory(eid, id)
  if (h.isPending) return <p className="muted">Loading…</p>
  if (h.isError) return <ErrorNote>{h.error.message}</ErrorNote>
  return (
    <ol className="history" aria-label="Change history">
      {h.data.map((c) => (
        <li key={c.id} className={`history-${c.kind}`}>
          <div>{describeChange(c, fields)}</div>
          {c.reason && <div className="history-reason">“{c.reason}”</div>}
          <div className="muted" style={{ fontSize: 'var(--text-xs)' }} title={formatDateTime(c.at)}>
            {c.kind === 'created' && c.actor.startsWith('capture ') ? 'automatic' : c.actor} · {relativeTime(c.at)}
          </div>
        </li>
      ))}
    </ol>
  )
}

export function AssetInspector({ eid, id, onClose }: { eid: number; id: number; onClose: () => void }) {
  const asset = useAsset(eid, id)
  const fields = useAssetFields()
  const eng = useEngagement(eid)
  const del = useDeleteAsset(eid)
  const [tab, setTab] = useState<Tab>('details')
  const canEdit = eng.data?.my_role === 'lead' || eng.data?.my_role === 'editor'
  const d = asset.data

  return (
    <div aria-label="Asset details">
      <div className="row" style={{ marginBottom: 'var(--space-3)', flexWrap: 'nowrap' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', display: 'flex', alignItems: 'center', gap: 6 }}>
            {d && <DeviceIcon type={d.asset_type} isPrivate={d.is_private} size={18} />}{d ? assetLabel(d) : 'Asset'}</div>
          {d && <div className="muted mono" style={{ fontSize: 'var(--text-xs)' }}>{[...d.ips, ...d.macs].slice(0, 3).join(' · ')}</div>}
        </div>
        {d?.origin === 'manual' && <span className="badge">added by hand</span>}
        <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close asset details" onClick={onClose}><X size={16} /></button>
      </div>
      {asset.isError && <ErrorNote>{asset.error instanceof ApiError && asset.error.status === 404 ? 'This asset no longer exists.' : asset.error.message}</ErrorNote>}
      {fields.isError && <ErrorNote>{fields.error.message}</ErrorNote>}
      {d && fields.data && (
        <>
          <Tabs<Tab> label="Asset sections" value={tab} onChange={setTab} tabs={[
            { id: 'details', label: 'Details' }, { id: 'evidence', label: 'Evidence' }, { id: 'history', label: 'History' },
          ]} />
          {tab === 'details' && <Details key={d.id} d={d} fields={fields.data} canEdit={canEdit} eid={eid} />}
          {tab === 'evidence' && <Evidence d={d} eid={eid} canEdit={canEdit} />}
          {tab === 'history' && <HistoryList eid={eid} id={d.id} fields={fields.data} />}
          {canEdit && d.capture_count === 0 && (
            <div className="inspector-section" style={{ marginTop: 'var(--space-4)' }}>
              <ConfirmButton onConfirm={() => del.mutate(d.id, { onSuccess: onClose })} confirmLabel="Click again to delete">
                Delete asset
              </ConfirmButton>
              {del.isError && <ErrorNote>{del.error.message}</ErrorNote>}
            </div>
          )}
          {tab !== 'history' && (
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setTab('history')} style={{ marginTop: 'var(--space-2)' }}>
              <History size={14} /> Change history
            </button>
          )}
        </>
      )}
    </div>
  )
}
