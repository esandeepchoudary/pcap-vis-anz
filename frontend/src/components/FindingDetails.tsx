import { X } from 'lucide-react'
import { useState } from 'react'
import type { Finding } from '../api/client'
import { useAssets } from '../api/assets'
import { useEngagement } from '../api/engagements'
import { useDeleteFinding, useFindings, useUpdateFinding } from '../api/findings'
import { STATUSES } from '../lib/findings'
import { SEVERITIES } from '../lib/severity'
import { formatDateTime } from '../lib/format'
import { AssetButton } from './LinkDetails'
import { ConfirmButton, ErrorNote, SeverityBadge } from './ui'


function Triage({ f, eid, canEdit }: { f: Finding; eid: number; canEdit: boolean }) {
  const update = useUpdateFinding(eid)
  const del = useDeleteFinding(eid)
  const [notes, setNotes] = useState(f.notes)
  const [rec, setRec] = useState(f.recommendation)
  const [saved, setSaved] = useState({ notes: f.notes, rec: f.recommendation })
  // Follow server changes (another user, or this save) only where the text wasn't edited here.
  if (saved.notes !== f.notes || saved.rec !== f.recommendation) {
    if (notes === saved.notes) setNotes(f.notes)
    if (rec === saved.rec) setRec(f.recommendation)
    setSaved({ notes: f.notes, rec: f.recommendation })
  }
  const dirty = notes !== f.notes || rec !== f.recommendation
  return (
    <div className="stack" style={{ gap: 'var(--space-3)' }}>
      <label className="field"><span>Status</span>
        <select className="select" value={f.status} disabled={!canEdit} onChange={(e) => update.mutate({ key: f.key, status: e.target.value as Finding['status'] })}>
          {STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
      </label>
      <label className="field"><span>Severity{f.detected_severity && f.detected_severity !== f.severity ? ` (detected: ${f.detected_severity})` : ''}</span>
        <select className="select" value={f.severity} disabled={!canEdit}
          onChange={(e) => update.mutate(e.target.value === f.detected_severity
            ? { key: f.key, clear_severity_override: true }
            : { key: f.key, severity_override: e.target.value as Finding['severity'] })}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <label className="row"><input type="checkbox" checked={f.include_in_report} disabled={!canEdit}
        onChange={(e) => update.mutate({ key: f.key, include_in_report: e.target.checked })} /> Include in the report</label>
      <label className="field"><span>Recommendation</span>
        <textarea className="textarea" value={rec} disabled={!canEdit} maxLength={20000} onChange={(e) => setRec(e.target.value)} /></label>
      <label className="field"><span>Analyst notes</span>
        <textarea className="textarea" value={notes} disabled={!canEdit} maxLength={20000} onChange={(e) => setNotes(e.target.value)} /></label>
      {canEdit && dirty && <button type="button" className="btn btn-primary btn-sm" onClick={() => update.mutate({ key: f.key, notes, recommendation: rec })}>Save notes</button>}
      {update.isError && <ErrorNote>{update.error.message}</ErrorNote>}
      {f.updated_by && <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>Last changed by {f.updated_by}{f.updated_at ? `, ${formatDateTime(f.updated_at)}` : ''}</div>}
      {canEdit && f.source === 'manual' && (
        <ConfirmButton onConfirm={() => del.mutate(f.key)} confirmLabel="Click again to delete">Delete finding</ConfirmButton>
      )}
    </div>
  )
}

export function FindingDetails({ eid, findingKey, onClose }: { eid: number; findingKey: string; onClose: () => void }) {
  const list = useFindings(eid)
  const assets = useAssets(eid)
  const eng = useEngagement(eid)
  const f = list.data?.find((x) => x.key === findingKey)
  const byId = new Map((assets.data ?? []).map((a) => [a.id, a]))
  const canEdit = eng.data?.my_role === 'lead' || eng.data?.my_role === 'editor'
  return (
    <div aria-label="Finding details">
      <div className="row" style={{ marginBottom: 'var(--space-3)', flexWrap: 'nowrap', alignItems: 'flex-start' }}>
        <div style={{ flex: 1, minWidth: 0, fontWeight: 700 }}>{f?.title ?? 'Finding'}</div>
        <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close finding details" onClick={onClose}><X size={16} /></button>
      </div>
      {list.isSuccess && !f && <p className="muted">This finding no longer exists.</p>}
      {f && (
        <>
          <div className="inspector-section">
            <div className="row"><SeverityBadge severity={f.severity} /><span className="badge">{f.source === 'manual' ? 'added by hand' : f.rule}</span>
              {f.attack.map((t) => <span key={t} className="badge mono">{t}</span>)}</div>
            {f.description && <p style={{ fontSize: 'var(--text-sm)' }}>{f.description}</p>}
            {f.evidence.length > 0 && <ul className="evidence" aria-label="Finding evidence">{f.evidence.map((e) => <li key={e}>{e}</li>)}</ul>}
            {f.asset_ids.length > 0 && <div className="row" style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-sm)' }}>Assets: {f.asset_ids.map((id) => <AssetButton key={id} a={byId.get(id)} eid={eid} />)}</div>}
            {f.source === 'rule' && <div className="muted" style={{ fontSize: 'var(--text-xs)', marginTop: 'var(--space-2)' }}>
              Seen {f.count}× in {f.captures.length} capture(s) · {formatDateTime(f.first_seen)} – {formatDateTime(f.last_seen)}</div>}
          </div>
          <div className="inspector-section">
            <h3>Triage</h3>
            <Triage key={f.key} f={f} eid={eid} canEdit={canEdit} />
          </div>
        </>
      )}
    </div>
  )
}
