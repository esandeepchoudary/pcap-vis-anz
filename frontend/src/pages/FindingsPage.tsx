import { Plus } from 'lucide-react'
import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { Engagement, Finding } from '../api/client'
import { useCreateFinding, useFindings } from '../api/findings'
import { ErrorNote, SeverityBadge } from '../components/ui'
import { useInspector } from '../inspector/context'
import { STATUSES } from '../lib/findings'
import { SEVERITIES } from '../lib/severity'
import { formatNumber } from '../lib/format'

function AddFinding({ eid, onDone }: { eid: number; onDone: (key: string) => void }) {
  const create = useCreateFinding(eid)
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<Finding['severity']>('medium')
  const [description, setDescription] = useState('')
  const [recommendation, setRecommendation] = useState('')
  return (
    <form className="card stack" aria-label="Add finding" onSubmit={(e) => {
      e.preventDefault()
      create.mutate({ title, severity, description, recommendation }, { onSuccess: (f) => onDone(f.key) })
    }}>
      <h2 style={{ margin: 0 }}>Add a finding</h2>
      <div className="form-grid">
        <label className="field"><span>Title</span><input className="input" required maxLength={300} value={title} onChange={(e) => setTitle(e.target.value)} /></label>
        <label className="field"><span>Severity</span>
          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value as Finding['severity'])}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select></label>
      </div>
      <label className="field"><span>Description</span><textarea className="textarea" value={description} onChange={(e) => setDescription(e.target.value)} /></label>
      <label className="field"><span>Recommendation</span><textarea className="textarea" value={recommendation} onChange={(e) => setRecommendation(e.target.value)} /></label>
      {create.isError && <ErrorNote>{create.error.message}</ErrorNote>}
      <div className="row"><button type="submit" className="btn btn-primary" disabled={create.isPending || !title.trim()}>Add finding</button></div>
    </form>
  )
}

export function FindingsPage() {
  const eng = useOutletContext<Engagement>()
  const findings = useFindings(eng.id)
  const { selection, select } = useInspector()
  const canEdit = eng.my_role === 'lead' || eng.my_role === 'editor'
  const [sev, setSev] = useState('all')
  const [status, setStatus] = useState('all')
  const [q, setQ] = useState('')
  const [adding, setAdding] = useState(false)
  const all = findings.data ?? []
  const needle = q.trim().toLowerCase()
  const rows = all.filter((f) => (sev === 'all' || f.severity === sev) && (status === 'all' || f.status === status)
    && (!needle || `${f.title} ${f.description} ${f.rule ?? ''} ${f.attack.join(' ')}`.toLowerCase().includes(needle)))
  const open = (key: string) => select({ kind: 'finding', eid: eng.id, key })
  const reported = all.filter((f) => f.include_in_report).length
  return (
    <div className="page" style={{ maxWidth: 'none' }}>
      <div className="page-head">
        <div>
          <h1>Findings</h1>
          <p>{all.length} finding{all.length === 1 ? '' : 's'} across all captures · {reported} in the report</p>
        </div>
        {canEdit && <button type="button" className="btn" onClick={() => setAdding((v) => !v)}><Plus size={14} /> Add finding</button>}
      </div>
      {findings.isError && <ErrorNote>{findings.error.message}</ErrorNote>}
      {adding && <AddFinding eid={eng.id} onDone={(k) => { setAdding(false); open(k) }} />}
      <div className="stack">
        <div className="row">
          <input className="input" placeholder="Search title, rule, ATT&CK id…" aria-label="Search findings" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 280 }} />
          <select className="select" aria-label="Filter by severity" value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="all">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="select" aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="all">All statuses</option>{STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
          <span className="muted">{rows.length} shown</span>
        </div>
        <div className="table-wrap">
          <table className="table" aria-label="Findings">
            <thead><tr><th>Severity</th><th>Finding</th><th>Status</th><th className="num">Seen</th><th>ATT&amp;CK</th><th>Report</th></tr></thead>
            <tbody>{rows.map((f) => (
              <tr key={f.key} className={`clickable${selection?.kind === 'finding' && selection.key === f.key ? ' selected' : ''}`} tabIndex={0}
                onClick={() => open(f.key)} onKeyDown={(e) => { if (e.key === 'Enter') open(f.key) }}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><strong>{f.title}</strong>{f.source === 'manual' && <span className="badge" style={{ marginLeft: 6 }}>manual</span>}
                  <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>{f.description.slice(0, 140)}{f.description.length > 140 ? '…' : ''}</div></td>
                <td>{STATUSES.find((s) => s.id === f.status)?.label}</td>
                <td className="num">{f.source === 'rule' ? formatNumber(f.count) : '—'}</td>
                <td className="mono" style={{ fontSize: 'var(--text-xs)' }}>{f.attack.join(', ')}</td>
                <td>{f.include_in_report ? 'yes' : <span className="muted">no</span>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        {findings.isSuccess && !all.length && <p className="muted">No findings yet. Rule findings appear as captures are analysed; add your own with "Add finding".</p>}
      </div>
    </div>
  )
}
