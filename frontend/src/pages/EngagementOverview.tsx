import { Download, Upload } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useOutletContext } from 'react-router-dom'
import type { Engagement, MemberRole, SystemInfo } from '../api/client'
import {
  exportUrl, useAudit, useCaptures, useDeleteEngagement, useDirectory, useMembers, useSetMember, useUpdateEngagement,
} from '../api/engagements'
import { ConfirmButton, ErrorNote, SeverityBadge, Tile } from '../components/ui'
import { SEVERITIES } from '../lib/severity'
import { formatNumber, relativeTime } from '../lib/format'

const ROLES: MemberRole[] = ['lead', 'editor', 'viewer']

function Settings({ eng }: { eng: Engagement }) {
  const update = useUpdateEngagement(eng.id)
  const del = useDeleteEngagement(eng.id)
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: eng.name, client: eng.client, site: eng.site, description: eng.description })
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [k]: e.target.value }))
  const submit = (e: FormEvent) => { e.preventDefault(); update.mutate(form) }
  return (
    <form className="card stack" onSubmit={submit} aria-label="Engagement settings">
      <h2 className="section-title">Settings</h2>
      <div className="form-grid">
        <label className="field"><span>Name</span><input className="input" required value={form.name} onChange={set('name')} /></label>
        <label className="field"><span>Client</span><input className="input" value={form.client} onChange={set('client')} /></label>
        <label className="field"><span>Site</span><input className="input" value={form.site} onChange={set('site')} /></label>
      </div>
      <label className="field"><span>Description</span><textarea className="textarea" value={form.description} onChange={set('description')} /></label>
      {(update.isError || del.isError) && <ErrorNote>{(update.error ?? del.error)?.message}</ErrorNote>}
      <div className="row">
        <button className="btn btn-primary" type="submit" disabled={update.isPending}>Save</button>
        {eng.is_quicklook && (
          <button className="btn" type="button" onClick={() => update.mutate({ is_quicklook: false })}>Keep as engagement</button>
        )}
        <span className="spacer" />
        {!eng.is_quicklook && (
          <button className="btn" type="button"
            onClick={() => update.mutate({ status: eng.status === 'archived' ? 'active' : 'archived' })}>
            {eng.status === 'archived' ? 'Unarchive' : 'Archive'}
          </button>
        )}
        <ConfirmButton className="btn" confirmLabel="Delete everything?"
          onConfirm={() => del.mutate(undefined, { onSuccess: () => navigate('/') })}>
          Delete engagement
        </ConfirmButton>
      </div>
    </form>
  )
}

function Members({ eng, system }: { eng: Engagement; system: SystemInfo }) {
  const members = useMembers(eng.id)
  const isLead = eng.my_role === 'lead'
  const directory = useDirectory(isLead && system.auth_required)
  const setMember = useSetMember(eng.id)
  const [adding, setAdding] = useState({ userId: '', role: 'editor' as MemberRole })
  const memberIds = new Set((members.data ?? []).map((m) => m.user_id))
  const candidates = (directory.data ?? []).filter((u) => !memberIds.has(u.id))
  return (
    <section className="card" aria-labelledby="members-h">
      <h2 id="members-h" className="section-title">Members</h2>
      <table className="table">
        <tbody>
          {(members.data ?? []).map((m) => (
            <tr key={m.user_id}>
              <td><strong>{m.display_name}</strong> <span className="muted mono">{m.username}</span></td>
              <td>
                {isLead ? (
                  <select className="select" aria-label={`Role for ${m.username}`} value={m.role}
                    onChange={(e) => setMember.mutate({ userId: m.user_id, role: e.target.value as MemberRole })}>
                    {ROLES.map((r) => <option key={r} value={r} disabled={ROLES.indexOf(r) < ROLES.indexOf(m.max_role)}>{r}</option>)}
                  </select>
                ) : <span className="badge">{m.role}</span>}
              </td>
              <td>{isLead && <ConfirmButton onConfirm={() => setMember.mutate({ userId: m.user_id, role: null })}>Remove</ConfirmButton>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {isLead && candidates.length > 0 && (
        <div className="row" style={{ marginTop: 'var(--space-3)' }}>
          <select className="select" aria-label="User to add" value={adding.userId}
            onChange={(e) => setAdding((a) => ({ ...a, userId: e.target.value }))}>
            <option value="">Add a member…</option>
            {candidates.map((u) => <option key={u.id} value={u.id}>{u.display_name} ({u.role})</option>)}
          </select>
          <select className="select" aria-label="Role for new member" value={adding.role}
            onChange={(e) => setAdding((a) => ({ ...a, role: e.target.value as MemberRole }))}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="btn" type="button" disabled={!adding.userId}
            onClick={() => setMember.mutate({ userId: Number(adding.userId), role: adding.role },
              { onSuccess: () => setAdding((a) => ({ ...a, userId: '' })) })}>Add</button>
        </div>
      )}
      {setMember.isError && <ErrorNote>{setMember.error.message}</ErrorNote>}
    </section>
  )
}

export function EngagementOverview({ system }: { system: SystemInfo }) {
  const eng = useOutletContext<Engagement>()
  const captures = useCaptures(eng.id)
  const audit = useAudit(eng.id)
  const [withCaptures, setWithCaptures] = useState(true)
  const done = (captures.data ?? []).filter((c) => c.status === 'done')
  const total = (key: string) => done.reduce((n, c) => n + Number((c.summary as Record<string, number> | null)?.[key] ?? 0), 0)
  const findings = Object.fromEntries(SEVERITIES.map((s) => [s, done.reduce(
    (n, c) => n + Number(((c.summary as { findings?: Record<string, number> } | null)?.findings ?? {})[s] ?? 0), 0)]))
  const canEdit = eng.my_role !== 'viewer'

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>{eng.name}</h1>
          <p>{[eng.client, eng.site].filter(Boolean).join(' · ') || (eng.is_quicklook ? 'Quick look' : 'No client or site set')}</p>
          {eng.description && <p className="muted" style={{ whiteSpace: 'pre-wrap' }}>{eng.description}</p>}
        </div>
        <div className="row">
          {canEdit && <Link className="btn btn-primary" to={`/e/${eng.id}/captures`}><Upload size={16} /> Add captures</Link>}
        </div>
      </div>
      <div className="stack">
        <div className="tiles" aria-label="Engagement totals">
          <Tile label="Captures analysed" value={`${done.length} / ${captures.data?.length ?? 0}`} />
          <Tile label="Packets" value={formatNumber(total('packets'))} />
          <Tile label="Hosts (sum)" value={formatNumber(total('hosts'))} />
          <Tile label="OT writes" value={formatNumber(total('ot_writes'))} tone={total('ot_writes') ? 'warn' : undefined} />
          <Tile label="Credentials" value={formatNumber(total('credentials'))} tone={total('credentials') ? 'danger' : undefined} />
        </div>
        <div className="row">{SEVERITIES.map((s) => findings[s] > 0 && <SeverityBadge key={s} severity={s} count={findings[s]} />)}</div>
        <p className="muted" style={{ margin: 0, fontSize: 'var(--text-sm)' }}>
          Totals add up per capture. The merged asset inventory across captures arrives in M3.
        </p>

        <section className="card" aria-labelledby="export-h">
          <h2 id="export-h" className="section-title">Export</h2>
          <p className="muted" style={{ marginTop: 0 }}>A single .pcapvis file with this engagement's data, for handover or for importing on another machine.</p>
          <div className="row">
            <label className="row"><input type="checkbox" checked={withCaptures} onChange={(e) => setWithCaptures(e.target.checked)} /> Include original captures</label>
            <a className="btn" href={exportUrl(eng.id, withCaptures, true)} download><Download size={16} /> Export .pcapvis</a>
          </div>
        </section>

        {system.auth_required && !eng.is_quicklook && <Members eng={eng} system={system} />}
        {eng.my_role === 'lead' && <Settings key={eng.revision} eng={eng} />}

        <section className="card" aria-labelledby="activity-h">
          <h2 id="activity-h" className="section-title">Activity</h2>
          <ul className="stage-list">
            {(audit.data ?? []).slice(0, 12).map((a) => (
              <li key={a.id}>
                <span className="mono muted" style={{ minWidth: 90 }}>{relativeTime(a.at)}</span>
                <span style={{ flex: 1 }}><strong>{a.user ?? 'system'}</strong> {a.action.replace('.', ' ')} <span className="muted">{a.target}</span></span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  )
}
