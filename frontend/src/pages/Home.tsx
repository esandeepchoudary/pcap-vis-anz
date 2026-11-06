import { CheckCircle2, FileUp, FolderPlus, ScanSearch, XCircle } from 'lucide-react'
import { useRef, useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import type { SystemInfo, User } from '../api/client'
import { importEngagement, useCreateEngagement, useEngagements } from '../api/engagements'
import { ErrorNote, ProgressBar } from '../components/ui'
import { relativeTime } from '../lib/format'
import { useQueryClient } from '@tanstack/react-query'

function canCreate(system: SystemInfo, user: User) {
  return !system.auth_required || user.role === 'admin' || user.role === 'lead'
}

function NewEngagementForm({ onDone }: { onDone: () => void }) {
  const create = useCreateEngagement()
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', client: '', site: '', description: '' })
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [k]: e.target.value }))
  const submit = (e: FormEvent) => {
    e.preventDefault()
    create.mutate(form, { onSuccess: (eng) => { onDone(); navigate(`/e/${eng.id}/captures`) } })
  }
  return (
    <form className="card stack" onSubmit={submit} aria-label="New engagement">
      <h2 className="section-title">New engagement</h2>
      <div className="form-grid">
        <label className="field"><span>Name</span><input className="input" required autoFocus value={form.name} onChange={set('name')} placeholder="ACME Plant 3 OT assessment" /></label>
        <label className="field"><span>Client</span><input className="input" value={form.client} onChange={set('client')} /></label>
        <label className="field"><span>Site</span><input className="input" value={form.site} onChange={set('site')} /></label>
      </div>
      <label className="field"><span>Description</span><textarea className="textarea" value={form.description} onChange={set('description')} placeholder="Scope, dates, contacts…" /></label>
      {create.isError && <ErrorNote>{create.error.message}</ErrorNote>}
      <div className="row">
        <button className="btn btn-primary" type="submit" disabled={create.isPending}>Create engagement</button>
        <button className="btn btn-ghost" type="button" onClick={onDone}>Cancel</button>
      </div>
    </form>
  )
}

function ImportButton() {
  const input = useRef<HTMLInputElement>(null)
  const [progress, setProgress] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const qc = useQueryClient()
  const onFile = async (file: File) => {
    setError(null)
    setProgress(0)
    try {
      const eng = await importEngagement(file, setProgress)
      await qc.invalidateQueries({ queryKey: ['engagements'] })
      navigate(`/e/${eng.id}/overview`)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setProgress(null)
    }
  }
  return (
    <>
      <button className="btn" type="button" onClick={() => input.current?.click()} disabled={progress !== null}>
        <FileUp size={16} /> Import .pcapvis
      </button>
      <input ref={input} type="file" accept=".pcapvis,.zip" hidden data-testid="import-input"
        onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void onFile(f) }} />
      {progress !== null && <div style={{ width: 160 }}><ProgressBar value={progress} label="Import progress" /></div>}
      {error && <div style={{ flexBasis: '100%' }}><ErrorNote>Import failed: {error}</ErrorNote></div>}
    </>
  )
}

export function Home({ system, user }: { system: SystemInfo; user: User }) {
  const [params, setParams] = useSearchParams()
  const [showArchived, setShowArchived] = useState(false)
  const engagements = useEngagements(false, showArchived)
  const quicklooks = useEngagements(true)
  const creating = params.get('new') === '1'
  const mayCreate = canCreate(system, user)
  const t = system.tshark

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Engagements</h1>
          <p>Each engagement holds a site's captures, assets, findings and deliverables.</p>
        </div>
        <div className="row">
          <Link className="btn" to="/quicklook"><ScanSearch size={16} /> Quick look</Link>
          {mayCreate && <ImportButton />}
          {mayCreate && (
            <button className="btn btn-primary" type="button" onClick={() => setParams({ new: '1' })}>
              <FolderPlus size={16} /> New engagement
            </button>
          )}
        </div>
      </div>

      <div className="stack">
        {creating && mayCreate && <NewEngagementForm onDone={() => setParams({})} />}
        {!t.ok && <ErrorNote>tshark problem: {t.message} Packet analysis won't work until this is fixed.</ErrorNote>}

        {engagements.isError && <ErrorNote>{engagements.error.message}</ErrorNote>}
        {engagements.data && engagements.data.length === 0 && !creating && (
          <div className="card empty">
            <FolderPlus size={36} strokeWidth={1.5} aria-hidden />
            <strong>No engagements yet</strong>
            <span>{mayCreate ? 'Create one for a site assessment, or start a Quick look to analyse a single capture.'
              : 'Ask a lead to add you to an engagement, or start a Quick look.'}</span>
          </div>
        )}
        {engagements.data && engagements.data.length > 0 && (
          <div className="eng-grid" aria-label="Engagement list">
            {engagements.data.map((e) => (
              <Link key={e.id} to={`/e/${e.id}/overview`} className="card eng-card">
                <div className="row">
                  <h3 style={{ flex: 1 }}>{e.name}</h3>
                  {e.status === 'archived' && <span className="badge">Archived</span>}
                </div>
                <div className="muted">{[e.client, e.site].filter(Boolean).join(' · ') || 'No client or site set'}</div>
                <div className="row muted" style={{ fontSize: 'var(--text-xs)' }}>
                  <span>{e.capture_count} capture{e.capture_count === 1 ? '' : 's'}</span>
                  {system.auth_required && <span>· {e.member_count} member{e.member_count === 1 ? '' : 's'}</span>}
                  <span>· updated {relativeTime(e.updated_at)}</span>
                  <span className="spacer" />
                  <span className="badge">{e.my_role}</span>
                </div>
              </Link>
            ))}
          </div>
        )}
        <label className="row muted" style={{ fontSize: 'var(--text-sm)' }}>
          <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} /> Show archived
        </label>

        {quicklooks.data && quicklooks.data.length > 0 && (
          <section className="card" aria-labelledby="ql-h">
            <h2 id="ql-h" className="section-title">Your Quick looks</h2>
            <ul className="stage-list">
              {quicklooks.data.map((q) => (
                <li key={q.id}>
                  <ScanSearch size={16} aria-hidden />
                  <Link to={`/e/${q.id}/captures`} style={{ flex: 1 }}>{q.name}</Link>
                  <span className="muted">{relativeTime(q.created_at)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="card" aria-labelledby="sys-h">
          <h2 id="sys-h" className="section-title">System</h2>
          <dl className="kv">
            <dt>Version</dt><dd className="mono">v{system.version}</dd>
            <dt>Mode</dt><dd>{system.mode === 'server' ? 'Team server' : 'Laptop (single user)'}</dd>
            <dt>Packet engine</dt>
            <dd>{t.ok
              ? <span className="badge badge-ok"><CheckCircle2 size={12} /> tshark {t.version}</span>
              : <span className="badge badge-danger"><XCircle size={12} /> unavailable</span>}</dd>
          </dl>
        </section>
      </div>
    </div>
  )
}
