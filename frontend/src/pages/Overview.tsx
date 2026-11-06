import { CheckCircle2, FolderPlus, ScanSearch, XCircle } from 'lucide-react'
import type { SystemInfo } from '../api/client'
import { STAGES } from '../stages'

export function Overview({ system }: { system: SystemInfo }) {
  const t = system.tshark
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Welcome</h1>
          <p>Map OT/ICS networks from packet captures: assets, Purdue levels, zones, and findings.</p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <button className="btn" type="button" disabled title="Arrives in M2">
            <ScanSearch size={16} /> Quick look
          </button>
          <button className="btn btn-primary" type="button" disabled title="Arrives in M2">
            <FolderPlus size={16} /> New engagement
          </button>
        </div>
      </div>

      <div className="grid-2">
        <section className="card" aria-labelledby="sys-h">
          <h2 id="sys-h">System</h2>
          {!t.ok && (
            <div className="alert alert-danger" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
              <XCircle size={16} /> <span>tshark problem: {t.message} Packet analysis won't work until this is fixed.</span>
            </div>
          )}
          <dl className="kv">
            <dt>Version</dt>
            <dd className="mono">v{system.version}</dd>
            <dt>Mode</dt>
            <dd>
              {system.mode === 'server' ? 'Team server' : 'Laptop (single user)'}
            </dd>
            <dt>Packet engine</dt>
            <dd>
              {t.ok ? (
                <span className="badge badge-ok"><CheckCircle2 size={12} /> tshark {t.version}</span>
              ) : (
                <span className="badge badge-danger"><XCircle size={12} /> unavailable</span>
              )}
            </dd>
            {t.path && (
              <>
                <dt>tshark path</dt>
                <dd className="mono">{t.path}</dd>
              </>
            )}
          </dl>
        </section>

        <section className="card" aria-labelledby="road-h">
          <h2 id="road-h">Workflow</h2>
          <ul className="stage-list">
            {STAGES.filter((s) => s.id !== 'overview').map(({ id, label, icon: Icon, milestone, summary }) => (
              <li key={id}>
                <Icon size={16} aria-hidden />
                <span style={{ flex: 1 }}><strong>{label}</strong> <span className="muted">— {summary}</span></span>
                <span className="badge">{milestone}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  )
}
