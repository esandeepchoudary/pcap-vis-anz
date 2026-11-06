import { ArrowLeft, Download, Eye, EyeOff } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useOutletContext, useParams } from 'react-router-dom'
import type { AnalysisResult, Engagement } from '../api/client'
import { fileDownloadUrl, useCaptureResult, useCaptures } from '../api/engagements'
import { ErrorNote, ProgressBar, SeverityBadge, StatusBadge, Tabs, Tile } from '../components/ui'
import { SEVERITIES } from '../lib/severity'
import { useInspector } from '../inspector/context'
import { formatBytes, formatDuration, formatNumber, purdueLabel } from '../lib/format'

type Tab = 'findings' | 'hosts' | 'ot' | 'credentials' | 'files'

function Findings({ r }: { r: AnalysisResult }) {
  const [sev, setSev] = useState<string>('all')
  const shown = r.anomalies.filter((a) => sev === 'all' || a.severity === sev)
  return (
    <div className="stack">
      <div className="row">
        <select className="select" aria-label="Filter findings by severity" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="muted">{shown.length} finding{shown.length === 1 ? '' : 's'}</span>
      </div>
      {shown.map((a) => (
        <article key={a.id} className={`finding ${a.severity}`} aria-label={a.title}>
          <div className="row">
            <SeverityBadge severity={a.severity} />
            <span className="finding-title">{a.title}</span>
            <span className="spacer" />
            {a.count > 1 && <span className="badge">×{a.count}</span>}
            {a.attack.map((t) => <span key={t} className="badge mono" title="MITRE ATT&CK technique">{t}</span>)}
          </div>
          <div>{a.description}</div>
          {a.evidence.length > 0 && <ul>{a.evidence.map((e) => <li key={e}>{e}</li>)}</ul>}
        </article>
      ))}
      {r.anomalies.length === 0 && <p className="muted">No findings in this capture.</p>}
    </div>
  )
}

function Hosts({ r }: { r: AnalysisResult }) {
  const [q, setQ] = useState('')
  const { selection, select } = useInspector()
  const needle = q.trim().toLowerCase()
  const shown = r.hosts.filter((h) => !needle || [h.ip, h.hostname, h.host_type, h.mac_vendor, h.mac, ...h.protocols]
    .some((v) => v?.toLowerCase().includes(needle)))
  return (
    <div className="stack">
      <input className="input" placeholder="Filter by IP, name, type, vendor, protocol…" aria-label="Filter hosts"
        value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 420 }} />
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Address</th><th>Type</th><th>Purdue</th><th>Vendor</th><th>Protocols</th><th className="num">Packets</th></tr></thead>
          <tbody>
            {shown.map((h) => (
              <tr key={h.ip} className={`clickable${selection?.kind === 'host' && selection.host.ip === h.ip ? ' selected' : ''}`}
                onClick={() => select({ kind: 'host', host: h })} tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter') select({ kind: 'host', host: h }) }}>
                <td><span className="mono">{h.ip}</span>{h.hostname && <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>{h.hostname}</div>}</td>
                <td>{h.host_type}{' '}<span className={`badge ${h.host_type_confidence === 'high' ? 'badge-ok' : h.host_type_confidence === 'medium' ? 'badge-warn' : ''}`}>{h.host_type_confidence}</span></td>
                <td>{purdueLabel(h.purdue_level)}</td>
                <td>{h.mac_vendor ?? '—'}</td>
                <td className="muted" style={{ maxWidth: 260 }}>{h.protocols.slice(0, 6).join(', ')}{h.protocols.length > 6 ? '…' : ''}</td>
                <td className="num">{formatNumber(h.packets_sent + h.packets_recv)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted" style={{ fontSize: 'var(--text-sm)' }}>Select a host to see the evidence behind its classification.</p>
    </div>
  )
}

function OtCommands({ r }: { r: AnalysisResult }) {
  const rows = useMemo(() => {
    const m = new Map<string, { src: string; dst: string; protocol: string; function: string; kind: string; count: number }>()
    for (const c of r.ot_commands) {
      if (!c.is_request && c.kind !== 'error') continue
      const key = `${c.src}|${c.dst}|${c.protocol}|${c.function}|${c.kind}`
      const row = m.get(key) ?? { src: c.src, dst: c.dst, protocol: c.protocol, function: c.function, kind: c.kind, count: 0 }
      row.count++
      m.set(key, row)
    }
    return [...m.values()].sort((a, b) => (a.kind === 'write' ? -1 : 0) - (b.kind === 'write' ? -1 : 0) || b.count - a.count)
  }, [r])
  if (!rows.length) return <p className="muted">No OT commands in this capture.</p>
  return (
    <div className="table-wrap">
      <table className="table" aria-label="OT commands">
        <thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Function</th><th>Kind</th><th className="num">Count</th></tr></thead>
        <tbody>{rows.map((x) => (
          <tr key={`${x.src}${x.dst}${x.protocol}${x.function}${x.kind}`}>
            <td className="mono">{x.src}</td><td className="mono">{x.dst}</td><td>{x.protocol}</td><td>{x.function}</td>
            <td><span className={`badge ${x.kind === 'write' ? 'badge-danger' : x.kind === 'error' ? 'badge-warn' : ''}`}>{x.kind}</span></td>
            <td className="num">{formatNumber(x.count)}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

function Credentials({ r }: { r: AnalysisResult }) {
  const [reveal, setReveal] = useState(false)
  if (!r.credentials.length) return <p className="muted">No cleartext credentials in this capture.</p>
  return (
    <div className="stack">
      <div className="row">
        <button className="btn btn-sm" type="button" onClick={() => setReveal((v) => !v)}>
          {reveal ? <><EyeOff size={14} /> Hide secrets</> : <><Eye size={14} /> Reveal secrets</>}
        </button>
        <span className="muted" style={{ fontSize: 'var(--text-sm)' }}>Handle per your engagement's data-handling rules.</span>
      </div>
      <table className="table" aria-label="Credentials">
        <thead><tr><th>Protocol</th><th>Client → server</th><th>User</th><th>Secret</th><th className="num">Seen</th></tr></thead>
        <tbody>{r.credentials.map((c) => (
          <tr key={`${c.protocol}${c.client}${c.server}${c.username}${c.secret}`}>
            <td>{c.protocol} <span className="muted">{c.kind.replace('_', ' ')}</span></td>
            <td className="mono">{c.client} → {c.server}:{c.server_port}</td>
            <td>{c.username ?? '—'}</td>
            <td className={`mono${reveal ? '' : ' masked'}`} aria-label={reveal ? undefined : 'hidden secret'}>{c.secret ?? '—'}</td>
            <td className="num">{c.count}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

function Files({ r, eid }: { r: AnalysisResult; eid: number }) {
  if (!r.files.length) return <p className="muted">No files were transferred in this capture.</p>
  return (
    <table className="table" aria-label="Files">
      <thead><tr><th>File</th><th>Protocol</th><th>Type</th><th className="num">Size</th><th>SHA-256</th><th /></tr></thead>
      <tbody>{r.files.map((f) => (
        <tr key={`${f.sha256}${f.filename}`}>
          <td>{f.filename} {f.interesting && <span className="badge badge-warn">review</span>}<div className="muted" style={{ fontSize: 'var(--text-xs)' }}>{f.source_url}</div></td>
          <td>{f.protocol}</td><td>{f.mime}</td><td className="num">{formatBytes(f.size)}</td>
          <td className="mono" style={{ fontSize: 'var(--text-xs)' }}>{f.sha256.slice(0, 16)}…</td>
          <td><a className="btn btn-ghost btn-sm" href={fileDownloadUrl(eid, f.sha256, f.filename)} aria-label={`Download ${f.filename}`}><Download size={14} /></a></td>
        </tr>
      ))}</tbody>
    </table>
  )
}

export function CaptureReport() {
  const eng = useOutletContext<Engagement>()
  const cid = Number(useParams().cid)
  const captures = useCaptures(eng.id)
  const cap = captures.data?.find((c) => c.id === cid)
  const result = useCaptureResult(eng.id, cid, cap?.status === 'done', cap?.finished_at ?? '')
  const [tab, setTab] = useState<Tab>('findings')
  const r = result.data

  return (
    <div className="page" style={{ maxWidth: 1400 }}>
      <Link to={`/e/${eng.id}/captures`} className="row muted" style={{ textDecoration: 'none', marginBottom: 'var(--space-3)' }}>
        <ArrowLeft size={14} /> Captures
      </Link>
      {captures.isSuccess && !cap && <ErrorNote>Capture not found.</ErrorNote>}
      {cap && (
        <div className="page-head">
          <div>
            <h1>{cap.file_name}</h1>
            <p>{cap.capture_point ?? 'No capture point'} · {formatBytes(cap.size)}</p>
          </div>
          <StatusBadge status={cap.status} />
        </div>
      )}
      {cap && cap.status !== 'done' && (
        <div className="card stack">
          {cap.status === 'processing' && <><span>Analysing… {Math.round(cap.progress * 100)}%</span><ProgressBar value={cap.progress} label="Analysis progress" /></>}
          {cap.status === 'queued' && <span>Waiting in the analysis queue…</span>}
          {cap.status === 'failed' && <ErrorNote>{cap.error}</ErrorNote>}
          {cap.status === 'cancelled' && <span className="muted">The analysis was cancelled. Re-analyse it from the Captures list.</span>}
        </div>
      )}
      {result.isError && <ErrorNote>{result.error.message}</ErrorNote>}
      {r && (
        <div className="stack">
          <div className="tiles" aria-label="Capture summary">
            <Tile label="Packets" value={formatNumber(r.capture.packets)} />
            <Tile label="Duration" value={formatDuration(r.capture.first_seen != null && r.capture.last_seen != null ? r.capture.last_seen - r.capture.first_seen : null)} />
            <Tile label="Hosts" value={formatNumber(r.hosts.length)} />
            <Tile label="Flows" value={formatNumber(r.flows.length)} />
            <Tile label="OT writes" value={formatNumber(r.ot_commands.filter((c) => c.is_request && c.kind === 'write').length)}
              tone={r.ot_commands.some((c) => c.kind === 'write') ? 'warn' : undefined} />
            <Tile label="Credentials" value={formatNumber(r.credentials.length)} tone={r.credentials.length ? 'danger' : undefined} />
          </div>
          {r.capture.truncated && <div className="alert alert-warn" role="status">Analysis stopped at the packet limit; the rest of the capture was not analysed.</div>}
          <Tabs<Tab> label="Report sections" value={tab} onChange={setTab} tabs={[
            { id: 'findings', label: 'Findings', count: r.anomalies.length },
            { id: 'hosts', label: 'Hosts', count: r.hosts.length },
            { id: 'ot', label: 'OT commands', count: r.ot_commands.length },
            { id: 'credentials', label: 'Credentials', count: r.credentials.length },
            { id: 'files', label: 'Files', count: r.files.length },
          ]} />
          {tab === 'findings' && <Findings r={r} />}
          {tab === 'hosts' && <Hosts r={r} />}
          {tab === 'ot' && <OtCommands r={r} />}
          {tab === 'credentials' && <Credentials r={r} />}
          {tab === 'files' && <Files r={r} eid={eng.id} />}
        </div>
      )}
    </div>
  )
}
