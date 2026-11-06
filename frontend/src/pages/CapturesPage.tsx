import { Download, FileSearch, Pencil, Plus, RotateCcw, Square, Trash2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import type { Capture, CapturePoint, Engagement } from '../api/client'
import {
  captureDownloadUrl, uploadCaptures, useCaptureAction, useCapturePoints, useCaptures, useDeleteCapturePoint,
  useSaveCapturePoint,
} from '../api/engagements'
import { ConfirmButton, Dropzone, ErrorNote, ProgressBar, SeverityBadge, StatusBadge } from '../components/ui'
import { SEVERITIES } from '../lib/severity'
import { formatBytes, formatNumber, relativeTime } from '../lib/format'
import { useQueryClient } from '@tanstack/react-query'

type Findings = Record<string, number>

function PointEditor({ eid, point, onDone }: { eid: number; point?: CapturePoint; onDone: () => void }) {
  const save = useSaveCapturePoint(eid)
  const [name, setName] = useState(point?.name ?? '')
  const [description, setDescription] = useState(point?.description ?? '')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate({ id: point?.id, name, description }, { onSuccess: onDone })
  }
  return (
    <form className="row" onSubmit={submit} aria-label={point ? `Edit ${point.name}` : 'New capture point'}>
      <input className="input" aria-label="Capture point name" required placeholder="e.g. Core switch SPAN Gi0/24"
        value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      <input className="input" aria-label="Capture point description" placeholder="Where / what it sees"
        value={description} onChange={(e) => setDescription(e.target.value)} style={{ flex: 1 }} />
      <button className="btn btn-primary btn-sm" type="submit" disabled={save.isPending}>Save</button>
      <button className="btn btn-ghost btn-sm" type="button" onClick={onDone}>Cancel</button>
      {save.isError && <div style={{ flexBasis: '100%' }}><ErrorNote>{save.error.message}</ErrorNote></div>}
    </form>
  )
}

function CapturePoints({ eng }: { eng: Engagement }) {
  const points = useCapturePoints(eng.id)
  const del = useDeleteCapturePoint(eng.id)
  const [editing, setEditing] = useState<number | 'new' | null>(null)
  const canEdit = eng.my_role !== 'viewer'
  return (
    <section className="card" aria-labelledby="points-h">
      <div className="row">
        <h2 id="points-h" className="section-title" style={{ margin: 0, flex: 1 }}>Capture points</h2>
        {canEdit && editing === null && (
          <button className="btn btn-sm" type="button" onClick={() => setEditing('new')}><Plus size={14} /> Add</button>
        )}
      </div>
      <p className="muted" style={{ fontSize: 'var(--text-sm)' }}>Where each capture was taken: a SPAN port, a TAP, a segment.</p>
      <ul className="stage-list">
        {(points.data ?? []).map((p) => editing === p.id ? (
          <li key={p.id}><PointEditor eid={eng.id} point={p} onDone={() => setEditing(null)} /></li>
        ) : (
          <li key={p.id}>
            <strong>{p.name}</strong><span className="muted" style={{ flex: 1 }}>{p.description}</span>
            {canEdit && <>
              <button className="btn btn-ghost btn-icon btn-sm" type="button" aria-label={`Edit ${p.name}`} onClick={() => setEditing(p.id)}><Pencil size={14} /></button>
              <ConfirmButton className="btn btn-ghost btn-sm" confirmLabel="Delete?" onConfirm={() => del.mutate(p.id)}>
                <Trash2 size={14} aria-label={`Delete ${p.name}`} />
              </ConfirmButton>
            </>}
          </li>
        ))}
        {editing === 'new' && <li><PointEditor eid={eng.id} onDone={() => setEditing(null)} /></li>}
        {points.data?.length === 0 && editing !== 'new' && <li className="muted">None yet.</li>}
      </ul>
    </section>
  )
}

function Uploader({ eng }: { eng: Engagement }) {
  const points = useCapturePoints(eng.id)
  const qc = useQueryClient()
  const [pointId, setPointId] = useState<number | null>(null)
  const [progress, setProgress] = useState<number | null>(null)
  const [notes, setNotes] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const onFiles = async (files: File[]) => {
    setError(null)
    setNotes([])
    setProgress(0)
    try {
      const res = await uploadCaptures(eng.id, files, pointId, setProgress)
      setNotes(res.filter((r) => r.duplicate).map((r) => `${r.capture.file_name} was already uploaded; skipped.`))
      await qc.invalidateQueries({ queryKey: ['engagement', eng.id] })
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setProgress(null)
    }
  }
  return (
    <section className="card stack" aria-labelledby="upload-h">
      <div className="row">
        <h2 id="upload-h" className="section-title" style={{ margin: 0, flex: 1 }}>Add captures</h2>
        <label className="row" style={{ fontSize: 'var(--text-sm)' }}>
          <span className="muted">Capture point</span>
          <select className="select" aria-label="Capture point for upload" value={pointId ?? ''}
            onChange={(e) => setPointId(e.target.value ? Number(e.target.value) : null)}>
            <option value="">Not set</option>
            {(points.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
      </div>
      <Dropzone onFiles={(f) => void onFiles(f)} disabled={progress !== null}>
        Drop .pcap, .pcapng or .cap files here. They are analysed in the background.
      </Dropzone>
      {progress !== null && (
        <div className="row"><span className="muted">Uploading {Math.round(progress * 100)}%</span><div style={{ flex: 1 }}><ProgressBar value={progress} label="Upload progress" /></div></div>
      )}
      {notes.map((n) => <div key={n} className="alert alert-warn" role="status">{n}</div>)}
      {error && <ErrorNote>{error}</ErrorNote>}
    </section>
  )
}

function CaptureRow({ eng, c, points }: { eng: Engagement; c: Capture; points: CapturePoint[] }) {
  const act = useCaptureAction(eng.id)
  const canEdit = eng.my_role !== 'viewer'
  const s = c.summary as { packets?: number; hosts?: number; findings?: Findings } | null
  const busy = c.status === 'queued' || c.status === 'processing'
  return (
    <tr>
      <td>
        {c.status === 'done'
          ? <Link to={`/e/${eng.id}/captures/${c.id}`}><strong>{c.file_name}</strong></Link>
          : <strong>{c.file_name}</strong>}
        <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>
          {formatBytes(c.size)} · {c.uploaded_by ?? '—'} · {relativeTime(c.uploaded_at)}
        </div>
      </td>
      <td>
        {canEdit ? (
          <select className="select" aria-label={`Capture point for ${c.file_name}`} value={c.capture_point_id ?? ''}
            onChange={(e) => act.mutate({ cid: c.id, action: { capture_point_id: e.target.value ? Number(e.target.value) : null } })}>
            <option value="">Not set</option>
            {points.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        ) : (c.capture_point ?? '—')}
      </td>
      <td>
        <StatusBadge status={c.status} />
        {c.status === 'processing' && <div style={{ marginTop: 4 }}><ProgressBar value={c.progress} label={`Analysis of ${c.file_name}`} /></div>}
        {c.error && <div className="muted" style={{ fontSize: 'var(--text-xs)', maxWidth: 260 }}>{c.error}</div>}
      </td>
      <td className="num">{formatNumber(s?.packets)}</td>
      <td className="num">{formatNumber(s?.hosts)}</td>
      <td>
        <div className="chips">
          {s?.findings && SEVERITIES.filter((k) => (s.findings?.[k] ?? 0) > 0).map((k) => (
            <SeverityBadge key={k} severity={k} count={s.findings?.[k]} />
          ))}
        </div>
      </td>
      <td>
        <div className="row" style={{ flexWrap: 'nowrap' }}>
          {c.status === 'done' && <Link className="btn btn-ghost btn-icon btn-sm" to={`/e/${eng.id}/captures/${c.id}`} aria-label={`Open report for ${c.file_name}`}><FileSearch size={15} /></Link>}
          <a className="btn btn-ghost btn-icon btn-sm" href={captureDownloadUrl(eng.id, c.id)} aria-label={`Download ${c.file_name}`}><Download size={15} /></a>
          {canEdit && busy && <button className="btn btn-ghost btn-icon btn-sm" type="button" aria-label={`Cancel ${c.file_name}`} onClick={() => act.mutate({ cid: c.id, action: 'cancel' })}><Square size={15} /></button>}
          {canEdit && !busy && <button className="btn btn-ghost btn-icon btn-sm" type="button" aria-label={`Re-analyse ${c.file_name}`} onClick={() => act.mutate({ cid: c.id, action: 'reanalyze' })}><RotateCcw size={15} /></button>}
          {canEdit && c.status !== 'processing' && (
            <ConfirmButton className="btn btn-ghost btn-sm" confirmLabel="Delete?" onConfirm={() => act.mutate({ cid: c.id, action: 'delete' })}>
              <Trash2 size={15} aria-label={`Delete ${c.file_name}`} />
            </ConfirmButton>
          )}
        </div>
        {act.isError && <div className="muted" role="alert">{act.error.message}</div>}
      </td>
    </tr>
  )
}

export function CapturesPage() {
  const eng = useOutletContext<Engagement>()
  const captures = useCaptures(eng.id)
  const points = useCapturePoints(eng.id)
  const canEdit = eng.my_role !== 'viewer'
  return (
    <div className="page">
      <div className="page-head"><div><h1>Captures</h1><p>Packet captures for {eng.name}, tagged by where they were taken.</p></div></div>
      <div className="stack">
        {canEdit && <Uploader eng={eng} />}
        <section className="card" style={{ padding: 0 }} aria-label="Captures">
          {captures.isError && <ErrorNote>{captures.error.message}</ErrorNote>}
          {captures.data?.length === 0 && <div className="empty"><strong>No captures yet</strong><span>Upload a capture to start the analysis.</span></div>}
          {!!captures.data?.length && (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>File</th><th>Capture point</th><th>Status</th><th className="num">Packets</th><th className="num">Hosts</th><th>Findings</th><th /></tr></thead>
                <tbody>{captures.data.map((c) => <CaptureRow key={c.id} eng={eng} c={c} points={points.data ?? []} />)}</tbody>
              </table>
            </div>
          )}
        </section>
        <CapturePoints eng={eng} />
      </div>
    </div>
  )
}
