import { useQueryClient } from '@tanstack/react-query'
import { GitMerge } from 'lucide-react'
import { useState } from 'react'
import { ApiError, uploadForm, type MergeReport } from '../api/client'
import { formatValue } from '../lib/assets'
import type { EditableField } from '../api/client'
import { Dropzone, ErrorNote, ProgressBar } from './ui'

/** Merge a .pcapvis bundle (e.g. from a consultant's laptop) into this engagement. Leads only. */
export function MergeBundle({ eid }: { eid: number }) {
  const qc = useQueryClient()
  const [progress, setProgress] = useState<number | null>(null)
  const [report, setReport] = useState<MergeReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const run = async (file: File) => {
    setError(null)
    setReport(null)
    setProgress(0)
    const form = new FormData()
    form.append('file', file)
    try {
      setReport(await uploadForm<MergeReport>(`/api/engagements/${eid}/merge`, form, setProgress))
      void qc.invalidateQueries({ queryKey: ['engagement', eid] })
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Merge failed.')
    } finally {
      setProgress(null)
    }
  }
  return (
    <section className="card stack" aria-labelledby="merge-h">
      <div className="row"><GitMerge size={18} aria-hidden /><h2 id="merge-h" className="section-title" style={{ margin: 0 }}>Merge work from another machine</h2></div>
      <p className="muted" style={{ margin: 0 }}>
        Add a .pcapvis exported elsewhere (for example a consultant's laptop) to this engagement. Captures already here are skipped;
        edits are applied where this engagement has none, and where both sides changed a field, the value here is kept and listed below.
      </p>
      <Dropzone onFiles={(f) => void run(f[0])} multiple={false} accept=".pcapvis,.zip" disabled={progress !== null}>Drop a .pcapvis file here</Dropzone>
      {progress !== null && <ProgressBar value={progress} label="Merge upload progress" />}
      {error && <ErrorNote>{error}</ErrorNote>}
      {report && (
        <div className="alert alert-ok" role="status" style={{ display: 'grid', gap: 6 }}>
          <strong>Merged.</strong>
          <span>
            {report.captures_added} capture(s) added{report.captures_skipped ? `, ${report.captures_skipped} already here` : ''} ·
            {' '}{report.fields_applied} edit(s) applied to {report.assets_updated} asset(s) · {report.assets_created} asset(s) added ·
            {' '}{report.zones_added} zone(s), {report.conduits_added} conduit(s), {report.findings_added} finding(s) added
          </span>
          {report.conflicts.length > 0 && (
            <div>
              <div>{report.conflicts.length} field(s) were changed on both sides; the values here were kept:</div>
              <ul aria-label="Merge conflicts">{report.conflicts.map((c) => (
                <li key={`${c.asset_id}-${c.field}`}>{c.asset}: {c.field.replaceAll('_', ' ')} kept "{formatValue(c.field as EditableField, c.kept)}", bundle had "{formatValue(c.field as EditableField, c.imported)}"</li>
              ))}</ul>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
