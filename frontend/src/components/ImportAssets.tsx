import { FileUp, X } from 'lucide-react'
import { useRef, useState } from 'react'
import { useImportAssets } from '../api/assets'
import type { AssetFields, EditableField, FieldValue } from '../api/client'
import { formatValue } from '../lib/assets'
import { ErrorNote } from './ui'

const SHOWN = 200

/**
 * The client filled in the exported register: read it back, show exactly what would change, then apply.
 * Blank cells leave assets as they are.
 */
export function ImportAssets({ eid, fields, onClose }: { eid: number; fields: AssetFields; onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [reason, setReason] = useState('')
  const preview = useImportAssets(eid)
  const apply = useImportAssets(eid)
  const input = useRef<HTMLInputElement>(null)
  const label = (f: string) => fields.fields.find((x) => x.name === f)?.label ?? f
  const pick = (f: File | null) => {
    setFile(f)
    apply.reset()
    if (f) preview.mutate({ file: f, apply: false, reason: '' })
  }
  const p = preview.data
  const done = apply.data?.applied

  return (
    <section className="card stack import-panel" aria-label="Import asset edits" style={{ gap: 'var(--space-3)' }}>
      <div className="row">
        <h2 style={{ margin: 0, flex: 1 }}>Import edits from a spreadsheet</h2>
        <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close import" onClick={onClose}><X size={16} /></button>
      </div>
      <p className="muted" style={{ margin: 0 }}>
        Export the register (CSV or Excel), have it filled in, and load it here. Rows match by asset ID, else by IP address.
        Blank cells leave an asset as it is. You'll see every change before anything is saved.
      </p>
      <div className="row">
        <input ref={input} type="file" accept=".csv,.xlsx,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
          aria-label="Register file" onChange={(e) => pick(e.target.files?.[0] ?? null)} />
        {preview.isPending && <span className="muted" role="status">Reading…</span>}
      </div>
      {preview.isError && <ErrorNote>{preview.error.message}</ErrorNote>}
      {p && !done && (
        <>
          <div className="row" role="status" aria-label="Import summary">
            <strong>{p.changes.length} change{p.changes.length === 1 ? '' : 's'}</strong>
            <span className="muted">{p.matched} of {p.rows} rows matched an asset</span>
          </div>
          {(p.unmatched.length > 0 || p.errors.length > 0) && (
            <details open={p.changes.length === 0}>
              <summary>{p.unmatched.length + p.errors.length} row{p.unmatched.length + p.errors.length === 1 ? '' : 's'} skipped or with problems</summary>
              <ul className="import-problems">{[...p.errors, ...p.unmatched].slice(0, SHOWN).map((m) => <li key={m}>{m}</li>)}</ul>
            </details>
          )}
          {p.changes.length > 0 && (
            <>
              <div className="table-wrap">
                <table className="table" aria-label="Changes to apply">
                  <thead><tr><th>Asset</th><th>Field</th><th>Now</th><th>New</th></tr></thead>
                  <tbody>{p.changes.slice(0, SHOWN).map((c) => (
                    <tr key={`${c.asset_id}-${c.field}`}>
                      <td>{c.label}</td><td>{label(c.field)}</td>
                      <td className="muted">{formatValue(c.field as EditableField, c.old as FieldValue)}</td>
                      <td><strong>{formatValue(c.field as EditableField, c.new as FieldValue)}</strong></td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
              {p.changes.length > SHOWN && <span className="muted">…and {p.changes.length - SHOWN} more.</span>}
              <div className="row">
                <input className="input" aria-label="Import reason" placeholder={`Reason (default: Imported from ${file?.name ?? 'the file'})`}
                  value={reason} maxLength={1000} onChange={(e) => setReason(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
                <button type="button" className="btn btn-primary" disabled={apply.isPending || !file}
                  onClick={() => file && apply.mutate({ file, apply: true, reason })}>
                  <FileUp size={16} /> Apply {p.changes.length} change{p.changes.length === 1 ? '' : 's'}
                </button>
              </div>
            </>
          )}
        </>
      )}
      {apply.isError && <ErrorNote>{apply.error.message}</ErrorNote>}
      {done && (
        <div className="alert alert-ok" role="status">
          Updated {apply.data!.assets_changed} asset{apply.data!.assets_changed === 1 ? '' : 's'}. Every change is in the assets' history with your reason.
          <button type="button" className="link-btn" style={{ marginLeft: 8 }} onClick={() => { pick(null); if (input.current) input.current.value = '' }}>Import another</button>
        </div>
      )}
    </section>
  )
}
