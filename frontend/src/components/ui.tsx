import { AlertCircle, CheckCircle2, CircleDashed, Loader2, Upload, XCircle } from 'lucide-react'
import { useRef, useState, type DragEvent, type ReactNode } from 'react'
import type { Capture } from '../api/client'
import type { Severity } from '../lib/severity'


export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`sev sev-${severity}`}>
      {count !== undefined ? `${count} ${severity}` : severity}
    </span>
  )
}

const STATUS: Record<Capture['status'], { label: string; cls: string; Icon: typeof CheckCircle2 }> = {
  queued: { label: 'Queued', cls: 'badge', Icon: CircleDashed },
  processing: { label: 'Analysing', cls: 'badge badge-accent', Icon: Loader2 },
  done: { label: 'Done', cls: 'badge badge-ok', Icon: CheckCircle2 },
  failed: { label: 'Failed', cls: 'badge badge-danger', Icon: XCircle },
  cancelled: { label: 'Cancelled', cls: 'badge', Icon: XCircle },
}

export function StatusBadge({ status }: { status: Capture['status'] }) {
  const s = STATUS[status]
  return (
    <span className={s.cls}>
      <s.Icon size={12} className={status === 'processing' ? 'spin-inline' : undefined} aria-hidden /> {s.label}
    </span>
  )
}

export function ProgressBar({ value, label }: { value: number; label?: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100)
  return (
    <div className="progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
      <div className="progress-fill" style={{ width: `${pct}%` }} />
    </div>
  )
}

export function Tile({ label, value, tone }: { label: string; value: ReactNode; tone?: 'danger' | 'warn' | 'ok' }) {
  return (
    <div className={`tile${tone ? ` tile-${tone}` : ''}`}>
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  )
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div className="alert alert-danger" role="alert">
      <AlertCircle size={16} aria-hidden /> <span>{children}</span>
    </div>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange, label }: {
  tabs: { id: T; label: string; count?: number }[]
  value: T
  onChange: (t: T) => void
  label: string
}) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button key={t.id} role="tab" type="button" aria-selected={t.id === value}
          className={`tab${t.id === value ? ' active' : ''}`} onClick={() => onChange(t.id)}>
          {t.label}
          {t.count !== undefined && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

/** A button that needs a second click to confirm a destructive action. */
export function ConfirmButton({ onConfirm, children, confirmLabel = 'Click again to confirm', className = 'btn btn-sm', disabled }: {
  onConfirm: () => void
  children: ReactNode
  confirmLabel?: string
  className?: string
  disabled?: boolean
}) {
  const [armed, setArmed] = useState(false)
  return (
    <button type="button" className={`${className}${armed ? ' btn-danger' : ''}`} disabled={disabled}
      onBlur={() => setArmed(false)}
      onClick={() => {
        if (armed) {
          setArmed(false)
          onConfirm()
        } else setArmed(true)
      }}>
      {armed ? confirmLabel : children}
    </button>
  )
}

export function Dropzone({ onFiles, multiple = true, accept = '.pcap,.pcapng,.cap,.gz', disabled, children }: {
  onFiles: (files: File[]) => void
  multiple?: boolean
  accept?: string
  disabled?: boolean
  children?: ReactNode
}) {
  const input = useRef<HTMLInputElement>(null)
  const [over, setOver] = useState(false)
  const drop = (e: DragEvent) => {
    e.preventDefault()
    setOver(false)
    if (disabled) return
    const files = Array.from(e.dataTransfer.files)
    if (files.length) onFiles(multiple ? files : files.slice(0, 1))
  }
  return (
    <div
      className={`dropzone${over ? ' over' : ''}${disabled ? ' disabled' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={drop}
    >
      <Upload size={28} strokeWidth={1.6} aria-hidden />
      <div>{children ?? 'Drop capture files here'}</div>
      <button type="button" className="btn btn-sm" disabled={disabled} onClick={() => input.current?.click()}>
        Choose files…
      </button>
      <input ref={input} type="file" hidden multiple={multiple} accept={accept} data-testid="file-input"
        onChange={(e) => {
          const files = Array.from(e.target.files ?? [])
          e.target.value = ''
          if (files.length) onFiles(files)
        }} />
    </div>
  )
}
