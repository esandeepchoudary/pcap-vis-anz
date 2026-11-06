import { CheckCircle2, AlertCircle } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useChangePassword } from '../api/hooks'

export function Account() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)
  const change = useChangePassword()

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setLocalError(null)
    if (next !== repeat) {
      setLocalError("New passwords don't match.")
      return
    }
    change.mutate({ current_password: current, new_password: next }, {
      onSuccess: () => { setCurrent(''); setNext(''); setRepeat('') },
    })
  }
  const error = localError ?? (change.isError ? change.error.message : null)

  return (
    <div className="page">
      <div className="page-head"><div><h1>Account</h1><p>Change your password. Your other sessions will be signed out.</p></div></div>
      <form className="card" onSubmit={submit} style={{ maxWidth: 420, display: 'grid', gap: 'var(--space-3)' }} aria-label="Change password">
        <label className="field"><span>Current password</span>
          <input className="input" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
        <label className="field"><span>New password (10+ characters)</span>
          <input className="input" type="password" autoComplete="new-password" required minLength={10} value={next} onChange={(e) => setNext(e.target.value)} /></label>
        <label className="field"><span>Repeat new password</span>
          <input className="input" type="password" autoComplete="new-password" required value={repeat} onChange={(e) => setRepeat(e.target.value)} /></label>
        {error && <div className="alert alert-danger" role="alert"><AlertCircle size={16} /> <span>{error}</span></div>}
        {change.isSuccess && <div className="alert alert-ok" role="status"><CheckCircle2 size={16} /> <span>Password changed.</span></div>}
        <div><button className="btn btn-primary" type="submit" disabled={change.isPending}>Change password</button></div>
      </form>
    </div>
  )
}
