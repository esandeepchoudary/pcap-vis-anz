import { AlertCircle } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import type { SystemInfo } from '../api/client'
import { useLogin } from '../api/hooks'
import '../components/AppShell.css'

export function Login({ system }: { system: SystemInfo }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const login = useLogin()

  const submit = (e: FormEvent) => {
    e.preventDefault()
    login.mutate({ username, password })
  }

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="brand">
          <img src="/favicon.svg" alt="" width={28} height={28} />
          <span>PCAP Visualizer</span>
        </div>
        <form onSubmit={submit} aria-label="Sign in">
          <label className="field">
            <span>Username</span>
            <input className="input" autoComplete="username" autoFocus required
              value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label className="field">
            <span>Password</span>
            <input className="input" type="password" autoComplete="current-password" required
              value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          {login.isError && (
            <div className="alert alert-danger" role="alert">
              <AlertCircle size={16} /> <span>{login.error.message}</span>
            </div>
          )}
          <button className="btn btn-primary" type="submit" disabled={login.isPending}>
            {login.isPending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="muted" style={{ margin: 0, fontSize: 'var(--text-xs)', textAlign: 'center' }}>
          Team server · v{system.version} · Ask an admin for an account.
        </p>
      </div>
    </div>
  )
}
