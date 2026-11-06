import { AlertCircle, UserPlus } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import type { Role, User } from '../api/client'
import { useCreateUser, useUpdateUser, useUsers } from '../api/hooks'

const ROLES: Role[] = ['admin', 'lead', 'consultant', 'viewer']
const ROLE_HELP: Record<Role, string> = {
  admin: 'Manage users and all engagements',
  lead: 'Manage engagements and their members',
  consultant: 'Edit engagements they belong to',
  viewer: 'Read-only',
}

function CreateUserForm() {
  const create = useCreateUser()
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('consultant')

  const submit = (e: FormEvent) => {
    e.preventDefault()
    create.mutate({ username, display_name: displayName, password, role }, {
      onSuccess: () => { setUsername(''); setDisplayName(''); setPassword(''); setRole('consultant') },
    })
  }

  return (
    <form className="card" onSubmit={submit} aria-label="Create user" style={{ display: 'grid', gap: 'var(--space-3)' }}>
      <h2 style={{ marginBottom: 0 }}>Add user</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 'var(--space-3)' }}>
        <label className="field"><span>Username</span>
          <input className="input" required value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label className="field"><span>Display name</span>
          <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
        <label className="field"><span>Initial password</span>
          <input className="input" type="password" autoComplete="new-password" required minLength={10} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <label className="field"><span>Role</span>
          <select className="select" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select></label>
      </div>
      <p className="muted" style={{ margin: 0, fontSize: 'var(--text-xs)' }}>{role}: {ROLE_HELP[role]}</p>
      {create.isError && <div className="alert alert-danger" role="alert"><AlertCircle size={16} /> <span>{create.error.message}</span></div>}
      <div><button className="btn btn-primary" type="submit" disabled={create.isPending}><UserPlus size={16} /> Add user</button></div>
    </form>
  )
}

function UserRow({ user, me }: { user: User; me: User }) {
  const update = useUpdateUser()
  return (
    <tr>
      <td><strong>{user.display_name}</strong><div className="muted mono">{user.username}{user.id === me.id ? ' (you)' : ''}</div></td>
      <td>
        <select className="select" aria-label={`Role for ${user.username}`} value={user.role}
          onChange={(e) => update.mutate({ id: user.id, body: { role: e.target.value as Role } })}>
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
      </td>
      <td>{user.is_active ? <span className="badge badge-ok">Active</span> : <span className="badge">Disabled</span>}</td>
      <td className="muted">{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never'}</td>
      <td>
        <button className="btn btn-sm" type="button"
          onClick={() => update.mutate({ id: user.id, body: { is_active: !user.is_active } })}>
          {user.is_active ? 'Disable' : 'Enable'}
        </button>
        {update.isError && <div className="alert alert-danger" role="alert" style={{ marginTop: 4 }}>{update.error.message}</div>}
      </td>
    </tr>
  )
}

export function Users({ me }: { me: User }) {
  const users = useUsers()
  return (
    <div className="page">
      <div className="page-head"><div><h1>Users</h1><p>Local accounts for this team server.</p></div></div>
      <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
        <CreateUserForm />
        <section className="card" style={{ padding: 0 }}>
          {users.isPending && <p className="muted" style={{ padding: 'var(--space-4)' }}>Loading…</p>}
          {users.isError && <div className="alert alert-danger" role="alert">{users.error.message}</div>}
          {users.data && (
            <table className="table">
              <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
              <tbody>{users.data.map((u) => <UserRow key={u.id} user={u} me={me} />)}</tbody>
            </table>
          )}
        </section>
      </div>
    </div>
  )
}
