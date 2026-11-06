import { AlertCircle, Loader2 } from 'lucide-react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { ApiError } from './api/client'
import { useMe, useSystem } from './api/hooks'
import { AppShell } from './components/AppShell'
import { Account } from './pages/Account'
import { Login } from './pages/Login'
import { Overview } from './pages/Overview'
import { StagePage } from './pages/StagePage'
import { Users } from './pages/Users'
import { STAGES } from './stages'

function FullPage({ children }: { children: React.ReactNode }) {
  return <div className="auth-page"><div style={{ display: 'grid', justifyItems: 'center', gap: 12 }}>{children}</div></div>
}

export default function App() {
  const system = useSystem()
  const me = useMe(system.isSuccess)

  if (system.isPending) {
    return <FullPage><Loader2 className="spin" aria-label="Loading" /></FullPage>
  }
  if (system.isError) {
    return (
      <FullPage>
        <div className="alert alert-danger" role="alert">
          <AlertCircle size={16} /> <span>Can't reach the PCAP Visualizer server. Is it running?</span>
        </div>
      </FullPage>
    )
  }
  if (me.isPending) {
    return <FullPage><Loader2 className="spin" aria-label="Loading" /></FullPage>
  }
  if (me.isError) {
    if (me.error instanceof ApiError && me.error.status === 401) return <Login system={system.data} />
    return <FullPage><div className="alert alert-danger" role="alert">{me.error.message}</div></FullPage>
  }

  const user = me.data
  return (
    <Routes>
      <Route element={<AppShell system={system.data} user={user} />}>
        <Route index element={<Overview system={system.data} />} />
        {STAGES.filter((s) => s.id !== 'overview').map((s) => (
          <Route key={s.id} path={s.path.slice(1)} element={<StagePage stage={s} />} />
        ))}
        {system.data.auth_required && <Route path="account" element={<Account />} />}
        {system.data.auth_required && user.role === 'admin' && (
          <Route path="admin/users" element={<Users me={user} />} />
        )}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
