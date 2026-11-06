import { AlertCircle, Loader2 } from 'lucide-react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { ApiError } from './api/client'
import { useMe, useSystem } from './api/hooks'
import { AppShell } from './components/AppShell'
import { Account } from './pages/Account'
import { CaptureReport } from './pages/CaptureReport'
import { CapturesPage } from './pages/CapturesPage'
import { EngagementLayout } from './pages/EngagementLayout'
import { EngagementOverview } from './pages/EngagementOverview'
import { Home } from './pages/Home'
import { Login } from './pages/Login'
import { QuickLook } from './pages/QuickLook'
import { StagePage } from './pages/StagePage'
import { Users } from './pages/Users'
import { STAGES } from './stages'

function FullPage({ children }: { children: React.ReactNode }) {
  return <div className="auth-page"><div style={{ display: 'grid', justifyItems: 'center', gap: 12 }}>{children}</div></div>
}

const LATER_STAGES = STAGES.filter((s) => s.id !== 'overview' && s.id !== 'captures')

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
  const sys = system.data
  return (
    <Routes>
      <Route element={<AppShell system={sys} user={user} />}>
        <Route index element={<Home system={sys} user={user} />} />
        <Route path="quicklook" element={user.role === 'viewer' ? <Navigate to="/" replace /> : <QuickLook />} />
        <Route path="e/:eid" element={<EngagementLayout />}>
          <Route index element={<Navigate to="overview" replace />} />
          <Route path="overview" element={<EngagementOverview system={sys} />} />
          <Route path="captures" element={<CapturesPage />} />
          <Route path="captures/:cid" element={<CaptureReport />} />
          {LATER_STAGES.map((s) => <Route key={s.id} path={s.segment} element={<StagePage stage={s} />} />)}
        </Route>
        {sys.auth_required && <Route path="account" element={<Account />} />}
        {sys.auth_required && user.role === 'admin' && <Route path="admin/users" element={<Users me={user} />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
