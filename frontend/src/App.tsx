import { AlertCircle, Loader2 } from 'lucide-react'
import { lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { ApiError } from './api/client'
import { useMe, useSystem } from './api/hooks'
import { AppShell } from './components/AppShell'
import { Account } from './pages/Account'
import { AssetsPage } from './pages/AssetsPage'
import { FindingsPage } from './pages/FindingsPage'
import { CapturesPage } from './pages/CapturesPage'
import { EngagementLayout } from './pages/EngagementLayout'
import { EngagementOverview } from './pages/EngagementOverview'
import { Home } from './pages/Home'
import { Login } from './pages/Login'
import { QuickLook } from './pages/QuickLook'
import { ReportPage } from './pages/ReportPage'
import { StagePage } from './pages/StagePage'
import { Users } from './pages/Users'
import { STAGES } from './stages'

// The graph-heavy pages (React Flow, d3) load on first visit, keeping the initial bundle small.
const lazyPage = <K extends string>(load: () => Promise<Record<K, React.ComponentType>>, name: K) =>
  lazy(() => load().then((m) => ({ default: m[name] })))
const ArchitecturePage = lazyPage(() => import('./pages/ArchitecturePage'), 'ArchitecturePage')
const CaptureReport = lazyPage(() => import('./pages/CaptureReport'), 'CaptureReport')
const FlowsPage = lazyPage(() => import('./pages/FlowsPage'), 'FlowsPage')
const PurduePage = lazyPage(() => import('./pages/PurduePage'), 'PurduePage')

function FullPage({ children }: { children: React.ReactNode }) {
  return <div className="auth-page"><div style={{ display: 'grid', justifyItems: 'center', gap: 12 }}>{children}</div></div>
}

const BUILT = new Set(['overview', 'captures', 'assets', 'purdue', 'architecture', 'flows', 'findings', 'report'])
const LATER_STAGES = STAGES.filter((s) => !BUILT.has(s.id))

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
          <Route path="assets" element={<AssetsPage />} />
          <Route path="purdue" element={<PurduePage />} />
          <Route path="architecture" element={<ArchitecturePage />} />
          <Route path="flows" element={<FlowsPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="report" element={<ReportPage />} />
          {LATER_STAGES.map((s) => <Route key={s.id} path={s.segment} element={<StagePage stage={s} />} />)}
        </Route>
        {sys.auth_required && <Route path="account" element={<Account />} />}
        {sys.auth_required && user.role === 'admin' && <Route path="admin/users" element={<Users me={user} />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
