import { Outlet } from 'react-router-dom'
import type { SystemInfo, User } from '../api/client'
import './AppShell.css'
import { Header } from './Header'
import { Inspector } from './Inspector'
import { StageRail } from './StageRail'

export function AppShell({ system, user }: { system: SystemInfo; user: User }) {
  return (
    <div className="shell">
      <Header system={system} user={user} />
      <StageRail showAdmin={system.auth_required && user.role === 'admin'} />
      <main className="main">
        <Outlet />
      </main>
      <Inspector />
      <footer className="timeline" aria-label="Timeline">
        <span>Timeline</span>
        <div className="timeline-track" />
        <span>No capture loaded</span>
      </footer>
    </div>
  )
}
