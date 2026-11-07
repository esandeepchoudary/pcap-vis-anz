import { useState } from 'react'
import { Outlet, useMatch } from 'react-router-dom'
import type { SystemInfo, User } from '../api/client'
import { InspectorContext, type Selection } from '../inspector/context'
import './AppShell.css'
import { Header } from './Header'
import { Inspector } from './Inspector'
import { StageRail } from './StageRail'
import './ui.css'

export function AppShell({ system, user }: { system: SystemInfo; user: User }) {
  const match = useMatch('/e/:eid/*')
  const eid = match ? Number(match.params.eid) || null : null
  const [selection, select] = useState<Selection>(null)
  return (
    <InspectorContext.Provider value={{ selection, select }}>
      <div className="shell">
        <Header system={system} user={user} eid={eid} />
        <StageRail eid={eid} showAdmin={system.auth_required && user.role === 'admin'} />
        <main className="main">
          <Outlet />
        </main>
        <Inspector />
      </div>
    </InspectorContext.Provider>
  )
}
