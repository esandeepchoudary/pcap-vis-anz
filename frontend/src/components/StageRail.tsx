import { Home, ScanSearch, Users } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { STAGES } from '../stages'

/** Workflow stages of the open engagement. Without one, stages are shown but disabled. */
export function StageRail({ eid, showAdmin }: { eid: number | null; showAdmin: boolean }) {
  return (
    <nav className="rail" aria-label="Workflow stages">
      <NavLink to="/" end className="rail-link">
        <Home size={20} strokeWidth={1.8} aria-hidden />
        <span>Home</span>
      </NavLink>
      {STAGES.map(({ id, segment, label, icon: Icon }) =>
        eid ? (
          <NavLink key={id} to={`/e/${eid}/${segment}`} className="rail-link">
            <Icon size={20} strokeWidth={1.8} aria-hidden />
            <span>{label}</span>
          </NavLink>
        ) : (
          <span key={id} className="rail-link disabled" aria-disabled title="Open an engagement first">
            <Icon size={20} strokeWidth={1.8} aria-hidden />
            <span>{label}</span>
          </span>
        ),
      )}
      <div className="rail-spacer" />
      <NavLink to="/quicklook" className="rail-link">
        <ScanSearch size={20} strokeWidth={1.8} aria-hidden />
        <span>Quick look</span>
      </NavLink>
      {showAdmin && (
        <NavLink to="/admin/users" className="rail-link">
          <Users size={20} strokeWidth={1.8} aria-hidden />
          <span>Users</span>
        </NavLink>
      )}
    </nav>
  )
}
