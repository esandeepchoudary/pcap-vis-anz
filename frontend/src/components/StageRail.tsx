import { Users } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { STAGES } from '../stages'

export function StageRail({ showAdmin }: { showAdmin: boolean }) {
  return (
    <nav className="rail" aria-label="Workflow stages">
      {STAGES.map(({ id, path, label, icon: Icon }) => (
        <NavLink key={id} to={path} end={path === '/'} className="rail-link">
          <Icon size={20} strokeWidth={1.8} aria-hidden />
          <span>{label}</span>
        </NavLink>
      ))}
      <div className="rail-spacer" />
      {showAdmin && (
        <NavLink to="/admin/users" className="rail-link">
          <Users size={20} strokeWidth={1.8} aria-hidden />
          <span>Users</span>
        </NavLink>
      )}
    </nav>
  )
}
