import { ChevronDown, KeyRound, LogOut, Moon, Search, Sun } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import type { SystemInfo, User } from '../api/client'
import { useLogout } from '../api/hooks'
import { useTheme } from '../theme/context'
import { EngagementSwitcher } from './EngagementSwitcher'

function initials(user: User) {
  const name = user.display_name || user.username
  return name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()
}

export function Header({ system, user, eid }: { system: SystemInfo; user: User; eid: number | null }) {
  const { theme, toggle } = useTheme()
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const logout = useLogout()

  useEffect(() => {
    if (!menuOpen) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !menuRef.current?.contains(e.target as Node)) {
        setMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [menuOpen])

  return (
    <header className="header">
      <div className="brand">
        <img src="/favicon.svg" alt="" />
        <span>PCAP Visualizer</span>
        <small>v{system.version}</small>
      </div>
      <EngagementSwitcher eid={eid} />
      <label className="header-search">
        <span className="sr-only">Search</span>
        <Search size={15} aria-hidden />
        <input className="input" placeholder="Search assets, IPs, findings…" disabled title="Search arrives with the asset inventory (M3)" />
      </label>
      <div className="header-actions" ref={menuRef}>
        {system.mode === 'laptop' && <span className="badge">Laptop mode</span>}
        <button
          type="button"
          className="btn btn-ghost btn-icon"
          onClick={toggle}
          aria-label={theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'}
          title={theme === 'light' ? 'Dark theme' : 'Light theme'}
        >
          {theme === 'light' ? <Moon size={18} /> : <Sun size={18} />}
        </button>
        <button
          type="button"
          className="user-chip"
          onClick={() => setMenuOpen((o) => !o)}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
        >
          <span className="avatar" aria-hidden>{initials(user)}</span>
          <span>{user.display_name || user.username}</span>
          <ChevronDown size={14} aria-hidden />
        </button>
        {menuOpen && (
          <div className="menu" role="menu">
            <div className="menu-head">
              <div><strong>{user.display_name || user.username}</strong></div>
              <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>
                {user.username} · {user.role}
              </div>
            </div>
            {system.auth_required && (
              <>
                <Link className="menu-item" role="menuitem" to="/account" onClick={() => setMenuOpen(false)}>
                  <KeyRound size={15} /> Change password
                </Link>
                <button className="menu-item" role="menuitem" type="button" onClick={() => logout.mutate()}>
                  <LogOut size={15} /> Sign out
                </button>
              </>
            )}
            {!system.auth_required && (
              <div className="menu-item muted" role="menuitem" aria-disabled>
                Single-user laptop mode: no sign-in needed
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  )
}
