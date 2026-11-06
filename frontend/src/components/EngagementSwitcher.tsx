import { Briefcase, Check, ChevronDown, FolderOpen, Plus } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useEngagement, useEngagements } from '../api/engagements'

export function EngagementSwitcher({ eid }: { eid: number | null }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const list = useEngagements()
  const current = useEngagement(eid)
  const navigate = useNavigate()

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open])

  const label = eid && current.data ? current.data.name : 'No engagement open'
  return (
    <div className="switcher" ref={ref}>
      <button type="button" className="engagement-switch" aria-haspopup="menu" aria-expanded={open}
        onClick={() => setOpen((o) => !o)}>
        <Briefcase size={15} aria-hidden /> <span className="switch-label">{label}</span>
        {eid && current.data?.is_quicklook && <span className="badge">Quick look</span>}
        <ChevronDown size={14} aria-hidden />
      </button>
      {open && (
        <div className="menu menu-left" role="menu" aria-label="Engagements">
          {(list.data ?? []).slice(0, 8).map((e) => (
            <button key={e.id} type="button" role="menuitem" className="menu-item"
              onClick={() => { setOpen(false); navigate(`/e/${e.id}/overview`) }}>
              {e.id === eid ? <Check size={15} aria-hidden /> : <span style={{ width: 15 }} />}
              <span style={{ flex: 1 }}>{e.name}</span>
              {e.client && <span className="muted">{e.client}</span>}
            </button>
          ))}
          {list.data?.length === 0 && <div className="menu-item muted">No engagements yet</div>}
          <hr className="menu-sep" />
          <Link className="menu-item" role="menuitem" to="/" onClick={() => setOpen(false)}>
            <FolderOpen size={15} aria-hidden /> All engagements
          </Link>
          <Link className="menu-item" role="menuitem" to="/?new=1" onClick={() => setOpen(false)}>
            <Plus size={15} aria-hidden /> New engagement
          </Link>
        </div>
      )}
    </div>
  )
}
