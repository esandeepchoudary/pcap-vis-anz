import { Boxes, Briefcase, Search, ShieldAlert, Shapes, X } from 'lucide-react'
import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAssets } from '../api/assets'
import { useEngagements } from '../api/engagements'
import { useFindings } from '../api/findings'
import { useZones } from '../api/zones'
import { useInspector } from '../inspector/context'
import { searchEngagement, searchEngagements, type SearchHit } from '../lib/search'

const ICONS = { asset: Boxes, finding: ShieldAlert, zone: Shapes, engagement: Briefcase }
const KIND_LABEL = { asset: 'Asset', finding: 'Finding', zone: 'Zone', engagement: 'Engagement' }

/** Header search: the open engagement's assets, findings and zones; without one, the engagements. "/" focuses it. */
export function GlobalSearch({ eid, onClose }: { eid: number | null; onClose?: () => void }) {
  return eid ? <EngagementSearch eid={eid} onClose={onClose} /> : <EngagementsSearch onClose={onClose} />
}

function EngagementSearch({ eid, onClose }: { eid: number; onClose?: () => void }) {
  const [q, setQ] = useState('')
  const assets = useAssets(eid)
  const findings = useFindings(eid)
  const zones = useZones(eid)
  const hits = useMemo(() => searchEngagement(q, { assets: assets.data, findings: findings.data, zones: zones.data }),
    [q, assets.data, findings.data, zones.data])
  return <SearchBox q={q} setQ={setQ} hits={hits} eid={eid} placeholder="Search assets, IPs, findings…" onClose={onClose} />
}

function EngagementsSearch({ onClose }: { onClose?: () => void }) {
  const [q, setQ] = useState('')
  const engagements = useEngagements()
  const hits = useMemo(() => searchEngagements(q, engagements.data ?? []), [q, engagements.data])
  return <SearchBox q={q} setQ={setQ} hits={hits} eid={null} placeholder="Search engagements…" onClose={onClose} />
}

function SearchBox({ q, setQ, hits, eid, placeholder, onClose }: {
  q: string; setQ: (q: string) => void; hits: SearchHit[]; eid: number | null; placeholder: string; onClose?: () => void
}) {
  const navigate = useNavigate()
  const { select } = useInspector()
  const input = useRef<HTMLInputElement>(null)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const listId = useId()

  // "/" anywhere (outside a text field) jumps to search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey || t.closest('input, textarea, select, [contenteditable="true"]')) return
      e.preventDefault()
      input.current?.focus()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])
  useEffect(() => { if (onClose) input.current?.focus() }, [onClose]) // opened on a phone: focus straight away

  const choose = (h: SearchHit) => {
    if (h.kind === 'asset' && eid) select({ kind: 'asset', eid, id: h.id })
    else if (h.kind === 'finding' && eid) select({ kind: 'finding', eid, key: h.key })
    else if (h.kind === 'zone' && eid) navigate(`/e/${eid}/architecture`)
    else if (h.kind === 'engagement') navigate(`/e/${h.id}/overview`)
    setQ('')
    setOpen(false)
    input.current?.blur()
    onClose?.()
  }
  const show = open && q.trim() !== ''
  const cur = Math.min(active, Math.max(0, hits.length - 1))

  return (
    <div className="header-search" role="search">
      <Search size={15} aria-hidden />
      <input
        ref={input}
        className="input"
        placeholder={placeholder}
        aria-label="Search"
        role="combobox"
        aria-expanded={show}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={show && hits.length ? `${listId}-${cur}` : undefined}
        value={q}
        onChange={(e) => { setQ(e.target.value); setOpen(true); setActive(0) }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') { e.preventDefault(); setActive(Math.min(cur + 1, hits.length - 1)) }
          else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(Math.max(cur - 1, 0)) }
          else if (e.key === 'Enter' && hits[cur]) { e.preventDefault(); choose(hits[cur]) }
          else if (e.key === 'Escape') { setQ(''); setOpen(false); input.current?.blur(); onClose?.() }
        }}
      />
      {onClose && <button type="button" className="btn btn-ghost btn-icon btn-sm search-close" aria-label="Close search" onClick={onClose}><X size={15} /></button>}
      {!onClose && !q && <kbd className="search-kbd" aria-hidden>/</kbd>}
      {show && (
        <ul className="search-results" role="listbox" id={listId} aria-label="Search results">
          {hits.length === 0 && <li className="search-empty muted">No matches</li>}
          {hits.map((h, i) => {
            const Icon = ICONS[h.kind]
            return (
              <li key={`${h.kind}-${h.kind === 'finding' ? h.key : h.id}`} id={`${listId}-${i}`} role="option" aria-selected={i === cur}
                className={i === cur ? 'active' : ''} onMouseDown={(e) => { e.preventDefault(); choose(h) }} onMouseEnter={() => setActive(i)}>
                <Icon size={15} aria-hidden />
                <span className="search-label">{h.label}{h.sub && <small>{h.sub}</small>}</span>
                <span className="search-kind">{KIND_LABEL[h.kind]}</span>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
