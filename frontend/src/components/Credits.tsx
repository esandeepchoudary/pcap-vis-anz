import { Sparkles, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

const CLICKS = 5
const WITHIN_MS = 2000

/** The version badge. Click it five times quickly for the credits (a small easter egg). */
export function VersionBadge({ version }: { version: string }) {
  const [open, setOpen] = useState(false)
  const clicks = useRef<number[]>([])
  const tap = () => {
    const now = Date.now()
    clicks.current = [...clicks.current.filter((t) => now - t < WITHIN_MS), now]
    if (clicks.current.length >= CLICKS) { clicks.current = []; setOpen(true) }
  }
  return (
    <>
      <small className="version-badge" onClick={tap}>v{version}</small>
      {open && createPortal(<Credits version={version} onClose={() => setOpen(false)} />, document.body)}
    </>
  )
}

function Credits({ version, onClose }: { version: string; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    closeRef.current?.focus()
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', esc)
    return () => document.removeEventListener('keydown', esc)
  }, [onClose])
  return (
    <div className="credits-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="credits card" role="dialog" aria-modal="true" aria-labelledby="credits-title">
        <button ref={closeRef} type="button" className="btn btn-ghost btn-icon btn-sm credits-close" aria-label="Close" onClick={onClose}><X size={15} /></button>
        <Sparkles size={28} className="credits-spark" aria-hidden />
        <h2 id="credits-title">PCAP Visualizer v{version}</h2>
        <p className="muted">You found the credits.</p>
        <dl className="credits-list">
          <dt>Built by</dt>
          <dd><a href="https://github.com/esandeepchoudary" target="_blank" rel="noreferrer">Sandeep Egalapati</a></dd>
          <dt>Pair-programmed with</dt>
          <dd>Claude, by Anthropic</dd>
        </dl>
        <p className="muted credits-foot">Packets decoded by Wireshark's tshark. Made for the people who keep the lights on.</p>
      </div>
    </div>
  )
}
