import { Pause, Play, RotateCcw } from 'lucide-react'
import { useEffect, useState, type Dispatch, type SetStateAction } from 'react'

const STEPS = 1000
const SWEEP_MS = 12_000 // a full replay at 1x
const TICK_MS = 100
const SPEEDS = [0.5, 1, 2, 4, 8]

export type Window = [number, number]

function fmt(t: number, span: number) {
  const d = new Date(t * 1000)
  return span < 86_400 ? d.toLocaleTimeString() : d.toLocaleString()
}

/**
 * Two-handle time range over the capture span, with replay: Play grows the window's end from its start to the
 * end of the captures, so connections appear in the order they were first seen.
 */
export function GraphTimeline({ bounds, value, onChange, visible, total }: {
  bounds: Window
  value: Window
  onChange: Dispatch<SetStateAction<Window>>
  visible: number
  total: number
}) {
  const [lo, hi] = bounds
  const span = hi - lo
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const toStep = (t: number) => Math.round(((t - lo) / span) * STEPS)
  const fromStep = (s: number) => lo + (s / STEPS) * span

  useEffect(() => {
    if (!playing) return
    const step = (span * TICK_MS * speed) / SWEEP_MS
    const id = window.setInterval(() => onChange(([from, to]) => [from, Math.min(hi, to + step)]), TICK_MS)
    return () => window.clearInterval(id)
  }, [playing, speed, span, hi, onChange])
  // Reached the end: stop (state derived during render rather than in an effect).
  if (playing && value[1] >= hi) setPlaying(false)

  const play = () => {
    if (playing) { setPlaying(false); return }
    if (value[1] >= hi) onChange(([from]) => [from, from]) // replay from the window's start
    setPlaying(true)
  }
  const full = value[0] <= lo && value[1] >= hi

  return (
    <div className="graph-timeline" role="group" aria-label="Timeline">
      <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={play} aria-label={playing ? 'Pause' : 'Play'}>
        {playing ? <Pause size={15} /> : <Play size={15} />}
      </button>
      <select className="select" style={{ width: 70, height: 28 }} value={speed} onChange={(e) => setSpeed(Number(e.target.value))} aria-label="Playback speed">
        {SPEEDS.map((s) => <option key={s} value={s}>{s}×</option>)}
      </select>
      <span className="tl-time">{fmt(value[0], span)}</span>
      <div className="tl-range">
        <input type="range" min={0} max={STEPS} value={toStep(value[0])} aria-label="Window start"
          onChange={(e) => { setPlaying(false); const t = fromStep(Number(e.target.value)); onChange(([, to]) => [Math.min(t, to), to]) }} />
        <input type="range" min={0} max={STEPS} value={toStep(value[1])} aria-label="Window end"
          onChange={(e) => { setPlaying(false); const t = fromStep(Number(e.target.value)); onChange(([from]) => [from, Math.max(t, from)]) }} />
        <div className="tl-fill" style={{ left: `${(toStep(value[0]) / STEPS) * 100}%`, right: `${100 - (toStep(value[1]) / STEPS) * 100}%` }} />
      </div>
      <span className="tl-time">{fmt(value[1], span)}</span>
      <span className="muted tl-count">{visible} of {total} connections</span>
      {!full && (
        <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Whole capture"
          onClick={() => { setPlaying(false); onChange([lo, hi]) }}><RotateCcw size={14} /></button>
      )}
    </div>
  )
}
