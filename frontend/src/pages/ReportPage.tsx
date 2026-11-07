import { Download, FileSpreadsheet, FileText, Network, Package, Shapes } from 'lucide-react'
import { useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import type { Engagement } from '../api/client'
import { assetExportUrl } from '../api/assets'
import { exportUrl } from '../api/engagements'
import { reportUrl, useFindings } from '../api/findings'
import { SeverityBadge } from '../components/ui'
import { SEVERITIES } from '../lib/severity'

function Deliverable({ icon: Icon, title, children, links }: {
  icon: typeof FileText; title: string; children: React.ReactNode; links: { href: string; label: string }[]
}) {
  return (
    <section className="card stack" style={{ gap: 'var(--space-2)' }} aria-label={title}>
      <div className="row"><Icon size={18} aria-hidden /><h2 style={{ margin: 0 }}>{title}</h2></div>
      <p className="muted" style={{ margin: 0 }}>{children}</p>
      <div className="row">{links.map((l) => <a key={l.href} className="btn btn-sm" href={l.href} download><Download size={14} /> {l.label}</a>)}</div>
    </section>
  )
}

export function ReportPage() {
  const eng = useOutletContext<Engagement>()
  const findings = useFindings(eng.id)
  const [withCaptures, setWithCaptures] = useState(false)
  const included = (findings.data ?? []).filter((f) => f.include_in_report)
  return (
    <div className="page">
      <div className="page-head"><div><h1>Report &amp; exports</h1><p>Client-ready deliverables built from the current inventory, zones and triaged findings.</p></div></div>
      <div className="stack">
        <div className="row" aria-label="Report contents">
          <span>{included.length} finding{included.length === 1 ? '' : 's'} will be in the report:</span>
          {SEVERITIES.map((s) => { const n = included.filter((f) => f.severity === s).length; return n ? <SeverityBadge key={s} severity={s} count={n} /> : null })}
          <Link to={`/e/${eng.id}/findings`}>Review findings</Link>
        </div>
        <div className="grid-2">
          <Deliverable icon={FileText} title="Assessment report" links={[{ href: reportUrl(eng.id, 'report.docx'), label: 'Word (.docx)' }, { href: reportUrl(eng.id, 'report.html'), label: 'HTML (print to PDF)' }]}>
            Executive summary, scope, findings with evidence and recommendations, segmentation (zones, conduits, violations) and the asset register. For PDF, open the HTML version and print it.
          </Deliverable>
          <Deliverable icon={FileSpreadsheet} title="Asset register" links={[{ href: reportUrl(eng.id, 'assets.xlsx'), label: 'Excel (.xlsx)' }, { href: assetExportUrl(eng.id), label: 'CSV' }]}>
            Every asset with its detected and edited fields, plus sheets for zones, conduits, violations, findings and OT commands.
          </Deliverable>
          <Deliverable icon={Shapes} title="Purdue diagram" links={[{ href: reportUrl(eng.id, 'purdue.drawio'), label: 'draw.io (editable)' }, { href: reportUrl(eng.id, 'purdue.svg'), label: 'SVG' }]}>
            Levels, zones and assets with OT connections (writes in red). The draw.io file opens in diagrams.net for final touches.
          </Deliverable>
          <Deliverable icon={Network} title="Architecture diagram" links={[{ href: reportUrl(eng.id, 'architecture.drawio'), label: 'draw.io (editable)' }, { href: reportUrl(eng.id, 'architecture.svg'), label: 'SVG' }]}>
            Zones and conduits with their allowed traffic, and unapproved cross-zone traffic in red, laid out as on the Architecture page.
          </Deliverable>
          <section className="card stack" style={{ gap: 'var(--space-2)' }} aria-label="Engagement bundle">
            <div className="row"><Package size={18} aria-hidden /><h2 style={{ margin: 0 }}>Engagement bundle</h2></div>
            <p className="muted" style={{ margin: 0 }}>Everything in one .pcapvis file (inventory, edits and history, zones, findings triage), to hand over or import elsewhere.</p>
            <label className="row"><input type="checkbox" checked={withCaptures} onChange={(e) => setWithCaptures(e.target.checked)} /> Include original captures</label>
            <div className="row"><a className="btn btn-sm" href={exportUrl(eng.id, withCaptures, true)} download><Download size={14} /> .pcapvis</a></div>
          </section>
        </div>
      </div>
    </div>
  )
}
