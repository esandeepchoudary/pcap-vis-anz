import { X } from 'lucide-react'
import type { Asset } from '../api/client'
import { useAssets } from '../api/assets'
import { useLinks, useOtOperations } from '../api/purdue'
import { useInspector } from '../inspector/context'
import { assetLabel } from '../lib/assets'
import { formatDateTime, formatNumber, purdueLabel } from '../lib/format'
import { bypassesDmz } from '../lib/purdue'

export function AssetButton({ a, eid }: { a: Asset | undefined; eid: number }) {
  const { select } = useInspector()
  if (!a) return <span className="muted">unknown</span>
  return <button type="button" className="link-btn" onClick={() => select({ kind: 'asset', eid, id: a.id })}>{assetLabel(a)}</button>
}

export function LinkDetails({ eid, src, dst, onClose }: { eid: number; src: number; dst: number; onClose: () => void }) {
  const assets = useAssets(eid)
  const links = useLinks(eid)
  const ops = useOtOperations(eid)
  const byId = new Map((assets.data ?? []).map((a) => [a.id, a]))
  const link = links.data?.find((l) => l.src === src && l.dst === dst)
  const mine = (ops.data ?? []).filter((o) => o.src === src && o.dst === dst)
  const s = byId.get(src)
  const d = byId.get(dst)
  return (
    <div aria-label="Connection details">
      <div className="row" style={{ marginBottom: 'var(--space-3)', flexWrap: 'nowrap' }}>
        <div style={{ flex: 1, minWidth: 0, fontWeight: 700 }}>Connection</div>
        <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close connection details" onClick={onClose}><X size={16} /></button>
      </div>
      {links.isSuccess && !link && <p className="muted">This connection is no longer in any capture.</p>}
      {link && (
        <>
          <div className="inspector-section">
            <dl className="kv">
              <dt>From (client)</dt><dd><AssetButton a={s} eid={eid} /> <span className="muted">{s && purdueLabel(s.purdue_level)}</span></dd>
              <dt>To (server)</dt><dd><AssetButton a={d} eid={eid} /> <span className="muted">{d && purdueLabel(d.purdue_level)}</span></dd>
              <dt>Flows</dt><dd>{formatNumber(link.flows)} · {formatNumber(link.packets)} pkts</dd>
              <dt>Seen</dt><dd>{formatDateTime(link.first_seen)} – {formatDateTime(link.last_seen)}</dd>
              <dt>Captures</dt><dd>{link.captures.length}</dd>
            </dl>
            {s && d && bypassesDmz(s.purdue_level, d.purdue_level) && (
              <div className="alert alert-warn" style={{ marginTop: 'var(--space-2)' }}>
                Goes straight from {purdueLabel(s.purdue_level)} to {purdueLabel(d.purdue_level)}, bypassing the industrial DMZ.
              </div>
            )}
          </div>
          <div className="inspector-section">
            <h3>Protocols</h3>
            <ul className="evidence">{link.protocols.map((p) => (
              <li key={p.protocol}><strong>{p.protocol}</strong> <span className="muted">{p.ports.join(', ')}</span>
                <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>{formatNumber(p.flows)} flows · {formatNumber(p.packets)} pkts{p.ot_writes ? ` · ${p.ot_writes} writes` : ''}</div></li>
            ))}</ul>
          </div>
          {mine.length > 0 && (
            <div className="inspector-section">
              <h3>OT commands</h3>
              <ul className="evidence" aria-label="OT commands on this connection">{mine.map((o) => (
                <li key={`${o.protocol}-${o.function}-${o.kind}-${o.function_code}`}>
                  <span className={`badge ${o.kind === 'write' ? 'badge-danger' : o.kind === 'error' ? 'badge-warn' : ''}`}>{o.kind}</span>{' '}
                  {o.function} <span className="muted">×{formatNumber(o.count)}</span>
                  {o.sample && <div className="muted" style={{ fontSize: 'var(--text-xs)' }}>{o.sample}</div>}
                </li>
              ))}</ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}
