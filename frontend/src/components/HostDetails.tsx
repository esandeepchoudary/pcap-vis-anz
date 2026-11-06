import { X } from 'lucide-react'
import { Fragment } from 'react'
import type { Host } from '../api/client'
import { formatBytes, formatDateTime, formatNumber, purdueLabel } from '../lib/format'

export function HostDetails({ host, onClose }: { host: Host; onClose: () => void }) {
  const identity = Object.entries(host.identity ?? {})
  return (
    <div aria-label={`Host ${host.ip}`}>
      <div className="row" style={{ marginBottom: 'var(--space-3)' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="mono" style={{ fontWeight: 700 }}>{host.ip}</div>
          {host.hostname && <div className="muted" style={{ fontSize: 'var(--text-sm)' }}>{host.hostname}</div>}
        </div>
        <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close host details" onClick={onClose}>
          <X size={16} />
        </button>
      </div>
      <div className="inspector-section">
        <h3>Classification</h3>
        <div className="row">
          <strong>{host.host_type}</strong>
          <span className={`badge ${host.host_type_confidence === 'high' ? 'badge-ok' : host.host_type_confidence === 'medium' ? 'badge-warn' : ''}`}>
            {host.host_type_confidence} confidence
          </span>
          <span className="badge badge-accent">Purdue {purdueLabel(host.purdue_level)}</span>
        </div>
        <ul className="evidence" style={{ marginTop: 'var(--space-2)' }} aria-label="Evidence">
          {[...host.host_type_evidence, ...host.purdue_evidence].map((e, i) => <li key={i}>{e.detail}</li>)}
        </ul>
      </div>
      <div className="inspector-section">
        <h3>Identity</h3>
        <dl className="kv">
          <dt>MAC</dt><dd className="mono">{host.mac ?? (host.mac_is_gateway ? 'behind a router' : '—')}</dd>
          <dt>Vendor</dt><dd>{host.mac_vendor ?? '—'}</dd>
          <dt>OS hint</dt><dd>{host.os_hint ?? '—'}{host.ttl != null && <span className="muted"> (TTL {host.ttl})</span>}</dd>
          <dt>VLANs</dt><dd>{host.vlans.length ? host.vlans.join(', ') : host.vlan_untagged ? 'untagged' : '—'}</dd>
          {host.ot_role !== 'unknown' && <><dt>OT role</dt><dd>{host.ot_role}</dd></>}
          {host.modbus_unit_ids.length > 0 && <><dt>Modbus units</dt><dd>{host.modbus_unit_ids.join(', ')}</dd></>}
          {identity.map(([k, v]) => (
            <Fragment key={k}><dt>{k.replaceAll('_', ' ')}</dt><dd>{v}</dd></Fragment>
          ))}
        </dl>
      </div>
      {host.services.length > 0 && (
        <div className="inspector-section">
          <h3>Services</h3>
          <ul className="evidence">
            {host.services.map((s) => (
              <li key={`${s.transport}/${s.port}`}>{s.protocol} on {s.transport}/{s.port} · {s.clients} client(s) · {formatNumber(s.packets)} pkts</li>
            ))}
          </ul>
        </div>
      )}
      <div className="inspector-section">
        <h3>Traffic</h3>
        <dl className="kv">
          <dt>Sent</dt><dd>{formatNumber(host.packets_sent)} pkts · {formatBytes(host.bytes_sent)}</dd>
          <dt>Received</dt><dd>{formatNumber(host.packets_recv)} pkts · {formatBytes(host.bytes_recv)}</dd>
          <dt>First seen</dt><dd>{formatDateTime(host.first_seen)}</dd>
          <dt>Last seen</dt><dd>{formatDateTime(host.last_seen)}</dd>
          {host.protocols.length > 0 && <><dt>Protocols</dt><dd>{host.protocols.join(', ')}</dd></>}
        </dl>
      </div>
    </div>
  )
}
