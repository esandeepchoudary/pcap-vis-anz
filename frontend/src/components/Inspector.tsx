import { MousePointerClick, PanelRightClose, PanelRightOpen, X } from 'lucide-react'
import { useState } from 'react'
import { useInspector } from '../inspector/context'
import { NARROW, useMediaQuery } from '../lib/useMediaQuery'
import { AssetInspector } from './AssetInspector'
import { FindingDetails } from './FindingDetails'
import { HostDetails } from './HostDetails'
import { LinkDetails } from './LinkDetails'

const KEY = 'pcapvis.inspector.collapsed'

export function Inspector() {
  const [wideCollapsed, setCollapsed] = useState(() => localStorage.getItem(KEY) === '1')
  const { selection, select } = useInspector()
  // Narrow screens: a drawer over the page, open while something is selected (closing clears the selection).
  const narrow = useMediaQuery(NARROW)
  const collapsed = narrow ? !selection : wideCollapsed
  const toggle = () => {
    setCollapsed((c) => {
      localStorage.setItem(KEY, c ? '0' : '1')
      return !c
    })
  }
  return (
    <>
    {narrow && selection && <div className="inspector-backdrop" onClick={() => select(null)} aria-hidden />}
    <aside className={`inspector${collapsed ? ' collapsed' : ''}${narrow ? ' drawer' : ''}`} aria-label="Inspector" aria-hidden={narrow && !selection ? true : undefined}>
      <div className="inspector-head">
        {!collapsed && <span>Inspector</span>}
        {narrow ? (
          <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={() => select(null)} aria-label="Close inspector">
            <X size={16} />
          </button>
        ) : (
          <button
            type="button"
            className="btn btn-ghost btn-icon btn-sm"
            onClick={toggle}
            aria-label={collapsed ? 'Expand inspector' : 'Collapse inspector'}
          >
            {collapsed ? <PanelRightOpen size={16} /> : <PanelRightClose size={16} />}
          </button>
        )}
      </div>
      {!collapsed && selection?.kind === 'host' && (
        <div className="inspector-body">
          <HostDetails host={selection.host} onClose={() => select(null)} />
        </div>
      )}
      {!collapsed && selection?.kind === 'asset' && (
        <div className="inspector-body">
          <AssetInspector key={`${selection.eid}-${selection.id}`} eid={selection.eid} id={selection.id} onClose={() => select(null)} />
        </div>
      )}
      {!collapsed && selection?.kind === 'link' && (
        <div className="inspector-body">
          <LinkDetails eid={selection.eid} src={selection.src} dst={selection.dst} onClose={() => select(null)} />
        </div>
      )}
      {!collapsed && selection?.kind === 'finding' && (
        <div className="inspector-body">
          <FindingDetails key={selection.key} eid={selection.eid} findingKey={selection.key} onClose={() => select(null)} />
        </div>
      )}
      {!collapsed && !selection && (
        <div className="inspector-body">
          <div className="empty">
            <MousePointerClick size={36} strokeWidth={1.5} aria-hidden />
            <strong>Nothing selected</strong>
            <span>Select an asset, flow, or finding to see and edit its details here.</span>
          </div>
        </div>
      )}
    </aside>
    </>
  )
}
