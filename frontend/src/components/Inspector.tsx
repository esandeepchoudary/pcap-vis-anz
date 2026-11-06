import { MousePointerClick, PanelRightClose, PanelRightOpen } from 'lucide-react'
import { useState } from 'react'
import { useInspector } from '../inspector/context'
import { AssetInspector } from './AssetInspector'
import { HostDetails } from './HostDetails'
import { LinkDetails } from './LinkDetails'

const KEY = 'pcapvis.inspector.collapsed'

export function Inspector() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(KEY) === '1')
  const { selection, select } = useInspector()
  const toggle = () => {
    setCollapsed((c) => {
      localStorage.setItem(KEY, c ? '0' : '1')
      return !c
    })
  }
  return (
    <aside className={`inspector${collapsed ? ' collapsed' : ''}`} aria-label="Inspector">
      <div className="inspector-head">
        {!collapsed && <span>Inspector</span>}
        <button
          type="button"
          className="btn btn-ghost btn-icon btn-sm"
          onClick={toggle}
          aria-label={collapsed ? 'Expand inspector' : 'Collapse inspector'}
        >
          {collapsed ? <PanelRightOpen size={16} /> : <PanelRightClose size={16} />}
        </button>
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
  )
}
