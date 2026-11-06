import { MousePointerClick, PanelRightClose, PanelRightOpen } from 'lucide-react'
import { useState } from 'react'

const KEY = 'pcapvis.inspector.collapsed'

export function Inspector() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(KEY) === '1')
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
      {!collapsed && (
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
