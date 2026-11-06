import { createContext, useContext } from 'react'
import type { Host } from '../api/client'

export type Selection = { kind: 'host'; host: Host } | null

export const InspectorContext = createContext<{ selection: Selection; select: (s: Selection) => void }>({
  selection: null,
  select: () => {},
})

export function useInspector() {
  return useContext(InspectorContext)
}
