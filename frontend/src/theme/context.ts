import { createContext, useContext } from 'react'

export type Theme = 'light' | 'dark'
export const THEME_KEY = 'pcapvis.theme'
export const ThemeContext = createContext<{ theme: Theme; toggle: () => void } | null>(null)

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used inside ThemeProvider')
  return ctx
}
