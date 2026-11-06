import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { THEME_KEY, useTheme } from './context'
import { ThemeProvider } from './theme'

function Probe() {
  const { theme, toggle } = useTheme()
  return <button onClick={toggle}>theme:{theme}</button>
}

describe('theme', () => {
  it('defaults to light', () => {
    render(<ThemeProvider><Probe /></ThemeProvider>)
    expect(screen.getByRole('button')).toHaveTextContent('theme:light')
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('restores a saved dark theme', () => {
    localStorage.setItem(THEME_KEY, 'dark')
    render(<ThemeProvider><Probe /></ThemeProvider>)
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('ignores garbage in storage', () => {
    localStorage.setItem(THEME_KEY, '<script>')
    render(<ThemeProvider><Probe /></ThemeProvider>)
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('toggles and persists', async () => {
    render(<ThemeProvider><Probe /></ThemeProvider>)
    await userEvent.click(screen.getByRole('button'))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem(THEME_KEY)).toBe('dark')
    await userEvent.click(screen.getByRole('button'))
    expect(localStorage.getItem(THEME_KEY)).toBe('light')
  })

  it('throws when used outside the provider', () => {
    expect(() => render(<Probe />)).toThrow(/ThemeProvider/)
  })
})
