import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it } from 'vitest'
import { VersionBadge } from './Credits'

it('shows the credits after five quick clicks on the version, and closes with Escape', async () => {
  render(<VersionBadge version="1.2.0" />)
  const badge = screen.getByText('v1.2.0')
  for (let i = 0; i < 4; i++) await userEvent.click(badge)
  expect(screen.queryByRole('dialog')).toBeNull()
  await userEvent.click(badge)
  const dialog = screen.getByRole('dialog', { name: 'PCAP Visualizer v1.2.0' })
  expect(dialog).toHaveTextContent('Sandeep Egalapati')
  expect(dialog).toHaveTextContent('Claude, by Anthropic')
  await userEvent.keyboard('{Escape}')
  expect(screen.queryByRole('dialog')).toBeNull()
})
