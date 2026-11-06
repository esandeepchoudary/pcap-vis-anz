import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { json, mockApi, renderWithProviders } from '../test/utils'
import { Account } from './Account'

async function fill(current: string, next: string, repeat: string) {
  await userEvent.type(screen.getByLabelText('Current password'), current)
  await userEvent.type(screen.getByLabelText(/New password \(10\+/), next)
  await userEvent.type(screen.getByLabelText('Repeat new password'), repeat)
  await userEvent.click(screen.getByRole('button', { name: 'Change password' }))
}

describe('Account page', () => {
  it('rejects mismatched new passwords without calling the server', async () => {
    const { calls } = mockApi({})
    renderWithProviders(<Account />)
    await fill('old password!!', 'new password one', 'new password two')
    expect(await screen.findByRole('alert')).toHaveTextContent("don't match")
    expect(calls).toHaveLength(0)
  })

  it('changes the password and clears the form', async () => {
    const { calls } = mockApi({ 'POST /api/auth/password': new Response(null, { status: 204 }) })
    renderWithProviders(<Account />)
    await fill('old password!!', 'new password one', 'new password one')
    expect(await screen.findByRole('status')).toHaveTextContent('Password changed.')
    expect(calls[0].body).toEqual({ current_password: 'old password!!', new_password: 'new password one' })
    expect(screen.getByLabelText('Current password')).toHaveValue('')
  })

  it('shows a wrong current password error', async () => {
    mockApi({ 'POST /api/auth/password': json(400, { detail: 'Current password is wrong.' }) })
    renderWithProviders(<Account />)
    await fill('bad password!!', 'new password one', 'new password one')
    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is wrong.')
  })
})
