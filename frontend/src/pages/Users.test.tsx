import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { adminUser, json, mockApi, renderWithProviders } from '../test/utils'
import { Users } from './Users'

const alice = { ...adminUser, id: 2, username: 'alice', display_name: 'Alice', role: 'consultant' as const }

describe('Users page', () => {
  it('lists users and marks the current one', async () => {
    mockApi({ 'GET /api/users': [adminUser, alice] })
    renderWithProviders(<Users me={adminUser} />)
    const rows = await screen.findAllByRole('row')
    expect(rows).toHaveLength(3) // header + 2
    expect(within(rows[1]).getByText(/admin \(you\)/)).toBeInTheDocument()
    expect(within(rows[2]).getByText('Never')).toBeInTheDocument()
  })

  it('creates a user with the chosen role and refreshes the list', async () => {
    let list = [adminUser]
    const { calls } = mockApi({
      'GET /api/users': () => json(200, list),
      'POST /api/users': (req) => req.json().then((b) => { list = [adminUser, { ...alice, username: b.username }]; return json(201, list[1]) }),
    })
    renderWithProviders(<Users me={adminUser} />)
    const form = await screen.findByRole('form', { name: 'Create user' })
    await userEvent.type(within(form).getByLabelText('Username'), 'bob')
    await userEvent.type(within(form).getByLabelText('Initial password'), 'correct horse battery')
    await userEvent.selectOptions(within(form).getByLabelText('Role'), 'lead')
    expect(within(form).getByText(/lead: Manage engagements/)).toBeInTheDocument()
    await userEvent.click(within(form).getByRole('button', { name: /Add user/ }))
    expect(await screen.findByText('bob')).toBeInTheDocument()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.body).toMatchObject({ username: 'bob', role: 'lead', password: 'correct horse battery' })
    expect(within(form).getByLabelText('Username')).toHaveValue('') // form reset
  })

  it('shows backend validation errors', async () => {
    mockApi({
      'GET /api/users': [adminUser],
      'POST /api/users': json(400, { detail: "User 'bob' already exists." }),
    })
    renderWithProviders(<Users me={adminUser} />)
    const form = await screen.findByRole('form', { name: 'Create user' })
    await userEvent.type(within(form).getByLabelText('Username'), 'bob')
    await userEvent.type(within(form).getByLabelText('Initial password'), 'correct horse battery')
    await userEvent.click(within(form).getByRole('button', { name: /Add user/ }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('already exists')
  })

  it('changes a role and disables a user via PATCH', async () => {
    const { calls } = mockApi({ 'GET /api/users': [adminUser, alice], 'PATCH /api/users/2': alice })
    renderWithProviders(<Users me={adminUser} />)
    await userEvent.selectOptions(await screen.findByLabelText('Role for alice'), 'viewer')
    const row = screen.getByLabelText('Role for alice').closest('tr')!
    await userEvent.click(within(row).getByRole('button', { name: 'Disable' }))
    const patches = calls.filter((c) => c.method === 'PATCH')
    expect(patches.map((p) => p.body)).toEqual([{ role: 'viewer' }, { is_active: false }])
  })

  it('surfaces the last-admin protection error', async () => {
    mockApi({
      'GET /api/users': [adminUser],
      'PATCH /api/users/1': json(400, { detail: 'There must be at least one active admin.' }),
    })
    renderWithProviders(<Users me={adminUser} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Disable' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('at least one active admin')
  })
})
