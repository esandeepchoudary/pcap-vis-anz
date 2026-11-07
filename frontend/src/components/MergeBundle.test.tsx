import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { FakeXhr, renderWithProviders } from '../test/utils'
import { MergeBundle } from './MergeBundle'

afterEach(() => vi.unstubAllGlobals())

it('uploads a bundle to merge and reports what changed, including conflicts', async () => {
  vi.stubGlobal('XMLHttpRequest', FakeXhr)
  FakeXhr.respond = {
    status: 200,
    body: {
      captures_added: 1, captures_skipped: 2, assets_created: 1, assets_updated: 3, fields_applied: 5,
      zones_added: 2, conduits_added: 1, findings_added: 1,
      conflicts: [{ asset_id: 4, asset: 'PLC-LINE2 (10.0.2.51)', field: 'purdue_level', kept: 1, imported: 2 }],
    },
  }
  renderWithProviders(<MergeBundle eid={7} />)
  await userEvent.upload(screen.getByTestId('file-input'), new File(['zip'], 'laptop.pcapvis'))
  const status = await screen.findByRole('status')
  expect(FakeXhr.last?.url).toBe('/api/engagements/7/merge')
  expect(status).toHaveTextContent('1 capture(s) added, 2 already here')
  expect(status).toHaveTextContent('5 edit(s) applied to 3 asset(s)')
  await waitFor(() => expect(screen.getByLabelText('Merge conflicts')).toHaveTextContent('PLC-LINE2 (10.0.2.51): purdue level kept "L1", bundle had "L2"'))
})

it('shows why a merge was refused', async () => {
  vi.stubGlobal('XMLHttpRequest', FakeXhr)
  FakeXhr.respond = { status: 400, body: { detail: 'Not a .pcapvis bundle (not a zip archive).' } }
  renderWithProviders(<MergeBundle eid={7} />)
  await userEvent.upload(screen.getByTestId('file-input'), new File(['x'], 'bad.pcapvis'))
  expect(await screen.findByRole('alert')).toHaveTextContent('Not a .pcapvis bundle')
})
