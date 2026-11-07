import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import type { Asset } from '../api/client'
import { InspectorContext, type Selection } from '../inspector/context'
import { engagement, mockApi, renderWithProviders } from '../test/utils'
import { GlobalSearch } from './GlobalSearch'

const plc = {
  id: 1, origin: 'observed', version: 1, ips: ['10.50.0.10'], macs: ['00:1b:1b:00:00:10'], name: 'PLC-A1', asset_type: 'PLC', purdue_level: 1,
  zone: null, criticality: null, vendor: 'Siemens', model: null, firmware: null, serial: null, location: null, owner: null, tags: [], notes: null,
  overridden: [], type_confidence: null, mac_vendor: null, is_private: true, protocols: [], vlans: [], ot_role: 'unknown', os_hint: null,
  packets: 0, bytes: 0, first_seen: null, last_seen: null, capture_count: 1, updated_at: '',
} as Asset

let picked: Selection = null
function Harness({ eid }: { eid: number | null }) {
  const [selection, setSel] = useState<Selection>(null)
  const select = (s: Selection) => { picked = s; setSel(s) }
  return <InspectorContext.Provider value={{ selection, select }}><GlobalSearch eid={eid} /></InspectorContext.Provider>
}

describe('Global search', () => {
  it('finds an asset by IP and opens it in the inspector with the keyboard', async () => {
    mockApi({
      'GET /api/engagements/7/assets': [plc],
      'GET /api/engagements/7/findings': [],
      'GET /api/engagements/7/zones': [],
    })
    renderWithProviders(<Harness eid={7} />)
    const box = screen.getByRole('combobox', { name: 'Search' })
    await userEvent.type(box, '10.50.0.10')
    const list = await screen.findByRole('listbox', { name: 'Search results' })
    await waitFor(() => expect(within(list).getByRole('option', { name: /PLC-A1/ })).toHaveAttribute('aria-selected', 'true'))
    await userEvent.keyboard('{Enter}')
    expect(picked).toEqual({ kind: 'asset', eid: 7, id: 1 })
    expect(box).toHaveValue('')
    expect(screen.queryByRole('listbox')).toBeNull()
  })

  it('says when nothing matches, and "/" focuses the box', async () => {
    mockApi({ 'GET /api/engagements/7/assets': [plc], 'GET /api/engagements/7/findings': [], 'GET /api/engagements/7/zones': [] })
    renderWithProviders(<Harness eid={7} />)
    const box = screen.getByRole('combobox', { name: 'Search' })
    await userEvent.keyboard('/')
    expect(box).toHaveFocus()
    await userEvent.keyboard('nonexistent')
    expect(await screen.findByText('No matches')).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(box).toHaveValue('')
  })

  it('searches engagements when none is open', async () => {
    mockApi({ 'GET /api/engagements': [engagement] })
    renderWithProviders(<Harness eid={null} />)
    await userEvent.type(screen.getByRole('combobox', { name: 'Search' }), 'acme')
    expect(await screen.findByRole('option', { name: /ACME Plant 3/ })).toBeInTheDocument()
  })
})
