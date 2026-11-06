import { screen, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { expect, it } from 'vitest'
import { engagement, laptopSystem, mockApi, renderWithProviders } from '../test/utils'
import { EngagementLayout } from './EngagementLayout'
import { EngagementOverview } from './EngagementOverview'

it('shows the engagement dashboard with totals and asset breakdowns', async () => {
  mockApi({
    'GET /api/engagements/7': engagement,
    'GET /api/engagements/7/audit': [],
    'GET /api/engagements/7/members': [],
    'GET /api/engagements/7/dashboard': {
      captures: 2, captures_done: 2, packets: 12000, assets: 27, assets_edited: 3,
      assets_by_level: { '-1': 4, '1': 3, '3': 1, '4': 19 }, assets_by_type: { 'Web Server': 6, PLC: 2 },
      ot_connections: 2, ot_writes: 7, zones: 2, conduits: 1, violations: 1,
      findings: { critical: 2, high: 1, medium: 0, low: 0, info: 0 }, credentials: 4, files: 1,
    },
  })
  renderWithProviders(
    <Routes><Route path="/e/:eid" element={<EngagementLayout />}><Route path="overview" element={<EngagementOverview system={laptopSystem} />} /></Route></Routes>,
    { route: '/e/7/overview' },
  )
  const tiles = await screen.findByLabelText('Engagement totals')
  expect(within(tiles).getByText('2 / 2')).toBeInTheDocument()
  expect(within(tiles).getByText('27')).toBeInTheDocument()
  expect(within(tiles).getByText('Zone violations').previousSibling).toHaveTextContent('1')
  const levels = screen.getByLabelText('Assets by Purdue level')
  expect(levels).toHaveTextContent('Unclassified4')
  expect(levels).toHaveTextContent('L419')
  expect(screen.getByText('2 critical')).toBeInTheDocument()
})
