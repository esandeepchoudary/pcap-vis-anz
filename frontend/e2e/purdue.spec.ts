import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { E2E_ADMIN } from '../playwright.config'

const DEMO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/network-capture-demo.pcap')

async function signIn(page: Page) {
  await page.goto('/')
  await page.getByLabel('Username').fill(E2E_ADMIN.username)
  await page.getByLabel('Password').fill(E2E_ADMIN.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
}

test('Purdue map: drag an asset to another level, then see it in the inventory and matrices', async ({ page }) => {
  await signIn(page)
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(`Purdue ${Date.now()}`)
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  const eid = Number(page.url().match(/\/e\/(\d+)\//)![1])
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible({ timeout: 90_000 })

  await page.goto(`/e/${eid}/purdue`)
  await expect(page.getByText(/OT connections/)).toBeVisible()
  const map = page.getByLabel('Purdue map')
  // Two engineering-workstation → PLC connections with writes are drawn.
  await expect(map.locator('.pm-edge-write')).toHaveCount(2)

  // Drag the S7 PLC from L1 into the L2 lane.
  const node = map.locator('.react-flow__node-asset', { hasText: '10.0.2.51' })
  const lane = map.locator('.react-flow__node-lane', { hasText: 'Level 2' })
  const nb = (await node.boundingBox())!
  const lb = (await lane.boundingBox())!
  await page.mouse.move(nb.x + nb.width / 2, nb.y + nb.height / 2)
  await page.mouse.down()
  await page.mouse.move(lb.x + lb.width * 0.6, lb.y + lb.height / 2, { steps: 12 })
  await page.mouse.up()
  await expect(page.getByRole('status').filter({ hasText: 'Moved 10.0.2.51 to L2' })).toBeVisible()

  // The inventory agrees, and the change is in the asset's history with its reason.
  await page.goto(`/e/${eid}/assets`)
  const row = page.getByRole('table', { name: 'Assets' }).getByRole('row').filter({ has: page.getByText('10.0.2.51', { exact: true }) })
  await expect(row).toContainText('L2')
  await row.click()
  await page.getByRole('tab', { name: 'History' }).click()
  await expect(page.getByLabel('Change history')).toContainText('Moved on the Purdue map')

  // Level matrix and OT command log.
  await page.goto(`/e/${eid}/purdue`)
  await page.getByRole('tab', { name: 'Level matrix' }).click()
  await expect(page.getByRole('button', { name: /L3 to L2: 1 pairs/ })).toBeVisible()
  await page.getByRole('tab', { name: /OT commands/ }).click()
  await expect(page.getByRole('table', { name: 'OT commands' })).toContainText('Request download')
  expect(errors).toEqual([])
})
