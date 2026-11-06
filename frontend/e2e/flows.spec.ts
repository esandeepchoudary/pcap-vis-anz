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

test('flows, DNS and the packet inspector on a real capture; dashboard on the overview', async ({ page }) => {
  await signIn(page)
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('400')) errors.push(m.text()) })
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(`Flows ${Date.now()}`)
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  const eid = Number(page.url().match(/\/e\/(\d+)\//)![1])
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible({ timeout: 90_000 })

  await page.goto(`/e/${eid}/overview`)
  const tiles = page.getByLabel('Engagement totals')
  await expect(tiles.getByText('Assets', { exact: true })).toBeVisible()
  await expect(page.getByLabel('Assets by Purdue level')).toBeVisible()

  await page.goto(`/e/${eid}/flows`)
  await expect(page.getByLabel('Network graph').locator('.react-flow__node').first()).toBeVisible()
  await page.getByRole('tab', { name: 'Flows' }).click()
  await page.getByLabel('Filter flows').fill('modbus')
  await expect(page.getByRole('table', { name: 'Flows' })).toContainText('10.0.2.50:502')

  await page.getByRole('tab', { name: 'Packets' }).click()
  await page.getByLabel('Display filter').fill('modbus.func_code == 6')
  await page.getByRole('button', { name: 'Apply' }).click()
  const row = page.getByRole('table', { name: 'Packets' }).getByRole('row').filter({ hasText: 'Write Single Register' }).first()
  await row.click()
  await expect(page.getByLabel('Packet details')).toContainText('Modbus/TCP')

  await page.getByLabel('Display filter').fill('not.a.field == 1')
  await page.getByRole('button', { name: 'Apply' }).click()
  await expect(page.getByText(/is not a valid protocol or protocol field/)).toBeVisible()
  expect(errors).toEqual([])
})
