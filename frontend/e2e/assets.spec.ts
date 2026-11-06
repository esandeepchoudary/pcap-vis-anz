import { expect, test, type Page } from '@playwright/test'
import fs from 'node:fs'
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

async function engagementWithDemo(page: Page, name: string) {
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(name)
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  const eid = Number(page.url().match(/\/e\/(\d+)\//)![1])
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible({ timeout: 90_000 })
  return eid
}

const assetRow = (page: Page, ip: string) =>
  page.getByRole('table', { name: 'Assets' }).getByRole('row').filter({ has: page.getByText(ip, { exact: true }) })

test('asset inventory: edit with reason, history, bulk edit, CSV export', async ({ page }, testInfo) => {
  const errors: string[] = []
  await signIn(page) // before listening: the sign-in page's 401 from /api/auth/me is expected
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  const eid = await engagementWithDemo(page, `Assets ${Date.now()}`)

  await page.getByRole('navigation', { name: 'Workflow stages' }).getByRole('link', { name: 'Assets' }).click()
  await expect(page.getByRole('heading', { name: 'Asset inventory' })).toBeVisible()
  const plc = assetRow(page, '10.0.2.51')
  await expect(plc).toContainText('PLC')

  // Edit one asset in the inspector.
  await plc.click()
  const form = page.getByRole('form', { name: 'Asset fields' })
  await form.getByLabel('Purdue level').selectOption('2')
  await form.getByLabel('Zone').fill('Line 2 cell')
  await form.getByLabel('Reason (recorded in history)').fill('Confirmed on site walkdown')
  await form.getByRole('button', { name: 'Save changes' }).click()
  await expect(form.getByText('Why: Confirmed on site walkdown').first()).toBeVisible()
  await expect(plc).toContainText('Line 2 cell')
  await expect(plc.getByLabel('set manually').first()).toBeVisible()

  // Survives a reload; the history explains it.
  await page.reload()
  await expect(assetRow(page, '10.0.2.51')).toContainText('L2')
  await assetRow(page, '10.0.2.51').click()
  await page.getByRole('tab', { name: 'History' }).click()
  const history = page.getByLabel('Change history')
  await expect(history).toContainText('Purdue level: L1 → L2')
  await expect(history).toContainText('Confirmed on site walkdown')

  // Bulk: tag two assets with a zone.
  await page.getByLabel('Select 10.0.2.10', { exact: true }).check()
  await assetRow(page, '10.0.2.51').getByRole('checkbox').check()
  const bar = page.getByRole('region', { name: 'Bulk edit' })
  await expect(bar).toContainText('2 selected')
  await bar.getByLabel('Field to change').selectOption('criticality')
  await bar.getByLabel('New value').selectOption('high')
  await bar.getByRole('button', { name: 'Apply' }).click()
  await expect(bar).toBeHidden()
  await expect(assetRow(page, '10.0.2.51')).toContainText('high')

  // The CSV register carries the edits.
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: /Export CSV/ }).click()])
  const file = testInfo.outputPath('assets.csv')
  await download.saveAs(file)
  const csv = fs.readFileSync(file, 'utf-8')
  expect(csv).toContain('Line 2 cell')
  expect(csv.split('\n')[0]).toContain('purdue_level')
  expect(eid).toBeGreaterThan(0)
  expect(errors).toEqual([])
})

test('edits appear live for another user without reloading', async ({ browser }) => {
  const a = await (await browser.newContext()).newPage()
  const b = await (await browser.newContext()).newPage()
  await signIn(a)
  await signIn(b)
  const eid = await engagementWithDemo(a, `Live ${Date.now()}`)
  await b.goto(`/e/${eid}/assets`)
  await expect(assetRow(b, '10.0.2.51')).toContainText('PLC')

  await a.goto(`/e/${eid}/assets`)
  await assetRow(a, '10.0.2.51').click()
  await a.getByRole('form', { name: 'Asset fields' }).getByLabel('Zone').fill('Shared zone')
  await a.getByRole('button', { name: 'Save changes' }).click()
  await expect(assetRow(a, '10.0.2.51')).toContainText('Shared zone')

  await expect(assetRow(b, '10.0.2.51')).toContainText('Shared zone', { timeout: 10_000 })
})
