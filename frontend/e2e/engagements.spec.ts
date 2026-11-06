import { expect, test, type Page } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { E2E_ADMIN } from '../playwright.config'

const DEMO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/network-capture-demo.pcap')

async function signIn(page: Page, username = E2E_ADMIN.username, password = E2E_ADMIN.password) {
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
}

async function newEngagement(page: Page, name: string) {
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(name)
  await page.getByLabel('Client').fill('ACME')
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  return Number(page.url().match(/\/e\/(\d+)\//)![1])
}

test('engagement journey: capture point, upload, live analysis, report, inspector', async ({ page }) => {
  const errors: string[] = []
  await signIn(page)
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  await newEngagement(page, `Journey ${Date.now()}`)

  const points = page.getByRole('region', { name: 'Capture points' })
  await points.getByRole('button', { name: /Add/ }).click()
  await points.getByLabel('Capture point name').fill('Core switch SPAN')
  await points.getByRole('button', { name: 'Save' }).click()
  await expect(points.locator('li strong', { hasText: 'Core switch SPAN' })).toBeVisible()

  await expect(page.getByRole('option', { name: 'Core switch SPAN' }).first()).toBeAttached()
  await page.getByLabel('Capture point for upload').selectOption({ label: 'Core switch SPAN' })
  await page.getByTestId('file-input').setInputFiles(DEMO)
  // The analysis runs in the background; the row updates live (server-sent events), no reload.
  const link = page.getByRole('link', { name: 'network-capture-demo.pcap', exact: true })
  await expect(link).toBeVisible({ timeout: 90_000 })
  const row = page.getByRole('row', { name: /network-capture-demo.pcap/ })
  await expect(row.getByText('Done')).toBeVisible()
  await expect(row.getByText(/\d+ critical/)).toBeVisible()

  await link.click()
  await expect(page.getByRole('article').first()).toContainText(/critical/i)
  await expect(page.getByText('PLC program download (S7comm)')).toBeVisible()
  await page.getByRole('tab', { name: /Hosts/ }).click()
  await page.getByRole('row', { name: /10\.0\.2\.10/ }).click()
  const inspector = page.getByLabel('Host 10.0.2.10')
  await expect(inspector.getByText('Engineering Workstation', { exact: true })).toBeVisible()
  await expect(inspector.getByText(/Downloads PLC program blocks/)).toBeVisible()

  await page.getByRole('tab', { name: /Credentials/ }).click()
  await expect(page.getByText('P@ssw0rd123!')).toHaveClass(/masked/)
  expect(errors).toEqual([])
})

test('export a .pcapvis bundle and import it again', async ({ page }, testInfo) => {
  await signIn(page)
  const eid = await newEngagement(page, `Export ${Date.now()}`)
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('link', { name: 'network-capture-demo.pcap', exact: true })).toBeVisible({ timeout: 90_000 })

  await page.goto(`/e/${eid}/overview`)
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: /Export .pcapvis/ }).click()])
  const file = testInfo.outputPath('bundle.pcapvis')
  await download.saveAs(file)
  expect(fs.statSync(file).size).toBeGreaterThan(1000)

  await page.goto('/')
  await page.getByTestId('import-input').setInputFiles(file)
  await expect(page.getByRole('heading', { name: /Export \d+ \(imported\)/ })).toBeVisible()
  await page.getByRole('link', { name: /Captures/ }).click()
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible()
})

test('Quick look analyses one capture and can be found again', async ({ page }) => {
  await signIn(page)
  await page.goto('/quicklook')
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('tab', { name: /Findings/ })).toBeVisible({ timeout: 90_000 })
  await page.goto('/')
  await expect(page.getByRole('region', { name: 'Your Quick looks' }).getByRole('link', { name: 'network-capture-demo.pcap' }).first()).toBeVisible()
})

test('a viewer member can read but not upload, and outsiders cannot see the engagement', async ({ browser, page }) => {
  await signIn(page)
  const eid = await newEngagement(page, `Shared ${Date.now()}`)
  const stamp = Date.now() % 100000
  for (const [name, role] of [[`view${stamp}`, 'viewer'], [`out${stamp}`, 'consultant']]) {
    const r = await page.request.post('/api/users', { headers: { 'X-PcapVis-Client': '1' },
      data: { username: name, password: 'e2e user password', role } })
    expect(r.status()).toBe(201)
  }
  await page.goto(`/e/${eid}/overview`)
  const members = page.getByRole('region', { name: 'Members' })
  const option = members.getByLabel('User to add').locator('option', { hasText: `view${stamp}` })
  await members.getByLabel('User to add').selectOption((await option.getAttribute('value'))!)
  await members.getByLabel('Role for new member').selectOption('viewer')
  await members.getByRole('button', { name: 'Add' }).click()
  await expect(members.getByRole('row', { name: new RegExp(`view${stamp}`) })).toBeVisible()

  const viewer = await browser.newPage()
  await signIn(viewer, `view${stamp}`, 'e2e user password')
  await viewer.goto(`/e/${eid}/captures`)
  await expect(viewer.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  await expect(viewer.getByRole('region', { name: 'Add captures' })).toHaveCount(0)
  const up = await viewer.request.post(`/api/engagements/${eid}/captures`, { headers: { 'X-PcapVis-Client': '1' },
    multipart: { files: { name: 'x.pcap', mimeType: 'application/octet-stream', buffer: fs.readFileSync(DEMO) } } })
  expect(up.status()).toBe(403)

  const outsider = await browser.newPage()
  await signIn(outsider, `out${stamp}`, 'e2e user password')
  await outsider.goto(`/e/${eid}/overview`)
  await expect(outsider.getByRole('alert')).toContainText("doesn't exist or you don't have access")
  await viewer.close()
  await outsider.close()
})
