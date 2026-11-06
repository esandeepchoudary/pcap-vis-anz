import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { E2E_ADMIN } from '../playwright.config'

const DEMO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/network-capture-demo.pcap')
const H = { 'X-PcapVis-Client': '1' }

async function signIn(page: Page) {
  await page.goto('/')
  await page.getByLabel('Username').fill(E2E_ADMIN.username)
  await page.getByLabel('Password').fill(E2E_ADMIN.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
}

test('zones and conduits: violation found, approved as a conduit, drawn on the diagram', async ({ page }) => {
  await signIn(page)
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(`Zones ${Date.now()}`)
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  const eid = Number(page.url().match(/\/e\/(\d+)\//)![1])
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible({ timeout: 90_000 })

  // Put the engineering workstation and the PLCs in zones (bulk edit API).
  const assets: { id: number; ips: string[] }[] = await (await page.request.get(`/api/engagements/${eid}/assets`)).json()
  const id = (ip: string) => assets.find((a) => a.ips.includes(ip))!.id
  for (const [ips, zone] of [[['10.0.2.10'], 'Control'], [['10.0.2.50', '10.0.2.51'], 'Cell 1']] as const) {
    const r = await page.request.post(`/api/engagements/${eid}/assets/bulk`, { headers: H, data: { asset_ids: ips.map(id), set: { zone } } })
    expect(r.ok()).toBe(true)
  }

  await page.goto(`/e/${eid}/architecture`)
  await page.getByRole('tab', { name: 'Zones & conduits' }).click()
  for (const name of ['Cell 1', 'Control']) {
    await page.getByRole('row', { name: new RegExp(name) }).getByRole('button', { name: 'Define' }).click()
    await expect(page.getByLabel(`Zone name ${name}`)).toBeVisible()
  }
  await page.getByRole('tab', { name: /Violations/ }).click()
  const table = page.getByRole('table', { name: 'Violations' })
  await expect(table).toContainText('no conduit')
  await table.getByRole('button', { name: 'Approve as conduit' }).first().click()
  await expect(page.getByText('No cross-zone traffic outside the approved conduits.')).toBeVisible()

  await page.getByRole('tab', { name: 'Diagram' }).click()
  const diagram = page.getByLabel('Architecture diagram')
  await expect(diagram.locator('.az-zone', { hasText: 'Control' })).toBeVisible()
  await expect(diagram.locator('.az-conduit')).toHaveCount(1)
  await expect(diagram.locator('.az-violation')).toHaveCount(0)
  expect(errors).toEqual([])
})
