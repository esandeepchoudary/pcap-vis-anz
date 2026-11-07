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

test('triage a finding, then download the report and exports', async ({ page }, testInfo) => {
  await signIn(page)
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(`Report ${Date.now()}`)
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  const eid = Number(page.url().match(/\/e\/(\d+)\//)![1])
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible({ timeout: 90_000 })

  await page.goto(`/e/${eid}/findings`)
  await page.getByRole('table', { name: 'Findings' }).getByText('PLC program download (S7comm)').click()
  const panel = page.getByLabel('Finding details')
  await panel.getByLabel('Status').selectOption('confirmed')
  await panel.getByLabel('Recommendation').fill('Allow S7 program downloads only from the engineering workstation.')
  await panel.getByRole('button', { name: 'Save notes' }).click()
  await expect(page.getByRole('table', { name: 'Findings' }).getByRole('row', { name: /PLC program download/ })).toContainText('Confirmed')

  await page.goto(`/e/${eid}/report`)
  const save = async (name: RegExp, file: string, card?: string) => {
    const scope = card ? page.getByRole('region', { name: card }) : page
    const [dl] = await Promise.all([page.waitForEvent('download'), scope.getByRole('link', { name }).click()])
    const out = testInfo.outputPath(file)
    await dl.saveAs(out)
    return out
  }
  const htmlFile = await save(/HTML/, 'report.html')
  const html = fs.readFileSync(htmlFile, 'utf-8')
  expect(html).toContain('Allow S7 program downloads only from the engineering workstation.')
  expect(html).toContain('<h1>Executive summary</h1>')
  expect(fs.statSync(await save(/Word/, 'report.docx')).size).toBeGreaterThan(5000)
  expect(fs.statSync(await save(/Excel/, 'assets.xlsx')).size).toBeGreaterThan(3000)
  expect(fs.readFileSync(await save(/draw.io/, 'purdue.drawio', 'Purdue diagram'), 'utf-8')).toContain('<mxfile')
  expect(fs.readFileSync(await save(/SVG/, 'architecture.svg', 'Architecture diagram'), 'utf-8')).toContain('<svg')
  expect(errors).toEqual([])
})
