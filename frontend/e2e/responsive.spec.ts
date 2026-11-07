import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { E2E_ADMIN } from '../playwright.config'

// Every page must fit phones and tablets: no sideways page scroll, navigation reachable, inspector usable.
// Wide content (tables, tab bars, graphs) may scroll inside its own box, never the page.
const DEMO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/network-capture-demo.pcap')
const VIEWPORTS = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'tablet', width: 820, height: 1180 },
]
const PAGES = ['overview', 'captures', 'assets', 'purdue', 'architecture', 'flows', 'findings', 'report']

async function signIn(page: Page) {
  await page.goto('/')
  await page.getByLabel('Username').fill(E2E_ADMIN.username)
  await page.getByLabel('Password').fill(E2E_ADMIN.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
}

/** Elements sticking out past the viewport that aren't inside a scroll container or a graph canvas. */
function overflowing(page: Page) {
  return page.evaluate(() => {
    const vw = document.documentElement.clientWidth
    const out: string[] = []
    for (const el of document.querySelectorAll('.main *')) {
      const r = el.getBoundingClientRect()
      if (r.width === 0 || r.right <= vw + 1) continue
      let a = el.parentElement
      let contained = false
      while (a && !a.classList.contains('main')) {
        if (['auto', 'scroll', 'hidden'].includes(getComputedStyle(a).overflowX) || a.classList.contains('react-flow')) { contained = true; break }
        a = a.parentElement
      }
      if (!contained) out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} (right edge ${Math.round(r.right)} > ${vw})`)
    }
    return { pageWidth: document.documentElement.scrollWidth, vw, offenders: out.slice(0, 5) }
  })
}

let eid = 0
test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage()
  await signIn(page)
  await page.goto('/?new=1')
  await page.getByLabel('Name').fill(`Responsive ${Date.now()} with a long engagement name to test truncation`)
  await page.getByRole('button', { name: 'Create engagement' }).click()
  await expect(page.getByRole('heading', { name: 'Captures', exact: true })).toBeVisible()
  eid = Number(page.url().match(/\/e\/(\d+)\//)![1])
  await page.getByTestId('file-input').setInputFiles(DEMO)
  await expect(page.getByRole('row', { name: /network-capture-demo.pcap/ }).getByText('Done')).toBeVisible({ timeout: 90_000 })
  await page.close()
})

for (const vp of VIEWPORTS) {
  test(`every page fits a ${vp.name} (${vp.width}px)`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height })
    await signIn(page)
    for (const p of ['/', '/quicklook', '/admin/users', '/account', ...PAGES.map((s) => `/e/${eid}/${s}`)]) {
      await page.goto(p)
      await expect(page.locator('.main h1').first()).toBeVisible()
      await page.waitForTimeout(400) // graphs lay out after first paint
      const r = await overflowing(page)
      expect(r.offenders, `${p} at ${vp.width}px`).toEqual([])
      expect(r.pageWidth, `${p} page width at ${vp.width}px`).toBeLessThanOrEqual(r.vw)
      // Every stage stays reachable from the navigation.
      await expect(page.getByRole('navigation', { name: 'Workflow stages' }).getByRole('link', { name: 'Home' })).toBeVisible()
    }
  })

  test(`the inspector opens over the page and closes on a ${vp.name}`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height })
    await signIn(page)
    await page.goto(`/e/${eid}/assets`)
    const inspector = page.getByRole('complementary', { name: 'Inspector' })
    await expect(inspector).toBeHidden()
    await page.locator('table tbody tr').first().click()
    await expect(inspector).toBeVisible()
    // Fully on screen once the slide-in finishes.
    await expect.poll(async () => { const b = (await inspector.boundingBox())!; return b.x + b.width }).toBeLessThanOrEqual(vp.width + 1)
    await page.getByRole('button', { name: 'Close inspector' }).click()
    await expect(inspector).toBeHidden()
  })
}
