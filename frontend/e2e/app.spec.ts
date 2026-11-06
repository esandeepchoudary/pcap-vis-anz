import { expect, test, type Page } from '@playwright/test'
import { E2E_ADMIN } from '../playwright.config'

/** Fail the test on any console error or CSP violation. */
function watchConsole(page: Page) {
  const problems: string[] = []
  page.on('console', (m) => { if (m.type() === 'error') problems.push(m.text()) })
  page.on('pageerror', (e) => problems.push(e.message))
  return problems
}

async function signIn(page: Page, username = E2E_ADMIN.username, password = E2E_ADMIN.password) {
  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
}

test('sign-in page, wrong password, then sign in', async ({ page }) => {
  const problems = watchConsole(page)
  await page.goto('/')
  await expect(page.getByRole('form', { name: 'Sign in' })).toBeVisible()
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password').fill('definitely wrong')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('alert')).toHaveText(/Wrong username or password/)
  await page.getByLabel('Password').fill(E2E_ADMIN.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
  await expect(page.getByText(/tshark \d+\.\d+\.\d+/)).toBeVisible()
  expect(problems.filter((p) => !p.includes('401'))).toEqual([])
})

test('deep links and reload keep the session', async ({ page }) => {
  await signIn(page)
  const problems = watchConsole(page)
  await page.goto('/quicklook')
  await expect(page.getByRole('heading', { name: /Quick look/ })).toBeVisible()
  await page.reload()
  await expect(page.getByRole('heading', { name: /Quick look/ })).toBeVisible()
  expect(problems).toEqual([])
})

test('theme toggle persists across reloads with no flash', async ({ page }) => {
  await signIn(page)
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await page.getByRole('button', { name: 'Switch to dark theme' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
  expect(bg).toBe('rgb(13, 17, 23)')
})

test('admin creates a user who can then sign in with restricted access', async ({ browser, page }) => {
  await signIn(page)
  await page.getByRole('link', { name: 'Users' }).click()
  const form = page.getByRole('form', { name: 'Create user' })
  const username = `viewer${Date.now() % 100000}`
  await form.getByLabel('Username').fill(username)
  await form.getByLabel('Initial password').fill('viewer password 1')
  await form.getByLabel('Role').selectOption('viewer')
  await form.getByRole('button', { name: /Add user/ }).click()
  await expect(page.getByRole('cell', { name: new RegExp(username) })).toBeVisible()

  const other = await browser.newPage()
  await signIn(other, username, 'viewer password 1')
  await expect(other.getByRole('link', { name: 'Users' })).toHaveCount(0)
  await other.goto('/admin/users')
  await expect(other.getByRole('heading', { name: 'Engagements', exact: true })).toBeVisible()
  // The API refuses too, not just the UI.
  const r = await other.request.get('/api/users')
  expect(r.status()).toBe(403)

  // Disabling the user ends their session immediately.
  const row = page.getByRole('row', { name: new RegExp(username) })
  await row.getByRole('button', { name: 'Disable' }).click()
  await expect(row.getByText('Disabled')).toBeVisible()
  await other.reload()
  await expect(other.getByRole('form', { name: 'Sign in' })).toBeVisible()
  await other.close()
})

test('sign out returns to the sign-in page and the old cookie stops working', async ({ page }) => {
  await signIn(page)
  const cookie = (await page.context().cookies()).find((c) => c.name === 'pcapvis_session')
  expect(cookie?.httpOnly).toBe(true)
  expect(cookie?.sameSite).toBe('Strict')
  await page.getByRole('button', { name: /Administrator/ }).click()
  await page.getByRole('menuitem', { name: /Sign out/ }).click()
  await expect(page.getByRole('form', { name: 'Sign in' })).toBeVisible()
  await page.context().addCookies([cookie!])
  expect((await page.request.get('/api/auth/me')).status()).toBe(401)
})

test('security headers are present on the app shell', async ({ request }) => {
  const r = await request.get('/')
  expect(r.headers()['content-security-policy']).toContain("script-src 'self'")
  expect(r.headers()['x-frame-options']).toBe('DENY')
})

test('API rejects unsafe requests without the CSRF header', async ({ request }) => {
  const r = await request.post('/api/auth/login', { data: { username: 'admin', password: E2E_ADMIN.password } })
  expect(r.status()).toBe(403)
})
