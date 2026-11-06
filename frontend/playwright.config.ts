import { defineConfig, devices } from '@playwright/test'

// E2E runs the production build served by the real FastAPI backend in team-server mode,
// so it exercises the CSP, cookies, CSRF header, and SPA routing exactly as deployed.
const PORT = Number(process.env.E2E_PORT ?? 8765)
export const E2E_ADMIN = { username: 'admin', password: 'e2e admin password' }

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `rm -rf .e2e-data && uv run --project ../backend pcapvis serve --host 127.0.0.1 --port ${PORT}`,
    url: `http://127.0.0.1:${PORT}/api/health`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      PCAPVIS_MODE: 'server',
      PCAPVIS_DATA_DIR: '.e2e-data',
      PCAPVIS_FRONTEND_DIST: 'dist',
      PCAPVIS_ADMIN_USERNAME: E2E_ADMIN.username,
      PCAPVIS_ADMIN_PASSWORD: E2E_ADMIN.password,
      PCAPVIS_REQUIRE_TSHARK: process.env.PCAPVIS_REQUIRE_TSHARK ?? 'true',
    },
  },
})
