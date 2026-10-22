import { defineConfig } from '@playwright/test'

const PORT = 4352 // unique across the crypto-lab fleet — never the Vite default 4173

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}/crypto-lab-spdz-forge/`,
    colorScheme: 'dark', // the site intentionally ships a dark-only theme
  },
  webServer: {
    // build first: preview only serves what is already in dist/, so a failed
    // build would leave the last good bundle on disk and the suite would pass
    // green against source that no longer compiles
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}/crypto-lab-spdz-forge/`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
