import { defineConfig } from '@playwright/test'

const PORT = 4352 // unique across the crypto-lab fleet — never the Vite default 4173

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}/crypto-lab-spdz-forge/`,
    colorScheme: 'dark', // scan the real dark default; the toggle reaches light
  },
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}/crypto-lab-spdz-forge/`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
