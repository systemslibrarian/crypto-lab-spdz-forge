import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/**
 * Drive every panel into its post-interaction states before scanning — an
 * unscanned state is an ungated state. This walks: the addition run, all six
 * Beaver steps, both break-it outcomes (fresh, then reuse so the ALARM state
 * is what remains), the MAC-check cheat (abort + alarm columns), the honest
 * MAC-check run, preprocessing, and the variance run in both the lying
 * (abort) and honest (accepted) variants.
 */
async function driveDemos(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  })

  // Panel 1 — addition.
  await page.getByRole('button', { name: 'Share & add' }).click()
  await expect(page.locator('#panel-add table.share-table')).toBeVisible()

  // Panel 2 — Beaver stepper, all six steps.
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  const next = page.getByRole('button', { name: 'Next step →' })
  for (let i = 0; i < 5; i++) {
    await next.click()
  }
  await expect(page.locator('#panel-beaver .wire')).toBeVisible()

  // Break-it: fresh triple first, spent-triple reuse last (ALARM state stays rendered).
  await page.getByRole('button', { name: 'Use a fresh triple' }).click()
  await expect(page.locator('#panel-beaver .chip-ok').last()).toBeVisible()
  await page.getByRole('button', { name: 'Reuse the spent triple' }).click()
  await expect(page.locator('#panel-beaver .chip-alarm')).toBeVisible()

  // Panel 3 — MAC check: cheat (delta 100 → semi-honest ALARM, SPDZ abort)…
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac .proto-col')).toHaveCount(2)
  // …and the honest run (delta 0 → both accept), then cheat again so the
  // alarm/abort variant is the state that gets scanned.
  await page.locator('#mac-delta').fill('0')
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac .chip-ok').first()).toBeVisible()
  await page.locator('#mac-delta').fill('100')
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac .chip-alarm')).toBeVisible()

  // Panel 4 — preprocessing refill (keeps the bank stocked for the variance runs).
  await page.getByRole('button', { name: /Run preprocessing \(deal/ }).click()

  // Panel 5 — variance: lying variant (abort) first, honest (accepted) last.
  await page.locator('#var-lie').check()
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await expect(page.locator('#panel-var .chip-ok')).toBeVisible()
  await page.locator('#var-lie').uncheck()
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await expect(page.locator('#panel-var .chip-ok').first()).toBeVisible()

  // Reveal all progressive-disclosure content.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => {
      d.open = true
    })
  })
  await page.waitForTimeout(300)
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([])
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.')
  await driveDemos(page)
  await scan(page)
})

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.')
  await page.locator('#cl-theme-toggle').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await driveDemos(page)
  await scan(page)
})
