import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => {
      d.open = true
    })
  })
}

async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  })
}

/**
 * Phase A drives every ALARM/ABORT state: the reuse leak, the opening-lie
 * attack, the MAC cheat, the σ-last-sender attack, and the lying-hospital
 * variance abort. These states are scanned while rendered — an unscanned
 * state is an ungated state.
 */
async function driveAbortStates(page: Page): Promise<void> {
  await killMotion(page)

  // Panel 1 — addition.
  await page.getByRole('button', { name: 'Share & add' }).click()
  await expect(page.locator('#panel-add table.share-table').first()).toBeVisible()

  // Panel 2 — Beaver stepper, all six steps.
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  const next = page.getByRole('button', { name: 'Next step →' })
  for (let i = 0; i < 5; i++) {
    await next.click()
  }
  await expect(page.locator('#panel-beaver .wire')).toBeVisible()

  // Break-it 1: reuse the spent triple (leak → ALARM).
  await page.getByRole('button', { name: 'Reuse the spent triple' }).click()
  await expect(page.locator('#panel-beaver .chip-alarm').first()).toBeVisible()

  // Break-it 2: lie during the d opening (valid-MAC-wrong-product + abort).
  await page.getByRole('button', { name: 'Lie during the opening' }).click()
  await expect(page.getByText('a WRONG product with a perfectly VALID MAC')).toBeVisible()

  // Panel 3 — MAC cheat (delta 100 → semi-honest ALARM, SPDZ abort)…
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac .proto-col').first()).toBeVisible()
  // …and the σ-last-sender attack inside the advanced disclosure.
  await openAllDetails(page)
  await page.getByRole('button', { name: 'Cheat & send your σ last' }).click()
  await expect(page.getByText('forged value accepted — no α guessing, just patience')).toBeVisible()

  // Panel 4 — preprocessing refill (keeps the bank stocked).
  await page.getByRole('button', { name: /Run preprocessing \(deal/ }).click()

  // Panel 5 — variance with the lying-hospital scenario (abort state).
  await page.locator('#var-lie').check()
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await expect(page.getByText('ABORT — no statistic released')).toBeVisible()

  await openAllDetails(page)
  await page.waitForTimeout(300)
}

/** Phase B drives the honest/accepted variants that phase A's states replaced. */
async function driveHonestStates(page: Page): Promise<void> {
  await page.locator('#mac-delta').fill('0')
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac .chip-ok').first()).toBeVisible()

  await page.getByRole('button', { name: 'Use a fresh triple' }).click()
  await expect(page.getByText('No leak: a fresh random')).toBeVisible()

  await page.locator('#var-lie').uncheck()
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await expect(page.getByText('Population variance:')).toBeVisible()

  await openAllDetails(page)
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

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations — ${theme} theme, abort states and honest states`, async ({ page }) => {
    await page.goto('.')
    if (theme === 'light') {
      await page.locator('#cl-theme-toggle').click()
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
    }
    await driveAbortStates(page)
    await scan(page) // scan the alarm/abort variants while they are rendered
    await driveHonestStates(page)
    await scan(page) // then the accepted variants that replaced them
  })
}
