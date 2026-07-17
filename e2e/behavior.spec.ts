/**
 * Functional browser tests: the arithmetic, the abort semantics, the
 * no-attribution rule, and the triple-bank accounting — asserted against the
 * production build, not just visited.
 */
import { expect, test, type Page } from '@playwright/test'

async function bankCount(page: Page): Promise<number> {
  const text = await page.locator('.bank-chip').textContent()
  return Number(/(\d+)/.exec(text ?? '')?.[1] ?? NaN)
}

test('Beaver multiplication computes the real product and drains the bank', async ({ page }) => {
  await page.goto('.')
  const before = await bankCount(page)
  await page.locator('#mul-x').fill('123')
  await page.locator('#mul-y').fill('456')
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  const next = page.getByRole('button', { name: 'Next step →' })
  for (let i = 0; i < 5; i++) await next.click()
  await expect(page.getByText('both sides equal').first()).toBeVisible()
  await expect(page.locator('#panel-beaver').getByText(String(123 * 456)).first()).toBeVisible()
  expect(await bankCount(page)).toBe(before - 1)
})

test('both opening checks are shown as passed on an honest run', async ({ page }) => {
  await page.goto('.')
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  const next = page.getByRole('button', { name: 'Next step →' })
  for (let i = 0; i < 3; i++) await next.click()
  await expect(page.getByText('opening MAC-checked').first()).toBeVisible()
})

test('GS-01: lying during the d opening aborts under SPDZ but yields a valid-MAC wrong product without opening checks', async ({ page }) => {
  await page.goto('.')
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  const next = page.getByRole('button', { name: 'Next step →' })
  for (let i = 0; i < 5; i++) await next.click()
  await page.getByRole('button', { name: 'Lie during the opening' }).click()
  await expect(page.getByText('a WRONG product with a perfectly VALID MAC')).toBeVisible()
  await expect(page.getByText('the lie died at the opening — no product was ever computed')).toBeVisible()
})

test('GS-02: the σ-last-sender attack passes the unordered check and dies against commit-then-open', async ({ page }) => {
  await page.goto('.')
  await page.evaluate(() => document.querySelectorAll('details').forEach((d) => (d.open = true)))
  await page.getByRole('button', { name: 'Cheat & send your σ last' }).click()
  await expect(page.getByText('forged value accepted — no α guessing, just patience')).toBeVisible()
  await expect(page.getByText('the cancellation attempt died — commitments bind before reveals')).toBeVisible()
})

test('MAC panel: same tampered shares — semi-honest accepts (ALARM), SPDZ aborts (OK)', async ({ page }) => {
  await page.goto('.')
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.getByText('ACCEPTED — opened value 142')).toBeVisible()
  await expect(page.getByText('ALARM — a wrong answer was accepted and nobody can tell')).toBeVisible()
  await expect(page.getByText('ABORT — no value released')).toBeVisible()
})

test('GS-03: a variance abort never attributes — no hospital is named in the protocol outcome', async ({ page }) => {
  await page.goto('.')
  await page.locator('#var-lie').check()
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await expect(page.getByText('ABORT — no statistic released')).toBeVisible()
  const outcome = await page.locator('#panel-var .result-region').textContent()
  // The protocol-visible outcome must not name a culprit; only the clearly
  // labeled lab-control note (omniscient view) exists, and even it names no one.
  for (const name of ["St. Mary", 'General', 'County', 'P₀', 'P₁', 'P₂']) {
    expect(outcome).not.toContain(name)
  }
  await expect(page.locator('#panel-var .lab-note')).toBeVisible()
})

test('honest variance matches the direct plaintext computation', async ({ page }) => {
  await page.goto('.')
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  // Inputs 120, 95, 160: M = 3·(120²+95²+160²) − 375² = 147075 − 140625 = 6450.
  await expect(page.getByText('both sides equal')).toBeVisible()
  await expect(page.locator('#panel-var').getByText('6450').first()).toBeVisible()
})

test('empty bank fails closed and preprocessing unblocks it', async ({ page }) => {
  await page.goto('.')
  // Drain the initial 8 triples: two variance runs consume 8.
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await page.locator('#mul-x').fill('3')
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  await expect(page.getByText('Triple bank is empty — the online phase is blocked')).toBeVisible()
  await page.getByRole('button', { name: 'Run preprocessing now' }).click()
  await expect(page.getByText('Step 1 · Share the secrets')).toBeVisible()
})
