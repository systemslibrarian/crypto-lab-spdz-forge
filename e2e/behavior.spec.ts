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

test('MAC panel: shifting the MAC share by α·Δ forges a valid MAC — Σσᵢ = 0, no abort', async ({ page }) => {
  // The panel names this attack ("shift your MAC share by α·Δ") and prints α.
  // This test executes it end to end: the guarantee is that the check is worth
  // exactly as much as α is secret, and here the dealer hands α over.
  await page.goto('.')
  const forging = (await page.locator('#mac-forging-value').textContent())!.trim()
  expect(forging).toMatch(/^\d+$/)
  await page.locator('#mac-delta').fill('100')
  await page.locator('#mac-delta-gamma').fill(forging)
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  // The forged value is released, and the SPDZ column says so.
  await expect(page.locator('#panel-mac').getByText('ACCEPTED — opened value 142')).toHaveCount(2)
  await expect(page.getByText('ALARM — a forged value carried a valid MAC')).toBeVisible()
  await expect(page.locator('#panel-mac').getByText('ABORT — no value released')).toHaveCount(0)
})

test('MAC panel: a MAC shift that is NOT α·Δ still aborts — no partial credit', async ({ page }) => {
  await page.goto('.')
  const forging = BigInt((await page.locator('#mac-forging-value').textContent())!.trim())
  await page.locator('#mac-delta').fill('100')
  await page.locator('#mac-delta-gamma').fill(String(forging - 1n))
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac').getByText('ABORT — no value released')).toBeVisible()
  await expect(page.getByText('cheating detected — the system worked')).toBeVisible()
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

test('research note is visible and preserves the attack-model limits', async ({ page }) => {
  await page.goto('.')
  const note = page.locator('#off-key-research')
  await expect(note).toBeVisible()
  await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/2533')
  await expect(note).toContainText('preprint')
  await expect(note).toContainText('same global MAC key')
  await expect(note).toContainText('bounded three-party trusted-dealer model')
  await expect(note).toContainText('does not reproduce the evaluated frameworks')
})

test('PR-05: a matching guess passes the masked Off-Key check and both attacker deductions recover y', async ({ page }) => {
  await page.goto('.')
  await page.locator('#offkey-secret').fill('1')
  await page.locator('#offkey-guess').fill('1')
  await page.getByRole('button', { name: 'Run the context comparison' }).click()

  const attack = page.locator('[data-context="off-key"]')
  await expect(attack.getByText('ACCEPTED — masked check value is zero')).toBeVisible()
  await expect(attack.getByText('recovers y = 1')).toBeVisible()
  await expect(attack.getByText('outcome reveals y = 1')).toBeVisible()
  await expect(page.locator('[data-view="attacker"]')).toContainText('contains no y, mask, global key, or honest-party share')
  await expect(page.locator('[data-view="attacker"]')).toContainText('alternative MAC-check protocols')
  await expect(page.locator('#panel-offkey')).toContainText('μ = 0 creates a 1/p false-zero exception')
})

test('PR-05: a wrong bit guess aborts and the observable outcome identifies the other bit', async ({ page }) => {
  await page.goto('.')
  await page.locator('#offkey-secret').fill('1')
  await page.locator('#offkey-guess').fill('0')
  await page.getByRole('button', { name: 'Run the context comparison' }).click()

  const attack = page.locator('[data-context="off-key"]')
  await expect(attack.getByText('ABORT — masked check value is non-zero')).toBeVisible()
  await expect(attack.getByText('outcome reveals y = 1')).toBeVisible()
  await expect(attack).toContainText('For a general field value, one abort would only rule out this guess')
})

test('PR-05: same-context repair and ordinary-corruption control stay distinct from privacy leakage', async ({ page }) => {
  await page.goto('.')
  await page.getByRole('button', { name: 'Run the context comparison' }).click()

  const same = page.locator('[data-context="same"]')
  await expect(same.getByText('ACCEPTED — residual 0')).toBeVisible()
  await expect(same).toContainText('Δ·(g − d)')
  await expect(same).toContainText('not equality to hidden y')
  await expect(page.locator('[data-view="correctness-control"]')).toContainText('wrong computation detected')

  await page.getByText('Omniscient teaching audit: reveal hidden state and verify both formulas').click()
  await expect(page.locator('[data-formula="same"]')).toContainText('independently matched')
  await expect(page.locator('[data-formula="off-key"]')).toContainText('independently matched')
  await expect(page.locator('.offkey-audit')).toContainText('Different αᵢ values across parties are legitimate')
})

test('editable panel controls retire results produced for earlier inputs', async ({ page }) => {
  await page.goto('.')

  await page.getByRole('button', { name: 'Share & add' }).click()
  await expect(page.locator('#add-out')).not.toBeEmpty()
  await page.locator('#add-x').fill('13')
  await expect(page.locator('#add-out')).toBeEmpty()

  await page.getByRole('button', { name: 'Start multiplication' }).click()
  await expect(page.locator('#mul-stage')).toContainText('Step 1')
  await page.locator('#mul-y').fill('8')
  await expect(page.locator('#mul-stage')).toBeEmpty()
  await expect(page.locator('#mul-breakout')).toBeEmpty()

  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#mac-out')).not.toBeEmpty()
  await page.locator('#mac-delta-gamma').fill('1')
  await expect(page.locator('#mac-out')).toBeEmpty()

  await page.getByRole('button', { name: 'Run the context comparison' }).click()
  await expect(page.locator('#offkey-out')).not.toBeEmpty()
  await page.locator('#offkey-guess').fill('0')
  await expect(page.locator('#offkey-out')).toBeEmpty()

  await page.getByRole('button', { name: 'Compute variance over MPC' }).click()
  await expect(page.locator('#var-out')).not.toBeEmpty()
  await page.locator('#var-lie').check()
  await expect(page.locator('#var-out')).toBeEmpty()
})

test('nested Beaver attack controls retire their earlier evidence', async ({ page }) => {
  await page.goto('.')
  await page.getByRole('button', { name: 'Start multiplication' }).click()
  const next = page.getByRole('button', { name: 'Next step →' })
  for (let i = 0; i < 5; i++) await next.click()

  await page.getByRole('button', { name: 'Reuse the spent triple' }).click()
  await expect(page.locator('#mul-reuse-out')).toContainText('LEAK')
  await page.locator('#mul-x2').fill('5')
  await expect(page.locator('#mul-reuse-out')).toBeEmpty()

  await page.getByRole('button', { name: 'Lie during the opening' }).click()
  await expect(page.locator('#mul-opening-out')).not.toBeEmpty()
  await page.locator('#mul-ddelta').fill('10')
  await expect(page.locator('#mul-opening-out')).toBeEmpty()

  await page.locator('#mul-x').fill('9')
  await expect(page.locator('#mul-stage')).toBeEmpty()
  await expect(page.locator('#mul-breakout')).toBeEmpty()
})
