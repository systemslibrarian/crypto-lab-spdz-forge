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

// ── Rushing at SPDZ: the MAC key that leaks through a failed check ─────────
//
// Kyster, Huss Nielsen, Oechsner and Scholl, "Rushing at SPDZ", §3.1–§3.2.
// The figures are compared against each other and re-derived here, in the
// test's own BigInt arithmetic over p = 2^61 − 1, rather than asserted as
// strings: α from the printed Σσᵢ, and the released value from the input the
// test typed.

const P61 = (1n << 61n) - 1n
const fieldNeg = (v: bigint): bigint => (P61 - (v % P61)) % P61

async function runRush(page: Page, schedule: string, y: string): Promise<void> {
  await page.fill('#rush-y', y)
  await page.selectOption('#rush-schedule', schedule)
  await page.getByRole('button', { name: 'Run both checks' }).click()
  await expect(page.locator('#rush-verdict')).toBeVisible()
}

test('RUSH-01: concurrent checks — α is recovered exactly and the forged opening releases P₀’s input', async ({ page }) => {
  await page.goto('.')
  await runRush(page, 'concurrent', '987654321')

  // α = −Σσᵢ, recomputed from the Σσᵢ on screen.
  const sigmaSum = BigInt((await page.locator('#rush-sigma-sum').innerText()).trim())
  const recovered = BigInt((await page.locator('#rush-recovered').innerText()).trim())
  expect(recovered).toBe(fieldNeg(sigmaSum))

  await expect(page.locator('[data-check="1"]')).toContainText('HANGING — P₁ withholds its opening')
  await expect(page.locator('[data-check="2"]')).toContainText('ACCEPTED — opened value 987654321')
  await expect(page.locator('[data-check="2"]')).toContainText('ALARM — every MAC check passed')
  expect((await page.locator('#rush-released').innerText()).trim()).toBe('987654321')
  await expect(page.locator('#rush-verdict')).toContainText('P₀’s private input 987654321 was released')

  // The dealer's α, disclosed only in the audit, is the value P₁ computed.
  await page.locator('#rush-out summary', { hasText: 'Dealer’s audit' }).click()
  expect(BigInt((await page.locator('#rush-true-alpha').innerText()).trim())).toBe(recovered)
  await expect(page.locator('#rush-out .offkey-audit')).toContainText('equals the dealer’s α exactly')
})

test('RUSH-02: one check at a time — check 2 aborts in either order and nothing is released', async ({ page }) => {
  await page.goto('.')

  await runRush(page, 'sequential-leak-first', '4242')
  await expect(page.locator('[data-check="1"]')).toContainText('ABORT — the check must finish')
  await expect(page.locator('[data-check="2"]')).toContainText('ABORT — no value released')
  await expect(page.locator('[data-check="2"]')).toContainText('check 1 ended the session')
  await expect(page.locator('#rush-released')).toHaveCount(0)
  await expect(page.locator('#rush-verdict')).toContainText('P₀’s input was not released')

  await runRush(page, 'sequential-forge-first', '4242')
  await expect(page.locator('[data-check="2"]')).toContainText('a guess')
  await expect(page.locator('[data-check="2"]')).toContainText('ABORT — no value released')
  await expect(page.locator('[data-check="1"]')).toContainText('NOT RUN')
  await expect(page.locator('#rush-released')).toHaveCount(0)
  await expect(page.locator('#rush-verdict')).toContainText('P₀’s input was not released')
  await page.locator('#rush-out summary', { hasText: 'Dealer’s audit' }).click()
  await expect(page.locator('#rush-out .offkey-audit')).toContainText('P₁ recovered nothing')
})

test('RUSH-03: the masked check keeps concurrency and loses the leak', async ({ page }) => {
  await page.goto('.')
  await runRush(page, 'masked', '4242')
  await expect(page.locator('[data-check="1"]')).toContainText('The check still fails')
  await expect(page.locator('[data-check="2"]')).toContainText('ABORT — no value released')
  await expect(page.locator('#rush-verdict')).toContainText('P₀’s input was not released')
  const estimate = BigInt((await page.locator('#rush-recovered').innerText()).trim())
  await page.locator('#rush-out summary', { hasText: 'Dealer’s audit' }).click()
  expect(BigInt((await page.locator('#rush-true-alpha').innerText()).trim())).not.toBe(estimate)
  await expect(page.locator('#rush-out .offkey-audit')).toContainText('P₁’s value is not α')
})

test('RUSH-04: changing an input retires the rushing result', async ({ page }) => {
  await page.goto('.')
  await runRush(page, 'concurrent', '77')
  await page.fill('#rush-y', '78')
  await expect(page.locator('#rush-out')).toBeEmpty()
  await runRush(page, 'concurrent', '78')
  await page.selectOption('#rush-schedule', 'masked')
  await expect(page.locator('#rush-out')).toBeEmpty()
  await page.fill('#rush-y', 'abc')
  await page.getByRole('button', { name: 'Run both checks' }).click()
  await expect(page.locator('#rush-out .chip-warn')).toContainText('at most 9 digits')
})

test('RUSH-05: batched what-if — predicted coefficients pass two wrong values, fresh ones abort', async ({ page }) => {
  await page.goto('.')
  const num = async (sel: string): Promise<bigint> => BigInt((await page.locator(sel).innerText()).trim())

  await page.selectOption('#rush-batch-timing', 'known-before')
  await page.getByRole('button', { name: 'Run the batched check' }).click()
  await expect(page.locator('#rush-batch-out')).toContainText('ACCEPTED — the weighted check is unchanged')
  expect(await num('#rush-batch-weighted')).toBe(0n)
  // The opened pair is not the honest (50, 600), and no input explains it:
  // P − 20(S − 20) is re-derived here from the two opened values on screen.
  const s = await num('#rush-batch-s')
  const p = await num('#rush-batch-p')
  expect([s, p]).not.toEqual([50n, 600n])
  const derived = (((p - 20n * (s - 20n)) % P61) + P61) % P61
  expect(derived).not.toBe(0n)
  expect(await num('#rush-batch-residue')).toBe(derived)

  await page.selectOption('#rush-batch-timing', 'drawn-after')
  await expect(page.locator('#rush-batch-out')).toBeEmpty()
  await page.getByRole('button', { name: 'Run the batched check' }).click()
  await expect(page.locator('#rush-batch-out')).toContainText('ABORT — the shift was built for coefficients the check did not use')
  expect(await num('#rush-batch-weighted')).not.toBe(0n)
})

test('RUSH-06: the paper’s two residues are recomputed from its recorded pairs and labelled as the paper’s', async ({ page }) => {
  await page.goto('.')
  const rows = page.locator('#rush-huang-table tbody tr')
  await expect(rows).toHaveCount(2)
  const M = 1n << 64n
  for (let i = 0; i < 2; i++) {
    const cells = await rows.nth(i).locator('td').allInnerTexts()
    const [S, Pv, computed, printed] = cells.map((c) => BigInt(c.trim())) as [bigint, bigint, bigint, bigint]
    expect((((Pv - 20n * (S - 20n)) % M) + M) % M).toBe(computed)
    expect(computed).toBe(printed)
  }
  expect((await rows.nth(0).locator('td').nth(3).innerText()).trim()).toBe('11202993594072244072')
  expect((await rows.nth(1).locator('td').nth(3).innerText()).trim()).toBe('735198847291711055')
  await expect(page.locator('#panel-rush')).toContainText('nothing on this page produced them')
})

test('MAC panel: "no party holds α" is qualified by what implementations have done', async ({ page }) => {
  await page.goto('.')
  // The abort branch.
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  const abortCaveat = page.locator('#panel-mac [data-caveat="implementation"]')
  await expect(abortCaveat).toHaveCount(1)
  await expect(abortCaveat).toContainText('That holds for the protocol')
  await expect(abortCaveat).toContainText('Rushing at SPDZ')
  await expect(abortCaveat).toContainText('withholds its last opening')
  // The page never says "no party holds it" without that sentence beside it.
  const panel = (await page.locator('#panel-mac').innerText()).replace(/\s+/g, ' ')
  const claims = panel.match(/no party holds it|nobody ever holds it/g) ?? []
  const caveats = panel.match(/That holds for the protocol\./g) ?? []
  expect(claims.length).toBeGreaterThan(0)
  expect(caveats.length).toBe(claims.length)

  // The forged branch carries it too.
  const forging = (await page.locator('#mac-forging-value').innerText()).trim()
  await page.fill('#mac-delta-gamma', forging)
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click()
  await expect(page.locator('#panel-mac').getByText('ALARM — a forged value carried a valid MAC')).toBeVisible()
  await expect(page.locator('#panel-mac [data-caveat="implementation"]')).toHaveCount(1)
  const forgedPanel = (await page.locator('#panel-mac').innerText()).replace(/\s+/g, ' ')
  expect((forgedPanel.match(/That holds for the protocol\./g) ?? []).length).toBe(
    (forgedPanel.match(/no party holds it|nobody ever holds it/g) ?? []).length,
  )
})

