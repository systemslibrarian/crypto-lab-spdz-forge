import { expect, test } from '@playwright/test'
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate'

/**
 * WCAG A/AA regression gate for SPDZ Forge.
 *
 * The lab is driven along everything it teaches, and EVERY state is scanned
 * while it is on screen: the arrival page, where three of the five panels ship
 * with an empty output region and two have already rendered; the skip link
 * focused; each of the six input validators' rejection branches; the addition
 * panel and its MAC-share disclosure; all six Beaver steps individually,
 * including a step BACKWARDS and both endpoint `disabled` states; both break-its
 * in both outcomes (spent triple leaking x − x′, fresh triple masking it; a lied
 * d opening producing a valid MAC on a wrong product beside SPDZ aborting); all
 * three MAC-panel forks (abort, forged-and-accepted at exactly α·Δ, honest); the
 * σ-last-sender ordering exhibit; the offline phase dealing a batch; the
 * variance application released and aborted; and — built on purpose by draining
 * the triple bank to zero — both fail-closed states with their inline recovery
 * buttons, which no default-state gate ever reaches.
 *
 * Four configurations: {dark, light} × {1280, 380}. The spec this replaces ran
 * two, both at Playwright's default 1280 viewport, so the `@media (max-width:
 * 640px)` block that collapses `.party-row` and `.proto-row` to one column had
 * never been rendered by any test in this repo.
 *
 * See `gate.ts` for what the old spec did — it injected motion suppression
 * instead of exercising the lab's own reduced-motion block, opened every
 * `<details>` by setting `.open` from script, scanned ONCE after a fourteen-step
 * drive that had already overwritten every state it built, and pointed its
 * 1.4.11 check at exactly the one selector `--control-border` was applied to.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000)
    const errors = watchPageErrors(page)
    await boot(page, theme)
    await driveAllStates(page, theme)
    expect(errors, errors.join('\n')).toEqual([])
    expectBaselineNotStale()
    reportCollected()
  })

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000)
    const errors = watchPageErrors(page)
    await page.setViewportSize(NARROW)
    await boot(page, theme)
    await driveAllStates(page, `${theme} @380px`)
    expect(errors, errors.join('\n')).toEqual([])
    expectBaselineNotStale()
    reportCollected()
  })
}
