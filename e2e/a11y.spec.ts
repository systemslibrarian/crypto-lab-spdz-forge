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

/**
 * WCAG 1.4.11 (non-text contrast) regression for text-entry control boundaries.
 * Axe does not flag low-contrast control borders, so we measure them directly:
 * every visible text input's rendered border color must reach 3:1 against both
 * the control's own fill and the first opaque ancestor surface behind it.
 * Translucent colors are composited against those real surfaces first.
 */
async function minimumControlBoundaryRatio(page: Page): Promise<number> {
  return page.locator('#app input[type="text"]:visible').evaluateAll((elements) => {
    const parse = (value: string): { c: number[]; a: number } => {
      const n = (value.match(/[\d.]+/g) ?? ['0', '0', '0']).map(Number)
      return { c: n.slice(0, 3), a: n[3] ?? 1 }
    }
    const luminance = (parts: number[]): number => {
      const c = parts.map((part) => {
        const v = part / 255
        return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
      })
      return 0.2126 * (c[0] ?? 0) + 0.7152 * (c[1] ?? 0) + 0.0722 * (c[2] ?? 0)
    }
    const ratio = (a: number[], b: number[]): number => {
      const [la, lb] = [luminance(a), luminance(b)]
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
    }
    const composite = (fg: number[], alpha: number, bg: number[]): number[] =>
      fg.map((v, i) => v * alpha + (bg[i] ?? 0) * (1 - alpha))
    const surfaceBehind = (el: Element): number[] => {
      for (let node = el.parentElement; node; node = node.parentElement) {
        const bg = parse(getComputedStyle(node).backgroundColor)
        if (bg.a >= 1) return bg.c
      }
      return [255, 255, 255]
    }
    return Math.min(
      ...elements.map((el) => {
        const style = getComputedStyle(el)
        const exterior = surfaceBehind(el)
        const bg = parse(style.backgroundColor)
        const fill = bg.a >= 1 ? bg.c : composite(bg.c, bg.a, exterior)
        const b = parse(style.borderTopColor)
        const border = b.a >= 1 ? b.c : composite(b.c, b.a, fill)
        return Math.min(ratio(border, fill), ratio(border, exterior))
      }),
    )
  })
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
    expect(await minimumControlBoundaryRatio(page)).toBeGreaterThanOrEqual(3)
    await driveAbortStates(page)
    await scan(page) // scan the alarm/abort variants while they are rendered
    await driveHonestStates(page)
    await scan(page) // then the accepted variants that replaced them
  })
}
