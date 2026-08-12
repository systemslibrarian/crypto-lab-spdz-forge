import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate on SPDZ Forge.
 *
 * WHAT THE SPEC THIS REPLACES ACTUALLY DID. Five mechanisms, each of which made
 * a green run mean less than it read as:
 *
 *  1. IT INJECTED MOTION SUPPRESSION. `killMotion()` pushed
 *     `*,*::before,*::after{animation:none!important;transition:none!important}`
 *     through `addStyleTag`. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one thing worth checking — whether cancelling `fresh-flash` strands
 *     anything at an invisible start value — was never checked. It also reached
 *     further than the lab's own block does: the lab cancels motion only inside
 *     `#app *`, so the shared top bar's `.cl-btn` transitions and the skip
 *     link's `top` transition stayed live in the real rendering and were
 *     silently killed in the measured one. This gate asks for the preference,
 *     asserts it took effect, injects nothing, and waits for real quiescence.
 *
 *  2. IT FORCE-OPENED EVERY DISCLOSURE FROM SCRIPT. `openAllDetails()` set
 *     `d.open = true` on every `<details>` on the page, including the one nested
 *     inside the Beaver step-6 stage and the advanced ordering exhibit. Setting
 *     `.open` is not the route a reader has; clicking the `<summary>` is, and it
 *     is also the only route that proves the summary is operable. Every
 *     disclosure here is opened by its own summary.
 *
 *  3. IT SCANNED TWICE, FOR ~14 DRIVEN STATES. `driveAbortStates()` walked the
 *     addition panel, all six Beaver steps, both Beaver break-its, the MAC
 *     cheat, the σ-last attack, preprocessing and the lying-hospital variance —
 *     and then called `scan()` ONCE, at the end. Every state it built had
 *     already been overwritten by the next `clear()`/`replaceChildren()` before
 *     anything measured it. The six Beaver steps in particular exist only one at
 *     a time: step 3 is gone the moment step 4 renders. This gate scans after
 *     every single step.
 *
 *  4. IT SCANNED ONE VIEWPORT. `playwright.config.ts` ships no viewport
 *     override, so both tests ran at Playwright's 1280x720 default and the
 *     `@media (max-width: 640px)` block — which collapses `.party-row` and
 *     `.proto-row` from three/two columns to one — was never rendered, let alone
 *     measured for reflow. This gate runs {dark, light} x {1280, 380}.
 *
 *  5. ITS 1.4.11 CHECK WAS SELF-CONFIRMING. `minimumControlBoundaryRatio()`
 *     queried `#app input[type="text"]:visible` — which is EXACTLY and only the
 *     selector `--control-border` is applied to. `style.css` defines
 *     `--control-border` once and uses it once, on `#app input[type='text']`,
 *     while `--border` — a SURFACE divider — is used eleven times, including on
 *     `.meter`, the bank gauge whose track boundary is the only thing that says
 *     how full it is. The check pointed at the one place the rule was already
 *     kept and reported 4.0:1, and the divider-drawn boundaries it did not look
 *     at measured 1.63:1 (dark) and 1.55:1 (light). Pointing a check only where
 *     a rule is already kept is the same as not having it.
 *
 * And `scan()` asserted `violations` alone, which is not a complete oracle. Two
 * things on this page are invisible to it in particular: `aria-label` on a
 * role-less element is PROHIBITED and lands in `incomplete`, never in
 * `violations` (this lab had one, on `div.wire`); and neither axe nor a
 * violations array has any rule for reflow (1.4.10) or non-text contrast
 * (1.4.11) at all.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * This page has real work for it even under reduced motion, because the lab's
 * own reduced-motion block is scoped to `#app *`: the shared top bar's `.cl-btn`
 * (`transition: background .15s, border-color .15s, color .15s`) and the skip
 * link (`transition: top .15s ease`) are outside that scope and still animate.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders invisible for every reader with the preference set.
 *
 * This lab has exactly one animation, and it is the shape that has to be
 * checked rather than reasoned about: `.fresh` runs `fresh-flash 1.4s`, which
 * marks the rows a protocol step just produced, and the reduced-motion block
 * cancels it with `animation: none !important`. `fresh-flash` animates
 * `background-color` from an accent tint TO `transparent`, which is also the
 * declared value, so cancelling it leaves the row exactly where it would have
 * ended — and every party card in the Beaver stepper carries `.fresh` on the
 * rows born in the current step, so the drive puts this assertion under load in
 * six consecutive states. What would break it is someone animating `opacity`
 * from 0, which is why this measures rather than reads.
 *
 * `aria-hidden` subtrees are excluded. On this page that is only the chip icon
 * glyphs (`✓ ✗ ⚠ ▸`), each of which sits immediately beside its own words in
 * the same ink, so nothing carrying meaning is skipped.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. That matters here because every panel renders by building a DOM tree
 * and appending it in one go: a throw partway through `renderStep` leaves the
 * PREVIOUS step on screen, and the drive's own `expect`s would be the only
 * thing that noticed. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page has two `<header>` elements — the shared `.cl-topbar`, which
 * declares `role="banner"`, and `.cl-hero`, which sits INSIDE `<main id="app">`.
 * Being scoped by `<main>` strips the hero's implicit banner role on its own,
 * and `index.html`'s `dedupeBanner()` also skips it for that reason
 * (`el.closest('main, …')` returns early). Asserting the OUTCOME rather than
 * either mechanism means a change to the nesting is caught too.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** Text of the Beaver panel's live triple-bank counter, as a number. */
export async function bankCount(page: Page): Promise<number> {
  const text = (await page.locator('.bank-chip').textContent()) ?? '';
  const n = Number(/(\d+)/.exec(text)?.[1] ?? NaN);
  expect(Number.isFinite(n), `bank chip must read a number, got "${text}"`).toBe(true);
  return n;
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page — and asserted a second time against a
 * property the lab's own block controls, because `matchMedia` reporting `true`
 * only proves the preference reached the browser, not that this stylesheet
 * honours it. `.meter-fill` declares `transition: width 0.3s ease` and the
 * reduced-motion block cancels it, so a computed `transition-duration` of `0s`
 * on an element that ships on the page at first paint is direct evidence the
 * block applied.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')` and the shared bar's toggle
 * writes `localStorage.setItem('theme', …)`. If those keys drift apart the
 * theme silently stops persisting, and this boot fails on `data-theme` rather
 * than quietly scanning dark twice.
 *
 * The defaults are asserted at length because this lab's five panels ship in
 * three different conditions and the old spec assumed all of them. Two panels
 * (MAC, preprocessing) RENDER CONTENT ON MOUNT — the authenticated share table
 * with α printed in the clear, and the triple-bank gauge at 8/8. Three
 * (addition, Beaver, variance) ship with an EMPTY `.result-region`, which
 * `style.css` removes from the flow entirely via `.result-region:empty {
 * display: none }`. And every input ships pre-filled with a working value, so
 * "click the button" is a valid first move everywhere. Getting any of that
 * wrong means scanning a page that is not the page a reader arrives at.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: theme });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // The lab's own reduced-motion block, asserted rather than assumed: it is
  // scoped to `#app *`, and `.meter-fill` is the one element inside that scope
  // which declares a transition and exists at first paint.
  expect(
    await page.evaluate(() => getComputedStyle(document.querySelector('.meter-fill')!).transitionDuration),
    "the lab's own reduced-motion block must cancel the meter transition"
  ).toBe('0s');

  // Every panel is mounted by `src/main.ts` into an empty `<div>`; a navigation
  // that resolves proves nothing about whether the module ran.
  for (const id of ['panel-add', 'panel-beaver', 'panel-mac', 'panel-pre', 'panel-var']) {
    await expect(page.locator(`#${id}`)).not.toBeEmpty();
  }

  // ── The three panels that ship with nothing generated ────────────────────
  // `.result-region:empty { display: none }` takes them out of the flow, so
  // "hidden" here is the real arrival rendering, not a guess.
  for (const sel of ['#panel-add .result-region', '#panel-beaver .result-region', '#panel-var .result-region']) {
    await expect(page.locator(sel).first()).toBeHidden();
  }

  // ── The two that DO render on mount ──────────────────────────────────────
  // The MAC panel deals shares and prints α at load; the preprocessing panel
  // shows the bank gauge. Both are first-paint state the old spec never scanned.
  await expect(page.locator('#panel-mac table.share-table tbody tr')).toHaveCount(3);
  await expect(page.locator('#panel-mac tr.you-row')).toHaveCount(1);
  await expect(page.locator('#mac-forging-value')).toHaveText(/^\d+$/);
  await expect(page.locator('#panel-pre .meter')).toBeVisible();
  await expect(page.locator('#panel-pre .meter')).toHaveAttribute('aria-valuenow', '8');
  await expect(page.locator('#panel-pre .meter')).toHaveAttribute('aria-valuemax', '8');

  // ── Every shipped control default ────────────────────────────────────────
  await expect(page.locator('#add-x')).toHaveValue('12');
  await expect(page.locator('#add-y')).toHaveValue('30');
  await expect(page.locator('#mul-x')).toHaveValue('6');
  await expect(page.locator('#mul-y')).toHaveValue('7');
  await expect(page.locator('#mac-delta')).toHaveValue('100');
  await expect(page.locator('#mac-delta-gamma')).toHaveValue('0');
  await expect(page.locator('#var-0')).toHaveValue('120');
  await expect(page.locator('#var-1')).toHaveValue('95');
  await expect(page.locator('#var-2')).toHaveValue('160');
  // The scenario switch ships OFF. Which half of this lab a single-configuration
  // gate measures depends entirely on that, so it is asserted, not assumed.
  await expect(page.locator('#var-lie')).not.toBeChecked();

  // Five disclosures ship shut: the jargon primer, three in the expert section,
  // and the MAC panel's advanced ordering exhibit.
  await expect(page.locator('#app details')).toHaveCount(5);
  await expect(page.locator('#app details[open]')).toHaveCount(0);

  // The bank starts full, and the drive's accounting is built on this number.
  expect(await bankCount(page), 'the triple bank must ship with 8 unused triples').toBe(8);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the spec this
 * replaces never rendered a narrow viewport, so the whole 380px column was
 * unmeasured. This page is the shape that breaks it: every value on it is a
 * full-precision field element up to 19 digits (`code.fe`, never truncated —
 * that is a deliberate teaching decision), the share tables are four columns of
 * them, and `.party-row`/`.proto-row` collapse to a single `1fr` grid track
 * below 640px, where a track's automatic minimum is its content's min-content.
 * Each table is meant to scroll inside its own `.scroll-x`; the assertion here
 * is that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That cost
    // a run elsewhere in this fleet, and this page has a decoy behind every
    // `.scroll-x`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab already handles its known case: every share table is wrapped in a
 * `div.scroll-x` carrying `tabindex="0"`, `role="region"` and an `aria-label`.
 * The assertion stays because that wrapper is written out by hand at each of the
 * three call sites rather than produced by a helper, so it is a convention and
 * not an enforcement — and because the content inside those scrollers is the
 * evidence for everything this lab claims: the three parties' shares, their MAC
 * shares, and the tampered row the whole MAC exhibit turns on.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * This is the old spec's `minimumControlBoundaryRatio()`, kept because the idea
 * was right, with its aim corrected. It queried `#app input[type="text"]` — and
 * that is exactly, and only, the selector `--control-border` is applied to. The
 * palette defines that token once and uses it once; `--border`, a SURFACE
 * divider, is used eleven times. So the check measured the one control the rule
 * was already kept for, reported 4.0:1, and never looked at anything else.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it (how `#app button` works: a
 *     transparent border over an `--accent` fill), or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how `#app input[type='text']` works: a `--panel-2` fill with a
 *     drawn `--control-border` edge).
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 * Taking the max of the two mechanisms is what keeps this from failing a
 * perfectly delineated solid button for having no border.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page ships
 *    the Beaver stepper's `← Back` disabled at step 1 and `Next step →`
 *    disabled at step 6, both at `opacity: 0.45`.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a byte-identical copy — and its `.cl-btn`
 *    boundary is measured, ratcheted and reported by `nontext.ts` instead, which
 *    walks the whole document. Stated here so the exclusion is a decision rather
 *    than an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette uses
    // `color-mix()` for the tampered-row highlight and every status chip's fill,
    // and `getComputedStyle` reports those unchanged — a regex reads them as
    // null and lands the walk on the wrong backdrop.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0]!, g: d[1]!, b: d[2]!, a: d[3]! / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * SC 1.4.11 for the ONE meaningful graphic on this page: the triple-bank gauge.
 *
 * `div.meter` is a `role="meter"` whose fill width is the fraction of dealt
 * triples still unused. Neither oracle above can reach it — `auditControlBoundaries`
 * queries form controls, and `nontext.ts`'s CONTROL list is interactive roles,
 * which `meter` is not. But a gauge is precisely the "part of a graphic required
 * to understand the content" 1.4.11 names: the FILL says how much is left and
 * the TRACK BOUNDARY says how much that is out of. Both edges are load-bearing,
 * and the drive deliberately drives the gauge down from 100% so the track is
 * visible beside the fill rather than covered by it.
 *
 * Returns both measurements so a regression names which edge moved.
 */
export async function auditMeter(
  page: Page
): Promise<Array<{ what: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0]!, g: d[1]!, b: d[2]!, a: d[3]! / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return Math.round(((Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)) * 100) / 100;
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i]!, out);
      return out;
    };

    const out: Array<{ what: string; ratio: number }> = [];
    const meter = document.querySelector<HTMLElement>('.meter');
    if (!meter) return out;
    const fillEl = meter.querySelector<HTMLElement>('.meter-fill');
    if (!fillEl) return out;
    const cs = getComputedStyle(meter);
    const surround = backdrop(meter.parentElement);
    const track = over(parse(cs.backgroundColor), surround);
    const fill = over(parse(getComputedStyle(fillEl).backgroundColor), track);
    const border = over(parse(cs.borderTopColor), track);
    out.push({ what: 'meter fill vs track (how much is left)', ratio: ratio(fill, track) });
    out.push({ what: 'meter track edge vs page (out of how much)', ratio: ratio(border, surround) });
    out.push({ what: 'meter track edge vs its own track fill', ratio: ratio(border, track) });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * IT IS CALLED FROM `scan()`, not from inside another oracle's soft wrapper.
 * Fleet-wide, `expectNoNewNonTextFailures` was called from the body of
 * `expectScrollersReachableSoft`, AFTER that function's
 * `if (!COLLECTING) return …` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves clean
 * against a baseline captured while nothing had ever looked.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Eight assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result axe
 *    simply could not finish — including `aria-prohibited-attr`, which is where
 *    an `aria-label` on a role-less element hides, a defect that never reaches
 *    the violations array at all. That one was LIVE here: `beaver.ts` put an
 *    `aria-label` on the role-less `div.wire` that carries every public opening.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    which matters on this page because the tampered row is
 *    `color-mix(in oklab, var(--accent) 14%, transparent)` and every status chip
 *    fills itself with `color-mix(in oklab, currentColor 10%, transparent)`.
 *    axe files all of those under `incomplete`.
 *  - non-text contrast for interactive controls — SC 1.4.11.
 *  - the bank gauge's two edges — SC 1.4.11 for a meaningful graphic.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])` axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. `withTags(TAGS)` selects 69 of axe-core
  // 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the shape they catch: a shared sticky `<header role="banner">` above a
  // `<main>` that contains a second `<header>`, with the hero's
  // `<aside role="complementary">` inside it.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  const meter = await auditMeter(page);
  expect(meter.length, `the bank gauge must be measurable in state: ${label}`).toBe(3);
  const dimGauge = meter.filter((m) => m.ratio < 3).map((m) => `${m.ratio}:1 ${m.what}`);
  softExpect(dimGauge, `bank gauge edges under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open one shut disclosure by clicking its summary, and assert it opened.
 *
 * The disclosure is located by its own summary text rather than by a
 * `:not([open])` selector, because that selector stops matching the instant the
 * click succeeds and the post-condition would then be asserted against nothing.
 * Shut-ness is asserted first, as a precondition, so this cannot silently pass
 * on an already-open element.
 */
async function openDetails(page: Page, summaryText: string | RegExp): Promise<void> {
  const details = page
    .locator('#app details')
    .filter({ has: page.locator('summary', { hasText: summaryText }) })
    .first();
  await expect(details).not.toHaveAttribute('open', '');
  await details.locator('summary').first().click();
  await expect(details).toHaveAttribute('open', '');
}

/**
 * Open every VISIBLE shut disclosure by clicking its summary.
 *
 * `:visible` is load-bearing: two of this page's disclosures do not exist until
 * a panel has produced output — the addition panel's "Inspect the MAC shares
 * too" and the Beaver stepper's "Inspect the MAC shares that rode along", which
 * is only built at step 6. The spec this replaces reached all of them at once by
 * setting `.open = true` from script, which is not a route any reader has and
 * which opens disclosures inside output regions that have nothing in them.
 */
async function openAllDisclosures(page: Page, expectSome = true): Promise<void> {
  const shut = page.locator('#app details:not([open]) > summary:visible');
  let opened = 0;
  for (let i = await shut.count(); i > 0 && opened < 40; i = await shut.count()) {
    await shut.first().click();
    opened += 1;
  }
  await expect(page.locator('#app details:not([open]) > summary:visible')).toHaveCount(0);
  if (expectSome) {
    expect(opened, 'no shut disclosure was found where one was expected').toBeGreaterThan(0);
  }
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS HALF-EMPTY. Three of the five
 *    panels ship with an empty `.result-region` that `.result-region:empty`
 *    removes from the flow; two render on mount. That mixed rendering is the
 *    first thing every reader sees and the old spec never scanned it — it went
 *    straight to clicking.
 *
 *  - EVERY ERROR STATE IS DRIVEN. Each of the five input validators has a
 *    rejection branch that renders a `.chip-warn`, and `--warn-text` as PROSE
 *    ink appears nowhere else on this page except `.edited-tag` and `.lab-note`.
 *    Every one of the six is driven: three bad numeric fields, a bad second
 *    secret, a zero δ, and an over-long MAC shift.
 *
 *  - EVERY BEAVER STEP IS SCANNED WHILE IT IS ON SCREEN. The stepper renders one
 *    step at a time into the same node, so step 3 ceases to exist the instant
 *    step 4 renders; the old spec pressed `Next` five times and then scanned the
 *    wreckage. Steps 1..6 are scanned individually, `← Back` is exercised, and
 *    both endpoint `disabled` states are asserted.
 *
 *  - THE FAIL-CLOSED STATES ARE BUILT ON PURPOSE. `takeTriples` returns null
 *    when the bank cannot cover a request, and both the Beaver stepper and the
 *    variance panel then render a warning WITH AN INLINE RECOVERY BUTTON. Those
 *    states only exist after the bank is deliberately drained, which is a whole
 *    rendering — chip, prose and a second button inside a live region — that no
 *    default-state gate ever reaches. The drive drains it, scans both, and
 *    recovers through the inline button.
 *
 *  - BOTH OUTCOMES OF EVERY FORK. The MAC panel has three: abort (Δ≠0, no MAC
 *    shift), forged-and-accepted (MAC shift exactly α·Δ, read live off the page
 *    rather than recomputed here), and honest. The Beaver break-its have leak
 *    and no-leak. The variance panel has released-statistic and ABORT, and only
 *    the ABORT branch renders `.lab-note`, the dashed `--warn-text` box.
 *
 *  - NO FIXED TIMEOUTS. Every panel is synchronous BigInt arithmetic except the
 *    ordering exhibit, which awaits real SHA-256 commitments; each has a DOM
 *    completion signal — a table row count, a verdict chip, a step title, the
 *    bank counter changing — and the drive waits on those. The spec this
 *    replaces ended each of its two phases with `waitForTimeout(300)`.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint: three output regions empty, the bank full at 8');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── Panel 1: addition ────────────────────────────────────────────────────
  await page.fill('#add-x', 'twelve');
  await page.getByRole('button', { name: 'Share & add' }).click();
  await expect(page.locator('#panel-add .chip-warn')).toContainText('at most 9 digits');
  await scanAt('addition rejected a non-numeric secret');

  await page.fill('#add-x', '12');
  await page.getByRole('button', { name: 'Share & add' }).click();
  await expect(page.locator('#panel-add table.share-table').first().locator('tbody tr')).toHaveCount(3);
  await expect(page.locator('#panel-add .chip-ok')).toContainText('both sides equal');
  // The MAC-share table is built in the same pass but ships inside a shut
  // disclosure, so it is present in the DOM and painting nothing — which is the
  // exact shape `contrast.ts`'s `checkVisibility()` guard exists for, and the
  // exact shape the old spec destroyed by setting `.open` from script.
  await expect(page.locator('#panel-add table.share-table')).toHaveCount(2);
  await expect(page.locator('#panel-add table.share-table').nth(1)).toBeHidden();
  await scanAt('addition: three shares, summed locally, opened and verified');

  await openDetails(page, 'Inspect the MAC shares too');
  await expect(page.locator('#panel-add table.share-table').nth(1)).toBeVisible();
  await scanAt('addition MAC-share table disclosed');

  // ── Panel 2: the Beaver stepper ──────────────────────────────────────────
  await page.fill('#mul-x', '');
  await page.getByRole('button', { name: 'Start multiplication' }).click();
  await expect(page.locator('#panel-beaver .chip-warn')).toContainText('nothing was run');
  expect(await bankCount(page), 'a rejected input must not consume a triple').toBe(8);
  await scanAt('Beaver rejected an empty secret, bank untouched');

  await page.fill('#mul-x', '6');
  await page.getByRole('button', { name: 'Start multiplication' }).click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 1 · Share the secrets/);
  await expect(page.locator('.party-card')).toHaveCount(3);
  await expect(page.getByRole('button', { name: '← Back' })).toBeDisabled();
  expect(await bankCount(page), 'starting a multiplication must consume one triple').toBe(7);
  await scanAt('Beaver step 1 of 6: secrets shared, Back disabled');

  const next = page.getByRole('button', { name: 'Next step →' });
  await next.click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 2 · Fetch a preprocessed triple/);
  await scanAt('Beaver step 2 of 6: the preprocessed triple');

  await next.click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 3 · Reveal d/);
  await expect(page.locator('#panel-beaver .wire')).toBeVisible();
  await expect(page.locator('#panel-beaver .wire .chip-ok')).toContainText('opening MAC-checked');
  await scanAt('Beaver step 3 of 6: d on the public wire, opening MAC-checked');

  // The Back button, exercised rather than assumed — it is the only control on
  // the page that renders a state a reader has already left.
  await page.getByRole('button', { name: '← Back' }).click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 2 · Fetch a preprocessed triple/);
  await expect(page.locator('#panel-beaver .wire')).toHaveCount(0);
  await scanAt('Beaver stepped back to 2 of 6, the wire withdrawn');

  await next.click();
  await next.click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 4 · Reveal e/);
  await expect(page.locator('#panel-beaver .wire .kv')).toHaveCount(2);
  await scanAt('Beaver step 4 of 6: both openings on the wire');

  await next.click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 5 · Combine locally/);
  await scanAt('Beaver step 5 of 6: local combination, no messages');

  await next.click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 6 · Open z/);
  await expect(page.getByRole('button', { name: 'Next step →' })).toBeDisabled();
  await expect(page.locator('#panel-beaver').getByText('MAC check passed')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Reuse the spent triple' })).toBeVisible();
  await scanAt('Beaver step 6 of 6: z opened and MAC-checked, Next disabled');

  await openDetails(page, 'Inspect the MAC shares that rode along');
  await expect(page.locator('#panel-beaver').getByText('exactly 0, as the algebra demands')).toBeVisible();
  await scanAt('the MAC shares that rode through the linear combination');

  // ── Break-it 1: reuse the spent triple ───────────────────────────────────
  await page.fill('#mul-x2', 'four');
  await page.getByRole('button', { name: 'Reuse the spent triple' }).click();
  await expect(page.locator('#panel-beaver .chip-warn')).toContainText('at most 9 digits');
  await scanAt('the reuse attack rejected a non-numeric second secret');

  await page.fill('#mul-x2', '4');
  await page.getByRole('button', { name: 'Reuse the spent triple' }).click();
  await expect(page.locator('#panel-beaver .chip-alarm')).toContainText('LEAK: the public wire just revealed');
  expect(await bankCount(page), 'reusing a spent triple must not draw a new one').toBe(7);
  await scanAt('triple reused: the wire leaked x − x′');

  await page.getByRole('button', { name: 'Use a fresh triple' }).click();
  await expect(page.locator('#panel-beaver .chip-ok').last()).toContainText('No leak: a fresh random');
  expect(await bankCount(page), 'a fresh triple must be drawn from the bank').toBe(6);
  await scanAt('fresh triple: the difference stays masked');

  // ── Break-it 2: lie during the d opening ─────────────────────────────────
  await page.fill('#mul-ddelta', '0');
  await page.getByRole('button', { name: 'Lie during the opening' }).click();
  await expect(page.locator('#panel-beaver .chip-warn')).toContainText('non-zero whole number');
  await scanAt('the opening attack rejected a zero lie');

  await page.fill('#mul-ddelta', '9');
  await page.getByRole('button', { name: 'Lie during the opening' }).click();
  await expect(page.locator('#panel-beaver .proto-col')).toHaveCount(2);
  await expect(page.getByText('a WRONG product with a perfectly VALID MAC')).toBeVisible();
  await expect(page.getByText('the lie died at the opening — no product was ever computed')).toBeVisible();
  expect(await bankCount(page), 'the opening attack consumes a triple').toBe(5);
  await scanAt('lied d opening: valid MAC on a wrong product, vs SPDZ aborting');

  // ── Panel 3: the MAC check ───────────────────────────────────────────────
  await page.fill('#mac-delta-gamma', '12345678901234567890');
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click();
  await expect(page.locator('#panel-mac .chip-warn')).toContainText('up to 19 digits');
  await scanAt('the MAC panel rejected an over-long MAC shift');

  await page.fill('#mac-delta-gamma', '0');
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click();
  await expect(page.locator('#panel-mac').getByText('ALARM — a wrong answer was accepted and nobody can tell')).toBeVisible();
  await expect(page.locator('#panel-mac').getByText('ABORT — no value released')).toBeVisible();
  await expect(page.locator('#panel-mac tr.you-row .edited-tag')).toHaveCount(1);
  await scanAt('MAC cheat: semi-honest accepts a wrong answer, SPDZ aborts');

  // The forgery the abort message names, executed with the number the page
  // itself prints — recomputing it here would be asserting against this gate's
  // arithmetic instead of against the lab's.
  const forging = (await page.locator('#mac-forging-value').textContent())!.trim();
  expect(forging, 'the panel must print the forging value α·Δ').toMatch(/^\d+$/);
  await page.fill('#mac-delta', '100');
  await page.fill('#mac-delta-gamma', forging);
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click();
  await expect(page.locator('#panel-mac').getByText('ALARM — a forged value carried a valid MAC')).toBeVisible();
  await expect(page.locator('#panel-mac tr.you-row .edited-tag')).toHaveCount(2);
  await scanAt('MAC forged: the shift landed on α·Δ and the value was released');

  await page.fill('#mac-delta', '0');
  await page.fill('#mac-delta-gamma', '0');
  await page.getByRole('button', { name: 'Cheat & open in both protocols' }).click();
  await expect(page.locator('#panel-mac').getByText('MAC check passed: Σσᵢ = 0')).toBeVisible();
  await expect(page.locator('#panel-mac tr.you-row .edited-tag')).toHaveCount(0);
  await scanAt('MAC honest run: nothing tampered, nothing edited');

  await openDetails(page, 'Advanced break-it: attack the check itself');
  await scanAt('the ordering exhibit disclosed, before it is run');

  await page.getByRole('button', { name: 'Cheat & send your σ last' }).click();
  await expect(page.getByText('forged value accepted — no α guessing, just patience')).toBeVisible();
  await expect(page.getByText('the cancellation attempt died — commitments bind before reveals')).toBeVisible();
  await scanAt('σ sent last: it passes unordered and dies against commit-then-open');

  // ── Panel 4: preprocessing ───────────────────────────────────────────────
  // The gauge is at 5/8 here, so its track is visible BESIDE its fill — which
  // is the only state in which the track boundary's contrast is answerable.
  await expect(page.locator('#panel-pre .meter')).toHaveAttribute('aria-valuenow', '5');
  await scanAt('the bank gauge partly drained, track visible beside fill');

  await page.getByRole('button', { name: /^Run preprocessing \(deal 8 triples\)$/ }).click();
  await expect(page.locator('#panel-pre .meter')).toHaveAttribute('aria-valuenow', '13');
  await expect(page.locator('#panel-pre .meter')).toHaveAttribute('aria-valuemax', '16');
  expect(await bankCount(page), 'preprocessing deals a batch of 8 into the bank').toBe(13);
  await scanAt('offline phase run: eight more triples banked');

  // ── Panel 5: the variance application ────────────────────────────────────
  await page.fill('#var-1', '9999999');
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click();
  await expect(page.locator('#panel-var .chip-warn')).toContainText('at most 6 digits');
  expect(await bankCount(page), 'a rejected input must not consume triples').toBe(13);
  await scanAt('variance rejected an over-long count');

  await page.fill('#var-1', '95');
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click();
  await expect(page.locator('#panel-var').getByText('Population variance:')).toBeVisible();
  await expect(page.locator('#panel-var .chip-ok').first()).toContainText('MAC check passed');
  expect(await bankCount(page), 'a variance run burns four triples').toBe(9);
  await scanAt('variance released: M opened under a MAC check, no count revealed');

  await page.locator('#var-lie').check();
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click();
  await expect(page.locator('#panel-var').getByText('ABORT — no statistic released')).toBeVisible();
  await expect(page.locator('#panel-var .lab-note')).toBeVisible();
  expect(await bankCount(page), 'the aborting run still burns its triples').toBe(5);
  await scanAt('variance ABORT: detection without attribution, plus the lab note');

  // ── The fail-closed states, built on purpose ─────────────────────────────
  // 5 triples left, 4 needed: one more run empties the bank to 1, and the run
  // after that cannot be covered.
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click();
  await expect(page.locator('#panel-var').getByText('ABORT — no statistic released')).toBeVisible();
  expect(await bankCount(page)).toBe(1);
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click();
  await expect(page.locator('#panel-var .chip-warn')).toContainText('Not enough triples banked');
  await expect(page.locator('#panel-var').getByRole('button', { name: 'Run preprocessing now' })).toBeVisible();
  await scanAt('variance failed closed: not enough triples, with an inline recovery');

  // Recovery through the inline button, which preprocesses AND re-runs.
  await page.locator('#panel-var').getByRole('button', { name: 'Run preprocessing now' }).click();
  await expect(page.locator('#panel-var').getByText('ABORT — no statistic released')).toBeVisible();
  expect(await bankCount(page), '1 + 8 dealt, 4 burned by the re-run').toBe(5);
  await scanAt('recovered from the inline button and the run completed');

  // Now empty the bank entirely and hit the Beaver stepper's own fail-closed
  // branch, which renders a different message and its own inline button.
  await page.getByRole('button', { name: 'Compute variance over MPC' }).click();
  expect(await bankCount(page)).toBe(1);
  await page.getByRole('button', { name: 'Start multiplication' }).click();
  await expect(page.locator('.step-title')).toBeVisible();
  expect(await bankCount(page), 'the last triple in the bank').toBe(0);
  await scanAt('a multiplication run on the last triple in the bank');

  await page.getByRole('button', { name: 'Start multiplication' }).click();
  await expect(page.locator('#panel-beaver .chip-warn')).toContainText('Triple bank is empty');
  await expect(page.locator('#panel-beaver').getByRole('button', { name: 'Run preprocessing now' })).toBeVisible();
  await expect(page.locator('#panel-pre .meter')).toHaveAttribute('aria-valuenow', '0');
  await scanAt('the online phase blocked on an empty bank, gauge at zero');

  await page.locator('#panel-beaver').getByRole('button', { name: 'Run preprocessing now' }).click();
  await expect(page.locator('.step-title')).toHaveText(/^Step 1 · Share the secrets/);
  expect(await bankCount(page), '0 + 8 dealt, 1 consumed by the restarted run').toBe(7);
  await scanAt('unblocked by preprocessing and the multiplication restarted');

  // Everything the page can render is now on it; open whatever is still shut.
  await openAllDisclosures(page);
  await scanAt('the finished page with every disclosure open');
}
