/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * What the live oracle finds on this lab, over {dark, light} × {1280, 380} and
 * every one of the ~37 states the drive builds, is exactly the two entries
 * below — both in the SHARED Crypto Lab top bar, and neither one this repo's to
 * fix.
 *
 * `.cl-btn` draws its edge as
 * `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)` over
 * the bar's fixed `#0b1512`. This lab's `--accent` is `#b45309`, so the
 * composited edge resolves to rgb(75, 45, 15): 1.49:1 against the bar,
 * IDENTICALLY IN BOTH THEMES, because the bar is always dark and `--accent` is
 * one value shared by both themes here. (The number is accent-dependent, which
 * is why sibling repos in this fleet record a different one for the same CSS —
 * drbg-arena, which defines no `--accent` at all and falls back to the teal,
 * records 2.45:1.) Every repo in this fleet carries a byte-identical copy of
 * that markup and CSS, and `CLAUDE.md` is explicit that a change every lab
 * should get is a deliberate reviewed fleet-wide pass and never an overwrite
 * driven from one repo. So it is measured here, ratcheted here, and reported
 * upward.
 *
 * Everything inside `<main id="app">`, the hero and the footer is audited with
 * no exemption and comes back clean. Two findings that WERE here have been
 * fixed rather than baselined, and their absence from this file is the ratchet
 * working: the triple-bank gauge's track edge (1.63:1 dark / 1.75:1 light
 * against the panel, drawn with the surface-divider token `--border`; now
 * `--control-border`, 4.53:1 / 4.08:1), and `#app button:hover`, whose
 * `filter: brightness(1.12)` dropped its own #ffffff ink to 4.13:1 — a class no
 * oracle in this gate can see at all, because a CSS filter is applied after
 * every property either oracle reads, so it was measured from screenshot
 * pixels.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  'control-boundary|a.cl-btn': { ratio: 1.49, required: 3, unverified: false },
};
