/**
 * Panel 2 — THE BEAVER TRIPLE (headline mechanism #1).
 *
 * A stepped animation of one real multiplication: deal shares, take a
 * preprocessed triple, publicly reveal d = x − a and e = y − b, locally
 * combine, open. Every number on screen is genuine field arithmetic.
 *
 * Break-it: reuse the consumed triple for a second multiplication and watch
 * the public wire leak x − x′ — the exact reason a triple is single-use.
 */

import { add, mul, sub } from '../../spdz/field'
import { beaverMulChecked, beaverMulUnsafe, combineWithOpenings } from '../../spdz/beaver'
import { macCheck, openAuthenticated, openValue, shareSecret, subShares, tamperShare } from '../../spdz/sharing'
import type { AuthShares, MacCheckResult, Triple } from '../../spdz/types'
import { alphaShares, bankStats, onBankChange, preprocess, takeTriples } from '../state'
import { chip, clear, fe, h } from '../dom'

const PARTIES = ['P₀', 'P₁', 'P₂']

interface Run {
  x: bigint
  y: bigint
  xs: AuthShares
  ys: AuthShares
  triple: Triple
  d: bigint
  e: bigint
  dCheck: MacCheckResult
  eCheck: MacCheckResult
  z: AuthShares
  step: number
}

const STEP_TITLES = [
  'Step 1 · Share the secrets',
  'Step 2 · Fetch a preprocessed triple (offline phase output)',
  'Step 3 · Reveal d = x − a on the public wire',
  'Step 4 · Reveal e = y − b on the public wire',
  'Step 5 · Combine locally: zᵢ = cᵢ + d·bᵢ + e·aᵢ (+ d·e once)',
  'Step 6 · Open z and check its MAC',
]

function readSmallInt(input: HTMLInputElement): bigint | null {
  const v = input.value.trim()
  if (!/^\d{1,9}$/.test(v)) return null
  return BigInt(v)
}

export function renderBeaverPanel(mount: HTMLElement): void {
  const xInput = h('input', { id: 'mul-x', type: 'text', inputmode: 'numeric', value: '6' })
  const yInput = h('input', { id: 'mul-y', type: 'text', inputmode: 'numeric', value: '7' })
  const bankChip = h('span', { class: 'bank-chip' })
  const stage = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })
  const breakout = h('div', {})
  let run: Run | null = null

  const refreshBank = (): void => {
    const { available } = bankStats()
    bankChip.textContent = `Triple bank: ${available} unused`
  }
  onBankChange(refreshBank)
  refreshBank()

  interface Row {
    label: string
    val: Node
    step: number
  }

  // Rows born in the current step get a one-shot highlight — motion that marks
  // exactly which data this protocol step produced, nothing decorative.
  const partyCard = (i: number, rows: Row[], currentStep: number): HTMLElement =>
    h(
      'div',
      { class: 'party-card' },
      h('h3', {}, PARTIES[i] as string),
      ...rows.map((row) =>
        h(
          'p',
          { class: row.step === currentStep ? 'kv fresh' : 'kv' },
          h('span', { class: 'kv-label' }, row.label + ' '),
          row.val,
        ),
      ),
    )

  const renderStep = (): void => {
    clear(stage)
    if (!run) return
    const r = run
    const title = STEP_TITLES[r.step] as string
    const cards: HTMLElement[] = []
    const wire: (Node | string)[] = []
    const notes: HTMLElement[] = []

    for (let i = 0; i < 3; i++) {
      const rows: Row[] = []
      if (r.step >= 0) {
        rows.push(
          { label: 'xᵢ', val: fe(r.xs[i]!.value), step: 0 },
          { label: 'yᵢ', val: fe(r.ys[i]!.value), step: 0 },
        )
      }
      if (r.step >= 1) {
        rows.push(
          { label: 'aᵢ', val: fe(r.triple.a[i]!.value), step: 1 },
          { label: 'bᵢ', val: fe(r.triple.b[i]!.value), step: 1 },
          { label: 'cᵢ', val: fe(r.triple.c[i]!.value), step: 1 },
        )
      }
      if (r.step >= 2) rows.push({ label: 'xᵢ − aᵢ →', val: fe(sub(r.xs[i]!.value, r.triple.a[i]!.value)), step: 2 })
      if (r.step >= 3) rows.push({ label: 'yᵢ − bᵢ →', val: fe(sub(r.ys[i]!.value, r.triple.b[i]!.value)), step: 3 })
      if (r.step >= 4) rows.push({ label: 'zᵢ', val: fe(r.z[i]!.value), step: 4 })
      cards.push(partyCard(i, rows, r.step))
    }

    if (r.step >= 2)
      wire.push(
        h(
          'p',
          { class: r.step === 2 ? 'kv fresh' : 'kv' },
          'd = x − a = ',
          fe(r.d),
          ' (public) ',
          r.dCheck.ok
            ? chip('ok', '✓', 'opening MAC-checked')
            : chip('alarm', '✗', 'opening check failed'),
        ),
      )
    if (r.step >= 3)
      wire.push(
        h(
          'p',
          { class: r.step === 3 ? 'kv fresh' : 'kv' },
          'e = y − b = ',
          fe(r.e),
          ' (public) ',
          r.eCheck.ok
            ? chip('ok', '✓', 'opening MAC-checked')
            : chip('alarm', '✗', 'opening check failed'),
        ),
      )

    switch (r.step) {
      case 0:
        notes.push(
          h('p', { class: 'note' }, 'Each secret is split into three uniformly random shares that sum to it mod p. No party can learn x or y from what it holds.'),
        )
        break
      case 1:
        notes.push(
          h(
            'p',
            { class: 'note' },
            'The triple (a, b, c) with c = a·b was generated before x and y existed, and a, b, c are unknown to every party — each holds only shares. In this demo a trusted dealer produces triples (the modeled part); real SPDZ makes them with somewhat-homomorphic encryption or oblivious transfer.',
          ),
        )
        break
      case 2:
        notes.push(
          h(
            'p',
            { class: 'note' },
            'd is safe to publish: a is uniformly random and used exactly once, so d = x − a is itself a uniformly random field element. Anyone watching the wire learns nothing about x. (The break-it below shows how this guarantee dies the moment a is reused.) Note the check chip: the opening itself is MAC-authenticated. That is not ceremony — the second break-it below shows the attack that slips through if the parties skip it.',
          ),
        )
        break
      case 3:
        notes.push(h('p', { class: 'note' }, 'Same argument: fresh random b makes e = y − b a one-time pad on y.'))
        break
      case 4:
        notes.push(
          h(
            'p',
            { class: 'note' },
            'Algebra check: c + d·b + e·a + d·e = ab + (x−a)b + (y−b)a + (x−a)(y−b) = x·y. Every term is either a share the party already holds or the public d, e — so this step needs no communication at all. The MAC shares ride through the same linear algebra, so z arrives already authenticated.',
          ),
        )
        break
      case 5: {
        const opened = openValue(r.z)
        const direct = mul(r.x, r.y)
        const check = macCheck(opened, r.z, alphaShares)
        notes.push(
          h(
            'p',
            {},
            'Opened z = ',
            fe(opened),
            ` — and directly, ${r.x} × ${r.y} mod p = `,
            fe(direct),
            ' ',
            opened === direct ? chip('ok', '✓', 'both sides equal') : chip('alarm', '✗', 'mismatch'),
            ' ',
            check.ok ? chip('ok', '✓', 'MAC check passed') : chip('alarm', '✗', 'MAC check failed'),
          ),
          h(
            'p',
            { class: 'note' },
            'The triple is now spent — one multiplication, one triple, gone (watch the bank counter above). That exchange rate is the online phase’s entire price list.',
          ),
          h(
            'details',
            {},
            h('summary', {}, 'Inspect the MAC shares that rode along'),
            h(
              'p',
              { class: 'note' },
              'The MAC shares went through the same linear combination as the value shares, so the product arrived already authenticated — no extra round, no dealer help:',
            ),
            ...r.z.map((sh, i) => h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, `γ(z)${['₀', '₁', '₂'][i]} = `), fe(sh.mac))),
            h(
              'p',
              { class: 'kv' },
              h('span', { class: 'kv-label' }, 'Check, computed live: '),
              'Σᵢ (γ(z)ᵢ − αᵢ·z) = ',
              fe(check.sum),
              ' ',
              check.sum === 0n ? chip('ok', '✓', 'exactly 0, as the algebra demands') : chip('alarm', '✗', 'non-zero — should be impossible here'),
            ),
          ),
        )
        break
      }
    }

    stage.append(
      h('h3', { class: 'step-title' }, title),
      h('div', { class: 'party-row' }, ...cards),
      wire.length ? h('div', { class: 'wire', 'aria-label': 'Public wire — values every party and any eavesdropper sees' }, h('p', { class: 'wire-label' }, 'PUBLIC WIRE'), ...wire) : '',
      ...notes,
      h(
        'div',
        { class: 'controls' },
        h('button', { type: 'button', onclick: () => { if (r.step > 0) { r.step--; renderStep() } }, disabled: r.step === 0 }, '← Back'),
        h('button', { type: 'button', onclick: () => { if (r.step < 5) { r.step++; renderStep() } }, disabled: r.step === 5 }, 'Next step →'),
      ),
    )
    if (r.step === 5) renderBreakout()
  }

  const start = (): void => {
    clear(breakout)
    const x = readSmallInt(xInput)
    const y = readSmallInt(yInput)
    clear(stage)
    if (x === null || y === null) {
      stage.append(chip('warn', '⚠', 'Inputs must be whole numbers of at most 9 digits — nothing was run.'))
      return
    }
    const taken = takeTriples(1)
    if (!taken) {
      stage.append(
        h(
          'p',
          {},
          chip('warn', '⚠', 'Triple bank is empty — the online phase is blocked until preprocessing runs.'),
          ' ',
          h('button', { type: 'button', onclick: () => { preprocess(); start() } }, 'Run preprocessing now'),
        ),
      )
      return
    }
    const triple = taken[0] as Triple
    const xs = shareSecret(x, alphaShares)
    const ys = shareSecret(y, alphaShares)
    const result = beaverMulChecked(xs, ys, triple, alphaShares)
    if (result.kind === 'abort') {
      stage.append(chip('alarm', '✗', 'An honest run aborted — impossible unless the lab has a bug.'))
      return
    }
    run = {
      x,
      y,
      xs,
      ys,
      triple,
      d: result.transcript.d,
      e: result.transcript.e,
      dCheck: result.dCheck,
      eCheck: result.eCheck,
      z: result.z,
      step: 0,
    }
    renderStep()
  }

  const renderBreakout = (): void => {
    clear(breakout)
    if (!run) return
    const r = run
    const x2Input = h('input', { id: 'mul-x2', type: 'text', inputmode: 'numeric', value: '4' })
    const out = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

    const attack = (reuse: boolean): void => {
      clear(out)
      const x2 = readSmallInt(x2Input)
      if (x2 === null) {
        out.append(chip('warn', '⚠', 'x′ must be a whole number of at most 9 digits.'))
        return
      }
      const xs2 = shareSecret(x2, alphaShares)
      let transcript: { d: bigint; e: bigint }
      if (reuse) {
        // Deliberately breaking the single-use rule — the one place the unsafe path is allowed.
        transcript = beaverMulUnsafe(xs2, r.ys, r.triple, alphaShares).transcript
      } else {
        const taken = takeTriples(1)
        if (!taken) {
          out.append(chip('warn', '⚠', 'No fresh triple available — run preprocessing below first.'))
          return
        }
        const fresh = beaverMulChecked(xs2, r.ys, taken[0] as Triple, alphaShares)
        if (fresh.kind === 'abort') {
          out.append(chip('alarm', '✗', 'Honest run aborted — impossible unless the lab has a bug.'))
          return
        }
        transcript = fresh.transcript
      }
      const diff = sub(r.d, transcript.d)
      const trueDiff = sub(r.x, x2)
      const leaked = diff === trueDiff
      out.append(
        h('p', { class: 'kv' }, 'First run published d = ', fe(r.d), '; this run published d′ = ', fe(transcript.d), '.'),
        h('p', { class: 'kv' }, 'Anyone on the wire computes d − d′ = ', fe(diff), ' and x − x′ actually is ', fe(trueDiff), '. '),
        leaked
          ? chip('alarm', '✗', 'LEAK: the public wire just revealed x − x′ — same a in both runs, so it cancels out')
          : chip('ok', '✓', 'No leak: a fresh random a′ masks the difference — d − d′ is uniformly random junk'),
        h(
          'p',
          { class: 'note' },
          reuse
            ? 'This is why the honest code path refuses a consumed triple. The "d leaks nothing" proof needs a to be uniform AND single-use — reuse silently deletes the second condition.'
            : 'With one-time randomness the wire carries only one-time-pad ciphertext. This is the guarantee reuse destroys.',
        ),
      )
    }

    breakout.append(
      h('h3', {}, 'Break it: reuse the triple'),
      h(
        'p',
        {},
        `The triple from the run above is spent. Multiply a second secret x′ by the same y — once reusing that spent triple, once with a fresh one — and compare what the public wire gives away.`,
      ),
      h(
        'div',
        { class: 'controls' },
        h('label', { for: 'mul-x2' }, 'Second secret x′'),
        x2Input,
        h('button', { type: 'button', class: 'danger-btn', onclick: () => attack(true) }, 'Reuse the spent triple'),
        h('button', { type: 'button', onclick: () => attack(false) }, 'Use a fresh triple'),
      ),
      out,
    )
    renderOpeningAttack()
  }

  const renderOpeningAttack = (): void => {
    if (!run) return
    const r = run
    const deltaInput = h('input', { id: 'mul-ddelta', type: 'text', inputmode: 'numeric', value: '9' })
    const out = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

    const attack = (): void => {
      clear(out)
      const raw = deltaInput.value.trim()
      if (!/^\d{1,9}$/.test(raw) || BigInt(raw) === 0n) {
        out.append(chip('warn', '⚠', 'The lie must be a non-zero whole number of at most 9 digits.'))
        return
      }
      const delta = BigInt(raw)
      const taken = takeTriples(1)
      if (!taken) {
        out.append(
          h(
            'p',
            {},
            chip('warn', '⚠', 'No triple available for the attack run.'),
            ' ',
            h('button', { type: 'button', onclick: () => { preprocess(); attack() } }, 'Run preprocessing now'),
          ),
        )
        return
      }
      const t = taken[0] as Triple
      t.consumed = true
      // You (P₁) lie in the broadcast that opens d: your share of x − a is off by δ.
      const dShares = tamperShare(subShares(r.xs, t.a), 1, delta)
      const dOpen = openAuthenticated(dShares, alphaShares)
      const eOpen = openAuthenticated(subShares(r.ys, t.b), alphaShares)

      // Counterfactual: parties who skip opening checks continue with the lied d.
      const zEvil = combineWithOpenings(t, dOpen.value, eOpen.value, alphaShares)
      const zOpened = openValue(zEvil)
      const finalCheck = macCheck(zOpened, zEvil, alphaShares)
      const trueProduct = mul(r.x, r.y)
      // The claim in the verdict below is "a WRONG product with a VALID MAC".
      // Both halves are checked, not asserted: the product is only wrong if it
      // actually differs from x·y (with y = 0 the lie is absorbed and z′ IS
      // correct), and the MAC is only valid if the final check really passes.
      const predicted = add(trueProduct, mul(delta, r.y))
      const productWrong = zOpened !== trueProduct
      const matchesPrediction = zOpened === predicted

      out.append(
        h(
          'div',
          { class: 'proto-row' },
          h(
            'div',
            { class: 'proto-col' },
            h('h3', {}, 'Parties who skip the opening check'),
            h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'They compute z′ = '), fe(zOpened)),
            h(
              'p',
              { class: 'kv' },
              h('span', { class: 'kv-label' }, 'True product: '),
              fe(trueProduct),
              ' — predicted z′ = x·y + δ·y = ',
              fe(predicted),
              ' ',
              matchesPrediction
                ? chip('ok', '✓', 'the opened z′ matches that prediction exactly')
                : chip('alarm', '✗', 'opened z′ does NOT match the prediction'),
            ),
            h(
              'p',
              { class: 'kv' },
              h('span', { class: 'kv-label' }, 'Final MAC check on z′: '),
              finalCheck.ok ? chip('neutral', '▸', 'PASSES — Σσᵢ = 0') : chip('neutral', '▸', `fails — Σσᵢ = ${finalCheck.sum}`),
            ),
            h(
              'p',
              { class: 'kv' },
              h('span', { class: 'kv-label' }, 'Verdict: '),
              productWrong && finalCheck.ok
                ? chip('alarm', '✗', 'a WRONG product with a perfectly VALID MAC')
                : productWrong
                  ? chip('ok', '✓', 'the wrong product did not carry a valid MAC')
                  : chip('neutral', '▸', 'the product is still correct — δ·y vanished'),
            ),
            h(
              'p',
              { class: 'note' },
              productWrong
                ? 'The MAC shares rode the same linear combination as the lie, so they authenticate z′ faithfully. A final check can never repair an unauthenticated opening.'
                : `δ·y = δ·${r.y} is zero in the field, so shifting d moved nothing: z′ still equals x·y. Set y to a non-zero secret and re-run to see the attack bite. (SPDZ aborts either way — the opening check does not care whether the lie happened to be harmless.)`,
            ),
          ),
          h(
            'div',
            { class: 'proto-col' },
            h('h3', {}, 'SPDZ: the opening itself is checked'),
            h(
              'p',
              { class: 'kv' },
              h('span', { class: 'kv-label' }, 'MAC check on the opened d: '),
              dOpen.ok
                ? chip('neutral', '▸', 'PASSES — you hit the 1/p forgery event')
                : chip('neutral', '▸', 'Σσᵢ ≠ 0 — ABORT at the d opening'),
            ),
            h(
              'p',
              { class: 'kv' },
              h('span', { class: 'kv-label' }, 'Verdict: '),
              dOpen.ok
                ? chip('alarm', '✗', 'forgery slipped through — probability ≈ 4.3×10⁻¹⁹ per attempt')
                : chip('ok', '✓', 'the lie died at the opening — no product was ever computed'),
            ),
            h(
              'p',
              { class: 'note' },
              dOpen.ok
                ? 'This session’s MAC key happens to annihilate your δ — the exactly-1/p event the security bound talks about. Reload the page for a fresh key and it will not happen again in the lifetime of the universe.'
                : 'd = x − a is itself a shared value with MAC shares, so its opening is authenticated like any other. The multiplication never reaches the combine step.',
            ),
          ),
        ),
      )
    }

    breakout.append(
      h('h3', {}, 'Break it: lie during the d opening'),
      h(
        'p',
        {},
        'The subtler attack. As P₁, add δ to your broadcast share of x − a, shifting the public d. Everyone then computes z′ = x·y + δ·y — and here is the trap: z′ arrives with a VALID MAC, because the MAC shares follow the same algebra. Compare what happens with and without authenticated openings.',
      ),
      h(
        'div',
        { class: 'controls' },
        h('label', { for: 'mul-ddelta' }, 'Your lie δ'),
        deltaInput,
        h('button', { type: 'button', class: 'danger-btn', onclick: attack }, 'Lie during the opening'),
      ),
      out,
    )
  }

  mount.append(
    h(
      'div',
      { class: 'controls' },
      h('label', { for: 'mul-x' }, 'Secret x'),
      xInput,
      h('label', { for: 'mul-y' }, 'Secret y'),
      yInput,
      h('button', { type: 'button', onclick: start }, 'Start multiplication'),
      bankChip,
    ),
    stage,
    breakout,
  )
}
