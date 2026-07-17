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

import { mul, sub } from '../../spdz/field'
import { beaverMul, beaverMulUnsafe } from '../../spdz/beaver'
import { macCheck, openValue, shareSecret } from '../../spdz/sharing'
import type { AuthShares, Triple } from '../../spdz/types'
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

  const partyCard = (i: number, rows: [string, Node][]): HTMLElement =>
    h(
      'div',
      { class: 'party-card' },
      h('h3', {}, PARTIES[i] as string),
      ...rows.map(([label, val]) => h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, label + ' '), val)),
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
      const rows: [string, Node][] = []
      if (r.step >= 0) {
        rows.push([`xᵢ`, fe(r.xs[i]!.value)], [`yᵢ`, fe(r.ys[i]!.value)])
      }
      if (r.step >= 1) {
        rows.push([`aᵢ`, fe(r.triple.a[i]!.value)], [`bᵢ`, fe(r.triple.b[i]!.value)], [`cᵢ`, fe(r.triple.c[i]!.value)])
      }
      if (r.step >= 2) rows.push(['xᵢ − aᵢ →', fe(sub(r.xs[i]!.value, r.triple.a[i]!.value))])
      if (r.step >= 3) rows.push(['yᵢ − bᵢ →', fe(sub(r.ys[i]!.value, r.triple.b[i]!.value))])
      if (r.step >= 4) rows.push([`zᵢ`, fe(r.z[i]!.value)])
      cards.push(partyCard(i, rows))
    }

    if (r.step >= 2) wire.push(h('p', { class: 'kv' }, 'd = x − a = ', fe(r.d), ' (public)'))
    if (r.step >= 3) wire.push(h('p', { class: 'kv' }, 'e = y − b = ', fe(r.e), ' (public)'))

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
            'd is safe to publish: a is uniformly random and used exactly once, so d = x − a is itself a uniformly random field element. Anyone watching the wire learns nothing about x. (The break-it below shows how this guarantee dies the moment a is reused.)',
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
    const { z, transcript } = beaverMul(xs, ys, triple, alphaShares)
    run = { x, y, xs, ys, triple, d: transcript.d, e: transcript.e, z, step: 0 }
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
        transcript = beaverMul(xs2, r.ys, taken[0] as Triple, alphaShares).transcript
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
