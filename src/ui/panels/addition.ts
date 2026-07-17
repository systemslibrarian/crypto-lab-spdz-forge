/**
 * Panel 1 — Addition is free.
 * Shares add locally, no communication, done. Establishes the baseline the
 * Beaver panel then breaks: multiplication has no such local trick.
 */

import { addShares, openValue, shareSecret } from '../../spdz/sharing'
import { alphaShares } from '../state'
import { chip, clear, fe, h } from '../dom'

const PARTIES = ['P₀', 'P₁', 'P₂']

function readSmallInt(input: HTMLInputElement): bigint | null {
  const v = input.value.trim()
  if (!/^\d{1,9}$/.test(v)) return null
  return BigInt(v)
}

export function renderAdditionPanel(mount: HTMLElement): void {
  const xInput = h('input', { id: 'add-x', type: 'text', inputmode: 'numeric', value: '12' })
  const yInput = h('input', { id: 'add-y', type: 'text', inputmode: 'numeric', value: '30' })
  const out = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

  const run = (): void => {
    clear(out)
    const x = readSmallInt(xInput)
    const y = readSmallInt(yInput)
    if (x === null || y === null) {
      out.append(chip('warn', '⚠', 'Inputs must be whole numbers of at most 9 digits — nothing was shared.'))
      return
    }
    const xs = shareSecret(x, alphaShares)
    const ys = shareSecret(y, alphaShares)
    const sum = addShares(xs, ys)
    const opened = openValue(sum)

    const table = h(
      'table',
      { class: 'share-table' },
      h(
        'thead',
        {},
        h(
          'tr',
          {},
          h('th', { scope: 'col' }, 'Party'),
          h('th', { scope: 'col' }, `share of x = ${x}`),
          h('th', { scope: 'col' }, `share of y = ${y}`),
          h('th', { scope: 'col' }, 'local sum (no messages sent)'),
        ),
      ),
      h(
        'tbody',
        {},
        ...PARTIES.map((name, i) =>
          h(
            'tr',
            {},
            h('th', { scope: 'row' }, name),
            h('td', {}, fe(xs[i]!.value)),
            h('td', {}, fe(ys[i]!.value)),
            h('td', {}, fe(sum[i]!.value)),
          ),
        ),
      ),
    )

    const direct = x + y
    const match = opened === direct
    out.append(
      h(
        'div',
        { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': 'Share table for the addition' },
        table,
      ),
      h(
        'p',
        {},
        'Each party added its two shares by itself. Opening the three local sums: ',
        fe(opened),
        ` — and computed directly, ${x} + ${y} = ${direct}. `,
        match
          ? chip('ok', '✓', 'both sides equal')
          : chip('alarm', '✗', 'mismatch — this should never happen'),
      ),
      h(
        'p',
        { class: 'note' },
        `The shares look nothing like ${x} or ${y} — each is a uniformly random field element, and any two of the three reveal nothing about the secret. Addition needed zero communication. Now try to do that for multiplication: x·y is not the sum of anything the parties hold locally. That is the problem the next panel solves.`,
      ),
      h(
        'details',
        {},
        h('summary', {}, 'Inspect the MAC shares too'),
        h(
          'p',
          { class: 'note' },
          'Every value share travels with a MAC share — a share of α·x under the global key α nobody holds. MAC shares are additive too, so the sum is born authenticated: γ(x)ᵢ + γ(y)ᵢ is automatically a share of α·(x+y). This is why SPDZ gets addition (and every linear operation) authenticated for free.',
        ),
        h(
          'div',
          { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': 'MAC share table for the addition' },
          h(
            'table',
            { class: 'share-table' },
            h(
              'thead',
              {},
              h(
                'tr',
                {},
                h('th', { scope: 'col' }, 'Party'),
                h('th', { scope: 'col' }, 'γ(x)ᵢ'),
                h('th', { scope: 'col' }, 'γ(y)ᵢ'),
                h('th', { scope: 'col' }, 'γ(x)ᵢ + γ(y)ᵢ = γ(x+y)ᵢ'),
              ),
            ),
            h(
              'tbody',
              {},
              ...PARTIES.map((name, i) =>
                h(
                  'tr',
                  {},
                  h('th', { scope: 'row' }, name),
                  h('td', {}, fe(xs[i]!.mac)),
                  h('td', {}, fe(ys[i]!.mac)),
                  h('td', {}, fe(sum[i]!.mac)),
                ),
              ),
            ),
          ),
        ),
      ),
    )
  }

  mount.append(
    h(
      'div',
      { class: 'controls' },
      h('label', { for: 'add-x' }, 'Secret x'),
      xInput,
      h('label', { for: 'add-y' }, 'Secret y'),
      yInput,
      h('button', { type: 'button', onclick: run }, 'Share & add'),
    ),
    out,
  )
}
