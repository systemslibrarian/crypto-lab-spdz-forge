/**
 * Panel 5 — Application: three hospitals compute a variance.
 *
 * Variance needs multiplication (squares), which addition-only MPC — like the
 * sibling silent-tally demo — cannot do. The parties compute the integer
 * M = n·Σv² − (Σv)² = n²·Var inside the field, open ONLY M under a MAC
 * check, and divide by n² in the clear. No individual input is ever opened.
 */

import { varianceFromNumerator, varianceNumeratorDirect, varianceOverMpc } from '../../spdz/protocol'
import { tamperShare } from '../../spdz/sharing'
import { alphaShares, preprocess, takeTriples } from '../state'
import { chip, clear, fe, h } from '../dom'

const HOSPITALS = ['General', "St. Mary's", 'County']

export function renderVariancePanel(mount: HTMLElement): void {
  const inputs = [
    h('input', { id: 'var-0', type: 'text', inputmode: 'numeric', value: '120' }),
    h('input', { id: 'var-1', type: 'text', inputmode: 'numeric', value: '95' }),
    h('input', { id: 'var-2', type: 'text', inputmode: 'numeric', value: '160' }),
  ]
  const lieBox = h('input', { id: 'var-lie', type: 'checkbox' })
  const out = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

  const run = (): void => {
    clear(out)
    const values: bigint[] = []
    for (const inp of inputs) {
      const v = inp.value.trim()
      if (!/^\d{1,6}$/.test(v)) {
        out.append(chip('warn', '⚠', 'Each count must be a whole number of at most 6 digits (so the integer result cannot wrap mod p).'))
        return
      }
      values.push(BigInt(v))
    }
    const triples = takeTriples(4)
    if (!triples) {
      out.append(
        h(
          'p',
          {},
          chip('warn', '⚠', 'Not enough triples banked — this computation needs 4 (three squares plus the square of the sum).'),
          ' ',
          h('button', { type: 'button', onclick: () => { preprocess(); run() } }, 'Run preprocessing now'),
        ),
      )
      return
    }
    const lying = lieBox.checked
    const runResult = varianceOverMpc(
      values,
      alphaShares,
      triples,
      undefined,
      lying ? { finalOpen: (num) => tamperShare(num, 1, 7n) } : undefined,
    )

    out.append(
      h(
        'p',
        { class: 'kv' },
        h('span', { class: 'kv-label' }, 'Online phase: '),
        `4 multiplications, 4 triples consumed, and the public wire carried only the 8 masked openings (d, e per multiply) plus the final result. No hospital's count was ever opened.`,
      ),
    )

    if (runResult.numerator.kind === 'abort') {
      out.append(
        h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Protocol outcome: '), chip('neutral', '▸', 'ABORT — no statistic released')),
        h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Verdict: '), chip('ok', '✓', 'a MAC inconsistency was detected — abort is the correct behavior')),
        h(
          'p',
          { class: 'note' },
          'That verdict is everything the participants learn. They do not get a corrected statistic, and nothing in the protocol transcript says which hospital cheated — abort detects, it does not attribute.',
        ),
        h(
          'p',
          { class: 'note lab-note' },
          h('strong', {}, 'Lab control (omniscient view): '),
          'the scenario checkbox you ticked altered one hospital’s contribution before the final reveal. You know that because you are outside the protocol looking in; the three hospitals cannot see it.',
        ),
      )
      return
    }

    const M = runResult.numerator.value
    const directM = varianceNumeratorDirect(values)
    const variance = varianceFromNumerator(M, 3)
    out.append(
      h(
        'p',
        { class: 'kv' },
        h('span', { class: 'kv-label' }, 'Opened (MAC-checked): '),
        'M = 3·Σv² − (Σv)² = ',
        fe(M),
        ' ',
        chip('ok', '✓', 'MAC check passed'),
      ),
      h(
        'p',
        { class: 'kv' },
        h('span', { class: 'kv-label' }, 'Population variance: '),
        `M / 9 = ${variance.toFixed(4)}`,
        ' — computed directly from the plaintext inputs it is ',
        `${(Number(directM) / 9).toFixed(4)} `,
        M === directM ? chip('ok', '✓', 'both sides equal') : chip('alarm', '✗', 'mismatch'),
      ),
    )
  }

  mount.append(
    h(
      'p',
      {},
      'Three hospitals want the variance of their patient counts without revealing any count. Variance needs Σv² — a multiplication — so the addition-only approach of the sibling ',
      h('a', { href: 'https://systemslibrarian.github.io/crypto-lab-silent-tally/' }, 'silent-tally'),
      ' demo (semi-honest, sums only) cannot compute it. SPDZ can, and maliciously-securely.',
    ),
    h(
      'div',
      { class: 'controls' },
      ...HOSPITALS.flatMap((name, i) => [h('label', { for: `var-${i}` }, `${name} count`), inputs[i] as HTMLElement]),
    ),
    h(
      'div',
      { class: 'controls' },
      lieBox,
      h('label', { for: 'var-lie' }, "Scenario control: make St. Mary's lie during the final open"),
      h('button', { type: 'button', onclick: run }, 'Compute variance over MPC'),
    ),
    out,
  )
}
