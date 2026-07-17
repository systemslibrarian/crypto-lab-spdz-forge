/**
 * Panel 3 — THE MAC CHECK (headline mechanism #2, the reason this lab exists).
 *
 * The learner plays the malicious party P₁: edit your share before the
 * reveal, then run the SAME tampered shares through both protocols side by
 * side. Semi-honest: the wrong answer is accepted by everyone. SPDZ: the MAC
 * check fails and the honest parties abort.
 *
 * Verdict separation (binding): each column renders the protocol's raw
 * outcome AND an independent integrity verdict. A wrong-but-accepted result
 * is ALARM even though the protocol "succeeded"; an abort on cheating is the
 * system WORKING.
 */

import { mul } from '../../spdz/field'
import { openSemiHonest, openSpdz } from '../../spdz/protocol'
import { macKeyOf, shareSecret, tamperShare } from '../../spdz/sharing'
import type { AuthShares } from '../../spdz/types'
import { alphaShares } from '../state'
import { chip, clear, fe, h } from '../dom'

const SECRET = 42n
const PARTIES = ['P₀', 'P₁ (you)', 'P₂']

export function renderMacPanel(mount: HTMLElement): void {
  const shares = shareSecret(SECRET, alphaShares)
  const deltaInput = h('input', { id: 'mac-delta', type: 'text', inputmode: 'numeric', value: '100' })
  const out = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

  const shareTable = (current: AuthShares): HTMLElement =>
    h(
      'div',
      { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': 'Authenticated shares of the value 42' },
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
            h('th', { scope: 'col' }, 'value share'),
            h('th', { scope: 'col' }, 'MAC share γ(x)ᵢ'),
          ),
        ),
        h(
          'tbody',
          {},
          ...PARTIES.map((name, i) =>
            h(
              'tr',
              { class: i === 1 ? 'you-row' : '' },
              h('th', { scope: 'row' }, name),
              h('td', {}, fe(current[i]!.value), i === 1 && current[i]!.value !== shares[i]!.value ? h('span', { class: 'edited-tag' }, ' (edited)') : ''),
              h('td', {}, fe(current[i]!.mac)),
            ),
          ),
        ),
      ),
    )

  const verdictBlock = (
    protoName: string,
    outcome: HTMLElement,
    verdict: HTMLElement,
    detail: HTMLElement | string,
  ): HTMLElement =>
    h(
      'div',
      { class: 'proto-col' },
      h('h3', {}, protoName),
      h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Protocol outcome: '), outcome),
      h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Verdict: '), verdict),
      typeof detail === 'string' ? h('p', { class: 'note' }, detail) : detail,
    )

  const runBoth = (): void => {
    clear(out)
    const raw = deltaInput.value.trim()
    if (!/^-?\d{1,12}$/.test(raw)) {
      out.append(chip('warn', '⚠', 'The tamper amount must be a whole number (up to 12 digits, may be negative).'))
      return
    }
    const delta = BigInt(raw)
    const tampered = tamperShare(shares, 1, delta)
    const honest = delta === 0n

    const semi = openSemiHonest(tampered)
    const spdz = openSpdz(tampered, alphaShares)

    const semiWrong = semi.value !== SECRET
    const semiCol = verdictBlock(
      'Semi-honest protocol (MAC off)',
      chip('neutral', '▸', `ACCEPTED — opened value ${semi.value}`),
      semiWrong
        ? chip('alarm', '✗', 'ALARM — a wrong answer was accepted and nobody can tell')
        : chip('ok', '✓', 'correct value, integrity held'),
      semiWrong
        ? `The true value is ${SECRET}. Every party dutifully summed the shares, got ${semi.value}, and accepted it. The protocol has no mechanism to even ask whether a share was honest — this is what "assumes the parties follow the protocol" costs.`
        : 'You tampered by 0, i.e. not at all — so of course the sum is right. Set a non-zero amount to actually cheat.',
    )

    let spdzCol: HTMLElement
    if (spdz.kind === 'abort') {
      spdzCol = verdictBlock(
        'SPDZ (MAC on)',
        chip('neutral', '▸', 'ABORT — no value released'),
        chip('ok', '✓', 'cheating detected — the system worked'),
        h(
          'div',
          {},
          h(
            'p',
            { class: 'note' },
            'Each party computed its check share σᵢ = γ(x)ᵢ − αᵢ·(opened value). The sum should be exactly 0; it came out ',
          ),
          h('p', { class: 'kv' }, 'Σσᵢ = ', fe(spdz.check.sum), ' ≠ 0'),
          h(
            'p',
            { class: 'note' },
            `To slip a change of Δ past the check you would need to shift your MAC share by α·Δ — and α is secret-shared, held by nobody. Your only move is guessing α: one chance in p ≈ 2.3×10¹⁸. Be precise about what just happened: SPDZ detected THAT someone cheated and refused to release a wrong answer. It did not compute the right answer despite the cheating, and it did not learn WHO cheated (that stronger property is called identifiable abort — a different protocol, not built here).`,
          ),
        ),
      )
    } else {
      spdzCol = verdictBlock(
        'SPDZ (MAC on)',
        chip('neutral', '▸', `ACCEPTED — opened value ${spdz.value}`),
        chip('ok', '✓', 'MAC check passed: Σσᵢ = 0'),
        honest
          ? 'No tampering, so the MAC check passes and the correct value is released.'
          : 'Accepted despite tampering — this should be impossible without knowing α. If you ever see this, the lab has a bug.',
      )
    }

    out.append(
      h('p', {}, honest ? 'Your shares, unchanged, run through both protocols:' : 'Your tampered shares, run through both protocols:'),
      shareTable(tampered),
      h('div', { class: 'proto-row' }, semiCol, spdzCol),
    )
  }

  mount.append(
    h(
      'p',
      {},
      'Three parties hold authenticated shares of the value ',
      fe(SECRET),
      '. You are P₁. The global MAC key α is itself secret-shared — for this session α = ',
      fe(macKeyOf(alphaShares)),
      ' (the dealer shows you; the parties never see it), and your MAC share was dealt as a share of α·42 = ',
      fe(mul(macKeyOf(alphaShares), SECRET)),
      '.',
    ),
    shareTable(shares),
    h(
      'div',
      { class: 'controls' },
      h('label', { for: 'mac-delta' }, 'Add this to your value share before the reveal'),
      deltaInput,
      h('button', { type: 'button', class: 'danger-btn', onclick: runBoth }, 'Cheat & open in both protocols'),
    ),
    out,
  )
}
