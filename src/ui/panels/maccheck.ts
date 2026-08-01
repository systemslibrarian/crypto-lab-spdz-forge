/**
 * Panel 3 — THE MAC CHECK (headline mechanism #2, the reason this lab exists).
 *
 * The learner plays the malicious party P₁: edit your shares before the
 * reveal, then run the SAME tampered shares through both protocols side by
 * side. Semi-honest: the wrong answer is accepted by everyone. SPDZ: the MAC
 * check fails and the honest parties abort.
 *
 * BOTH shares are editable — the value share and the MAC share. That second
 * control is deliberate. The abort message names the winning move ("you would
 * need to shift your MAC share by α·Δ") and the panel prints α in the clear,
 * so without a way to act on it the lab was describing an attack it would not
 * let you run. With it, the learner sets the MAC shift to α·Δ, watches
 * Σσᵢ land on exactly zero, and sees a forged value accepted in silence —
 * which is the guarantee stated exactly, not broken: the check is worth
 * precisely as much as α is secret, and α is visible here only because this
 * tab plays the dealer.
 *
 * Verdict separation (binding): each column renders the protocol's raw
 * outcome AND an independent integrity verdict. A wrong-but-accepted result
 * is ALARM even though the protocol "succeeded"; an abort on cheating is the
 * system WORKING.
 */

import { mod, mul } from '../../spdz/field'
import { openSemiHonest, openSpdz } from '../../spdz/protocol'
import { macKeyOf, openValue, shareSecret, tamperShare } from '../../spdz/sharing'
import { cancellingSigma, macCheckCommitThenOpen, macCheckNoCommit } from '../../spdz/transcript'
import type { AuthShares } from '../../spdz/types'
import { alphaShares } from '../state'
import { chip, clear, fe, h } from '../dom'

const SECRET = 42n
const PARTIES = ['P₀', 'P₁ (you)', 'P₂']

export function renderMacPanel(mount: HTMLElement): void {
  const shares = shareSecret(SECRET, alphaShares)
  const deltaInput = h('input', { id: 'mac-delta', type: 'text', inputmode: 'numeric', value: '100' })
  // The second control is the one that makes the named attack executable: the
  // panel tells you the winning move is to shift your MAC share by α·Δ, so
  // there has to be a way to shift it. Field elements are up to 19 digits, so
  // this one accepts a wider range than the value delta.
  const macDeltaInput = h('input', {
    id: 'mac-delta-gamma',
    type: 'text',
    inputmode: 'numeric',
    value: '0',
  })
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
              h('td', {}, fe(current[i]!.mac), i === 1 && current[i]!.mac !== shares[i]!.mac ? h('span', { class: 'edited-tag' }, ' (edited)') : ''),
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
    const rawMac = macDeltaInput.value.trim()
    if (!/^-?\d{1,19}$/.test(rawMac)) {
      out.append(chip('warn', '⚠', 'The MAC-share shift must be a whole number (up to 19 digits, may be negative). Use 0 to leave your MAC share alone.'))
      return
    }
    const delta = BigInt(raw)
    const macDelta = mod(BigInt(rawMac))
    const tampered = tamperShare(shares, 1, delta, macDelta)
    const honest = delta === 0n && macDelta === 0n

    // The single number that decides everything below. Σσᵢ = macDelta − α·Δ,
    // so the check passes iff the learner's MAC shift lands exactly on α·Δ.
    const forgingMac = mul(macKeyOf(alphaShares), mod(delta))

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
        ? `The true value is ${SECRET}. Every party dutifully summed the shares, got ${semi.value}, and accepted it. The protocol has no mechanism to even ask whether a share was honest — this is what "assumes the parties follow the protocol" costs. Note the MAC-share shift is irrelevant here: this protocol never looks at the MAC shares at all.`
        : 'You shifted the value share by 0, so of course the sum is right. Set a non-zero amount to actually cheat.',
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
            'Σσᵢ is not noise — it is exactly (your MAC shift) − α·Δ, in the field. For this run: ',
          ),
          h('p', { class: 'kv' }, 'α·Δ = ', fe(forgingMac), '  your MAC shift = ', fe(macDelta)),
          h(
            'p',
            { class: 'note' },
            macDelta === 0n
              ? `You left your MAC share alone, so the residue is −α·Δ. The winning move is the one this paragraph used to only describe: set the MAC-share shift to α·Δ = ${forgingMac}. The field above will take it, Σσᵢ will hit exactly zero, and the honest parties will release your forged value. That is not a bug in the check; it is the check's precise statement. In a real deployment you could not compute that number, because α is additively shared and no party holds it — your only move would be guessing, one chance in p ≈ 2.3×10¹⁸.`
              : `You shifted your MAC share, but not to α·Δ — you are off by exactly Σσᵢ. Every miss aborts identically; the check has no notion of "nearly right". Set the shift to ${forgingMac} to watch it pass. You can only do that here because this tab plays the dealer and prints α above; in a real deployment α is additively shared and no party holds it, so the same forgery costs one guess in p ≈ 2.3×10¹⁸.`,
          ),
          h(
            'p',
            { class: 'note' },
            `That bound assumes one more thing: your check share is fixed BEFORE you see anyone else's (the advanced break-it below shows why that ordering rule is load-bearing). Be precise about what just happened: SPDZ detected THAT someone cheated and refused to release a wrong answer. It did not compute the right answer despite the cheating, and it did not learn WHO cheated (that stronger property is called identifiable abort — a different protocol, not built here).`,
          ),
        ),
      )
    } else {
      const forged = !honest && macDelta === forgingMac && delta !== 0n
      spdzCol = verdictBlock(
        'SPDZ (MAC on)',
        chip('neutral', '▸', `ACCEPTED — opened value ${spdz.value}`),
        honest
          ? chip('ok', '✓', 'MAC check passed: Σσᵢ = 0')
          : chip('alarm', '✗', 'ALARM — a forged value carried a valid MAC'),
        honest
          ? 'No tampering, so the MAC check passes and the correct value is released.'
          : forged
            ? h(
                'div',
                {},
                h(
                  'p',
                  { class: 'note' },
                  `You executed the forgery the abort message names. Shifting your value share by Δ = ${delta} and your MAC share by exactly α·Δ = ${forgingMac} makes σ₁ absorb the change, so Σσᵢ = 0 and the honest parties release ${spdz.value} believing it is ${SECRET}. No abort, no attribution, no trace.`,
                ),
                h(
                  'p',
                  { class: 'note' },
                  'This is the guarantee stated exactly, not broken: the MAC check is worth precisely as much as α is secret. You could compute α·Δ only because this tab plays the dealer and prints α at the top of the panel. Take that number away — as SPDZ does by sharing α additively across the parties, so nobody ever holds it, and by producing the shares in an offline phase rather than from a dealer — and the same attack costs one guess in p ≈ 2.3×10¹⁸ per opening.',
                ),
              )
            : 'Accepted despite tampering — you hit the modeled 1/p forgery event (probability ≈ 4.3×10⁻¹⁹): this session’s α·Δ happens to equal your MAC shift. That is the exact strength, and the exact limit, of the information-theoretic MAC.',
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
      h('label', { for: 'mac-delta-gamma' }, 'Add this to your MAC share γ(x)₁'),
      macDeltaInput,
      h('button', { type: 'button', class: 'danger-btn', onclick: runBoth }, 'Cheat & open in both protocols'),
    ),
    h(
      'p',
      { class: 'note' },
      'Both controls are live. Leave the MAC shift at 0 for the ordinary cheat and the check aborts. To forge, set it to α·Δ — for the default Δ = 100 in this session that is ',
      (() => {
        const el = fe(mul(macKeyOf(alphaShares), 100n))
        el.id = 'mac-forging-value'
        return el
      })(),
      ' — and Σσᵢ hits exactly zero: a wrong value with a valid MAC, accepted in silence. Being able to do that here is the point. It works only because this tab plays the dealer and prints α above; strip α away, as sharing it additively across the parties does, and the same move costs one guess in p.',
    ),
    out,
    renderOrderingExhibit(shares),
  )
}

/**
 * GS-02 exhibit: the MAC check needs message ORDERING, not just algebra.
 * An adversary who may send its check share last can cancel Σσᵢ for any
 * forged value — no α guessing. Commit-then-open kills the move.
 */
function renderOrderingExhibit(shares: AuthShares): HTMLElement {
  const out = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

  const attack = async (): Promise<void> => {
    clear(out)
    // Forge the opened value, then attack the CHECK itself as the last sender.
    const forged = tamperShare(shares, 1, 100n)
    const opened = openValue(forged)

    const unordered = macCheckNoCommit(opened, forged, alphaShares, {
      party: 1,
      chooseSigma: cancellingSigma, // sees the honest σ's, sends their negation
    })
    const committed = await macCheckCommitThenOpen(opened, forged, alphaShares, {
      party: 1,
      // Same adversary: commits honestly, then — having seen the honest σ's — tries to swap in the cancelling value.
      revealOverride: (others) => cancellingSigma(others),
    })

    out.append(
      h(
        'div',
        { class: 'proto-row' },
        h(
          'div',
          { class: 'proto-col' },
          h('h3', {}, 'Unordered check (σ’s sent in the open)'),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'You waited, saw the honest σ’s, sent: '), fe(unordered.sigmas[1] as bigint)),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Protocol outcome: '),
            unordered.ok
              ? chip('neutral', '▸', `ACCEPTED — forged value ${opened}, Σσᵢ = 0`)
              : chip('neutral', '▸', 'rejected'),
          ),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Verdict: '),
            unordered.ok
              ? chip('alarm', '✗', 'forged value accepted — no α guessing, just patience')
              : chip('ok', '✓', 'rejected'),
          ),
          h(
            'p',
            { class: 'note' },
            'The 1/p security bound is simply false for this transcript: the last sender computes the cancelling σ from what everyone else revealed.',
          ),
        ),
        h(
          'div',
          { class: 'proto-col' },
          h('h3', {}, 'SPDZ transcript: commit, then open'),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Protocol outcome: '),
            committed.commitmentFailure !== null
              ? chip('neutral', '▸', 'ABORT — a reveal contradicted its commitment')
              : committed.ok
                ? chip('neutral', '▸', 'accepted')
                : chip('neutral', '▸', 'ABORT — Σσᵢ ≠ 0'),
          ),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Verdict: '),
            committed.ok
              ? chip('alarm', '✗', 'forgery slipped through — should be the 1/p event only')
              : chip('ok', '✓', 'the cancellation attempt died — commitments bind before reveals'),
          ),
          h(
            'p',
            { class: 'note' },
            'Every party commits to SHA-256(nonce ‖ σᵢ) before any σ is revealed. Your cancelling reveal no longer matches your commitment, and the honest parties abort. The commitments here are real hashes over real nonces; what this single tab models is only the network ordering.',
          ),
        ),
      ),
    )
  }

  return h(
    'details',
    {},
    h('summary', {}, 'Advanced break-it: attack the check itself by sending your σ last'),
    h(
      'p',
      { class: 'note' },
      'The check above sums σᵢ = γ(x)ᵢ − αᵢ·x and demands zero. Algebra alone is not enough: if you may send your σ AFTER seeing everyone else’s, you can send the exact negation of their sum and “pass” with any forged value. Real SPDZ therefore makes every party commit to its σ before any are revealed.',
    ),
    h(
      'div',
      { class: 'controls' },
      h('button', { type: 'button', class: 'danger-btn', onclick: () => void attack() }, 'Cheat & send your σ last'),
    ),
    out,
  )
}
