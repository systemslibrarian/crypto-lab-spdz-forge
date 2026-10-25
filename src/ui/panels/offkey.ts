/**
 * Paper extension — inconsistent MAC-key contexts (Off-Key).
 *
 * The visible comparison is generated from authenticated shares and the real
 * MAC-check arithmetic in src/spdz/offkey.ts.  Attacker-visible outputs and
 * the omniscient teaching audit are intentionally separate.
 */

import { runOffKeyExperiment, type CheckVerdict } from '../../spdz/offkey'
import { alphaShares } from '../state'
import { chip, clear, fe, h } from '../dom'

const PARTIES = ['P₀ (corrupt)', 'P₁', 'P₂']

function verdictChip(verdict: CheckVerdict): HTMLElement {
  return verdict === 'accepted'
    ? chip('neutral', '▸', 'ACCEPTED — masked check value is zero')
    : chip('neutral', '▸', 'ABORT — masked check value is non-zero')
}

export function renderOffKeyPanel(mount: HTMLElement): void {
  const secretInput = h('input', {
    id: 'offkey-secret',
    type: 'text',
    inputmode: 'numeric',
    maxlength: '1',
    value: '1',
  })
  const guessInput = h('input', {
    id: 'offkey-guess',
    type: 'text',
    inputmode: 'numeric',
    maxlength: '1',
    value: '1',
  })
  const out = h('div', {
    id: 'offkey-out',
    class: 'result-region',
    role: 'status',
    'aria-live': 'polite',
  })
  for (const input of [secretInput, guessInput]) input.addEventListener('input', () => clear(out))

  const run = (): void => {
    clear(out)
    const secretRaw = secretInput.value.trim()
    const guessRaw = guessInput.value.trim()
    if (!/^[01]$/.test(secretRaw) || !/^[01]$/.test(guessRaw)) {
      out.append(chip('warn', '⚠', 'The bounded fixture requires one bit (0 or 1) in each field.'))
      return
    }

    const result = runOffKeyExperiment(BigInt(secretRaw), BigInt(guessRaw), alphaShares)
    const request = result.request
    const audit = result.teachingAudit

    const attackerView = h(
      'div',
      { class: 'offkey-view', 'data-view': 'attacker' },
      h('h3', {}, 'Attacker-visible transcript'),
      h(
        'p',
        { class: 'note' },
        'P₀ knows its guess g = ',
        fe(request.guess),
        ', shifts only its own key share by Δ = ',
        fe(request.keyShareShift),
        ', and shifts only its own input-MAC share by Δ·g = ',
        fe(request.inputMacShareShift),
        '. This request object contains no y, mask, global key, or honest-party share.',
      ),
      h(
        'p',
        { class: 'kv' },
        h('span', { class: 'kv-label' }, 'Prescribed private affine output: '),
        'u = 1·y + r = ',
        fe(result.affineAttackerView.privateOutput),
        ' (r stays hidden, so u is uniform and reveals no y by itself)',
      ),
      h(
        'p',
        { class: 'note' },
        'The unmasked and masked readouts below are alternative MAC-check protocols applied to cloned authenticated state. A deployment exposes one variant, not both at once.',
      ),
      h(
        'div',
        { class: 'proto-row' },
        h(
          'div',
          { class: 'proto-col', 'data-context': 'same' },
          h('h3', {}, 'One bound context (restored assumption)'),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Honest baseline: '),
            result.honestBaseline.verdict === 'accepted'
              ? chip('ok', '✓', 'ACCEPTED — residual 0')
              : chip('alarm', '✗', 'unexpected abort'),
          ),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Public blind opening d = y − b: '), fe(result.sameContext.openedDifference)),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Unmasked residual: '), fe(result.sameContext.unmaskedCheckValue)),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Visible masked value z: '), fe(result.sameContext.maskedCheckValue)),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Masked check: '), verdictChip(result.sameContext.maskedVerdict)),
          h(
            'p',
            { class: 'note' },
            'The residual is Δ·(g − d). It tests equality to d, which is already public and uniformly masked—not equality to hidden y. This is the same-context control from §4.2, produced by protocol arithmetic rather than a client-side input rule.',
          ),
        ),
        h(
          'div',
          { class: 'proto-col', 'data-context': 'off-key' },
          h('h3', {}, 'Off-Key: input under α, mask/check under β'),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Public blind opening d = y − b: '), fe(result.offKey.openedDifference)),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Unmasked residual: '), fe(result.offKey.unmaskedCheckValue)),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Original unmasked check: '),
            chip('alarm', '✗', `recovers y = ${result.attackerDeductions.unmaskedRecoveredValue}`),
          ),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Visible masked value z: '), fe(result.offKey.maskedCheckValue)),
          h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Fresh-μ masked check: '), verdictChip(result.offKey.maskedVerdict)),
          h(
            'p',
            { class: 'kv' },
            h('span', { class: 'kv-label' }, 'Privacy verdict: '),
            chip('alarm', '✗', `outcome reveals y = ${result.attackerDeductions.maskedInferredBit}`),
          ),
          h(
            'p',
            { class: 'note' },
            result.offKey.maskedVerdict === 'accepted'
              ? `The masked value is zero, so this bit fixture proves y = g = ${request.guess}.`
              : `The masked value is non-zero, so y ≠ g. Because y is promised to be a bit, that identifies y = ${result.attackerDeductions.maskedInferredBit}. For a general field value, one abort would only rule out this guess.`,
          ),
        ),
      ),
    )

    const ordinary = h(
      'div',
      { class: 'lab-note', 'data-view': 'correctness-control' },
      h('strong', {}, 'Correctness control is not the privacy attack.'),
      h(
        'p',
        {},
        'Changing an ordinary value share by 1 while keeping one α context produced residual ',
        fe(result.ordinaryCorruption.residual),
        ' and ',
        result.ordinaryCorruption.verdict === 'abort'
          ? chip('ok', '✓', 'ABORT — wrong computation detected')
          : chip('alarm', '✗', 'accepted — the 1/p forgery event occurred'),
        '. That check protects correctness. Off-Key instead makes the accept/abort behavior depend on an honest input, violating privacy even when the computation aborts.',
      ),
    )

    const contextTable = h(
      'div',
      {
        class: 'scroll-x',
        tabindex: '0',
        role: 'region',
        'aria-label': 'Omniscient comparison of the alpha and beta MAC-key shares',
      },
      h(
        'table',
        { class: 'share-table' },
        h(
          'thead',
          {},
          h('tr', {}, h('th', { scope: 'col' }, 'Party'), h('th', { scope: 'col' }, 'α context share'), h('th', { scope: 'col' }, 'β context share')),
        ),
        h(
          'tbody',
          {},
          ...PARTIES.map((party, index) =>
            h(
              'tr',
              { class: index === request.corruptParty ? 'you-row' : '' },
              h('th', { scope: 'row' }, party),
              h('td', {}, fe(audit.alphaShares[index] as bigint)),
              h('td', {}, fe(audit.betaShares[index] as bigint)),
            ),
          ),
        ),
      ),
    )

    const teacherView = h(
      'details',
      { class: 'offkey-audit' },
      h('summary', {}, 'Omniscient teaching audit: reveal hidden state and verify both formulas'),
      h(
        'p',
        { class: 'note' },
        'This view is not available to P₀. It exists so the learner can independently compare the attack deductions with retained ground truth.',
      ),
      h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Hidden y: '), fe(audit.secretBit), ' · blind mask b: ', fe(audit.blindMask), ' · affine mask r: ', fe(audit.affineMask)),
      h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Reconstructed contexts: '), 'α = ', fe(audit.alpha), ' · β = α + Δ = ', fe(audit.beta)),
      contextTable,
      h(
        'p',
        { class: 'note' },
        'Different αᵢ values across parties are legitimate additive key sharing. The inconsistency is that α reconstructs from the first column while β reconstructs from the second; only P₀ changed its local share by Δ.',
      ),
      h('p', { class: 'kv', 'data-formula': 'same' }, h('span', { class: 'kv-label' }, 'Same-context formula: '), 'actual residual ', fe(result.sameContext.unmaskedCheckValue), ' = expected Δ·(g − d) ', fe(audit.sameContext.expectedResidual), '; hidden μ = ', fe(audit.sameContext.multiplier), ' gives z = ', fe(audit.sameContext.expectedMaskedCheckValue), ' ', chip('ok', '✓', 'independently matched')),
      h('p', { class: 'kv', 'data-formula': 'off-key' }, h('span', { class: 'kv-label' }, 'Off-Key formula: '), 'actual residual ', fe(result.offKey.unmaskedCheckValue), ' = expected Δ·(g − y) ', fe(audit.offKey.expectedResidual), '; hidden μ = ', fe(audit.offKey.multiplier), ' gives z = ', fe(audit.offKey.expectedMaskedCheckValue), ' ', chip('ok', '✓', 'independently matched')),
      h(
        'p',
        { class: 'kv' },
        h('span', { class: 'kv-label' }, 'Independent recovery checks: '),
        audit.unmaskedRecoveryVerified && audit.maskedInferenceVerified
          ? chip('ok', '✓', 'both deductions equal retained y')
          : chip('alarm', '✗', 'deduction mismatch'),
      ),
      h(
        'p',
        { class: 'note' },
        'All authenticated shares and residuals above are computed over Fₚ. The masked path computes z = μ·residual with fresh non-zero μ, so only zero versus non-zero remains useful. This lab computes that product directly; it does not build the paper’s distributed triple protocol for hiding μ.',
      ),
    )

    out.append(attackerView, ordinary, teacherView)
  }

  mount.append(
    h(
      'div',
      { class: 'lab-note' },
      h('strong', {}, 'Bounded model and roles.'),
      h(
        'p',
        {},
        'This is a three-party, trusted-dealer algebraic adaptation of Off-Key §§4.2–4.5. P₀ can cause a known key offset Δ between preprocessing contexts and observe one unbatched blind-opening check (batch coefficient λ = 1). The private affine value below is the prescribed-output privacy control, not a full MPC execution of that circuit. The paper studies two-party SPDZ-family implementations and real cross-batch/thread/process failures; this panel does not reproduce those frameworks, distributed preprocessing, persistence, batching, or concurrency.',
      ),
    ),
    h(
      'div',
      { class: 'controls' },
      h('label', { for: 'offkey-secret' }, 'Lab-only hidden bit y (omniscient setup; not attacker input)'),
      secretInput,
      h('label', { for: 'offkey-guess' }, 'P₀’s guess g'),
      guessInput,
      h('button', { type: 'button', class: 'danger-btn', onclick: run }, 'Run the context comparison'),
    ),
    h(
      'p',
      { class: 'note' },
      'For the masked check, one query learns whether y = g; the bit promise turns that predicate into the whole bit. This fixture samples μ from Fₚ* so that statement is exact. The paper samples μ uniformly from Fₚ, where μ = 0 creates a 1/p false-zero exception. The original unmasked check exposes a field residue and recovers y outright. Both attacks require y under α, the multiplication mask under β = α + Δ, checking under β, a known non-zero Δ, and observable check behavior. A key binding that keeps preprocessing under α restores the assumed protocol context.',
    ),
    out,
  )
}
