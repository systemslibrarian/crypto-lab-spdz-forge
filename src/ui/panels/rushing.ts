/**
 * Research extension — the MAC key that leaked through a rushing check.
 *
 * Kyster, Huss Nielsen, Oechsner and Scholl, "Rushing at SPDZ: On the
 * Practical Security of Malicious MPC Implementations", §3.1–§3.2. Every
 * figure on this panel comes out of src/spdz/rushing.ts: real authenticated
 * shares, real check shares, real SHA-256 commitments, real Beaver
 * multiplications. "Concurrent" is the one modeled thing -- a single tab has
 * no threads, so it is an explicit ordering of the same messages.
 *
 * The attacker's view and the dealer's audit are kept apart, as in the
 * Off-Key panel: the recovered α is computed from what the corrupt party was
 * sent, and only the audit disclosure compares it with the dealer's.
 */

import {
  HUANG_RECORDED_PAIRS,
  huangResidue,
  runBatchWhatIf,
  runRushing,
  type CoefficientTiming,
  type RushingRun,
  type Schedule,
} from '../../spdz/rushing'
import { P } from '../../spdz/field'
import { chip, clear, fe, h } from '../dom'

const SCHEDULE_LABEL: Record<Schedule, string> = {
  concurrent: 'Both checks in flight at once',
  'sequential-leak-first': 'One at a time — the failing check first',
  'sequential-forge-first': 'One at a time — the forging check first',
  masked: 'Both in flight, check 1 is the masked check',
}

function leakBlock(run: RushingRun): HTMLElement {
  const l = run.leak
  if (l.outcome === 'not-run') {
    return h(
      'div',
      { class: 'proto-col', 'data-check': '1' },
      h('h3', {}, 'Check 1 — the leak'),
      chip('neutral', '▸', 'NOT RUN — the session had already aborted'),
      h('p', { class: 'note' }, 'Check 2 was scheduled first and failed. An aborted session opens nothing more, so P₁ never gets a failing check to read α from.'),
    )
  }
  if (l.masked) {
    return h(
      'div',
      { class: 'proto-col', 'data-check': '1' },
      h('h3', {}, 'Check 1 — the leak, against the masked check'),
      h('p', { class: 'kv' }, 'P₁ opens x + 1: the parties reconstruct ', fe(l.opened), ' where the authenticated value is ', fe(l.x)),
      h('p', { class: 'kv' }, 'Broadcast s = Σ(αᵢ·x′ − γᵢ − aᵢ) = ', fe(l.masked.sum)),
      h('p', { class: 'kv' }, 'Σzᵢ = Σ(s·bᵢ + cᵢ) = ', fe(l.masked.zSum), ' ≠ 0'),
      chip('ok', '✓', 'The check still fails — the +1 is detected'),
      h('p', { class: 'kv' }, 'P₁’s estimate of α from what it saw: ', h('code', { class: 'fe', id: 'rush-recovered' }, l.recoveredAlpha.toString())),
      h('p', { class: 'note' }, 'Here s is α − a and Σzᵢ is α·b, for a random a and b that no party holds. The same subtraction that produced α from raw check shares now produces a number that is not α.'),
    )
  }
  return h(
    'div',
    { class: 'proto-col', 'data-check': '1' },
    h('h3', {}, 'Check 1 — the leak'),
    h('p', { class: 'kv' }, 'P₁ opens x + 1: the parties reconstruct ', fe(l.opened), ' where the authenticated value is ', fe(l.x)),
    h('p', { class: 'note' }, 'All three parties commit to a check share (SHA-256). P₁’s commitment is to a junk value. Then the honest parties open:'),
    ...l.honestOpened.map((o) =>
      h('p', { class: 'kv' }, `σ${'₀₁₂'[o.party]} opened by P${'₀₁₂'[o.party]} = `, fe(o.sigma)),
    ),
    h('p', { class: 'kv' }, 'σ₁, computed by P₁ and never sent = ', fe(l.corruptSigma)),
    h('p', { class: 'kv' }, 'Σσᵢ = ', h('code', { class: 'fe', id: 'rush-sigma-sum' }, l.sigmaSum.toString()), ' = −α'),
    h('p', { class: 'kv' }, 'So α = −Σσᵢ = ', h('code', { class: 'fe', id: 'rush-recovered' }, l.recoveredAlpha.toString())),
    l.outcome === 'hanging'
      ? chip('alarm', '✗', 'HANGING — P₁ withholds its opening; no abort, and P₁ holds α')
      : chip('ok', '✓', 'ABORT — the check must finish, and it cannot pass'),
    h(
      'p',
      { class: 'note' },
      l.outcome === 'hanging'
        ? 'The commitment round worked: P₁ cannot make this check pass. But the honest parties are waiting for an opening that is never coming, and nothing has told them to stop.'
        : 'P₁ learned α here too. The difference is what happens next: the scheduler does not let anything else proceed until this check has finished, and a missing or wrong opening is an abort.',
    ),
  )
}

function forgeBlock(run: RushingRun): HTMLElement {
  const f = run.forge
  const head = h('h3', {}, 'Check 2 — the forgery')
  if (f.outcome === 'not-run') {
    return h(
      'div',
      { class: 'proto-col', 'data-check': '2' },
      head,
      chip('neutral', '▸', 'NOT RUN — check 1 aborted the session first'),
      chip('ok', '✓', 'OK — check 1 ended the session before check 2 could open anything'),
      h('p', { class: 'note' }, 'P₁ holds the real α — the honest openings leaked it before the check aborted — but there is no live check left to spend it on. Everything authenticated under that key is discarded with the session, which is the paper’s recommendation: after an abort “all randomness used in the current execution should be erased”.'),
    )
  }
  const lines: (Node | string | null)[] = [
    head,
    h('p', { class: 'note' }, 'The function is (x·r)·y. P₁’s input is x = 0, so the honest result is 0 whatever P₀’s input y is. P₁ adds 1 to its share of [x·r] and its value for α to the MAC share.'),
    h('p', { class: 'kv' }, 'MAC-share shift P₁ used = ', fe(f.macShift), f.alphaSource === 'guess' ? '  (a guess — it has seen no failed check)' : '  (from check 1)'),
  ]
  if (f.outcome === 'accepted') {
    lines.push(
      chip('neutral', '▸', `ACCEPTED — opened value ${f.released}`),
      chip('alarm', '✗', 'ALARM — every MAC check passed and the result is P₀’s input'),
      h('p', { class: 'kv' }, 'Released: ', h('code', { class: 'fe', id: 'rush-released' }, String(f.released)), '   honest result: ', fe(run.honestOutput)),
      h('p', { class: 'note' }, 'The shifted sharing is a perfectly authenticated sharing of 1, because the shift on the MAC share is exactly α·1. Both Beaver openings and the final open verify, and (0·r + 1)·y = y is handed to everyone as the output.'),
    )
  } else {
    lines.push(
      chip('neutral', '▸', 'ABORT — no value released'),
      chip('ok', '✓', `OK — the forged share failed its MAC check at the ${f.abortAt === 'final' ? 'final' : f.abortAt} opening`),
      h('p', { class: 'note' }, 'Without the real α the shifted MAC share is wrong by a random field element, and the first opening that touches it fails. This is the 1/p guarantee doing its job.'),
    )
  }
  return h('div', { class: 'proto-col', 'data-check': '2' }, ...lines)
}

export function renderRushingPanel(mount: HTMLElement): void {
  const inputY = h('input', { id: 'rush-y', type: 'text', inputmode: 'numeric', maxlength: '9', value: '4242' })
  const schedule = h(
    'select',
    { id: 'rush-schedule' },
    ...(Object.keys(SCHEDULE_LABEL) as Schedule[]).map((s) => h('option', { value: s }, SCHEDULE_LABEL[s])),
  )
  const out = h('div', { id: 'rush-out', class: 'result-region', role: 'status', 'aria-live': 'polite' })
  const runBtn = h('button', { type: 'button', class: 'danger-btn' }, 'Run both checks')
  for (const control of [inputY, schedule]) control.addEventListener('input', () => clear(out))

  let token = 0
  runBtn.addEventListener('click', async () => {
    clear(out)
    const raw = inputY.value.trim()
    if (!/^\d{1,9}$/.test(raw)) {
      out.append(chip('warn', '⚠', 'P₀’s input must be a whole number of at most 9 digits.'))
      return
    }
    const mine = ++token
    runBtn.disabled = true
    try {
      const run = await runRushing(schedule.value as Schedule, BigInt(raw))
      if (mine !== token) return
      clear(out)
      const first = run.order[0] === 'check-1' ? leakBlock(run) : forgeBlock(run)
      const second = run.order[0] === 'check-1' ? forgeBlock(run) : leakBlock(run)
      out.append(
        h('p', {}, `Schedule: ${SCHEDULE_LABEL[run.schedule].toLowerCase()}. P₁ is corrupt; P₀ and P₂ follow the protocol.`),
        h('div', { class: 'proto-row' }, first, second),
        run.inputRevealed
          ? h('p', { class: 'kv', id: 'rush-verdict' }, chip('alarm', '✗', `P₀’s private input ${run.victimInput} was released, with no abort anywhere`))
          : h('p', { class: 'kv', id: 'rush-verdict' }, chip('ok', '✓', 'P₀’s input was not released')),
        h(
          'details',
          { class: 'offkey-audit' },
          h('summary', {}, 'Dealer’s audit: was that really α?'),
          h('p', { class: 'kv' }, 'Dealer’s α = ', h('code', { class: 'fe', id: 'rush-true-alpha' }, run.audit.alpha.toString())),
          h(
            'p',
            { class: 'kv' },
            run.leak.outcome === 'not-run'
              ? chip('ok', '✓', 'P₁ recovered nothing: no check failed in front of it')
              : run.alphaLeaked
                ? chip('alarm', '✗', 'P₁’s value equals the dealer’s α exactly')
                : chip('ok', '✓', 'P₁’s value is not α'),
          ),
          h('p', { class: 'note' }, 'This view is not part of what P₁ sees. Each run deals a fresh MAC key, so the α here is not the one the MAC panel prints.'),
        ),
      )
    } catch {
      if (mine === token) {
        clear(out)
        out.append(chip('warn', '⚠', 'The SHA-256 commitments could not be computed in this browser.'))
      }
    } finally {
      if (mine === token) runBtn.disabled = false
    }
  })

  // ── batched "what if" ────────────────────────────────────────────────────
  const timing = h(
    'select',
    { id: 'rush-batch-timing' },
    h('option', { value: 'known-before' }, 'Known before the shares are sent (the what-if)'),
    h('option', { value: 'drawn-after' }, 'Drawn after the values are fixed (the paper’s rule)'),
  )
  const batchOut = h('div', { id: 'rush-batch-out', class: 'result-region', role: 'status', 'aria-live': 'polite' })
  timing.addEventListener('input', () => clear(batchOut))
  const batchBtn = h('button', { type: 'button', class: 'action' }, 'Run the batched check')
  batchBtn.addEventListener('click', () => {
    clear(batchOut)
    const r = runBatchWhatIf(timing.value as CoefficientTiming)
    batchOut.append(
      h('p', { class: 'kv' }, 'Honest outputs: sum ', fe(r.honest[0]), ' and product ', fe(r.honest[1])),
      h('p', { class: 'kv' }, 'Coefficients P₁ predicted: r₁ = ', fe(r.predicted[0]), '  r₂ = ', fe(r.predicted[1])),
      h('p', { class: 'kv' }, 'P₁’s shifts e = (r₂, −r₁): ', fe(r.shift[0]), ' and ', fe(r.shift[1])),
      h('p', { class: 'kv' }, 'Coefficients the check used: r₁ = ', fe(r.used[0]), '  r₂ = ', fe(r.used[1])),
      h('p', { class: 'kv' }, 'r₁·e₁ + r₂·e₂ = ', h('code', { class: 'fe', id: 'rush-batch-weighted' }, r.weightedShift.toString())),
      h('p', { class: 'kv' }, 'Opened: sum ', h('code', { class: 'fe', id: 'rush-batch-s' }, r.opened[0].toString()), ' and product ', h('code', { class: 'fe', id: 'rush-batch-p' }, r.opened[1].toString())),
      r.outcome === 'accepted'
        ? chip('alarm', '✗', 'ACCEPTED — the weighted check is unchanged and both wrong values are released')
        : chip('ok', '✓', 'ABORT — the shift was built for coefficients the check did not use'),
      h('p', { class: 'kv' }, `P − ${r.honestInput}·(S − ${r.honestInput}) mod p = `, h('code', { class: 'fe', id: 'rush-batch-residue' }, r.residue.toString())),
      h(
        'p',
        { class: 'note' },
        r.outcome === 'accepted'
          ? `That last figure is 0 for every input P₁ could legitimately have used (S = ${r.honestInput} + b, P = ${r.honestInput}·b). It is not 0, so the released pair is an output no input explains — and the MAC check accepted it.`
          : 'P₁ sent the same kind of shift. The coefficients were drawn after its shares were fixed, so r₁·e₁ + r₂·e₂ is a random field element, and the check fails except with probability 1/p.',
      ),
    )
  })

  const residueRows = HUANG_RECORDED_PAIRS.map((pair) =>
    h(
      'tr',
      {},
      h('th', { scope: 'row' }, pair.label),
      h('td', {}, fe(pair.s)),
      h('td', {}, fe(pair.p)),
      h('td', { 'data-residue': pair.label }, fe(huangResidue(pair.s, pair.p))),
      h('td', {}, fe(pair.printedResidue)),
    ),
  )

  mount.append(
    h(
      'div',
      { class: 'lab-note' },
      h('strong', {}, 'Bounded model and roles.'),
      h(
        'p',
        {},
        'Three parties and a trusted dealer, in one tab. P₁ is corrupt and “rushes”: it waits to see the honest openings before sending its own, which commit-then-open allows. Two checks under one MAC key are scheduled four ways. “At once” is an ordering of messages, not real threads. Each run deals a fresh key.',
      ),
    ),
    h(
      'div',
      { class: 'controls' },
      h('label', { for: 'rush-y' }, 'P₀’s private input y'),
      inputY,
      h('label', { for: 'rush-schedule' }, 'How the two checks are scheduled'),
      schedule,
      runBtn,
    ),
    out,
    h('h3', {}, 'What if the batch coefficients are known in advance?'),
    h(
      'p',
      { class: 'note' },
      `A batched check accepts when one random combination Σ rₖ·σ⁽ᵏ⁾ is zero. This lab checks values one at a time, and the SPDZ paper draws the coefficients after the opened values are fixed. Huang, “Challenge Binding in FRESCO SPDZ2k: A Message-Level Case Study” (2026), examines an implementation whose coefficients came from a seed fixed at setup. Run that setting here, over p = ${P}, with the paper’s application: inputs 20 and 30, sum and product opened together.`,
    ),
    h('div', { class: 'controls' }, h('label', { for: 'rush-batch-timing' }, 'When P₁ can know the coefficients'), timing, batchBtn),
    batchOut,
    h(
      'p',
      { class: 'note' },
      'The paper’s own figures, for comparison. These two output pairs were recorded from FRESCO SPDZ2k runs at 64-bit width and are quoted from §4.3; nothing on this page produced them. The fourth column is computed here from the pair, as P − 20·(S − 20) mod 2⁶⁴; the fifth is the residue the paper prints.',
    ),
    h(
      'div',
      { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': 'Recorded FRESCO output pairs and their residues' },
      h(
        'table',
        { class: 'share-table', id: 'rush-huang-table' },
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Paper’s recorded pair'), h('th', { scope: 'col' }, 'S'), h('th', { scope: 'col' }, 'P'), h('th', { scope: 'col' }, 'Residue computed here'), h('th', { scope: 'col' }, 'Residue the paper prints'))),
        h('tbody', {}, ...residueRows),
      ),
    ),
  )
}
