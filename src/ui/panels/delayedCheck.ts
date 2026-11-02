import { runDelayedTrace } from '../../spdz/delayedCheck'
import { chip, h } from '../dom'

export function renderDelayedCheckPanel(mount: HTMLElement): void {
  const input = h('select', { id: 'delayed-secret' }, h('option', { value: '0' }, '0'), h('option', { value: '1' }, '1'))
  const inject = h('input', { id: 'delayed-inject', type: 'checkbox', checked: true })
  const result = h('div', { class: 'result-region', id: 'delayed-out', role: 'status', 'aria-live': 'polite' })
  const run = h('button', { type: 'button', class: 'action' }, 'Run two-gate trace')
  run.addEventListener('click', async () => {
    run.disabled = true
    result.replaceChildren('Computing the SHA-256 check…')
    try {
      const t = await runDelayedTrace(Number(input.value) as 0 | 1, inject.checked)
      result.replaceChildren(
        h('p', {}, 'The honest participant’s input is hidden from the attacker. The first gate feeds a second multiplication; the attacker ',
          inject.checked ? 'adds +1 to one first-gate message.' : 'sends the honest first-gate message.'),
        h('div', { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': 'Three check schedules compared' },
          h('table', { class: 'share-table' },
            h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Check schedule'), h('th', { scope: 'col' }, 'What happens before abort?'), h('th', { scope: 'col' }, 'Attacker learns from this trace'))),
            h('tbody', {},
              h('tr', {}, h('th', { scope: 'row' }, 'Immediate'), h('td', {}, t.immediateAbort ? 'First message checked; abort before gate two.' : 'Both gates run honestly.'), h('td', {}, 'No dependent hash.')),
              h('tr', {}, h('th', { scope: 'row' }, 'Delayed, separate hashes'), h('td', {}, t.delayedAbort ? 'Second gate runs on inconsistent states; abort later.' : 'Both gates run honestly.'), h('td', {}, inject.checked ? 'The dependent hash exposes a mask search.' : 'No injected shift; matching offset 0 reveals no mask.')),
              h('tr', {}, h('th', { scope: 'row' }, 'Delayed, joint check'), h('td', {}, t.jointAbort ? 'Joint check rejects before output.' : 'Joint check accepts.'), h('td', {}, 'Only one overall verdict; no individual digest or partial result.')),
            ),
          ),
        ),
        h('div', { class: 'offkey-view', 'data-view': 'attacker' },
          h('h3', {}, 'Attacker-visible synthetic transcript'),
          h('p', {}, `Known: m_d=${t.publicMask}, λ₂=${t.knownMask2}, λ₃=${t.knownMask3}, first-gate field=${t.firstMessage}, second-gate field=${t.secondMessage}.`),
          h('p', {}, `Delayed hash H(first field ∥ second field − offset): ${t.delayedDigest}`),
          h('p', {}, `Try each of 17 offsets: the matching offset is ${t.searchMatch}.`,
            inject.checked ? ` Because the injected change was +1, this equals the missing mask; d = m_d − λ₁ − λ₂ − λ₃ mod 17 = ${t.inferredInput}.` : ' With no injected change, this is zero; it is not the missing mask.'),
          inject.checked ? chip('alarm', '✗', 'Privacy lost before the eventual abort') : chip('ok', '✓', 'Honest control: no inferred input'),
        ),
        h('details', { class: 'offkey-audit' }, h('summary', {}, 'Learner-only audit: reveal hidden state'),
          h('p', {}, `Input d=${t.audit.input}; missing λ₁=${t.audit.hiddenMask1}. This view is not part of the attacker transcript.`)),
      )
    } catch {
      result.replaceChildren(chip('warn', '⚠', 'The hash trace could not run in this browser.'))
    } finally {
      run.disabled = false
    }
  })
  mount.append(
    h('p', { class: 'note' }, 'Synthetic Z₁₇ trace derived from the two-dependent-gate and hash-search relation in Brüggemann–Schneider §3.3. This is not a Trident or SPDZ protocol execution. The joint-check row represents only the paper’s intended aggregate-verdict boundary; it does not implement its secure functionality.'),
    h('div', { class: 'controls' }, h('label', { for: 'delayed-secret' }, 'Hidden input bit for learner audit'), input,
      h('label', { for: 'delayed-inject' }, inject, ' Inject +1 in gate one'), run), result,
  )
}
