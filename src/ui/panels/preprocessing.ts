/**
 * Panel 4 — Offline vs online: the two-phase architecture.
 *
 * Triples are expensive and input-independent, so real systems bank them in
 * advance; the online phase then costs one cheap triple per multiplication.
 * The bank here is live — the other panels genuinely drain it.
 */

import { BATCH_SIZE, bankStats, onBankChange, preprocess } from '../state'
import { clear, h } from '../dom'

export function renderPreprocessingPanel(mount: HTMLElement): void {
  const stats = h('div', { class: 'result-region', role: 'status', 'aria-live': 'polite' })

  const refresh = (): void => {
    clear(stats)
    const { available, dealt, consumed } = bankStats()
    const pct = dealt === 0 ? 0 : Math.round((available / dealt) * 100)
    stats.append(
      h(
        'div',
        { class: 'bank-meter' },
        h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Dealt (offline): '), String(dealt)),
        h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Consumed (online): '), String(consumed)),
        h('p', { class: 'kv' }, h('span', { class: 'kv-label' }, 'Available: '), String(available)),
        h(
          'div',
          {
            class: 'meter',
            role: 'meter',
            'aria-valuemin': '0',
            'aria-valuemax': String(dealt),
            'aria-valuenow': String(available),
            'aria-label': 'Unused triples remaining in the bank',
          },
          h('div', { class: 'meter-fill', style: `width:${pct}%` }),
        ),
      ),
    )
  }
  onBankChange(refresh)
  refresh()

  mount.append(
    h(
      'p',
      {},
      'Every multiplication anywhere on this page burns one triple from this bank. The split is the whole architecture: the offline phase is slow, heavy, and can run before the inputs even exist; the online phase is a few openings and local sums — fast enough for real workloads because all the hard work is already banked.',
    ),
    stats,
    h(
      'div',
      { class: 'controls' },
      h('button', { type: 'button', onclick: () => preprocess() }, `Run preprocessing (deal ${BATCH_SIZE} triples)`),
    ),
    h(
      'p',
      { class: 'note' },
      'Honest scoping: in this demo a trusted dealer conjures triples instantly — that generation step is the modeled part of the page. In real SPDZ the offline phase manufactures them with somewhat-homomorphic encryption (the original 2012 paper) or oblivious transfer (MASCOT), at a cost of milliseconds-to-seconds per batch of thousands, which is exactly why they are banked ahead of time. This lab does not build triple generation, MASCOT, or Overdrive.',
    ),
  )
}
