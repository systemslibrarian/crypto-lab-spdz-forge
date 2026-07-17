/**
 * Per-session protocol state shared across panels.
 *
 * The MAC key shares and the triple bank live only in memory for this page
 * load — nothing is persisted. The bank makes the offline/online split
 * tangible: preprocessing fills it, every online multiplication drains it.
 */

import { dealTriple } from '../spdz/beaver'
import { dealMacKey } from '../spdz/sharing'
import type { Triple } from '../spdz/types'

export const alphaShares = dealMacKey()

const INITIAL_TRIPLES = 8
export const BATCH_SIZE = 8

let bank: Triple[] = Array.from({ length: INITIAL_TRIPLES }, () => dealTriple(alphaShares))
let dealtTotal = INITIAL_TRIPLES
let consumedTotal = 0

type Listener = () => void
const listeners = new Set<Listener>()

export function onBankChange(fn: Listener): void {
  listeners.add(fn)
}
function notify(): void {
  for (const fn of listeners) fn()
}

export function bankStats(): { available: number; dealt: number; consumed: number } {
  return { available: bank.length, dealt: dealtTotal, consumed: consumedTotal }
}

/** Offline phase: deal a fresh batch into the bank. */
export function preprocess(count = BATCH_SIZE): void {
  for (let i = 0; i < count; i++) bank.push(dealTriple(alphaShares))
  dealtTotal += count
  notify()
}

/** Online phase: take n fresh triples, or null if the bank cannot cover it (fail closed). */
export function takeTriples(n: number): Triple[] | null {
  if (bank.length < n) return null
  const taken = bank.splice(0, n)
  consumedTotal += n
  notify()
  return taken
}
