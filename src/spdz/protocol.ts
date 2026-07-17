/**
 * Protocol-level flows the panels and tests share: opening a value under the
 * two trust models, and the hospital-variance application circuit.
 *
 * The two open paths embody the lab's thesis:
 * - semi-honest open: sum the shares, accept whatever comes out.
 * - SPDZ open: sum the shares, then run the MAC check; on failure the honest
 *   parties ABORT — no value is released. Abort means "someone cheated",
 *   not "here is the right answer anyway" and not "party j cheated".
 */

import { randFieldElement, type RandFn } from './field'
import { beaverMul, sumShares } from './beaver'
import { macCheck, mulPublic, openValue, shareSecret, subShares } from './sharing'
import type { AuthShares, MacCheckResult, Triple } from './types'

/** Semi-honest open: no authentication. Whatever the shares sum to is accepted. */
export interface SemiHonestOpen {
  kind: 'accepted'
  value: bigint
}

/** SPDZ open: the value is released only if the MAC check passes. */
export type SpdzOpen =
  | { kind: 'accepted'; value: bigint; check: MacCheckResult }
  | { kind: 'abort'; check: MacCheckResult }

export function openSemiHonest(shares: AuthShares): SemiHonestOpen {
  return { kind: 'accepted', value: openValue(shares) }
}

export function openSpdz(shares: AuthShares, alphaShares: readonly bigint[]): SpdzOpen {
  const value = openValue(shares)
  const check = macCheck(value, shares, alphaShares)
  return check.ok ? { kind: 'accepted', value, check } : { kind: 'abort', check }
}

/**
 * Hospital variance over MPC. Inputs are small non-negative integers
 * (bounded so the integer result cannot wrap mod p — enforced).
 *
 * The parties compute the integer  M = n·Σv² − (Σv)²  = n²·Var(v)
 * inside the field (n multiplications for the squares plus one for the
 * square of the sum → n+1 triples), open only M, and divide by n² in the
 * clear. Individual inputs are never opened.
 */
// [extension] point — generalize to n parties / other statistics (covariance,
// regression): the circuit shape below (linear ops free, one triple per
// multiplication) is the pattern any of them would follow.
export const VARIANCE_INPUT_MAX = 1_000_000n

export interface VarianceRun {
  /** Opened numerator M = n²·Var — the only value ever opened. */
  numerator: SpdzOpen
  /** Triples consumed (n + 1). */
  triplesUsed: number
  /** Public transcript values d, e from each multiplication. */
  transcripts: { d: bigint; e: bigint }[]
}

export function varianceOverMpc(
  inputs: readonly bigint[],
  alphaShares: readonly bigint[],
  triples: Triple[],
  rand: RandFn = randFieldElement,
  tamper?: (sumOfSquares: AuthShares) => AuthShares,
): VarianceRun {
  const n = BigInt(inputs.length)
  for (const v of inputs) {
    if (v < 0n || v > VARIANCE_INPUT_MAX) {
      throw new RangeError(`inputs must be integers in [0, ${VARIANCE_INPUT_MAX}]`)
    }
  }
  if (triples.length < inputs.length + 1) {
    throw new Error(`need ${inputs.length + 1} triples, have ${triples.length}`)
  }

  const shared = inputs.map((v) => shareSecret(v, alphaShares, rand))
  const transcripts: { d: bigint; e: bigint }[] = []
  let used = 0

  // Σv² — one triple per square.
  const squares = shared.map((s) => {
    const { z, transcript } = beaverMul(s, s, triples[used++] as Triple, alphaShares)
    transcripts.push(transcript)
    return z
  })
  const sumSq = sumShares(squares)

  // (Σv)² — sum is free, the square costs one more triple.
  const total = sumShares(shared)
  const { z: totalSq, transcript } = beaverMul(total, total, triples[used++] as Triple, alphaShares)
  transcripts.push(transcript)

  // M = n·Σv² − (Σv)², computed locally on shares.
  let numeratorShares = subShares(mulPublic(sumSq, n), totalSq)
  if (tamper) numeratorShares = tamper(numeratorShares)

  return { numerator: openSpdz(numeratorShares, alphaShares), triplesUsed: used, transcripts }
}

/** Clear-text variance from the opened numerator: Var = M / n². Exact by construction. */
export function varianceFromNumerator(numerator: bigint, n: number): number {
  return Number(numerator) / (n * n)
}

/** Direct (non-MPC) reference: n²·Var as a plain integer, for compare-both-sides. */
export function varianceNumeratorDirect(inputs: readonly bigint[]): bigint {
  const n = BigInt(inputs.length)
  const sum = inputs.reduce((s, v) => s + v, 0n)
  const sumSq = inputs.reduce((s, v) => s + v * v, 0n)
  return n * sumSq - sum * sum
}
