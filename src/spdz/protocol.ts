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
import { beaverMulChecked, sumShares } from './beaver'
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
 *
 * Every multiplication runs through the same authenticated-opening path as
 * the Beaver panel (beaverMulChecked) — there is no private bypass. An abort
 * outcome deliberately carries NO party attribution: from inside the
 * protocol, all the participants learn is that a check failed.
 */
// [extension] point — generalize to n parties / other statistics (covariance,
// regression): the circuit shape below (linear ops free, one triple per
// multiplication) is the pattern any of them would follow.
export const VARIANCE_INPUT_MAX = 1_000_000n

export type VarianceOutcome =
  | { kind: 'accepted'; value: bigint; check: MacCheckResult }
  | { kind: 'abort'; stage: 'opening' | 'final'; check: MacCheckResult }

export interface VarianceRun {
  /** Outcome for the numerator M = n²·Var — the only value ever opened. */
  numerator: VarianceOutcome
  /** Triples consumed (n + 1 on a run that reaches the final open). */
  triplesUsed: number
  /** Public transcript values d, e from each completed multiplication. */
  transcripts: { d: bigint; e: bigint }[]
}

export interface VarianceTampering {
  /** Alter the final opened numerator's shares (a lie at the last reveal). */
  finalOpen?: (numeratorShares: AuthShares) => AuthShares
  /** Lie during one multiplication's opening broadcast. */
  opening?: { mulIndex: number; at: 'd' | 'e'; party: number; delta: bigint }
}

export function varianceOverMpc(
  inputs: readonly bigint[],
  alphaShares: readonly bigint[],
  triples: Triple[],
  rand: RandFn = randFieldElement,
  tampering?: VarianceTampering,
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

  const multiply = (lhs: AuthShares, rhs: AuthShares): AuthShares | VarianceOutcome => {
    const mulIndex = used
    const tamper =
      tampering?.opening && tampering.opening.mulIndex === mulIndex
        ? { [tampering.opening.at]: { party: tampering.opening.party, delta: tampering.opening.delta } }
        : undefined
    const result = beaverMulChecked(lhs, rhs, triples[used++] as Triple, alphaShares, tamper)
    if (result.kind === 'abort') {
      return { kind: 'abort', stage: 'opening', check: result.check }
    }
    transcripts.push(result.transcript)
    return result.z
  }

  // Σv² — one triple per square.
  const squares: AuthShares[] = []
  for (const s of shared) {
    const out = multiply(s, s)
    if (!Array.isArray(out)) return { numerator: out, triplesUsed: used, transcripts }
    squares.push(out)
  }
  const sumSq = sumShares(squares)

  // (Σv)² — sum is free, the square costs one more triple.
  const total = sumShares(shared)
  const totalSqOut = multiply(total, total)
  if (!Array.isArray(totalSqOut)) return { numerator: totalSqOut, triplesUsed: used, transcripts }

  // M = n·Σv² − (Σv)², computed locally on shares.
  let numeratorShares = subShares(mulPublic(sumSq, n), totalSqOut)
  if (tampering?.finalOpen) numeratorShares = tampering.finalOpen(numeratorShares)

  const final = openSpdz(numeratorShares, alphaShares)
  const numerator: VarianceOutcome =
    final.kind === 'accepted'
      ? { kind: 'accepted', value: final.value, check: final.check }
      : { kind: 'abort', stage: 'final', check: final.check }
  return { numerator, triplesUsed: used, transcripts }
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
