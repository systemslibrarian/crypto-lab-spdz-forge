/**
 * SPDZ-style authenticated additive secret sharing over F_p.
 *
 * Every secret x is held as additive shares x_0 + x_1 + x_2 = x (mod p),
 * and every share carries a share of the information-theoretic MAC α·x,
 * where the global MAC key α is itself additively shared — no party ever
 * holds α. Linear operations (addition, public constants) are local;
 * multiplication needs a Beaver triple (see beaver.ts).
 *
 * Modeled part (stated in the UI and README): shares and MACs are dealt by
 * a trusted dealer here. Real SPDZ produces them in the offline phase with
 * somewhat-homomorphic encryption or OT (MASCOT) — out of scope by design.
 */

import { add, mul, mod, sub, type RandFn, randFieldElement } from './field'
import { N_PARTIES, type AuthShare, type AuthShares, type MacCheckResult } from './types'

/** Deal additive shares of the global MAC key α. Returns the per-party shares α_i. */
export function dealMacKey(rand: RandFn = randFieldElement): bigint[] {
  return Array.from({ length: N_PARTIES }, () => rand())
}

/** Reconstruct α from its shares (dealer/inspection only — parties never do this). */
export function macKeyOf(alphaShares: readonly bigint[]): bigint {
  return alphaShares.reduce((s, a) => add(s, a), 0n)
}

/** Split x into N additive shares summing to x mod p. */
function additiveShares(x: bigint, rand: RandFn): bigint[] {
  const shares: bigint[] = []
  let sum = 0n
  for (let i = 0; i < N_PARTIES - 1; i++) {
    const r = rand()
    shares.push(r)
    sum = add(sum, r)
  }
  shares.push(sub(mod(x), sum))
  return shares
}

/** Deal authenticated shares of secret x under the shared MAC key α. */
export function shareSecret(
  x: bigint,
  alphaShares: readonly bigint[],
  rand: RandFn = randFieldElement,
): AuthShares {
  const alpha = macKeyOf(alphaShares)
  const values = additiveShares(x, rand)
  const macs = additiveShares(mul(alpha, mod(x)), rand)
  return values.map((value, i) => ({ value, mac: macs[i] as bigint }))
}

/** Open a shared value: sum the value shares. (Does NOT verify the MAC — see macCheck.) */
export function openValue(shares: AuthShares): bigint {
  return shares.reduce((s, sh) => add(s, sh.value), 0n)
}

// [extension] point — batch checking: replace the single-value check with a
// random-linear-combination check over many opened values (the paper's
// amortized MACCheck), keeping this signature per value.
/**
 * SPDZ MAC check on an opened value y.
 * Each party computes σ_i = γ(y)_i − α_i·y and (after a commitment round,
 * modeled here) the σ_i are summed. Σσ_i = α·y_true − α·y_opened, which is 0
 * iff the opened value matches the authenticated one. A cheater who altered
 * a share passes only by guessing α — probability 1/p ≈ 2⁻⁶¹.
 */
export function macCheck(
  opened: bigint,
  shares: AuthShares,
  alphaShares: readonly bigint[],
): MacCheckResult {
  const sigmas = shares.map((sh, i) => sub(sh.mac, mul(alphaShares[i] as bigint, mod(opened))))
  const sum = sigmas.reduce((s, v) => add(s, v), 0n)
  return { ok: sum === 0n, sigmas, sum }
}

/** Result of an authenticated opening: the reconstructed value plus its MAC verdict. */
export interface AuthOpen {
  value: bigint
  check: MacCheckResult
  ok: boolean
}

/**
 * Authenticated opening — the ONLY way an honest SPDZ party accepts an opened
 * value, including the intermediate Beaver openings d and e. Reconstructing
 * without checking (openValue alone) is an inspection primitive, not a
 * protocol step: a final-product MAC cannot repair a lie told during an
 * earlier opening (see beaver.test.ts, "final check alone misses it").
 */
export function openAuthenticated(shares: AuthShares, alphaShares: readonly bigint[]): AuthOpen {
  const value = openValue(shares)
  const check = macCheck(value, shares, alphaShares)
  return { value, check, ok: check.ok }
}

/** [x] + [y] — purely local: each party adds its shares. No communication. */
export function addShares(x: AuthShares, y: AuthShares): AuthShares {
  return x.map((sx, i) => {
    const sy = y[i] as AuthShare
    return { value: add(sx.value, sy.value), mac: add(sx.mac, sy.mac) }
  })
}

/** [x] − [y] — purely local. */
export function subShares(x: AuthShares, y: AuthShares): AuthShares {
  return x.map((sx, i) => {
    const sy = y[i] as AuthShare
    return { value: sub(sx.value, sy.value), mac: sub(sx.mac, sy.mac) }
  })
}

/** [x] + k for public k: party 0 adjusts its value share; every party adjusts its MAC by α_i·k. */
export function addPublic(x: AuthShares, k: bigint, alphaShares: readonly bigint[]): AuthShares {
  return x.map((sx, i) => ({
    value: i === 0 ? add(sx.value, k) : sx.value,
    mac: add(sx.mac, mul(alphaShares[i] as bigint, mod(k))),
  }))
}

/** k·[x] for public k — purely local on both value and MAC shares. */
export function mulPublic(x: AuthShares, k: bigint): AuthShares {
  return x.map((sx) => ({ value: mul(sx.value, k), mac: mul(sx.mac, k) }))
}

/**
 * Tamper with one party's shares (the malicious act the lab teaches).
 *
 * `delta` shifts the value share. `macDelta` shifts the MAC share, and it is
 * the whole point of the MAC-check panel: the check passes iff the cheater's
 * MAC shift equals α·delta. Leaving it at 0 is the default cheat and always
 * fails; setting it to α·delta forges successfully, which is not a hole but
 * the statement of the guarantee — the check is exactly as strong as α is
 * secret, and α is additively shared so no party holds it. Anything else
 * misses, and Σσᵢ lands on α·delta − macDelta rather than 0.
 *
 * Exposing macDelta lets the learner execute the attack the UI names instead
 * of reading about it. It changes nothing for callers that omit it.
 */
export function tamperShare(
  shares: AuthShares,
  party: number,
  delta: bigint,
  macDelta: bigint = 0n,
): AuthShares {
  return shares.map((sh, i) =>
    i === party
      ? { value: add(sh.value, delta), mac: add(sh.mac, macDelta) }
      : { ...sh },
  )
}
