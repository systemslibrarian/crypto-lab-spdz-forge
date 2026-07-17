/**
 * Beaver-triple multiplication for SPDZ shares.
 *
 * A triple is a preprocessed random (a, b, c) with c = a·b, dealt as
 * authenticated shares while a and b remain unknown to every party.
 * To multiply [x]·[y] online:
 *
 *   open  d = x − a      (safe: a is uniform and used once, so d is uniform)
 *   open  e = y − b      (same)
 *   [x·y] = [c] + d·[b] + e·[a] + d·e     — entirely local from shares
 *
 * One multiplication consumes one triple, permanently. Reuse leaks (see
 * tests and the break-it panel): two d's under the same a satisfy
 * d − d′ = x − x′, a genuine relation between the secrets.
 */

import { mul, type RandFn, randFieldElement } from './field'
import {
  addPublic,
  addShares,
  mulPublic,
  openValue,
  shareSecret,
  subShares,
} from './sharing'
import type { AuthShares, MulTranscript, Triple } from './types'

/** Dealer-generated Beaver triple (the modeled offline phase — stated in-page). */
export function dealTriple(alphaShares: readonly bigint[], rand: RandFn = randFieldElement): Triple {
  const a = rand()
  const b = rand()
  const c = mul(a, b)
  return {
    a: shareSecret(a, alphaShares, rand),
    b: shareSecret(b, alphaShares, rand),
    c: shareSecret(c, alphaShares, rand),
    consumed: false,
  }
}

/**
 * Online Beaver multiplication. Consumes the triple (throws if already spent —
 * single-use is a security invariant, not a convention).
 * The MAC shares ride through the same linear algebra, so the product is
 * itself authenticated: Σγ(z)_i = α·(c + d·b + e·a + d·e) = α·z.
 */
export function beaverMul(
  x: AuthShares,
  y: AuthShares,
  triple: Triple,
  alphaShares: readonly bigint[],
): { z: AuthShares; transcript: MulTranscript } {
  if (triple.consumed) {
    throw new Error('Beaver triple already consumed — each triple is single-use')
  }
  triple.consumed = true
  return beaverMulUnsafe(x, y, triple, alphaShares)
}

/**
 * The same arithmetic WITHOUT the single-use guard. Exists only so the
 * break-it-yourself panel can demonstrate why reuse is forbidden; never call
 * this from an honest path.
 */
export function beaverMulUnsafe(
  x: AuthShares,
  y: AuthShares,
  triple: Triple,
  alphaShares: readonly bigint[],
): { z: AuthShares; transcript: MulTranscript } {
  const d = openValue(subShares(x, triple.a)) // public
  const e = openValue(subShares(y, triple.b)) // public
  // [z] = [c] + d·[b] + e·[a] + d·e
  const zLinear = addShares(addShares(triple.c, mulPublic(triple.b, d)), mulPublic(triple.a, e))
  const z = addPublic(zLinear, mul(d, e), alphaShares)
  return { z, transcript: { d, e } }
}

/** Sum a list of shared values locally (addition is free). */
export function sumShares(list: AuthShares[]): AuthShares {
  if (list.length === 0) throw new RangeError('nothing to sum')
  return list.reduce((acc, cur) => addShares(acc, cur))
}
