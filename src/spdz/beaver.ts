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
 * The openings of d and e are AUTHENTICATED (MAC-checked) protocol steps,
 * not bare reconstructions. This is load-bearing for malicious security: if
 * a corrupt party shifts the opened d by δ, every party computes
 * z′ = xy + δ·y — and because the MAC shares ride the same linear map, z′
 * carries a perfectly VALID MAC. A final-product check cannot catch a lie
 * told during an opening; only checking the opening itself can (there is a
 * regression test proving exactly this).
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
  openAuthenticated,
  openValue,
  shareSecret,
  subShares,
  tamperShare,
} from './sharing'
import type { AuthShares, MacCheckResult, MulTranscript, Triple } from './types'

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
 * The purely local combine from PUBLIC openings d, e:
 * [z] = [c] + d·[b] + e·[a] + d·e, MAC shares carried through the same
 * linear map (so Σγ(z)ᵢ = α·z for whatever z the public d, e produce —
 * including a wrong one, which is why the openings must be authenticated).
 */
export function combineWithOpenings(
  triple: Triple,
  d: bigint,
  e: bigint,
  alphaShares: readonly bigint[],
): AuthShares {
  const linear = addShares(addShares(triple.c, mulPublic(triple.b, d)), mulPublic(triple.a, e))
  return addPublic(linear, mul(d, e), alphaShares)
}

/** A lie told by one party during an opening broadcast. */
export interface OpeningTamper {
  party: number
  delta: bigint
}

export type BeaverResult =
  | { kind: 'ok'; z: AuthShares; transcript: MulTranscript; dCheck: MacCheckResult; eCheck: MacCheckResult }
  | { kind: 'abort'; at: 'd' | 'e'; opened: bigint; check: MacCheckResult }

/**
 * Online Beaver multiplication with authenticated openings — the honest
 * parties' path. Consumes the triple even on abort (its randomness has been
 * partially revealed; single-use is a security invariant, not a convention).
 * The optional tamper injects a corrupt party's lie into an opening
 * broadcast, for tests and the break-it exhibit.
 */
export function beaverMulChecked(
  x: AuthShares,
  y: AuthShares,
  triple: Triple,
  alphaShares: readonly bigint[],
  tamper?: { d?: OpeningTamper; e?: OpeningTamper },
): BeaverResult {
  if (triple.consumed) {
    throw new Error('Beaver triple already consumed — each triple is single-use')
  }
  triple.consumed = true

  let dShares = subShares(x, triple.a)
  if (tamper?.d) dShares = tamperShare(dShares, tamper.d.party, tamper.d.delta)
  const dOpen = openAuthenticated(dShares, alphaShares)
  if (!dOpen.ok) return { kind: 'abort', at: 'd', opened: dOpen.value, check: dOpen.check }

  let eShares = subShares(y, triple.b)
  if (tamper?.e) eShares = tamperShare(eShares, tamper.e.party, tamper.e.delta)
  const eOpen = openAuthenticated(eShares, alphaShares)
  if (!eOpen.ok) return { kind: 'abort', at: 'e', opened: eOpen.value, check: eOpen.check }

  const z = combineWithOpenings(triple, dOpen.value, eOpen.value, alphaShares)
  return {
    kind: 'ok',
    z,
    transcript: { d: dOpen.value, e: eOpen.value },
    dCheck: dOpen.check,
    eCheck: eOpen.check,
  }
}

/**
 * Honest-path convenience: authenticated multiplication that cannot abort
 * because nobody tampers. Throws if the impossible happens.
 */
export function beaverMul(
  x: AuthShares,
  y: AuthShares,
  triple: Triple,
  alphaShares: readonly bigint[],
): { z: AuthShares; transcript: MulTranscript } {
  const result = beaverMulChecked(x, y, triple, alphaShares)
  if (result.kind === 'abort') {
    throw new Error('authenticated opening failed on an honest run — impossible unless the lab has a bug')
  }
  return { z: result.z, transcript: result.transcript }
}

/**
 * UNCHECKED and unguarded: openings are bare reconstructions and the
 * single-use rule is not enforced. Exists only so the break-it exhibits can
 * demonstrate (a) the triple-reuse leak and (b) what skipping opening
 * authentication costs; never call this from an honest path.
 */
export function beaverMulUnsafe(
  x: AuthShares,
  y: AuthShares,
  triple: Triple,
  alphaShares: readonly bigint[],
): { z: AuthShares; transcript: MulTranscript } {
  const d = openValue(subShares(x, triple.a)) // public, UNAUTHENTICATED
  const e = openValue(subShares(y, triple.b)) // public, UNAUTHENTICATED
  return { z: combineWithOpenings(triple, d, e, alphaShares), transcript: { d, e } }
}

/** Sum a list of shared values locally (addition is free). */
export function sumShares(list: AuthShares[]): AuthShares {
  if (list.length === 0) throw new RangeError('nothing to sum')
  return list.reduce((acc, cur) => addShares(acc, cur))
}
