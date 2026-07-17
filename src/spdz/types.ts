/** Shared SPDZ protocol types. */

export const N_PARTIES = 3

/**
 * One party's authenticated share of a secret x:
 * - `value` is this party's additive share x_i  (Σ x_i = x mod p)
 * - `mac`   is this party's additive share γ(x)_i of the MAC α·x  (Σ γ(x)_i = α·x mod p)
 * α is the global MAC key; each party holds only a share α_i of it — nobody holds α.
 */
export interface AuthShare {
  value: bigint
  mac: bigint
}

/** All three parties' authenticated shares of one secret (index = party). */
export type AuthShares = AuthShare[]

/** A preprocessed Beaver triple: shares of random a, b and c = a·b. */
export interface Triple {
  a: AuthShares
  b: AuthShares
  c: AuthShares
  /** Set once the triple has been spent on a multiplication — a triple is single-use. */
  consumed: boolean
}

/** Result of a MAC check on an opened value. */
export interface MacCheckResult {
  ok: boolean
  /** Each party's check share σ_i = γ(y)_i − α_i·y (their commitment-round contribution). */
  sigmas: bigint[]
  /** Σ σ_i — zero iff the opened value is consistent with its MAC. */
  sum: bigint
}

/** Public transcript of one Beaver multiplication (what actually crosses the wire). */
export interface MulTranscript {
  /** Publicly opened d = x − a. */
  d: bigint
  /** Publicly opened e = y − b. */
  e: bigint
}
