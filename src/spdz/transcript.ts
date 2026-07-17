/**
 * The MAC-check transcript, with message ordering modeled honestly.
 *
 * Summing the check shares σᵢ = γ(y)ᵢ − αᵢ·y is the right algebra, but by
 * itself it does not carry the malicious threat model: a corrupt party who
 * may WAIT — see the honest σ's first, then send its own — can simply send
 * σ_evil = −Σσ_honest and cancel the check for any forged opening. No
 * guessing of α required. Real SPDZ prevents this by binding the order:
 * every party COMMITS to its σᵢ (hash of σ plus a random nonce), and only
 * after all commitments are in do the parties reveal and verify.
 *
 * Both variants are implemented here so the adaptive attack can be run
 * against the unsafe one and fail against the sound one. The commitments are
 * real SHA-256 over real nonces; what is modeled is only the network
 * ordering (this is one browser tab, stated in-page). The 1/p forgery bound
 * quoted everywhere on this page is a property of the COMMITTED transcript —
 * without ordering, the bound is simply false.
 *
 * Single-value checks are the pedagogical special case shown here; the
 * paper's batched MACCheck draws random coefficients (after the opened
 * values are fixed) and checks one random linear combination.
 */

import { add, mod, mul, neg, sub } from './field'
import type { AuthShares, MacCheckResult } from './types'

/** σᵢ = γ(y)ᵢ − αᵢ·y for every party, for a claimed opened value y. */
export function checkShares(
  opened: bigint,
  shares: AuthShares,
  alphaShares: readonly bigint[],
): bigint[] {
  return shares.map((sh, i) => sub(sh.mac, mul(alphaShares[i] as bigint, mod(opened))))
}

/**
 * UNSAFE variant — no commitment round. The adversary (if any) sees every
 * honest σ before choosing its own. Exists only so the attack can be
 * demonstrated; never a protocol path.
 */
export function macCheckNoCommit(
  opened: bigint,
  shares: AuthShares,
  alphaShares: readonly bigint[],
  adversary?: { party: number; chooseSigma: (othersSigmas: bigint[]) => bigint },
): MacCheckResult {
  const sigmas = checkShares(opened, shares, alphaShares)
  if (adversary) {
    const others = sigmas.filter((_, i) => i !== adversary.party)
    sigmas[adversary.party] = adversary.chooseSigma(others)
  }
  const sum = sigmas.reduce((s, v) => add(s, v), 0n)
  return { ok: sum === 0n, sigmas, sum }
}

/** The always-works adaptive cancellation an unordered check permits. */
export function cancellingSigma(othersSigmas: bigint[]): bigint {
  return neg(othersSigmas.reduce((s, v) => add(s, v), 0n))
}

/** SHA-256 commitment to a check share: H(nonce ‖ σ as 8 big-endian bytes). */
export async function commitTo(sigma: bigint, nonce: Uint8Array): Promise<string> {
  const buf = new Uint8Array(nonce.length + 8)
  buf.set(nonce, 0)
  const view = new DataView(buf.buffer)
  view.setBigUint64(nonce.length, sigma, false)
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

export function randomNonce(): Uint8Array {
  const n = new Uint8Array(16)
  crypto.getRandomValues(n)
  return n
}

export interface CommittedCheckOutcome {
  ok: boolean
  /** Party whose reveal contradicted its commitment (equivocation), or null. */
  commitmentFailure: number | null
  sigmas: bigint[]
  sum: bigint
  commitments: string[]
}

/**
 * Sound transcript: commit-then-open.
 *
 * 1. The opened value is fixed.
 * 2. Every party computes σᵢ and commits — the adversary chooses its σ
 *    BLIND (it has not seen any honest σ).
 * 3. All commitments are exchanged, then everyone reveals.
 * 4. Every reveal is verified against its commitment; equivocation aborts.
 * 5. Accept iff Σσᵢ = 0.
 */
export async function macCheckCommitThenOpen(
  opened: bigint,
  shares: AuthShares,
  alphaShares: readonly bigint[],
  adversary?: {
    party: number
    /** Chosen at commit time, before any honest σ is visible. */
    chooseSigma?: (ownHonestSigma: bigint) => bigint
    /** Attempted substitution at reveal time, after seeing the honest σ's. */
    revealOverride?: (othersSigmas: bigint[], committedSigma: bigint) => bigint
  },
): Promise<CommittedCheckOutcome> {
  const honest = checkShares(opened, shares, alphaShares)

  // Commit phase — adversary picks blind.
  const committed = [...honest]
  if (adversary?.chooseSigma) {
    committed[adversary.party] = adversary.chooseSigma(honest[adversary.party] as bigint)
  }
  const nonces = committed.map(() => randomNonce())
  const commitments = await Promise.all(
    committed.map((s, i) => commitTo(s, nonces[i] as Uint8Array)),
  )

  // Reveal phase — adversary now sees everything, but is bound by its commitment.
  const revealed = [...committed]
  if (adversary?.revealOverride) {
    const others = committed.filter((_, i) => i !== adversary.party)
    revealed[adversary.party] = adversary.revealOverride(
      others,
      committed[adversary.party] as bigint,
    )
  }

  // Verify every reveal against its commitment.
  for (let i = 0; i < revealed.length; i++) {
    const recomputed = await commitTo(revealed[i] as bigint, nonces[i] as Uint8Array)
    if (recomputed !== commitments[i]) {
      return {
        ok: false,
        commitmentFailure: i,
        sigmas: revealed,
        sum: revealed.reduce((s, v) => add(s, v), 0n),
        commitments,
      }
    }
  }

  const sum = revealed.reduce((s, v) => add(s, v), 0n)
  return { ok: sum === 0n, commitmentFailure: null, sigmas: revealed, sum, commitments }
}
