import { describe, expect, it } from 'vitest'
import { add } from './field'
import { dealMacKey, openValue, shareSecret, tamperShare } from './sharing'
import {
  cancellingSigma,
  checkShares,
  commitTo,
  macCheckCommitThenOpen,
  macCheckNoCommit,
  randomNonce,
} from './transcript'

const alpha = dealMacKey()

/** A forged opening: P₁ shifted its share, so the opened value is wrong. */
function forgedOpening() {
  const shares = tamperShare(shareSecret(42n, alpha), 1, 100n)
  return { shares, opened: openValue(shares) } // opened = 142, true value 42
}

describe('MAC-check transcript ordering (GS-02)', () => {
  it('honest check passes under both variants', async () => {
    const shares = shareSecret(7n, alpha)
    const opened = openValue(shares)
    expect(macCheckNoCommit(opened, shares, alpha).ok).toBe(true)
    const committed = await macCheckCommitThenOpen(opened, shares, alpha)
    expect(committed.ok).toBe(true)
    expect(committed.commitmentFailure).toBeNull()
  })

  it('ATTACK: without commitments, a last-mover cancels the check for a FORGED value', () => {
    const { shares, opened } = forgedOpening()
    // Sanity: the plain check would catch this.
    expect(macCheckNoCommit(opened, shares, alpha).ok).toBe(false)
    // But an adversary who sees the honest σ's first just sends their negation.
    const result = macCheckNoCommit(opened, shares, alpha, {
      party: 1,
      chooseSigma: cancellingSigma,
    })
    expect(result.ok).toBe(true) // forged value, check "passes" — no α guessing needed
    expect(result.sum).toBe(0n)
  })

  it('the same adversary FAILS against commit-then-open: it must choose σ blind', async () => {
    const { shares, opened } = forgedOpening()
    // Best the adversary can do blind is guess; any fixed guess is wrong w.p. 1 − 1/p.
    const result = await macCheckCommitThenOpen(opened, shares, alpha, {
      party: 1,
      chooseSigma: (own) => add(own, 12345n), // a blind stab — cannot depend on honest σ's
    })
    expect(result.ok).toBe(false)
    expect(result.commitmentFailure).toBeNull() // it didn't equivocate, it just failed the sum
  })

  it('equivocation is caught: revealing a σ that cancels, after committing, is rejected', async () => {
    const { shares, opened } = forgedOpening()
    const result = await macCheckCommitThenOpen(opened, shares, alpha, {
      party: 1,
      // Commits honestly, then — having seen the honest σ's — tries to swap in the cancelling value.
      revealOverride: (others) => cancellingSigma(others),
    })
    expect(result.ok).toBe(false)
    expect(result.commitmentFailure).toBe(1) // the binding commitment exposes the swap
  })

  it('commitments are binding on both value and nonce', async () => {
    const nonce = randomNonce()
    const c = await commitTo(77n, nonce)
    expect(await commitTo(78n, nonce)).not.toBe(c)
    expect(await commitTo(77n, randomNonce())).not.toBe(c)
    expect(await commitTo(77n, nonce)).toBe(c) // deterministic for the same (σ, nonce)
  })

  it('checkShares matches the definition σᵢ = γ(y)ᵢ − αᵢ·y and sums to 0 honestly', () => {
    const shares = shareSecret(99n, alpha)
    const sigmas = checkShares(openValue(shares), shares, alpha)
    expect(sigmas.reduce((s, v) => add(s, v), 0n)).toBe(0n)
  })
})
