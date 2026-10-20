import { describe, expect, it } from 'vitest'
import { add } from './field'
import { dealMacKey, openValue, shareSecret, tamperShare } from './sharing'
import { cancellingSigma, checkShares, commitTo, macCheckCommitThenOpen, macCheckNoCommit, randomNonce } from './transcript'
import { CAVP_SHA256_VIA_COMMIT } from './cavp-sha256-vectors'

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

describe('commitTo against NIST CAVP SHA-256 (GS-02 ground truth)', () => {
  /*
   * Every other test in this file, and in the other five, checks the commitment
   * BEHAVIOURALLY: commit, open, equivocate, see it rejected. All of them call
   * `commitTo` on both sides of the comparison, so the hash could be SHA-1 and sigma
   * could be little-endian with all of them still green. The lab's own KAT file says
   * plainly that "SPDZ is a paper, not an RFC — it publishes no test vectors", which is
   * true of the protocol and not of the hash underneath it.
   *
   * `commitTo` hashes `nonce || sigma as 8 big-endian bytes`, so any CAVP message of 8
   * or more bytes is reachable: nonce is the leading bytes, sigma the final 8 read
   * big-endian. The published digest then pins the hash, the concatenation order, the
   * byte order of sigma, and the hex encoding — in one assertion each.
   *
   * Asserted THROUGH `commitTo`, never against `crypto.subtle.digest` beside it: in
   * crypto-lab-bike-vault a test written the second way let a SHA-1 mutation pass.
   */
  const bytes = (hex: string): Uint8Array => {
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return out
  }

  it.each(CAVP_SHA256_VIA_COMMIT.map((v) => [v.lenBits, v] as const))(
    'CAVS Len = %i bits',
    async (_len, v) => {
      expect(v.nonceHex.length / 2 + 8).toBe(v.lenBits / 8)
      expect(await commitTo(v.sigma, bytes(v.nonceHex))).toBe(v.digest)
    },
  )

  it('encodes sigma in a FIXED 8 bytes, so nonce and sigma cannot be confused', async () => {
    /* No CAVP message has a zero byte at the split point, so this property is asserted
       rather than taken from a vector — and it is not circular, because it compares two
       commitments instead of recomputing an expected digest.

       Under a minimal-length bigint encoding these two collide: nonce AA01 with sigma
       0x02 and nonce AA with sigma 0x0102 would both hash AA0102. Under the fixed
       8-byte encoding they are 10 and 9 bytes and cannot. */
    const a = await commitTo(0x02n, bytes('aa01'))
    const b = await commitTo(0x0102n, bytes('aa'))
    expect(a).not.toBe(b)
  })

  it('returns 64 hex characters, keeping leading zero bytes', async () => {
    const commitment = await commitTo(0n, bytes(''))
    expect(commitment).toHaveLength(64)
    expect(commitment).toMatch(/^[0-9a-f]{64}$/)
  })
})
