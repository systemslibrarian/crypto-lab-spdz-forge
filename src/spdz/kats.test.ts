/**
 * Known-answer tests.
 *
 * SPDZ (Damgård–Pastro–Smart–Zakarias 2012) is a paper, not an RFC — it
 * publishes no test vectors. These KATs are therefore (a) closed-form field
 * identities over p = 2^61 − 1 whose expected values are derived
 * independently on paper (recorded as literals, never computed by the code
 * under test), and (b) fixed-randomness protocol vectors whose every share,
 * MAC, and transcript value is hand-computed from the SPDZ equations and
 * pinned as a literal. 16 KAT assertions total.
 */
import { describe, expect, it } from 'vitest'
import { fixedSequence, inv, mod, mul, pow, sub } from './field'
import { beaverMul, dealTriple } from './beaver'
import { macCheck, openValue, shareSecret } from './sharing'

describe('field KATs (closed-form, hand-derived)', () => {
  it('KAT 1: modulus p = 2^61 − 1 = 2305843009213693951', () => {
    expect((1n << 61n) - 1n).toBe(2305843009213693951n)
  })
  it('KAT 2: inv(2) = (p+1)/2 = 1152921504606846976', () => {
    expect(inv(2n)).toBe(1152921504606846976n)
  })
  it('KAT 3: inv(3) = (2p+1)/3 = 1537228672809129301', () => {
    expect(inv(3n)).toBe(1537228672809129301n)
  })
  it('KAT 4: 2^31 · 2^31 ≡ 2 (since 2^61 ≡ 1 mod p)', () => {
    expect(mul(1n << 31n, 1n << 31n)).toBe(2n)
  })
  it('KAT 5: 0 − 1 ≡ p − 1 = 2305843009213693950', () => {
    expect(sub(0n, 1n)).toBe(2305843009213693950n)
  })
  it('KAT 6: 3^(p−1) ≡ 1 (Fermat)', () => {
    expect(pow(3n, 2305843009213693950n)).toBe(1n)
  })
  it('KAT 7: mod(−1) = 2305843009213693950', () => {
    expect(mod(-1n)).toBe(2305843009213693950n)
  })
})

describe('protocol KATs (fixed randomness, every value hand-computed)', () => {
  // α shares [11, 22, 33] ⇒ α = 66. Secret x = 5 ⇒ α·x = 330.
  // Dealer draws, in order: value r0=100, r1=200; MAC m0=300, m1=400.
  const P = 2305843009213693951n

  it('KAT 8–11: shareSecret produces the exact hand-computed share vector', () => {
    const alpha = [11n, 22n, 33n]
    const rand = fixedSequence([100n, 200n, 300n, 400n])
    const shares = shareSecret(5n, alpha, rand)
    expect(shares[0]).toEqual({ value: 100n, mac: 300n }) // KAT 8
    expect(shares[1]).toEqual({ value: 200n, mac: 400n }) // KAT 9
    // last value share = 5 − 300 mod p; last MAC share = 330 − 700 mod p
    expect(shares[2]).toEqual({ value: P - 295n, mac: P - 370n }) // KAT 10
    expect(openValue(shares)).toBe(5n) // KAT 11
  })

  it('KAT 12–16: full Beaver multiplication 7 × 9 with a pinned transcript', () => {
    const alpha = [1n, 2n, 3n] // α = 6
    // Triple dealer draws: a=3, b=4 (⇒ c=12), then shares each of a, b, c
    // as (r0, r1 | m0, m1): a→(1,1|5,5), b→(2,2|6,6), c→(3,3|7,7).
    const triple = dealTriple(alpha, fixedSequence([3n, 4n, 1n, 1n, 5n, 5n, 2n, 2n, 6n, 6n, 3n, 3n, 7n, 7n]))
    // x = 7 (α·x = 42): draws (10,20|30,40); y = 9 (α·y = 54): draws (50,60|70,80).
    const x = shareSecret(7n, alpha, fixedSequence([10n, 20n, 30n, 40n]))
    const y = shareSecret(9n, alpha, fixedSequence([50n, 60n, 70n, 80n]))

    const { z, transcript } = beaverMul(x, y, triple, alpha)
    expect(transcript.d).toBe(4n) // KAT 12: d = x − a = 7 − 3
    expect(transcript.e).toBe(5n) // KAT 13: e = y − b = 9 − 4
    const opened = openValue(z)
    expect(opened).toBe(63n) // KAT 14: c + d·b + e·a + d·e = 12 + 16 + 15 + 20
    const check = macCheck(opened, z, alpha)
    expect(check.ok).toBe(true) // KAT 15
    expect(check.sum).toBe(0n) // KAT 16: Σσ_i = α·z − α·63 = 0 exactly
  })
})
