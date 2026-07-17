import { describe, expect, it } from 'vitest'
import { P, mul, randFieldElement, sub } from './field'
import { beaverMul, beaverMulUnsafe, dealTriple, sumShares } from './beaver'
import { dealMacKey, macCheck, openValue, shareSecret } from './sharing'

const alpha = dealMacKey()

describe('Beaver-triple multiplication', () => {
  it('multiplies correctly for typical and boundary operands', () => {
    for (const [x, y] of [
      [7n, 9n],
      [0n, 12345n],
      [P - 1n, P - 1n],
      [1n, P - 2n],
    ] as const) {
      const t = dealTriple(alpha)
      const { z } = beaverMul(shareSecret(x, alpha), shareSecret(y, alpha), t, alpha)
      const opened = openValue(z)
      expect(opened).toBe(mul(x, y))
      expect(macCheck(opened, z, alpha).ok).toBe(true) // the product is itself authenticated
    }
  })

  it('randomized rounds: 25 random multiplications all agree with direct field multiplication', () => {
    for (let i = 0; i < 25; i++) {
      const x = randFieldElement()
      const y = randFieldElement()
      const { z } = beaverMul(
        shareSecret(x, alpha),
        shareSecret(y, alpha),
        dealTriple(alpha),
        alpha,
      )
      expect(openValue(z)).toBe(mul(x, y))
    }
  })

  it('a triple is single-use: the honest path refuses a consumed triple', () => {
    const t = dealTriple(alpha)
    const x = shareSecret(2n, alpha)
    const y = shareSecret(3n, alpha)
    beaverMul(x, y, t, alpha)
    expect(() => beaverMul(x, y, t, alpha)).toThrow(/single-use/)
  })

  it('BREAK-IT: reusing a triple leaks the difference of the secrets through public d values', () => {
    const t = dealTriple(alpha)
    const x1 = 1000n
    const x2 = 730n
    const y = shareSecret(5n, alpha)
    const r1 = beaverMulUnsafe(shareSecret(x1, alpha), y, t, alpha)
    const r2 = beaverMulUnsafe(shareSecret(x2, alpha), y, t, alpha)
    // d = x − a is public. Same a twice ⇒ d1 − d2 = x1 − x2: a real relation, leaked.
    expect(sub(r1.transcript.d, r2.transcript.d)).toBe(sub(x1, x2))
  })

  it('with a FRESH triple the two d values reveal no such relation', () => {
    const y = shareSecret(5n, alpha)
    const r1 = beaverMulUnsafe(shareSecret(1000n, alpha), y, dealTriple(alpha), alpha)
    const r2 = beaverMulUnsafe(shareSecret(730n, alpha), y, dealTriple(alpha), alpha)
    // d1 − d2 = (x1 − x2) − (a1 − a2), masked by fresh uniform randomness.
    expect(sub(r1.transcript.d, r2.transcript.d)).not.toBe(sub(1000n, 730n))
  })

  it('sumShares adds any number of shared values locally', () => {
    const parts = [3n, 14n, 15n, 9n].map((v) => shareSecret(v, alpha))
    const total = sumShares(parts)
    expect(openValue(total)).toBe(41n)
    expect(macCheck(41n, total, alpha).ok).toBe(true)
  })

  it('sumShares of nothing fails closed', () => {
    expect(() => sumShares([])).toThrow(RangeError)
  })
})
