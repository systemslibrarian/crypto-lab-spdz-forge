import { describe, expect, it } from 'vitest'
import { P, add, mul, randFieldElement, sub } from './field'
import { beaverMul, beaverMulChecked, beaverMulUnsafe, combineWithOpenings, dealTriple, sumShares } from './beaver'
import { dealMacKey, macCheck, openValue, shareSecret, subShares } from './sharing'

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

  it('GS-01: a lie during the d opening ABORTS before any product is accepted', () => {
    for (const party of [0, 1, 2]) {
      const result = beaverMulChecked(
        shareSecret(6n, alpha),
        shareSecret(7n, alpha),
        dealTriple(alpha),
        alpha,
        { d: { party, delta: 9n } },
      )
      expect(result.kind).toBe('abort')
      if (result.kind === 'abort') expect(result.at).toBe('d')
    }
  })

  it('GS-01: a lie during the e opening independently ABORTS', () => {
    const result = beaverMulChecked(
      shareSecret(6n, alpha),
      shareSecret(7n, alpha),
      dealTriple(alpha),
      alpha,
      { e: { party: 2, delta: 123456n } },
    )
    expect(result.kind).toBe('abort')
    if (result.kind === 'abort') expect(result.at).toBe('e')
  })

  it('GS-01 regression: checking ONLY the final product would MISS the opening attack', () => {
    // A corrupt party shifts the public d by δ. Everyone computes
    // z' = xy + δ·y — and because MACs ride the same linear map, z' carries
    // a perfectly valid MAC. This is the attack authenticated openings exist for.
    const x = 6n
    const y = 7n
    const delta = 9n
    const t = dealTriple(alpha)
    const xs = shareSecret(x, alpha)
    const ys = shareSecret(y, alpha)
    const dTrue = openValue(subShares(xs, t.a))
    const eTrue = openValue(subShares(ys, t.b))
    const zEvil = combineWithOpenings(t, add(dTrue, delta), eTrue, alpha)
    const opened = openValue(zEvil)
    expect(opened).not.toBe(mul(x, y)) // the product is genuinely wrong…
    expect(opened).toBe(add(mul(x, y), mul(delta, y))) // …by exactly z' = xy + δ·y…
    expect(macCheck(opened, zEvil, alpha).ok).toBe(true) // …and the final MAC check PASSES on it
  })

  it('honest checked multiplication reports both opening checks as passed', () => {
    const result = beaverMulChecked(
      shareSecret(6n, alpha),
      shareSecret(7n, alpha),
      dealTriple(alpha),
      alpha,
    )
    expect(result.kind).toBe('ok')
    if (result.kind === 'ok') {
      expect(result.dCheck.ok).toBe(true)
      expect(result.eCheck.ok).toBe(true)
      expect(openValue(result.z)).toBe(42n)
    }
  })

  it('an aborted multiplication still consumes the triple (its randomness is burnt)', () => {
    const t = dealTriple(alpha)
    const result = beaverMulChecked(shareSecret(2n, alpha), shareSecret(3n, alpha), t, alpha, {
      d: { party: 0, delta: 1n },
    })
    expect(result.kind).toBe('abort')
    expect(t.consumed).toBe(true)
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
