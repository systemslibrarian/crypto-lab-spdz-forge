import { describe, expect, it } from 'vitest'
import { P, add, fixedSequence, inv, mod, mul, neg, pow, randFieldElement, sub } from './field'

describe('F_p field arithmetic (p = 2^61 - 1)', () => {
  it('P is the Mersenne prime 2^61 - 1', () => {
    expect(P).toBe(2305843009213693951n)
  })

  it('mod reduces negatives into [0, P)', () => {
    expect(mod(-1n)).toBe(P - 1n)
    expect(mod(-P)).toBe(0n)
    expect(mod(P)).toBe(0n)
    expect(mod(P + 7n)).toBe(7n)
  })

  it('add/sub/neg are inverse operations', () => {
    expect(add(P - 1n, 1n)).toBe(0n)
    expect(sub(0n, 1n)).toBe(P - 1n)
    expect(add(5n, neg(5n))).toBe(0n)
  })

  it('mul wraps at the modulus', () => {
    // 2^31 · 2^31 = 2^62 ≡ 2 (mod 2^61 − 1), since 2^61 ≡ 1
    expect(mul(1n << 31n, 1n << 31n)).toBe(2n)
  })

  it('pow satisfies Fermat: a^(p-1) = 1 for a ≠ 0', () => {
    expect(pow(3n, P - 1n)).toBe(1n)
    expect(pow(123456789n, P - 1n)).toBe(1n)
  })

  it('inv produces multiplicative inverses', () => {
    for (const a of [2n, 3n, 65537n, P - 1n]) {
      expect(mul(a, inv(a))).toBe(1n)
    }
  })

  it('inv(0) fails closed', () => {
    expect(() => inv(0n)).toThrow(RangeError)
  })

  it('randFieldElement returns elements in [0, P)', () => {
    for (let i = 0; i < 100; i++) {
      const r = randFieldElement()
      expect(r >= 0n && r < P).toBe(true)
    }
  })

  it('fixedSequence replays its values then fails closed', () => {
    const seq = fixedSequence([1n, 2n])
    expect(seq()).toBe(1n)
    expect(seq()).toBe(2n)
    expect(() => seq()).toThrow(RangeError)
  })
})
