import { describe, expect, it } from 'vitest'
import { dealTriple } from './beaver'
import { openSemiHonest, openSpdz, varianceFromNumerator, varianceNumeratorDirect, varianceOverMpc } from './protocol'
import { dealMacKey, shareSecret, tamperShare } from './sharing'

const alpha = dealMacKey()

describe('semi-honest open vs SPDZ open (the thesis of the lab)', () => {
  it('honest run: both models accept and agree', () => {
    const shares = shareSecret(42n, alpha)
    expect(openSemiHonest(shares).value).toBe(42n)
    const spdz = openSpdz(shares, alpha)
    expect(spdz.kind).toBe('accepted')
    if (spdz.kind === 'accepted') expect(spdz.value).toBe(42n)
  })

  it('VULNERABLE PATH EXHIBITS THE FLAW: semi-honest open ACCEPTS a tampered, wrong value', () => {
    const shares = tamperShare(shareSecret(42n, alpha), 1, 100n)
    const result = openSemiHonest(shares)
    expect(result.kind).toBe('accepted') // no mechanism even exists to object
    expect(result.value).toBe(142n) // genuinely wrong, genuinely accepted
  })

  it('SPDZ open ABORTS on the same tampering — no value is released', () => {
    const shares = tamperShare(shareSecret(42n, alpha), 1, 100n)
    const result = openSpdz(shares, alpha)
    expect(result.kind).toBe('abort')
    expect(result.check.ok).toBe(false)
    expect('value' in result).toBe(false) // abort releases nothing
  })

  it('tampering by any party, any delta, is caught', () => {
    for (const party of [0, 1, 2]) {
      for (const delta of [1n, 999999999n]) {
        const shares = tamperShare(shareSecret(7n, alpha), party, delta)
        expect(openSpdz(shares, alpha).kind).toBe('abort')
      }
    }
  })
})

describe('hospital variance over MPC', () => {
  const inputs = [3n, 5n, 10n] // Σ=18, Σv²=134, M = 3·134 − 18² = 78, Var = 78/9

  it('MPC result equals direct computation (compute both sides and compare)', () => {
    const triples = Array.from({ length: 4 }, () => dealTriple(alpha))
    const run = varianceOverMpc(inputs, alpha, triples)
    expect(run.numerator.kind).toBe('accepted')
    if (run.numerator.kind === 'accepted') {
      expect(run.numerator.value).toBe(78n)
      expect(run.numerator.value).toBe(varianceNumeratorDirect(inputs))
      expect(varianceFromNumerator(run.numerator.value, 3)).toBeCloseTo(78 / 9, 12)
    }
  })

  it('consumes exactly n + 1 triples (one per multiplication)', () => {
    const triples = Array.from({ length: 4 }, () => dealTriple(alpha))
    const run = varianceOverMpc(inputs, alpha, triples)
    expect(run.triplesUsed).toBe(4)
    expect(triples.every((t) => t.consumed)).toBe(true)
    expect(run.transcripts).toHaveLength(4)
  })

  it('a tampered contribution makes the final open ABORT (no attribution in the outcome)', () => {
    const triples = Array.from({ length: 4 }, () => dealTriple(alpha))
    const run = varianceOverMpc(inputs, alpha, triples, undefined, {
      finalOpen: (numShares) => tamperShare(numShares, 2, 1n),
    })
    expect(run.numerator.kind).toBe('abort')
    if (run.numerator.kind === 'abort') expect(run.numerator.stage).toBe('final')
    // The protocol outcome carries which CHECK failed, never which PARTY did it.
    expect(Object.keys(run.numerator)).not.toContain('party')
  })

  it('a lie during any multiplication OPENING also aborts — same authenticated path, no bypass', () => {
    for (const mulIndex of [0, 3]) {
      const triples = Array.from({ length: 4 }, () => dealTriple(alpha))
      const run = varianceOverMpc(inputs, alpha, triples, undefined, {
        opening: { mulIndex, at: 'd', party: 1, delta: 5n },
      })
      expect(run.numerator.kind).toBe('abort')
      if (run.numerator.kind === 'abort') expect(run.numerator.stage).toBe('opening')
    }
  })

  it('fails closed on out-of-range inputs and on a short triple supply', () => {
    expect(() => varianceOverMpc([1n, -1n, 2n], alpha, [])).toThrow(RangeError)
    expect(() => varianceOverMpc([1n, 2n, 3_000_000n], alpha, [])).toThrow(RangeError)
    const three = Array.from({ length: 3 }, () => dealTriple(alpha))
    expect(() => varianceOverMpc(inputs, alpha, three)).toThrow(/need 4 triples/)
  })

  it('variance of identical inputs is zero', () => {
    const triples = Array.from({ length: 4 }, () => dealTriple(alpha))
    const run = varianceOverMpc([7n, 7n, 7n], alpha, triples)
    expect(run.numerator.kind === 'accepted' && run.numerator.value === 0n).toBe(true)
  })
})
