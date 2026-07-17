import { describe, expect, it } from 'vitest'
import { P, add, mul, randFieldElement } from './field'
import {
  addPublic,
  addShares,
  dealMacKey,
  macCheck,
  macKeyOf,
  mulPublic,
  openValue,
  shareSecret,
  subShares,
  tamperShare,
} from './sharing'
import { N_PARTIES } from './types'

const alpha = dealMacKey()

describe('authenticated additive sharing', () => {
  it('share → open round-trips for typical, zero, and boundary secrets', () => {
    for (const x of [0n, 1n, 42n, P - 1n, 1234567890123456789n]) {
      expect(openValue(shareSecret(x, alpha))).toBe(x)
    }
  })

  it('shares carry a valid MAC: Σγ(x)_i = α·x', () => {
    const x = 987654321n
    const shares = shareSecret(x, alpha)
    const macSum = shares.reduce((s, sh) => add(s, sh.mac), 0n)
    expect(macSum).toBe(mul(macKeyOf(alpha), x))
  })

  it('MAC check passes on an honestly opened value', () => {
    const shares = shareSecret(77n, alpha)
    const opened = openValue(shares)
    const check = macCheck(opened, shares, alpha)
    expect(check.ok).toBe(true)
    expect(check.sum).toBe(0n)
  })

  it('MAC check fails when any single party tampers with its share', () => {
    for (let party = 0; party < N_PARTIES; party++) {
      const shares = shareSecret(1000n, alpha)
      const evil = tamperShare(shares, party, 5n)
      const opened = openValue(evil)
      expect(opened).toBe(1005n) // the wrong value really is what the sum produces
      expect(macCheck(opened, evil, alpha).ok).toBe(false)
    }
  })

  it('a zero-delta "tamper" changes nothing and still verifies (edge case)', () => {
    const shares = shareSecret(9n, alpha)
    const same = tamperShare(shares, 1, 0n)
    expect(macCheck(openValue(same), same, alpha).ok).toBe(true)
  })

  it('a cheater who KNEW α could forge the MAC — the check is exactly as strong as α is secret', () => {
    const shares = shareSecret(50n, alpha)
    const delta = 13n
    const evil = tamperShare(shares, 2, delta)
    // Forge: also shift the same party's MAC share by α·delta (requires the full key).
    const forged = evil.map((sh, i) =>
      i === 2 ? { value: sh.value, mac: add(sh.mac, mul(macKeyOf(alpha), delta)) } : sh,
    )
    const opened = openValue(forged)
    expect(opened).toBe(63n)
    expect(macCheck(opened, forged, alpha).ok).toBe(true) // wrong value, valid MAC — only with α
  })

  it('addition of shares is local and correct, MACs included', () => {
    const a = shareSecret(11n, alpha)
    const b = shareSecret(31n, alpha)
    const sum = addShares(a, b)
    const opened = openValue(sum)
    expect(opened).toBe(42n)
    expect(macCheck(opened, sum, alpha).ok).toBe(true)
  })

  it('subtraction, public addition, and public scaling stay authenticated', () => {
    const x = shareSecret(100n, alpha)
    const y = shareSecret(58n, alpha)

    const diff = subShares(x, y)
    expect(openValue(diff)).toBe(42n)
    expect(macCheck(42n, diff, alpha).ok).toBe(true)

    const plus = addPublic(x, 7n, alpha)
    expect(openValue(plus)).toBe(107n)
    expect(macCheck(107n, plus, alpha).ok).toBe(true)

    const scaled = mulPublic(x, 3n)
    expect(openValue(scaled)).toBe(300n)
    expect(macCheck(300n, scaled, alpha).ok).toBe(true)
  })

  it('any two of three shares look unrelated to the secret (statistical sanity)', () => {
    // Sharing the same secret twice yields unrelated share vectors.
    const s1 = shareSecret(5n, alpha, randFieldElement)
    const s2 = shareSecret(5n, alpha, randFieldElement)
    expect(s1[0]!.value === s2[0]!.value && s1[1]!.value === s2[1]!.value).toBe(false)
  })
})
