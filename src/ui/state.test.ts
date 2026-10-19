import { expect, test } from 'vitest'
import { beaverMulChecked } from '../spdz/beaver'
import { openAuthenticated, shareSecret } from '../spdz/sharing'
import { alphaShares, bankStats, preprocess, takeTriples } from './state'

test('initial and refilled triples authenticate and multiply under the original session key', () => {
  const originalKey = [...alphaShares]
  // Share inputs before any refill: resetting alpha during preprocessing must fail this test.
  const x = shareSecret(7n, originalKey)
  const y = shareSecret(9n, originalKey)
  for (let batch = 0; batch < 3; batch++) {
    if (batch > 0) preprocess(3)
    expect(alphaShares).toEqual(originalKey)
    const triples = takeTriples(bankStats().available)
    expect(triples).not.toBeNull()
    expect(triples!.length).toBeGreaterThan(0)
    for (const triple of triples!) {
      for (const shares of [triple.a, triple.b, triple.c]) {
        expect(openAuthenticated(shares, originalKey).ok).toBe(true)
      }
      const result = beaverMulChecked(x, y, triple, originalKey)
      expect(result.kind).toBe('ok')
      if (result.kind !== 'ok') throw new Error('honest multiplication aborted')
      expect(openAuthenticated(result.z, originalKey)).toMatchObject({ value: 63n, ok: true })
    }
  }
})
