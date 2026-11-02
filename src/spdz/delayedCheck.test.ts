import { describe, expect, it } from 'vitest'
import { RING, runDelayedTrace } from './delayedCheck'

describe('bounded delayed consistency trace', () => {
  function fixed(values: number[]): () => number {
    let i = 0
    return () => values[i++]!
  }

  it('reveals only an attacked bit when the dependent digest is exposed', async () => {
    for (const bit of [0, 1] as const) {
      for (const mask of [0, 3, 16]) {
        const t = await runDelayedTrace(bit, true, fixed([mask, 5, 7, 9, 11]))
        expect(t.searchMatch).toBe(mask)
        expect(t.inferredInput).toBe(bit)
        expect(t.publicMask).toBe((bit + mask + 5 + 7) % RING)
        expect(t.immediateAbort && t.delayedAbort && t.jointAbort).toBe(true)
        expect(Object.keys(t).sort()).not.toContain('secret')
      }
    }
  })

  it('honest control matches offset zero without exposing the missing mask', async () => {
    const t = await runDelayedTrace(1, false, fixed([16, 5, 7, 9, 11]))
    expect(t.searchMatch).toBe(0)
    expect(t.inferredInput).toBeNull()
    expect(t.immediateAbort || t.delayedAbort || t.jointAbort).toBe(false)
  })

  it('rejects an invalid fixture draw', async () => {
    await expect(runDelayedTrace(0, true, fixed([17, 5, 7, 9, 11]))).rejects.toThrow('draw must be in Z17')
  })
})
