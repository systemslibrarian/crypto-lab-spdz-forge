/**
 * Kyster, Huss Nielsen, Oechsner and Scholl, "Rushing at SPDZ", §3.1–§3.2,
 * as executable claims:
 *
 *  - α is recovered EXACTLY from one failed check the corrupt party never
 *    finishes;
 *  - the forged opening passes check 2 ONLY when the two checks are in flight
 *    together;
 *  - run one at a time, in either order, check 2 never releases the honest
 *    input;
 *  - the paper's masked check keeps concurrency and loses the leak.
 *
 * Plus the batched "what if" from Huang, "Challenge Binding in FRESCO SPDZ2k"
 * (2026), and that paper's two printed residues.
 */
import { describe, expect, it } from 'vitest'
import { P, add, mul, neg, sub } from './field'
import { dealMacKey, macKeyOf, shareSecret, tamperShare, openValue } from './sharing'
import { checkShares } from './transcript'
import {
  CORRUPT,
  HUANG_RECORDED_PAIRS,
  batchedMacCheck,
  huangResidue,
  recoverAlphaFromOpenings,
  runBatchWhatIf,
  runRushing,
} from './rushing'

const INPUTS = [0n, 1n, 7n, 123456789n, P - 1n]

describe('check 1: a failed check the corrupt party never finishes leaks α', () => {
  it('recovers α exactly, every run, from the honest openings and its own shares', async () => {
    for (let i = 0; i < 25; i++) {
      const run = await runRushing('concurrent', 42n)
      expect(run.leak.recoveredAlpha).toBe(run.audit.alpha)
      expect(run.alphaLeaked).toBe(true)
      // Σσᵢ = −α·1 in this lab's sign convention.
      expect(run.leak.sigmaSum).toBe(neg(run.audit.alpha))
      expect(run.leak.opened).toBe(add(run.leak.x, 1n))
      // Only the two honest parties opened; the corrupt one did not.
      expect(run.leak.honestOpened.map((h) => h.party)).toEqual([0, 2])
      expect(run.leak.commitments).toHaveLength(3)
      expect(run.leak.outcome).toBe('hanging')
    }
  })

  it('needs nothing the corrupt party does not hold: two openings, one MAC share, one key share', () => {
    const alphaShares = dealMacKey()
    const x = shareSecret(999n, alphaShares)
    for (const shift of [1n, 2n, 5n, P - 3n]) {
      const opened = openValue(tamperShare(x, CORRUPT, shift))
      const sigmas = checkShares(opened, x, alphaShares)
      const got = recoverAlphaFromOpenings(
        [sigmas[0] as bigint, sigmas[2] as bigint],
        { mac: x[CORRUPT]!.mac, alphaShare: alphaShares[CORRUPT] as bigint },
        opened,
        shift,
      )
      expect(got.alpha).toBe(macKeyOf(alphaShares))
      expect(got.sigmaSum).toBe(neg(mul(macKeyOf(alphaShares), shift)))
    }
  })

  it('an honest opening leaks nothing: Σσᵢ = 0 and a zero shift is refused', () => {
    const alphaShares = dealMacKey()
    const x = shareSecret(31337n, alphaShares)
    const sigmas = checkShares(openValue(x), x, alphaShares)
    expect(sigmas.reduce((s, v) => add(s, v), 0n)).toBe(0n)
    expect(() =>
      recoverAlphaFromOpenings(
        [sigmas[0] as bigint, sigmas[2] as bigint],
        { mac: x[CORRUPT]!.mac, alphaShare: alphaShares[CORRUPT] as bigint },
        openValue(x),
        0n,
      ),
    ).toThrow(RangeError)
  })
})

describe('check 2: the forged opening', () => {
  it('concurrent: passes every MAC check and releases the honest party’s input', async () => {
    for (const y of INPUTS) {
      const run = await runRushing('concurrent', y)
      expect(run.honestOutput).toBe(0n)
      expect(run.forge.honestProduct).toBe(0n)
      expect(run.forge.alphaSource).toBe('recovered')
      expect(run.forge.macShift).toBe(run.audit.alpha)
      expect(run.forge.outcome).toBe('accepted')
      expect(run.forge.released).toBe(y)
      expect(run.inputRevealed).toBe(true)
    }
  })

  it('sequential, leaking check first: α is learned, the session aborts, nothing is released', async () => {
    for (const y of INPUTS) {
      const run = await runRushing('sequential-leak-first', y)
      // The key still leaks to the corrupt party -- sequencing does not undo that ...
      expect(run.alphaLeaked).toBe(true)
      // ... but check 1 has to finish, it cannot, and check 2 never opens anything.
      expect(run.leak.outcome).toBe('abort')
      expect(run.forge.outcome).toBe('abort')
      expect(run.forge.abortAt).toBe('session')
      expect(run.forge.released).toBeNull()
      expect(run.inputRevealed).toBe(false)
    }
  })

  it('sequential, forging check first: no α yet, so the forgery dies at its first opening', async () => {
    for (const y of INPUTS) {
      const run = await runRushing('sequential-forge-first', y)
      expect(run.order).toEqual(['check-2', 'check-1'])
      expect(run.forge.alphaSource).toBe('guess')
      expect(run.forge.outcome).toBe('abort')
      expect(run.forge.abortAt).toBe('d')
      expect(run.forge.released).toBeNull()
      expect(run.leak.outcome).toBe('not-run')
      expect(run.alphaLeaked).toBe(false)
      expect(run.inputRevealed).toBe(false)
    }
  })

  it('the forgery passes only in concurrent mode', async () => {
    const outcomes: Record<string, boolean> = {}
    for (const schedule of ['concurrent', 'sequential-leak-first', 'sequential-forge-first', 'masked'] as const) {
      outcomes[schedule] = (await runRushing(schedule, 77n)).inputRevealed
    }
    expect(outcomes).toEqual({
      concurrent: true,
      'sequential-leak-first': false,
      'sequential-forge-first': false,
      masked: false,
    })
  })
})

describe('the masked check (the paper’s Figure 4)', () => {
  it('still fails on the wrong opening, and what it reveals is α·b, not α', async () => {
    for (let i = 0; i < 10; i++) {
      const run = await runRushing('masked', 5n)
      const m = run.leak.masked!
      expect(m).toBeDefined()
      // Σzᵢ ≠ 0: the check detects the +1.
      expect(m.zSum).not.toBe(0n)
      // s = Δ·α − a, so the corrupt party's estimate s/Δ is off by the mask a.
      expect(run.leak.recoveredAlpha).not.toBe(run.audit.alpha)
      expect(run.alphaLeaked).toBe(false)
      // Concurrency is allowed here: check 2 runs, and its forgery aborts.
      expect(run.leak.outcome).toBe('hanging')
      expect(run.forge.outcome).toBe('abort')
      expect(run.forge.released).toBeNull()
      expect(run.inputRevealed).toBe(false)
    }
  })
})

describe('batched check: what if the coefficients are known before the shares are sent', () => {
  it('known-before: e = (r₂, −r₁) leaves the weighted check at zero and two wrong values are released', () => {
    for (let i = 0; i < 20; i++) {
      const r = runBatchWhatIf('known-before')
      expect(r.honest).toEqual([50n, 600n])
      expect(r.used).toEqual(r.predicted)
      expect(r.shift).toEqual([r.predicted[1], neg(r.predicted[0])])
      expect(r.weightedShift).toBe(0n)
      expect(r.check.ok).toBe(true)
      expect(r.outcome).toBe('accepted')
      expect(r.opened).toEqual([add(50n, r.shift[0]), add(600n, r.shift[1])])
      // No input of the corrupt party explains the released pair.
      expect(r.residue).not.toBe(0n)
      // residue = e₂ − 20·e₁, derived independently of how the source computes it.
      expect(r.residue).toBe(sub(r.shift[1], mul(20n, r.shift[0])))
    }
  })

  it('drawn-after: the same shift meets fresh coefficients and the check aborts', () => {
    for (let i = 0; i < 20; i++) {
      const r = runBatchWhatIf('drawn-after')
      expect(r.used).not.toEqual(r.predicted)
      expect(r.weightedShift).not.toBe(0n)
      expect(r.check.ok).toBe(false)
      expect(r.outcome).toBe('abort')
    }
  })

  it('an honest batch passes under any coefficients, and the honest pair has residue 0', () => {
    const alphaShares = dealMacKey()
    const s = shareSecret(50n, alphaShares)
    const p = shareSecret(600n, alphaShares)
    expect(batchedMacCheck([50n, 600n], [s, p], alphaShares, [123n, 456n]).ok).toBe(true)
    expect(batchedMacCheck([51n, 600n], [s, p], alphaShares, [123n, 456n]).ok).toBe(false)
    expect(huangResidue(50n, 600n)).toBe(0n)
  })
})

describe('the two residues Huang’s paper prints (§4.3)', () => {
  it('P − 20(S − 20) mod 2⁶⁴ reproduces both, from the paper’s recorded pairs', () => {
    expect(HUANG_RECORDED_PAIRS).toHaveLength(2)
    for (const pair of HUANG_RECORDED_PAIRS) {
      expect(huangResidue(pair.s, pair.p)).toBe(pair.printedResidue)
    }
    expect(HUANG_RECORDED_PAIRS.map((p) => p.printedResidue)).toEqual([
      11202993594072244072n,
      735198847291711055n,
    ])
  })
})
