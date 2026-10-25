import { describe, expect, it } from 'vitest'
import { P, add, fixedSequence, mod, sub } from './field'
import {
  inferBitFromSelectiveFailure,
  makeOffKeyRequest,
  recoverFromUnmaskedCheck,
  runOffKeyExperiment,
  shiftMacKeyContext,
  type OffKeyRandomness,
} from './offkey'
import { macKeyOf } from './sharing'

const ALPHA_SHARES = [3n, 5n, 7n] as const

function deterministic(overrides: Partial<OffKeyRandomness> = {}): Partial<OffKeyRandomness> {
  return {
    blindMask: 9n,
    affineMask: 17n,
    sameContextMultiplier: 11n,
    offKeyMultiplier: 13n,
    // Three calls to shareSecret, four draws per call.  Distinct fixed values
    // make the test replayable while leaving the relation under test real.
    sharingRand: fixedSequence(Array.from({ length: 12 }, (_, i) => BigInt(i + 21))),
    ...overrides,
  }
}

describe('Off-Key bounded algebraic adaptation', () => {
  it('starts from legitimate distinct additive shares of one global key', () => {
    expect(new Set(ALPHA_SHARES).size).toBe(3)
    expect(macKeyOf(ALPHA_SHARES)).toBe(15n)

    const request = makeOffKeyRequest(1n)
    const betaShares = shiftMacKeyContext(ALPHA_SHARES, request)
    expect(betaShares).toEqual([4n, 5n, 7n])
    expect(sub(macKeyOf(betaShares), macKeyOf(ALPHA_SHARES))).toBe(1n)
  })

  it('off-key masked check accepts exactly the matching guess and exposes the paper residual', () => {
    const run = runOffKeyExperiment(1n, 1n, ALPHA_SHARES, deterministic())

    expect(run.honestBaseline).toMatchObject({ verdict: 'accepted', residual: 0n })
    expect(run.offKey.unmaskedCheckValue).toBe(0n)
    expect(run.offKey.maskedCheckValue).toBe(0n)
    expect(run.offKey.maskedVerdict).toBe('accepted')
    expect(run.attackerDeductions).toEqual({
      unmaskedRecoveredValue: 1n,
      maskedInferredBit: 1n,
    })
    expect(run.teachingAudit.offKey).toMatchObject({
      expectedResidual: 0n,
      residualMatchesFormula: true,
      multiplier: 13n,
      expectedMaskedCheckValue: 0n,
      maskedValueMatchesFormula: true,
    })
  })

  it('a wrong bit guess produces a non-zero masked check and the abort identifies the other bit', () => {
    const run = runOffKeyExperiment(1n, 0n, ALPHA_SHARES, deterministic())
    const expected = sub(0n, 1n)

    expect(run.offKey.unmaskedCheckValue).toBe(expected)
    expect(run.offKey.maskedCheckValue).toBe(mod(13n * expected))
    expect(run.offKey.maskedVerdict).toBe('abort')
    expect(run.attackerDeductions.unmaskedRecoveredValue).toBe(1n)
    expect(run.attackerDeductions.maskedInferredBit).toBe(1n)
    expect(run.teachingAudit.maskedInferenceVerified).toBe(true)
  })

  it('same-context repair keeps preprocessing under alpha and turns the residual into a function of public d', () => {
    const run = runOffKeyExperiment(1n, 1n, ALPHA_SHARES, deterministic())
    const d = sub(1n, 9n)
    const expected = sub(1n, d)

    expect(run.sameContext.openedDifference).toBe(d)
    expect(run.sameContext.unmaskedCheckValue).toBe(expected)
    expect(run.teachingAudit.sameContext.expectedResidual).toBe(expected)
    expect(run.teachingAudit.sameContext.residualMatchesFormula).toBe(true)
    expect(run.teachingAudit.sameContext.maskedValueMatchesFormula).toBe(true)
    expect(run.teachingAudit.sameMaskAuthenticatedUnderAlpha).toBe(true)
  })

  it('same-context observations do not become a hidden-input equality oracle', () => {
    // Choose two masks so both runs open the same public d = 7.  With one
    // context, the residual is identical despite different hidden bits.  In
    // the off-key context it changes with y, which is precisely the gap.
    const y0 = runOffKeyExperiment(0n, 0n, ALPHA_SHARES, deterministic({ blindMask: P - 7n }))
    const y1 = runOffKeyExperiment(1n, 0n, ALPHA_SHARES, deterministic({ blindMask: P - 6n }))

    expect(y0.sameContext.openedDifference).toBe(7n)
    expect(y1.sameContext.openedDifference).toBe(7n)
    expect(y0.sameContext.unmaskedCheckValue).toBe(y1.sameContext.unmaskedCheckValue)
    expect(y0.offKey.unmaskedCheckValue).not.toBe(y1.offKey.unmaskedCheckValue)
  })

  it('attacker deductions consume only the request and observable response', () => {
    const request = makeOffKeyRequest(0n, 7n, 2)
    expect(Object.keys(request).sort()).toEqual([
      'corruptParty',
      'guess',
      'inputMacShareShift',
      'keyShareShift',
    ])
    expect(request).not.toHaveProperty('secret')
    expect(request).not.toHaveProperty('secretBit')
    expect(request.inputMacShareShift).toBe(0n)

    // residual = Delta(g-y) = 7(0-1)
    const residual = mod(-7n)
    expect(recoverFromUnmaskedCheck(request, residual)).toBe(1n)
    expect(inferBitFromSelectiveFailure(request, 'abort')).toBe(1n)
  })

  it('attacker request adds Delta times the guess to its own MAC share', () => {
    const request = makeOffKeyRequest(1n, 19n, 1)
    expect(request.keyShareShift).toBe(19n)
    expect(request.inputMacShareShift).toBe(19n)
    expect(request.corruptParty).toBe(1)
  })

  it('the private affine output is computed but does not expose its hidden mask', () => {
    const run = runOffKeyExperiment(1n, 0n, ALPHA_SHARES, deterministic())
    expect(run.affineAttackerView).toEqual({ publicX: 1n, privateOutput: 18n })
    expect(run.affineAttackerView).not.toHaveProperty('affineMask')
    expect(run.affineAttackerView).not.toHaveProperty('secretBit')
    expect(run.teachingAudit.affineMask).toBe(17n)
    expect(add(run.teachingAudit.secretBit, run.teachingAudit.affineMask)).toBe(
      run.affineAttackerView.privateOutput,
    )
  })

  it('ordinary value-share corruption is detected but is not the privacy attack', () => {
    const run = runOffKeyExperiment(1n, 1n, ALPHA_SHARES, deterministic())
    expect(run.ordinaryCorruption.valueShift).toBe(1n)
    expect(run.ordinaryCorruption.verdict).toBe('abort')
    expect(run.ordinaryCorruption.residual).toBe(sub(0n, macKeyOf(ALPHA_SHARES)))
  })

  it('checks both secret bits and both guesses across several masks', () => {
    for (const secret of [0n, 1n]) {
      for (const guess of [0n, 1n]) {
        for (const blindMask of [0n, 1n, 42n, P - 1n]) {
          const run = runOffKeyExperiment(
            secret,
            guess,
            ALPHA_SHARES,
            deterministic({ blindMask }),
          )
          expect(run.offKey.maskedVerdict).toBe(secret === guess ? 'accepted' : 'abort')
          expect(run.attackerDeductions.unmaskedRecoveredValue).toBe(secret)
          expect(run.attackerDeductions.maskedInferredBit).toBe(secret)
          expect(run.teachingAudit.keyShiftVerified).toBe(true)
        }
      }
    }
  })

  it('rejects malformed bounded fixtures instead of manufacturing a verdict', () => {
    expect(() => runOffKeyExperiment(2n, 0n, ALPHA_SHARES, deterministic())).toThrow(/secretBit/)
    expect(() => runOffKeyExperiment(0n, -1n, ALPHA_SHARES, deterministic())).toThrow(/guess/)
    expect(() => makeOffKeyRequest(0n, 0n)).toThrow(/non-zero/)
    expect(() => makeOffKeyRequest(0n, 1n, 3)).toThrow(/corruptParty/)
    expect(() => shiftMacKeyContext([1n, 2n], makeOffKeyRequest(0n))).toThrow(/3 MAC-key shares/)
    expect(() => runOffKeyExperiment(0n, 0n, ALPHA_SHARES, deterministic({ offKeyMultiplier: 0n }))).toThrow(/offKeyMultiplier/)
  })
})
