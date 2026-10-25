/**
 * Bounded Off-Key teaching model.
 *
 * This module adapts the algebra in Keller, Navot and Tyagi, “Off-Key:
 * Inconsistent MAC Keys Compromise Privacy in SPDZ-Family MPC”, ePrint
 * 2026/2533, §§3.2 and 4.1–4.5.  It deliberately reuses this lab's
 * three-party trusted-dealer shares; it is not a reproduction of any of the
 * paper's evaluated frameworks or their distributed preprocessing.
 *
 * The important distinction is represented directly:
 *   - different parties normally hold different additive shares of ONE key;
 *   - Off-Key combines values authenticated under different RECONSTRUCTED
 *     keys, alpha and beta = alpha + Delta.
 *
 * The attacker creates a request from only (guess, Delta).  The protocol
 * runner owns the hidden bit and preprocessing state, and returns a separate
 * attacker-visible transcript and omniscient teaching audit.
 */

import { add, inv, mod, mul, sub, type RandFn, randFieldElement } from './field'
import { macCheck, macKeyOf, openValue, shareSecret, subShares, tamperShare } from './sharing'
import { N_PARTIES, type AuthShares } from './types'

export type CheckVerdict = 'accepted' | 'abort'

/** What the corrupt party chooses without access to the honest input. */
export interface OffKeyRequest {
  readonly corruptParty: number
  readonly guess: bigint
  readonly keyShareShift: bigint
  readonly inputMacShareShift: bigint
}

/** Values visible to a protocol participant during one blind opening/check. */
export interface BlindOpeningTranscript {
  readonly openedDifference: bigint
  /** The original SPDZ check reveals this sum. */
  readonly unmaskedCheckValue: bigint
  /** The bounded masked-check adaptation reveals mu times the check sum. */
  readonly maskedCheckValue: bigint
  readonly maskedVerdict: CheckVerdict
}

interface TrialAudit {
  readonly expectedResidual: bigint
  readonly residualMatchesFormula: boolean
  readonly multiplier: bigint
  readonly expectedMaskedCheckValue: bigint
  readonly maskedValueMatchesFormula: boolean
}

export interface OffKeyExperiment {
  readonly request: OffKeyRequest
  /** Prescribed one-sided affine output visible to the corrupt party. */
  readonly affineAttackerView: {
    readonly publicX: 1n
    readonly privateOutput: bigint
  }
  /** No malicious changes: input, mask and check all use alpha. */
  readonly honestBaseline: {
    readonly openedDifference: bigint
    readonly verdict: CheckVerdict
    readonly residual: bigint
  }
  /** Restored assumption: the mask remains bound to the input's alpha context. */
  readonly sameContext: BlindOpeningTranscript
  /** Vulnerable case: input under alpha, mask/check under beta = alpha + Delta. */
  readonly offKey: BlindOpeningTranscript
  /** Deductions computed only from the request and observable check results. */
  readonly attackerDeductions: {
    readonly unmaskedRecoveredValue: bigint
    readonly maskedInferredBit: bigint
  }
  /** Ordinary bad-value-share detection, contrasted with privacy leakage. */
  readonly ordinaryCorruption: {
    readonly valueShift: 1n
    readonly openedDifference: bigint
    readonly residual: bigint
    readonly verdict: CheckVerdict
  }
  /** Explicitly omniscient data for explaining and independently checking the run. */
  readonly teachingAudit: {
    readonly secretBit: bigint
    readonly blindMask: bigint
    readonly affineMask: bigint
    readonly alpha: bigint
    readonly beta: bigint
    readonly delta: bigint
    readonly alphaShares: readonly bigint[]
    readonly betaShares: readonly bigint[]
    readonly sameContext: TrialAudit
    readonly offKey: TrialAudit
    readonly keyShiftVerified: boolean
    readonly inputAuthenticatedUnderAlpha: boolean
    readonly sameMaskAuthenticatedUnderAlpha: boolean
    readonly offKeyMaskAuthenticatedUnderBeta: boolean
    readonly unmaskedRecoveryVerified: boolean
    readonly maskedInferenceVerified: boolean
  }
}

export interface OffKeyRandomness {
  readonly blindMask: bigint
  readonly affineMask: bigint
  readonly sameContextMultiplier: bigint
  readonly offKeyMultiplier: bigint
  readonly sharingRand: RandFn
}

function requireBit(value: bigint, name: string): void {
  if (value !== 0n && value !== 1n) throw new RangeError(`${name} must be 0 or 1`)
}

function requireNonZero(value: bigint, name: string): bigint {
  const reduced = mod(value)
  if (reduced === 0n) throw new RangeError(`${name} must be non-zero in F_p`)
  return reduced
}

function randomNonZero(rand: RandFn): bigint {
  // The expected number of draws is effectively one.  The cap turns a broken
  // injected RNG into an explicit failure instead of an infinite loop.
  for (let attempt = 0; attempt < 128; attempt++) {
    const candidate = mod(rand())
    if (candidate !== 0n) return candidate
  }
  throw new Error('random source returned zero 128 times while sampling a non-zero multiplier')
}

/** Build the corrupt party's message changes without reading the secret. */
export function makeOffKeyRequest(
  guess: bigint,
  keyShareShift: bigint = 1n,
  corruptParty = 0,
): OffKeyRequest {
  requireBit(guess, 'guess')
  const delta = requireNonZero(keyShareShift, 'keyShareShift')
  if (!Number.isInteger(corruptParty) || corruptParty < 0 || corruptParty >= N_PARTIES) {
    throw new RangeError(`corruptParty must be in [0, ${N_PARTIES - 1}]`)
  }
  return Object.freeze({
    corruptParty,
    guess,
    keyShareShift: delta,
    inputMacShareShift: mul(delta, guess),
  })
}

/** Change one local key share; the reconstructed context shifts by Delta. */
export function shiftMacKeyContext(
  alphaShares: readonly bigint[],
  request: OffKeyRequest,
): bigint[] {
  if (alphaShares.length !== N_PARTIES) {
    throw new RangeError(`expected ${N_PARTIES} MAC-key shares`)
  }
  return alphaShares.map((share, party) =>
    party === request.corruptParty ? add(share, request.keyShareShift) : mod(share),
  )
}

/**
 * Original unmasked-check recovery from §4.4:
 * residual = Delta (g - y), hence y = g - residual / Delta.
 * This function receives no hidden input.
 */
export function recoverFromUnmaskedCheck(
  request: OffKeyRequest,
  observableResidual: bigint,
): bigint {
  return sub(request.guess, mul(observableResidual, inv(request.keyShareShift)))
}

/**
 * For the bounded bit fixture, a non-zero masked result says y != g and zero
 * says y = g.  This function receives only the attacker's own request and the
 * visible success/failure bit.
 */
export function inferBitFromSelectiveFailure(
  request: OffKeyRequest,
  verdict: CheckVerdict,
): bigint {
  return verdict === 'accepted' ? request.guess : sub(1n, request.guess)
}

function addInputMacShift(input: AuthShares, request: OffKeyRequest): AuthShares {
  return input.map((share, party) => ({
    value: share.value,
    mac: party === request.corruptParty
      ? add(share.mac, request.inputMacShareShift)
      : share.mac,
  }))
}

function runBlindOpening(
  inputUnderAlpha: AuthShares,
  maskShares: AuthShares,
  checkKeyShares: readonly bigint[],
  request: OffKeyRequest,
  nonZeroMultiplier: bigint,
): BlindOpeningTranscript {
  const attackedInput = addInputMacShift(inputUnderAlpha, request)
  const differenceShares = subShares(attackedInput, maskShares)
  const openedDifference = openValue(differenceShares)
  const unmasked = macCheck(openedDifference, differenceShares, checkKeyShares)
  const maskedCheckValue = mul(nonZeroMultiplier, unmasked.sum)
  return {
    openedDifference,
    unmaskedCheckValue: unmasked.sum,
    maskedCheckValue,
    maskedVerdict: maskedCheckValue === 0n ? 'accepted' : 'abort',
  }
}

function verdict(ok: boolean): CheckVerdict {
  return ok ? 'accepted' : 'abort'
}

/**
 * Execute one complete, independently checked three-party teaching fixture.
 *
 * The masked path computes z = mu * residual with a fresh non-zero mu. This
 * conditions the paper's uniform-field multiplier on mu != 0, removing its
 * 1/p false-zero event so the bounded UI never labels a random false accept as
 * a successful guess. It is the exact conditioned check algebra, but it does
 * not implement the paper's distributed multiplication triple used to hide mu.
 */
export function runOffKeyExperiment(
  secretBit: bigint,
  guess: bigint,
  alphaShares: readonly bigint[],
  supplied: Partial<OffKeyRandomness> = {},
): OffKeyExperiment {
  requireBit(secretBit, 'secretBit')
  requireBit(guess, 'guess')
  if (alphaShares.length !== N_PARTIES) {
    throw new RangeError(`expected ${N_PARTIES} MAC-key shares`)
  }

  const request = makeOffKeyRequest(guess)
  const betaShares = shiftMacKeyContext(alphaShares, request)
  const alpha = macKeyOf(alphaShares)
  const beta = macKeyOf(betaShares)
  const blindMask = mod(supplied.blindMask ?? randFieldElement())
  const affineMask = mod(supplied.affineMask ?? randFieldElement())
  const sameContextMultiplier = supplied.sameContextMultiplier === undefined
    ? randomNonZero(randFieldElement)
    : requireNonZero(supplied.sameContextMultiplier, 'sameContextMultiplier')
  const offKeyMultiplier = supplied.offKeyMultiplier === undefined
    ? randomNonZero(randFieldElement)
    : requireNonZero(supplied.offKeyMultiplier, 'offKeyMultiplier')
  const sharingRand = supplied.sharingRand ?? randFieldElement

  const inputUnderAlpha = shareSecret(secretBit, alphaShares, sharingRand)
  const maskUnderAlpha = shareSecret(blindMask, alphaShares, sharingRand)
  const maskUnderBeta = shareSecret(blindMask, betaShares, sharingRand)

  const honestDifference = subShares(inputUnderAlpha, maskUnderAlpha)
  const honestOpened = openValue(honestDifference)
  const honestCheck = macCheck(honestOpened, honestDifference, alphaShares)

  // Same-context control: even if the corrupt party shifts its online key
  // share, the key-bound alpha mask cannot become beta-authenticated.  The
  // residue targets public d, not hidden y (§4.2).
  const sameContext = runBlindOpening(
    inputUnderAlpha,
    maskUnderAlpha,
    betaShares,
    request,
    sameContextMultiplier,
  )

  // Vulnerable case: a separately generated mask is authenticated under beta.
  // The same request now targets hidden y (§4.3).
  const offKey = runBlindOpening(
    inputUnderAlpha,
    maskUnderBeta,
    betaShares,
    request,
    offKeyMultiplier,
  )

  const expectedSameResidual = mul(request.keyShareShift, sub(request.guess, sameContext.openedDifference))
  const expectedOffKeyResidual = mul(request.keyShareShift, sub(request.guess, secretBit))
  const unmaskedRecoveredValue = recoverFromUnmaskedCheck(request, offKey.unmaskedCheckValue)
  const maskedInferredBit = inferBitFromSelectiveFailure(request, offKey.maskedVerdict)

  // Ordinary wrong-share control: this changes a value share under one
  // consistent context.  It is a correctness violation, not the Off-Key
  // privacy mechanism.
  const ordinaryShares = tamperShare(honestDifference, request.corruptParty, 1n)
  const ordinaryOpened = openValue(ordinaryShares)
  const ordinaryCheck = macCheck(ordinaryOpened, ordinaryShares, alphaShares)

  const inputAuthenticatedUnderAlpha = macCheck(
    openValue(inputUnderAlpha),
    inputUnderAlpha,
    alphaShares,
  ).ok
  const sameMaskAuthenticatedUnderAlpha = macCheck(
    openValue(maskUnderAlpha),
    maskUnderAlpha,
    alphaShares,
  ).ok
  const offKeyMaskAuthenticatedUnderBeta = macCheck(
    openValue(maskUnderBeta),
    maskUnderBeta,
    betaShares,
  ).ok
  const keyShiftVerified = sub(beta, alpha) === request.keyShareShift
  const sameResidualVerified = sameContext.unmaskedCheckValue === expectedSameResidual
  const offKeyResidualVerified = offKey.unmaskedCheckValue === expectedOffKeyResidual
  const expectedSameMaskedValue = mul(sameContextMultiplier, expectedSameResidual)
  const expectedOffKeyMaskedValue = mul(offKeyMultiplier, expectedOffKeyResidual)
  const sameMaskedVerified = sameContext.maskedCheckValue === expectedSameMaskedValue
  const offKeyMaskedVerified = offKey.maskedCheckValue === expectedOffKeyMaskedValue
  const unmaskedRecoveryVerified = unmaskedRecoveredValue === secretBit
  const maskedInferenceVerified = maskedInferredBit === secretBit

  if (
    !honestCheck.ok
    || !inputAuthenticatedUnderAlpha
    || !sameMaskAuthenticatedUnderAlpha
    || !offKeyMaskAuthenticatedUnderBeta
    || !keyShiftVerified
    || !sameResidualVerified
    || !offKeyResidualVerified
    || !sameMaskedVerified
    || !offKeyMaskedVerified
    || !unmaskedRecoveryVerified
    || !maskedInferenceVerified
  ) {
    throw new Error('Off-Key fixture failed an independent protocol invariant')
  }

  return {
    request,
    affineAttackerView: {
      publicX: 1n,
      privateOutput: add(secretBit, affineMask),
    },
    honestBaseline: {
      openedDifference: honestOpened,
      verdict: verdict(honestCheck.ok),
      residual: honestCheck.sum,
    },
    sameContext,
    offKey,
    attackerDeductions: { unmaskedRecoveredValue, maskedInferredBit },
    ordinaryCorruption: {
      valueShift: 1n,
      openedDifference: ordinaryOpened,
      residual: ordinaryCheck.sum,
      verdict: verdict(ordinaryCheck.ok),
    },
    teachingAudit: {
      secretBit,
      blindMask,
      affineMask,
      alpha,
      beta,
      delta: request.keyShareShift,
      alphaShares: [...alphaShares],
      betaShares,
      sameContext: {
        expectedResidual: expectedSameResidual,
        residualMatchesFormula: sameResidualVerified,
        multiplier: sameContextMultiplier,
        expectedMaskedCheckValue: expectedSameMaskedValue,
        maskedValueMatchesFormula: sameMaskedVerified,
      },
      offKey: {
        expectedResidual: expectedOffKeyResidual,
        residualMatchesFormula: offKeyResidualVerified,
        multiplier: offKeyMultiplier,
        expectedMaskedCheckValue: expectedOffKeyMaskedValue,
        maskedValueMatchesFormula: offKeyMaskedVerified,
      },
      keyShiftVerified,
      inputAuthenticatedUnderAlpha,
      sameMaskAuthenticatedUnderAlpha,
      offKeyMaskAuthenticatedUnderBeta,
      unmaskedRecoveryVerified,
      maskedInferenceVerified,
    },
  }
}
