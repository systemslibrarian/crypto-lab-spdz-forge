/**
 * The MAC key that leaks through a rushing check.
 *
 * Kyster, Huss Nielsen, Oechsner and Scholl, "Rushing at SPDZ: On the
 * Practical Security of Malicious MPC Implementations", §3.1 ("SPDZ MAC
 * Failure Leaks the MAC Key") and §3.2. The protocol statement elsewhere on
 * this page -- α is additively shared and no party holds it -- is true of the
 * protocol. This module runs what happens to it in an implementation that
 * lets two MAC checks be in flight at once.
 *
 *   CHECK 1 (the leak). An authenticated value [x] is opened. The corrupt
 *   party sends x₁ + 1, so the parties reconstruct x′ = x + 1 and the check
 *   is going to fail. Everyone commits to a check share, then the honest
 *   parties open theirs. The corrupt party has committed to junk and opens
 *   nothing. It now holds the honest σ's and can compute its own true one:
 *
 *       Σσᵢ = Σγᵢ − α·x′ = α·x − α·(x + 1) = −α        (this lab's sign)
 *
 *   so α = −Σσᵢ. (The paper writes σᵢ = x·αᵢ − γᵢ and gets Σσᵢ = α; same
 *   fact.) The commitment round did its job -- the corrupt party cannot make
 *   THIS check pass -- but because it never opens, the honest parties are
 *   left waiting rather than aborting.
 *
 *   CHECK 2 (the forgery). While check 1 hangs, a second computation is still
 *   live. The paper's example is f(x, y) = (x·r)·y with the corrupt input
 *   x = 0: the corrupt party adds 1 to its share of [x·r] and α to the MAC
 *   share, every later MAC check passes, and the opened result is
 *   (0·r + 1)·y = y -- the honest party's input.
 *
 * Three ways to schedule the same two checks are run here, with the same
 * adversary:
 *
 *   concurrent        both in flight                 → α leaks, y is released
 *   sequential        one at a time, nothing released until a check finishes
 *                     → whichever goes first, check 2 never releases y
 *   masked            the paper's Π_MaskedCheck (Figure 4) for check 1
 *                     → concurrency is fine, the failing check reveals α·b
 *                       for an unknown random b instead of α
 *
 * MODELED: three parties in one tab, a trusted dealer, and "concurrent" as an
 * explicit ordering of the same messages rather than real threads. REAL: every
 * share, MAC share, check share, SHA-256 commitment and Beaver multiplication.
 * The adversary functions below take only what the corrupt party holds or has
 * been sent; the dealer's α appears in the result solely so a test and the
 * learner's audit view can compare against it.
 */

import { add, inv, mod, mul, neg, sub, randFieldElement, type RandFn } from './field'
import { beaverMulChecked, dealTriple } from './beaver'
import { dealMacKey, macCheck, macKeyOf, openValue, shareSecret, tamperShare } from './sharing'
import { openSpdz } from './protocol'
import { checkShares, commitTo, randomNonce } from './transcript'
import { N_PARTIES, type AuthShare, type AuthShares } from './types'

/** The corrupt party. Index 1, the party the MAC panel already lets you play. */
export const CORRUPT = 1
/** The honest party whose input check 2 is about. */
export const VICTIM = 0

export type Schedule = 'concurrent' | 'sequential-leak-first' | 'sequential-forge-first' | 'masked'

export interface LeakCheck {
  /** The authenticated value that was meant to be opened. */
  x: bigint
  /** What the parties reconstructed after the corrupt party added `shift`. */
  opened: bigint
  shift: bigint
  /** SHA-256 commitments, index = party. The corrupt party's is to a junk value. */
  commitments: string[]
  /** Check shares the honest parties opened (and that verified against their commitments). */
  honestOpened: { party: number; sigma: bigint }[]
  /** The corrupt party's true check share: computed locally, never sent. */
  corruptSigma: bigint
  /** Σσᵢ over the two honest openings and the corrupt party's own. */
  sigmaSum: bigint
  /** What the corrupt party derives for α from everything it holds. */
  recoveredAlpha: bigint
  /**
   * `hanging`: the corrupt party withheld its opening and nothing forces the
   * issue. `abort`: the scheduler requires the check to finish, so a missing
   * or wrong opening ends the session.
   */
  outcome: 'hanging' | 'abort' | 'not-run'
  /** Present under the masked check: what was broadcast instead of raw σ's. */
  masked?: {
    /** Broadcast sᵢ = αᵢ·x′ − γᵢ − aᵢ. */
    broadcast: bigint[]
    /** s = Σsᵢ = Δ·α − a. */
    sum: bigint
    /** Honest zⱼ = s·bⱼ + cⱼ that were opened. */
    honestZ: { party: number; z: bigint }[]
    /** Σzᵢ = Δ·α·b -- α times a random value nobody holds. */
    zSum: bigint
  }
}

export interface ForgeCheck {
  /** What the corrupt party used as α: recovered, or a guess when it has none. */
  alphaUsed: bigint
  alphaSource: 'recovered' | 'guess'
  /** The honest value of [x·r] with x = 0. */
  honestProduct: bigint
  /** MAC-share shift applied alongside the +1 on the value share. */
  macShift: bigint
  outcome: 'accepted' | 'abort' | 'not-run'
  /** Which opening the abort happened at, when it did. */
  abortAt?: 'd' | 'e' | 'final' | 'session'
  /** The value the parties released, if any. */
  released: bigint | null
}

export interface RushingRun {
  schedule: Schedule
  /** The honest party's secret input y. */
  victimInput: bigint
  /** What f(x, y) = (x·r)·y honestly evaluates to with x = 0. */
  honestOutput: bigint
  /** The order the two checks' decisive messages were delivered in. */
  order: ('check-1' | 'check-2')[]
  leak: LeakCheck
  forge: ForgeCheck
  /** Dealer's view, for the test and the learner audit only. */
  audit: { alpha: bigint; alphaShares: bigint[] }
  /** The corrupt party ended up holding the real α. */
  alphaLeaked: boolean
  /** The parties released the honest party's input as the "result". */
  inputRevealed: boolean
}

/**
 * α from a failed check, using only what the corrupt party has.
 *
 * `honestSigmas` are the openings it was sent. `own` is its own share of the
 * opened value's MAC and of the key. `shift` is the error it introduced, which
 * it chose. Σσᵢ = −α·shift, so α = −Σσᵢ / shift.
 */
export function recoverAlphaFromOpenings(
  honestSigmas: readonly bigint[],
  own: { mac: bigint; alphaShare: bigint },
  opened: bigint,
  shift: bigint,
): { corruptSigma: bigint; sigmaSum: bigint; alpha: bigint } {
  if (mod(shift) === 0n) throw new RangeError('a zero shift opens the true value: the check passes and reveals nothing')
  const corruptSigma = sub(own.mac, mul(own.alphaShare, mod(opened)))
  const sigmaSum = honestSigmas.reduce((s, v) => add(s, v), corruptSigma)
  return { corruptSigma, sigmaSum, alpha: mul(neg(sigmaSum), inv(mod(shift))) }
}

/** An unauthenticated multiplication triple, additively shared: Σaᵢ·Σbᵢ = Σcᵢ. */
function dealPlainTriple(rand: RandFn): { a: bigint[]; b: bigint[]; c: bigint[] } {
  const split = (v: bigint): bigint[] => {
    const out: bigint[] = []
    let sum = 0n
    for (let i = 0; i < N_PARTIES - 1; i++) {
      const r = rand()
      out.push(r)
      sum = add(sum, r)
    }
    out.push(sub(v, sum))
    return out
  }
  const a = rand()
  const b = rand()
  return { a: split(a), b: split(b), c: split(mul(a, b)) }
}

/**
 * Check 1 with the ordinary commit-then-open MAC check.
 *
 * `mustComplete` is the scheduler's rule. False: the corrupt party may sit on
 * its opening for ever and the check hangs. True: the check has to finish
 * before anything else proceeds, so the missing opening is an abort.
 */
async function leakingCheck(
  xShares: AuthShares,
  alphaShares: readonly bigint[],
  shift: bigint,
  mustComplete: boolean,
): Promise<LeakCheck> {
  const x = openValue(xShares)
  const sent = tamperShare(xShares, CORRUPT, shift)
  const opened = openValue(sent)

  // Every party computes its check share for the value that was OPENED. The
  // MAC shares are the untouched ones: the corrupt party lied about its value
  // share only.
  const sigmas = checkShares(opened, xShares, alphaShares)

  // Commit round. Honest parties commit to their σ; the corrupt one to junk.
  const junk = randFieldElement()
  const nonces = sigmas.map(() => randomNonce())
  const commitments = await Promise.all(
    sigmas.map((s, i) => commitTo(i === CORRUPT ? junk : s, nonces[i] as Uint8Array)),
  )

  // Reveal round. Honest parties open, and each opening verifies.
  const honestOpened: { party: number; sigma: bigint }[] = []
  for (let i = 0; i < sigmas.length; i++) {
    if (i === CORRUPT) continue
    const sigma = sigmas[i] as bigint
    if ((await commitTo(sigma, nonces[i] as Uint8Array)) !== commitments[i]) {
      throw new Error('an honest opening failed its own commitment -- impossible unless the lab has a bug')
    }
    honestOpened.push({ party: i, sigma })
  }

  // The corrupt party, holding the honest openings and its own shares.
  const own = xShares[CORRUPT] as AuthShare
  const { corruptSigma, sigmaSum, alpha } = recoverAlphaFromOpenings(
    honestOpened.map((h) => h.sigma),
    { mac: own.mac, alphaShare: alphaShares[CORRUPT] as bigint },
    opened,
    shift,
  )

  return {
    x,
    opened,
    shift,
    commitments,
    honestOpened,
    corruptSigma,
    sigmaSum,
    recoveredAlpha: alpha,
    outcome: mustComplete ? 'abort' : 'hanging',
  }
}

/**
 * Check 1 with the paper's Π_MaskedCheck (Figure 4).
 *
 *   sᵢ := x′·αᵢ − γᵢ − aᵢ          broadcast, s = Σsᵢ
 *   zᵢ := s·bᵢ + cᵢ                committed, then opened
 *   accept iff Σzᵢ = 0
 *
 * for an unauthenticated preprocessed triple (a, b, c = a·b). Then
 * Σzᵢ = (Δ·α − a)·b + a·b = Δ·α·b. When the check fails the corrupt party
 * sees s (α hidden by a) and Σzᵢ (α hidden by b). It applies the same recovery
 * it used against the plain check and gets a number that is not α.
 */
async function maskedLeakingCheck(
  xShares: AuthShares,
  alphaShares: readonly bigint[],
  shift: bigint,
  rand: RandFn,
): Promise<LeakCheck> {
  const x = openValue(xShares)
  const opened = openValue(tamperShare(xShares, CORRUPT, shift))
  const t = dealPlainTriple(rand)

  const broadcast = xShares.map((sh, i) =>
    sub(sub(mul(alphaShares[i] as bigint, opened), sh.mac), t.a[i] as bigint),
  )
  const sum = broadcast.reduce((s, v) => add(s, v), 0n)
  const zs = broadcast.map((_, i) => add(mul(sum, t.b[i] as bigint), t.c[i] as bigint))

  const junk = randFieldElement()
  const nonces = zs.map(() => randomNonce())
  const commitments = await Promise.all(
    zs.map((z, i) => commitTo(i === CORRUPT ? junk : z, nonces[i] as Uint8Array)),
  )
  const honestZ = zs.map((z, party) => ({ party, z })).filter((h) => h.party !== CORRUPT)
  const zSum = zs.reduce((s, v) => add(s, v), 0n)

  // The corrupt party's best effort: treat what it saw the way it treated raw
  // σ's. Under the paper's sign convention Σσᵢ = Δ·α, so its estimate is s/Δ.
  const estimate = mul(sum, inv(mod(shift)))

  return {
    x,
    opened,
    shift,
    commitments,
    honestOpened: [],
    corruptSigma: broadcast[CORRUPT] as bigint,
    sigmaSum: sum,
    recoveredAlpha: estimate,
    outcome: 'hanging',
    masked: { broadcast, sum, honestZ, zSum },
  }
}

/**
 * Check 2: f(x, y) = (x·r)·y with the corrupt input x = 0.
 *
 * The corrupt party adds 1 to its share of [x·r] and `alphaUsed` to its MAC
 * share. If `alphaUsed` is the real α the shifted sharing is a perfectly
 * authenticated sharing of 1, both Beaver openings and the final open pass,
 * and the released "result" is y. If it is anything else the first opening
 * that touches the shifted share fails its MAC check and the parties abort.
 */
export function forgingCheck(
  victimInput: bigint,
  alphaShares: readonly bigint[],
  alphaUsed: bigint,
  alphaSource: 'recovered' | 'guess',
  rand: RandFn,
): ForgeCheck {
  const xShares = shareSecret(0n, alphaShares, rand) // the corrupt party's input
  const rShares = shareSecret(rand(), alphaShares, rand)
  const yShares = shareSecret(victimInput, alphaShares, rand) // the honest party's input

  const first = beaverMulChecked(xShares, rShares, dealTriple(alphaShares, rand), alphaShares)
  if (first.kind === 'abort') {
    throw new Error('the honest first multiplication aborted -- impossible unless the lab has a bug')
  }
  const honestProduct = openValue(first.z) // inspection only: 0·r = 0

  const macShift = mod(alphaUsed) // α·1
  const forged = tamperShare(first.z, CORRUPT, 1n, macShift)

  const second = beaverMulChecked(forged, yShares, dealTriple(alphaShares, rand), alphaShares)
  if (second.kind === 'abort') {
    return { alphaUsed, alphaSource, honestProduct, macShift, outcome: 'abort', abortAt: second.at, released: null }
  }
  const final = openSpdz(second.z, alphaShares)
  if (final.kind === 'abort') {
    return { alphaUsed, alphaSource, honestProduct, macShift, outcome: 'abort', abortAt: 'final', released: null }
  }
  return { alphaUsed, alphaSource, honestProduct, macShift, outcome: 'accepted', released: final.value }
}

const notRunLeak = (): LeakCheck => ({
  x: 0n,
  opened: 0n,
  shift: 1n,
  commitments: [],
  honestOpened: [],
  corruptSigma: 0n,
  sigmaSum: 0n,
  recoveredAlpha: 0n,
  outcome: 'not-run',
})

/**
 * Check 2 was never scheduled: check 1 went first and aborted, so the session
 * ended before check 2 opened anything. `alphaUsed` is the key the corrupt
 * party DID leak out of check 1 — real, but with no live check left to spend it
 * on. (The test runs `forgingCheck` with this same key to confirm it WOULD have
 * forged; the scheduling, not the algebra, is what stops it.)
 */
const notRunForge = (alphaUsed: bigint): ForgeCheck => ({
  alphaUsed,
  alphaSource: 'recovered',
  honestProduct: 0n,
  macShift: mod(alphaUsed),
  outcome: 'not-run',
  released: null,
})

/**
 * Run both checks under one schedule, against a freshly dealt MAC key.
 *
 * A fresh key per run is deliberate: once α has leaked, everything
 * authenticated under it is finished. The paper's recommendation is that
 * "after any abort potentially caused by cheating, all randomness used in the
 * current execution should be erased".
 */
export async function runRushing(
  schedule: Schedule,
  victimInput: bigint,
  rand: RandFn = randFieldElement,
): Promise<RushingRun> {
  const alphaShares = dealMacKey(rand)
  const alpha = macKeyOf(alphaShares)
  const y = mod(victimInput)
  const xShares = shareSecret(rand(), alphaShares, rand) // the value check 1 opens
  const shift = 1n
  const honestOutput = 0n // (0·r)·y

  let leak: LeakCheck
  let forge: ForgeCheck
  let order: ('check-1' | 'check-2')[]

  if (schedule === 'concurrent') {
    // Check 1 leaks and hangs; check 2 is still live and uses the key.
    leak = await leakingCheck(xShares, alphaShares, shift, false)
    forge = forgingCheck(y, alphaShares, leak.recoveredAlpha, 'recovered', rand)
    order = ['check-1', 'check-2']
  } else if (schedule === 'masked') {
    // Both in flight, as above -- but check 1 is the masked protocol.
    leak = await maskedLeakingCheck(xShares, alphaShares, shift, rand)
    forge = forgingCheck(y, alphaShares, leak.recoveredAlpha, 'recovered', rand)
    order = ['check-1', 'check-2']
  } else if (schedule === 'sequential-leak-first') {
    // Check 1 must finish before anything else is released. The corrupt party
    // still learns α from the honest openings -- and the check then aborts (its
    // own opening is missing), so the session ends and check 2 is never
    // scheduled. The forge's non-execution is a CONSEQUENCE of check 1's
    // computed outcome, not a fixed result: leakingCheck(mustComplete=true)
    // returns `abort`, so check 2 does not run.
    leak = await leakingCheck(xShares, alphaShares, shift, true)
    forge = leak.outcome === 'abort'
      ? notRunForge(leak.recoveredAlpha)
      : forgingCheck(victimInput, alphaShares, leak.recoveredAlpha, 'recovered', rand)
    order = ['check-1', 'check-2']
  } else {
    // Check 2 goes first. The corrupt party has not seen a failed check yet,
    // so it has no α: its forgery rides on a guess and dies at the first
    // opening. The session aborts and check 1 never runs.
    forge = forgingCheck(y, alphaShares, rand(), 'guess', rand)
    leak = notRunLeak()
    order = ['check-2', 'check-1']
  }

  return {
    schedule,
    victimInput: y,
    honestOutput,
    order,
    leak,
    forge,
    audit: { alpha, alphaShares: [...alphaShares] },
    alphaLeaked: leak.outcome !== 'not-run' && leak.recoveredAlpha === alpha,
    inputRevealed: forge.outcome === 'accepted' && forge.released === y,
  }
}

// ---------------------------------------------------------------------------
// The batched "what if": coefficients known before the shares are sent.
// ---------------------------------------------------------------------------

/**
 * A batched MAC check over K opened values: one random linear combination.
 *
 *   Σₖ rₖ·Σᵢ σᵢ⁽ᵏ⁾ = α·Σₖ rₖ·(yₖ − y′ₖ) = −α·Σₖ rₖ·eₖ
 *
 * where eₖ is the error in the k-th opened value. It is zero for honest
 * openings, and for dishonest ones it is zero only if Σ rₖ·eₖ = 0.
 */
export function batchedMacCheck(
  opened: readonly bigint[],
  shares: readonly AuthShares[],
  alphaShares: readonly bigint[],
  coefficients: readonly bigint[],
): { ok: boolean; sum: bigint } {
  if (opened.length !== shares.length || opened.length !== coefficients.length) {
    throw new RangeError('one coefficient and one share vector per opened value')
  }
  let sum = 0n
  for (let k = 0; k < opened.length; k++) {
    const check = macCheck(opened[k] as bigint, shares[k] as AuthShares, alphaShares)
    sum = add(sum, mul(coefficients[k] as bigint, check.sum))
  }
  return { ok: sum === 0n, sum }
}

export type CoefficientTiming = 'known-before' | 'drawn-after'

export interface BatchWhatIf {
  timing: CoefficientTiming
  honestInput: bigint
  corruptInput: bigint
  /** The honest outputs: sum and product. */
  honest: [bigint, bigint]
  /** The coefficients the corrupt party predicted before sending its shares. */
  predicted: [bigint, bigint]
  /** The coefficients the check actually used. */
  used: [bigint, bigint]
  /** The corrupt party's shifts e = (r₂, −r₁) on the two opened values. */
  shift: [bigint, bigint]
  /** The values the parties reconstructed. */
  opened: [bigint, bigint]
  check: { ok: boolean; sum: bigint }
  /** Σ rₖ·eₖ under the coefficients the check used. */
  weightedShift: bigint
  /**
   * P − h·(S − h) mod p for the opened pair, with h the honest input. Zero for
   * every input the corrupt party could legitimately have chosen (S = h + b,
   * P = h·b), so a non-zero value is an output no input explains.
   */
  residue: bigint
  outcome: 'accepted' | 'abort'
}

function nonZero(rand: RandFn): bigint {
  for (;;) {
    const v = rand()
    if (v !== 0n) return v
  }
}

/**
 * Two parties' inputs (20 and 30, the paper's application), their sum and
 * product opened together under one batched check.
 *
 * `known-before`: the coefficients come from a seed fixed before the opening
 * shares are sent, so the corrupt party can compute them first and choose
 * e = (r₂, −r₁). r₁·r₂ − r₂·r₁ = 0: the check is unchanged and both wrong
 * values are released. This is the setting Huang, "Challenge Binding in FRESCO
 * SPDZ2k: A Message-Level Case Study" (2026) reports for FRESCO's SPDZ2k suite.
 *
 * `drawn-after`: the coefficients are drawn once the opened values are fixed,
 * which is what the SPDZ paper specifies and what this lab's README says of
 * the batched check. The same shift now meets coefficients it was not built
 * for, and the check fails.
 */
export function runBatchWhatIf(
  timing: CoefficientTiming,
  rand: RandFn = randFieldElement,
  honestInput = 20n,
  corruptInput = 30n,
): BatchWhatIf {
  const alphaShares = dealMacKey(rand)
  const a = shareSecret(honestInput, alphaShares, rand)
  const b = shareSecret(corruptInput, alphaShares, rand)
  const sumShares: AuthShares = a.map((sa, i) => {
    const sb = b[i] as AuthShare
    return { value: add(sa.value, sb.value), mac: add(sa.mac, sb.mac) }
  })
  const mulResult = beaverMulChecked(a, b, dealTriple(alphaShares, rand), alphaShares)
  if (mulResult.kind === 'abort') {
    throw new Error('the honest multiplication aborted -- impossible unless the lab has a bug')
  }
  const prodShares = mulResult.z
  const honest: [bigint, bigint] = [openValue(sumShares), openValue(prodShares)]

  // The stream the corrupt party can compute before it sends anything.
  const predicted: [bigint, bigint] = [nonZero(rand), nonZero(rand)]
  const shift: [bigint, bigint] = [predicted[1], neg(predicted[0])]

  // It sends shifted VALUE shares and leaves its MAC shares alone.
  const sentSum = tamperShare(sumShares, CORRUPT, shift[0])
  const sentProd = tamperShare(prodShares, CORRUPT, shift[1])
  const opened: [bigint, bigint] = [openValue(sentSum), openValue(sentProd)]

  const used: [bigint, bigint] = timing === 'known-before' ? predicted : [nonZero(rand), nonZero(rand)]
  // The honest parties check the opened values against the MAC shares they hold.
  const check = batchedMacCheck(opened, [sumShares, prodShares], alphaShares, used)
  const weightedShift = add(mul(used[0], shift[0]), mul(used[1], shift[1]))
  const residue = sub(opened[1], mul(mod(honestInput), sub(opened[0], mod(honestInput))))

  return {
    timing,
    honestInput: mod(honestInput),
    corruptInput: mod(corruptInput),
    honest,
    predicted,
    used,
    shift,
    opened,
    check,
    weightedShift,
    residue,
    outcome: check.ok ? 'accepted' : 'abort',
  }
}

/**
 * The two output pairs Huang's paper records (§4.3), and the arithmetic it
 * applies to them. These are THE PAPER'S FIGURES, from FRESCO SPDZ2k runs at
 * 64-bit value width -- nothing in this lab produced them. What is computed
 * here is only the paper's own consistency relation over its printed numbers:
 *
 *     residue = P − 20·(S − 20)  (mod 2⁶⁴)
 *
 * which is 0 for every legitimate corrupt input and which the paper reports as
 * 11202993594072244072 and 735198847291711055.
 */
export const HUANG_RECORDED_PAIRS: readonly { label: string; s: bigint; p: bigint; printedResidue: bigint }[] = [
  {
    label: 'initial message-level pair',
    s: 15699666240690473753n,
    p: 11601669154819341260n,
    printedResidue: 11202993594072244072n,
  },
  {
    label: 'object-level pair',
    s: 4143675807337242761n,
    p: 9821738699198359411n,
    printedResidue: 735198847291711055n,
  },
]

export function huangResidue(s: bigint, p: bigint, honestInput = 20n): bigint {
  const m = 1n << 64n
  return (((p - honestInput * (s - honestInput)) % m) + m) % m
}
