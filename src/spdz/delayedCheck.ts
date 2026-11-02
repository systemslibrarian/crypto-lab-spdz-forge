/**
 * Bounded information-flow trace adapted from Brüggemann–Schneider §3.3.
 * This is NOT a Trident/SPDZ implementation. The small ring and two synthetic
 * message fields isolate the paper's hash-search relation after an injected +1.
 */
export const RING = 17
const mod = (x: number): number => ((x % RING) + RING) % RING

function drawRing(): number {
  const bytes = new Uint8Array(1)
  do crypto.getRandomValues(bytes)
  while (bytes[0]! === 255) // 255 is the only rejected byte: 255 = 15 × 17
  return bytes[0]! % RING
}

async function digest(c: number, e: number): Promise<string> {
  const data = new TextEncoder().encode(`delayed-check-teaching-v1:${c}:${mod(e)}`)
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data))
  return Array.from(hash, b => b.toString(16).padStart(2, '0')).join('')
}

export interface DelayedTrace {
  readonly publicMask: number
  readonly knownMask2: number
  readonly knownMask3: number
  readonly firstMessage: number
  readonly secondMessage: number
  readonly delayedDigest: string
  readonly searchMatch: number
  readonly inferredInput: number | null
  readonly immediateAbort: boolean
  readonly delayedAbort: boolean
  readonly jointAbort: boolean
  readonly audit: { readonly input: number; readonly hiddenMask1: number }
}

export async function runDelayedTrace(
  input: 0 | 1,
  inject: boolean,
  draw: () => number = drawRing,
): Promise<DelayedTrace> {
  const vals = Array.from({ length: 5 }, draw)
  if (vals.some(v => !Number.isInteger(v) || v < 0 || v >= RING)) throw new RangeError('draw must be in Z17')
  const [mask1, mask2, mask3, firstMessage, secondMessage] = vals as [number, number, number, number, number]
  // m_d = d + λ1_d + λ2_d + λ3_d (paper §3.3).
  const publicMask = mod(input + mask1 + mask2 + mask3)
  // Inject +1 in the first gate: the subsequent honest message shifts by -λ1_d.
  const delayedDigest = await digest(firstMessage, secondMessage - (inject ? mask1 : 0))
  const matches: number[] = []
  for (let candidate = 0; candidate < RING; candidate++) {
    if (await digest(firstMessage, secondMessage - candidate) === delayedDigest) matches.push(candidate)
  }
  if (matches.length !== 1) throw new Error('unexpected digest collision in bounded fixture')
  const searchMatch = matches[0]!
  return {
    publicMask, knownMask2: mask2, knownMask3: mask3, firstMessage, secondMessage,
    delayedDigest, searchMatch,
    inferredInput: inject ? mod(publicMask - searchMatch - mask2 - mask3) : null,
    immediateAbort: inject, delayedAbort: inject, jointAbort: inject,
    audit: { input, hiddenMask1: mask1 },
  }
}
