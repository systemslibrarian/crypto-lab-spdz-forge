/**
 * Prime field F_p with p = 2^61 - 1 (a Mersenne prime).
 *
 * This is a field real MPC frameworks use (MP-SPDZ's "Mersenne61"); every
 * operation below is genuine modular arithmetic over BigInt — nothing is
 * simulated. Hand-rolled on purpose: the field is a teaching subject here,
 * so the internals stay inspectable.
 */

export const P = (1n << 61n) - 1n // 2305843009213693951

/** Reduce any integer (including negatives) into [0, P). */
export function mod(x: bigint): bigint {
  const r = x % P
  return r < 0n ? r + P : r
}

export function add(a: bigint, b: bigint): bigint {
  return mod(a + b)
}

export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b)
}

export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b)
}

export function neg(a: bigint): bigint {
  return mod(-a)
}

/** Square-and-multiply exponentiation in F_p. */
export function pow(base: bigint, exp: bigint): bigint {
  let b = mod(base)
  let e = exp
  let acc = 1n
  while (e > 0n) {
    if (e & 1n) acc = mul(acc, b)
    b = mul(b, b)
    e >>= 1n
  }
  return acc
}

/** Multiplicative inverse via Fermat's little theorem: a^(p-2) mod p. */
export function inv(a: bigint): bigint {
  const r = mod(a)
  if (r === 0n) throw new RangeError('0 has no inverse in F_p')
  return pow(r, P - 2n)
}

/** A source of uniform field elements. Tests may substitute a fixed sequence. */
export type RandFn = () => bigint

/**
 * Uniform random field element from the platform CSPRNG
 * (crypto.getRandomValues), via rejection sampling on 61-bit candidates so
 * the distribution over [0, P) is exactly uniform.
 */
export const randFieldElement: RandFn = () => {
  const buf = new BigUint64Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    const candidate = (buf[0] as bigint) & ((1n << 61n) - 1n)
    // Reject the single out-of-range value 2^61 - 1 === P (maps to 0 otherwise, skewing it).
    if (candidate < P) return candidate
  }
}

/** Build a deterministic RandFn from a fixed sequence — for KATs only, never the UI. */
export function fixedSequence(values: readonly bigint[]): RandFn {
  let i = 0
  return () => {
    const v = values[i]
    if (v === undefined) throw new RangeError(`fixed sequence exhausted after ${i} draws`)
    i += 1
    return mod(v)
  }
}
