/*
 * NIST CAVP SHA-256 vectors — copied from the response files.
 *
 * Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
 *   zip      sha256 929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8
 *   ShortMsg sha256 75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c
 *   LongMsg  sha256 6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974
 *
 * COPIED FROM THE PUBLICATION, not regenerated. A digest produced by WebCrypto agrees
 * with `commitTo` for the same reason it agrees with itself.
 *
 * HOW THESE REACH `commitTo`. It hashes `nonce || sigma as 8 big-endian bytes`, so a
 * CAVP message of N >= 8 bytes is reachable by splitting it: the first N-8 bytes are the
 * nonce and the last 8 are sigma, read as an unsigned big-endian integer. The digest the
 * lab produces must then be the digest CAVP publishes for the whole message. That pins
 * four things at once — the hash is SHA-256, the nonce comes first, sigma is big-endian,
 * and the hex encoding keeps leading zeros.
 *
 * The parse was checked rather than trusted: all 129 rows across both files were
 * re-hashed and every published MD matched its own Msg, and each selected row's byte
 * length was checked against its stated Len. The files write `Msg = 00` for `Len = 0`,
 * a placeholder rather than a one-byte message, which is why Len is read in BITS and a
 * zero-length row is treated as the empty string.
 *
 * The spread is deliberate: 64 bits is the smallest message `commitTo` can express at
 * all (an empty nonce), 512 bits is exactly one SHA-256 block, and 1304 bits spans
 * several, so the padding edge is covered on both sides.
 */

export interface CommitVector {
  readonly lenBits: number;
  readonly nonceHex: string;
  readonly sigma: bigint;
  readonly digest: string;
}

export const CAVP_SHA256_VIA_COMMIT: readonly CommitVector[] = [
  {
    /* CAVS Len = 64 bits = 8 bytes: a 0-byte nonce and the 8-byte sigma. */
    lenBits: 64,
    nonceHex:
      '',
    sigma: 6284994461230746806n,
    digest: '963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf',
  },
  {
    /* CAVS Len = 128 bits = 16 bytes: a 8-byte nonce and the 8-byte sigma. */
    lenBits: 128,
    nonceHex:
      '0a27847cdc98bd6f',
    sigma: 7071226478592882219n,
    digest: '80c25ec1600587e7f28b18b1b18e3cdc89928e39cab3bc25e4d4a4c139bcedc4',
  },
  {
    /* CAVS Len = 512 bits = 64 bytes: a 56-byte nonce and the 8-byte sigma. */
    lenBits: 512,
    nonceHex:
      '5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8' +
      'a650547208251f6d4237e661c7bf4c77f335390394c37fa1',
    sigma: 12248030133251900681n,
    digest: '42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa',
  },
  {
    /* CAVS Len = 1304 bits = 163 bytes: a 155-byte nonce and the 8-byte sigma. */
    lenBits: 1304,
    nonceHex:
      '451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae08' +
      '6b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b8' +
      '5c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56' +
      'c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac' +
      '4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f',
    sigma: 9775674957484100588n,
    digest: '3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2',
  },
];
