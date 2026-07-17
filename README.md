# SPDZ Forge

**Malicious-secure arithmetic MPC · Beaver triples · MACs**

Three parties multiply secret-shared numbers they cannot see, and when one of them lies about their share, the arithmetic itself catches it.

## What It Is

An interactive, browser-only demo of **SPDZ** (Damgård–Pastro–Smart–Zakarias, 2012): additive secret sharing over the prime field **F_p with p = 2⁶¹ − 1** (the Mersenne field real frameworks like MP-SPDZ use), **Beaver multiplication triples** with a strict offline/online split, and **information-theoretic MACs** — every share carries a share of α·x under a global MAC key α that no party holds.

The problem it teaches: Shamir- and Yao-style MPC assumes the parties follow the protocol (**semi-honest** security). SPDZ doesn't. In the **malicious** model, even with a **dishonest majority** (all but one party corrupted), a party who submits a wrong share produces a MAC that doesn't check — and the honest parties **abort** rather than accept a wrong answer. Semi-honest MPC computes correctly if everyone behaves. Malicious-secure MPC tells you when they didn't.

All arithmetic on the page is genuine field arithmetic in BigInt, with shares drawn from the platform CSPRNG. **This is a teaching demo, not production crypto**: the three "parties" run in one browser tab, and triples/shares come from a trusted dealer (see *What's real vs modeled* below).

## Exhibits

1. **Addition is free** — shares of x plus shares of y are shares of x + y, computed locally with zero communication. Establishes the baseline multiplication then breaks.
2. **The Beaver triple** (headline #1) — a stepped animation of one real multiplication: fetch a preprocessed (a, b, c = a·b), publicly reveal d = x − a and e = y − b, combine locally via c + d·b + e·a + d·e. **Break it yourself:** reuse the spent triple for a second multiplication and watch the public wire leak x − x′ (with a fresh triple, the same difference is one-time-pad noise).
3. **The MAC check** (headline #2) — you play the malicious party P₁: edit your share, then open the *same tampered shares* in both protocols side by side. Semi-honest: the wrong answer is **accepted** and rendered as **ALARM**. SPDZ: the MAC check fails, the parties **abort**, and the abort is rendered as the system *working*. Cryptographic result and security verdict are separate indicators throughout.
4. **Offline vs online** — a live triple bank that every multiplication on the page genuinely drains, with preprocessing to refill it. The two-phase split is why SPDZ is deployable.
5. **Three hospitals compute a variance** — a real MPC computation that needs multiplication (Σv²), which addition-only MPC like the sibling [silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) cannot do. Opens only the aggregate M = n·Σv² − (Σv)² under a MAC check; a lying hospital triggers an abort.

## When to Use It

- To see why "the parties follow the protocol" is a real assumption with a real price, and what removing it costs.
- To understand Beaver triples: why multiplication needs preprocessing, why the openings d and e are safe, and why a triple is single-use.
- To learn what "abort" does and does not give you.
- **Do NOT use it** to run actual multi-party computations: there is one browser tab, one memory space, and a trusted dealer. Nothing here protects real secrets.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-spdz-forge/>**

Share and add secrets, step through a Beaver multiplication, reuse a triple to cause a genuine leak, tamper with your own share and watch semi-honest MPC swallow the lie while SPDZ aborts, drain and refill the triple bank, and run a three-hospital variance.

## What's Real vs Modeled

**Real:** all field arithmetic (BigInt over p = 2⁶¹ − 1, uniform rejection sampling from `crypto.getRandomValues`); additive sharing; MAC shares and the check σᵢ = γ(y)ᵢ − αᵢ·y, Σσᵢ = 0; Beaver's identity and the openings d, e; the triple-reuse leak; the abort logic. The tampering interactions run against the real verifier — no outcome is scripted.

**Modeled (stated in-page):** triples and shares come from a **trusted dealer** — the SHE/MASCOT offline phase is not built; the MAC-check commitment round is collapsed (σᵢ summed directly); opened values are checked individually rather than batched by random linear combination; all parties share one tab, so network adversaries are out of scope.

**What it does NOT prove:** SPDZ **detects that** someone cheated — it does not compute the correct answer despite cheating, and it does not identify **who** cheated (that stronger property, *identifiable abort*, is a different protocol and is not built here). A cheater passes the MAC check with probability exactly 1/p ≈ 4.3×10⁻¹⁹ — overwhelming, not absolute.

## What Can Go Wrong

- **Triple reuse** — the "d leaks nothing" argument requires a to be uniform *and single-use*; the break-it panel shows the wire leaking x − x′ the moment that's violated.
- **Skipping the MAC check** — the semi-honest column is exactly SPDZ without it: a single bad share silently corrupts the output for everyone.
- **Trusting the dealer** — in this demo the dealer is honest by fiat; a malicious dealer could deal c ≠ a·b or leak α. Real SPDZ replaces the dealer with heavy cryptography (SHE + ZK proofs, or OT à la MASCOT).

## Real-World Usage

SPDZ-family protocols power deployed and research MPC systems: MP-SPDZ and SCALE-MAMBA implement it directly; the offline/online architecture (bank expensive input-independent material, keep the input-dependent phase cheap) shows up across private machine learning, private set intersection deployments, and financial benchmarking consortia — settings where participants are competitors and semi-honest trust is not on the table.

## How to Run Locally

```bash
npm ci
npm run dev        # Vite dev server
npm test           # Vitest unit tests + KATs
npm run build      # typecheck + production build
npm run test:a11y  # axe-core WCAG 2.1 AA gate, both themes (preview on port 4352)
```

## Related Demos

- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — the semi-honest, addition-only predecessor.
- [crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/) — polynomial secret sharing, honest majority.
- [crypto-lab-garbled-gate](https://systemslibrarian.github.io/crypto-lab-garbled-gate/) — Yao's two-party boolean circuits.
- [crypto-lab-ot-gate](https://systemslibrarian.github.io/crypto-lab-ot-gate/) — oblivious transfer.

## Build & Verify

- **43 Vitest unit tests** across 5 files (`src/spdz/*.test.ts`), covering field arithmetic, share/open round trips, MAC accept/reject for every party and delta, Beaver correctness on typical/boundary/randomized operands, single-use enforcement, the triple-reuse leak, the semi-honest vulnerable path *exhibiting* the flaw, and the variance circuit incl. fail-closed edge cases.
- **16 known-answer assertions** in `src/spdz/kats.test.ts`. SPDZ is a paper, not an RFC — it publishes no test vectors — so the KATs are (a) closed-form Mersenne-61 field identities derived independently on paper, and (b) fixed-randomness protocol vectors with every share, MAC, and transcript value hand-computed from the SPDZ equations and pinned as literals.
- **Accessibility gate:** `@axe-core/playwright` scans the production build in **both themes** after driving every panel through its interaction states; zero WCAG 2.1 A/AA violations required. The GitHub Pages deploy is blocked if unit tests, the typechecked build, or the a11y gate fail.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
