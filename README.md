# SPDZ Forge

**Malicious-secure arithmetic MPC · Beaver triples · MACs**

Three parties multiply secret-shared numbers they cannot see, and when one of them lies about their share, the arithmetic itself catches it.

## What It Is

An interactive, browser-only demo of **SPDZ** (Damgård–Pastro–Smart–Zakarias, 2012): additive secret sharing over the prime field **F_p with p = 2⁶¹ − 1** (the Mersenne field real frameworks like MP-SPDZ use), **Beaver multiplication triples** with a strict offline/online split, and **information-theoretic MACs** — every share carries a share of α·x under a global MAC key α that no party holds.

The problem it teaches: Shamir- and Yao-style MPC assumes the parties follow the protocol (**semi-honest** security). SPDZ doesn't. In the **malicious** model, even with a **dishonest majority** (all but one party corrupted), a party who submits a wrong share produces a MAC that doesn't check — and the honest parties **abort** rather than accept a wrong answer. Semi-honest MPC computes correctly if everyone behaves. Malicious-secure MPC tells you when they didn't.

All arithmetic on the page is genuine field arithmetic in BigInt, with shares drawn from the platform CSPRNG. **This is a teaching demo, not production crypto**: the three "parties" run in one browser tab, and triples/shares come from a trusted dealer (see *What's real vs modeled* below).

## Exhibits

1. **Addition is free** — shares of x plus shares of y are shares of x + y, computed locally with zero communication. Establishes the baseline multiplication then breaks.
2. **The Beaver triple** (headline #1) — a stepped animation of one real multiplication: fetch a preprocessed (a, b, c = a·b), open d = x − a and e = y − b **as authenticated (MAC-checked) openings**, combine locally via c + d·b + e·a + d·e. **Break it yourself, twice:** (a) reuse the spent triple for a second multiplication and watch the public wire leak x − x′ (with a fresh triple, the same difference is one-time-pad noise); (b) lie during the d opening and see why opening authentication is load-bearing — parties who skip it compute z′ = xy + δy carrying a *perfectly valid MAC*, while SPDZ aborts at the opening itself.
3. **The MAC check** (headline #2) — you play the malicious party P₁: edit your share, then open the *same tampered shares* in both protocols side by side. Semi-honest: the wrong answer is **accepted** and rendered as **ALARM**. SPDZ: the MAC check fails, the parties **abort**, and the abort is rendered as the system *working*. An advanced break-it attacks the check itself: send your check share σ *last* and cancel the sum — it works against an unordered check (the 1/p bound is simply false there) and dies against the commit-then-open transcript (real SHA-256 commitments over random nonces). Cryptographic result and security verdict are separate indicators throughout.
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

**Real:** all field arithmetic (BigInt over p = 2⁶¹ − 1, uniform rejection sampling from `crypto.getRandomValues`); additive sharing; MAC shares and the check σᵢ = γ(y)ᵢ − αᵢ·y, Σσᵢ = 0; Beaver's identity; **authenticated openings for every opened value, including the intermediate d and e** (a lie in an opening produces an authenticated wrong product, so a final check alone cannot catch it — there is a regression test proving this); the commit-then-open ordering of the check-share exchange (real SHA-256 over random nonces); the triple-reuse leak; the σ-last-sender cancellation; the abort logic. The tampering interactions run against the real verifier — no outcome is scripted.

**Modeled (stated in-page):** triples and shares come from a **trusted dealer** — the SHE/MASCOT offline phase is not built; opened values are checked individually rather than batched by random linear combination (the paper draws batch coefficients after the opened values are fixed); all parties share one tab, so the commitment round models *message ordering*, not a real network, and network adversaries (scheduling, replay) are out of scope.

**What it does NOT prove:** SPDZ **detects that** someone cheated — it does not compute the correct answer despite cheating, and it does not identify **who** cheated (that stronger property, *identifiable abort*, is a different protocol and is not built here). A cheater whose messages are fixed before reveals passes the MAC check with probability exactly 1/p ≈ 4.3×10⁻¹⁹ — overwhelming, not absolute; without that ordering the bound does not hold at all, which the lab demonstrates rather than hides.

### Threat-model matrix

| Property | This lab | Full SPDZ-family deployment |
| --- | --- | --- |
| Field / share / MAC algebra | Implemented (BigInt, CSPRNG) | Implemented |
| Corruption threshold | The SPDZ theorem allows up to n−1 corruptions; this page executes one designated cheater at a time | Up to n−1, per family variant and setup |
| Input protocol | Trusted dealer shares inputs | Authenticated input procedure |
| Triple generation | Trusted dealer | SHE- or OT-based preprocessing with sacrifice checks |
| Opening authentication | Implemented for every opening, incl. d and e | Required |
| MAC-check ordering | Commit-then-open (SHA-256); single tab models the network order | Network protocol with commitments |
| Batched checking | Single-value checks (pedagogical case) | Random linear combination, amortized |
| Network, scheduling, replay | Not modeled (one browser tab) | Required |
| Fairness / guaranteed output | Not provided — abort only | Generally abort, not guaranteed output |
| Identifiable abort | Not provided (named, not built) | Separate stronger variants |

## What Can Go Wrong

- **Triple reuse** — the "d leaks nothing" argument requires a to be uniform *and single-use*; the break-it panel shows the wire leaking x − x′ the moment that's violated.
- **Skipping the MAC check** — the semi-honest column is exactly SPDZ without it: a single bad share silently corrupts the output for everyone.
- **Trusting the dealer** — in this demo the dealer is honest by fiat; a malicious dealer could deal c ≠ a·b or leak α. Real SPDZ replaces the dealer with heavy cryptography (SHE + ZK proofs, or OT à la MASCOT).

## Real-World Usage

SPDZ-family protocols are implemented in research and production-grade frameworks — [MP-SPDZ](https://github.com/data61/MP-SPDZ) (whose Mersenne61 backend uses this exact field) and [SCALE-MAMBA](https://github.com/KULeuven-COSIC/SCALE-MAMBA) implement them directly — and the offline/online architecture (bank expensive input-independent material, keep the input-dependent phase cheap) is the standard shape of maliciously secure arithmetic MPC in settings where participants are competitors and semi-honest trust is not on the table. No throughput numbers are quoted here on purpose: performance claims are meaningless without hardware, network, security parameters, party count, and preprocessing backend, so consult the papers below for benchmarks in context.

## References

- Damgård, Pastro, Smart, Zakarias — [Multiparty Computation from Somewhat Homomorphic Encryption](https://eprint.iacr.org/2011/535) (CRYPTO 2012). The SPDZ protocol: information-theoretic MACs, offline/online split, active security with up to n−1 corruptions.
- Beaver — [Efficient Multiparty Protocols Using Circuit Randomization](https://link.springer.com/chapter/10.1007/3-540-46766-1_34) (CRYPTO 1991). The multiplication triple.
- Keller, Orsini, Scholl — [MASCOT](https://eprint.iacr.org/2016/505) (CCS 2016). OT-based triple generation (named in-page, not built).
- Keller, Pastro, Rotaru — [Overdrive](https://eprint.iacr.org/2017/1230) (EUROCRYPT 2018). Faster SHE-based preprocessing (named in-page, not built).
- [MP-SPDZ](https://github.com/data61/MP-SPDZ) — corroborating implementation: its `MAC_Check` performs the commit-then-open, batched check this lab teaches the single-value case of.

Original SPDZ (2012) is distinguished throughout from later SPDZ-family work — MASCOT and Overdrive are separate constructions, named where relevant and explicitly out of scope.

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

- **55 Vitest unit tests** across 6 files (`src/spdz/*.test.ts`), covering field arithmetic, share/open round trips, MAC accept/reject for every party and delta, Beaver correctness on typical/boundary/randomized operands, single-use enforcement, the triple-reuse leak, the semi-honest vulnerable path *exhibiting* the flaw, and the variance circuit incl. fail-closed edge cases — plus the adversarial message boundaries: tampered d and e openings abort; a regression test proves a final-only check would miss the opening attack (z′ = xy + δy verifies); the σ-last-sender cancellation succeeds against the unordered check and fails against commit-then-open; equivocation after commitment is caught; commitments are binding on value and nonce.
- **16 known-answer assertions** in `src/spdz/kats.test.ts`. SPDZ is a paper, not an RFC — it publishes no test vectors — so the KATs are (a) closed-form Mersenne-61 field identities derived independently on paper, and (b) fixed-randomness protocol vectors with every share, MAC, and transcript value hand-computed from the SPDZ equations and pinned as literals.
- **8 functional browser tests** (`e2e/behavior.spec.ts`) assert the real arithmetic, abort semantics, the no-attribution rule for aborts, triple-bank accounting, and fail-closed behavior against the production build.
- **Accessibility gate:** `@axe-core/playwright` scans the production build in **both themes**, scanning the ALARM/ABORT variants *while they are rendered* and then the accepted variants that replace them; zero WCAG 2.1 A/AA violations required. Pull requests run the same gate (`ci.yml`); the GitHub Pages deploy is blocked if unit tests, the typechecked build, or the browser gate fail.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
