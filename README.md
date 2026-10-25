# SPDZ Forge

**Malicious-secure arithmetic MPC · Beaver triples · MACs**

Three parties multiply secret-shared numbers they cannot see, and when one of them lies about their share, the arithmetic itself catches it. A bounded research extension also shows why that correctness check can become a privacy oracle if an implementation mixes values authenticated under different reconstructed MAC keys.

## What It Is

An interactive, browser-only demo of **SPDZ** (Damgård–Pastro–Smart–Zakarias, 2012): additive secret sharing over the prime field **F_p with p = 2⁶¹ − 1** (the Mersenne field real frameworks like MP-SPDZ use), **Beaver multiplication triples** with a strict offline/online split, and **information-theoretic MACs** — every share carries a share of α·x under a global MAC key α that no party holds.

The problem it teaches: Shamir- and Yao-style MPC assumes the parties follow the protocol (**semi-honest** security). SPDZ doesn't. In the **malicious** model, even with a **dishonest majority** (all but one party corrupted), a party who submits a wrong share produces a MAC that doesn't check — and the honest parties **abort** rather than accept a wrong answer. Semi-honest MPC computes correctly if everyone behaves. Malicious-secure MPC tells you when they didn't.

All arithmetic on the page is genuine field arithmetic in BigInt, with shares drawn from the platform CSPRNG. **This is a teaching demo, not production crypto**: the three "parties" run in one browser tab, and triples/shares come from a trusted dealer (see *What's real vs modeled* below).

## Exhibits

1. **Addition is free** — shares of x plus shares of y are shares of x + y, computed locally with zero communication. Establishes the baseline multiplication then breaks.
2. **The Beaver triple** (headline #1) — a stepped animation of one real multiplication: fetch a preprocessed (a, b, c = a·b), open d = x − a and e = y − b **as authenticated (MAC-checked) openings**, combine locally via c + d·b + e·a + d·e. **Break it yourself, twice:** (a) reuse the spent triple for a second multiplication and watch the public wire leak x − x′ (with a fresh triple, the same difference is one-time-pad noise); (b) lie during the d opening and see why opening authentication is load-bearing — parties who skip it compute z′ = xy + δy carrying a *perfectly valid MAC*, while SPDZ aborts at the opening itself.
3. **The MAC check** (headline #2) — you play the malicious party P₁: edit your shares, then open the *same tampered shares* in both protocols side by side. Semi-honest: the wrong answer is **accepted** and rendered as **ALARM**. SPDZ: the MAC check fails, the parties **abort**, and the abort is rendered as the system *working*. **Both** shares are editable — the value share *and* the MAC share γ(x)₁ — because the abort message names the winning move ("shift your MAC share by α·Δ") and the panel prints α in the clear. Set the MAC shift to α·Δ and Σσᵢ lands on exactly zero: a forged value carrying a valid MAC, accepted in silence. That is the guarantee stated precisely rather than broken — the check is worth exactly as much as α is secret, and you can only compute α·Δ here because this tab plays the dealer. An advanced break-it attacks the check itself: send your check share σ *last* and cancel the sum — it works against an unordered check (the 1/p bound is simply false there) and dies against the commit-then-open transcript (real SHA-256 commitments over random nonces). Cryptographic result and security verdict are separate indicators throughout.
4. **Off-Key: when abort leaks a secret** — a bounded three-party trusted-dealer adaptation of Keller, Navot and Tyagi's attack. The same request runs against (a) a key-bound α context, where the check residue is Δ(g−d) and d is already public, and (b) an inconsistent context with the input under α and multiplication mask/check under β=α+Δ, where the residue becomes Δ(g−y). The original unmasked check recovers y; a fresh-nonzero-μ masked check reveals only whether y=g, which identifies y in the explicitly promised one-bit fixture. A private affine output, an ordinary wrong-share control, and a same-context repair keep privacy leakage distinct from correctness detection.
5. **Offline vs online** — a live triple bank that every multiplication on the page genuinely drains, with preprocessing to refill it. The two-phase split is why SPDZ is deployable.
6. **Three hospitals compute a variance** — a real MPC computation that needs multiplication (Σv²), which addition-only MPC like the sibling [silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) cannot do. Opens only the aggregate M = n·Σv² − (Σv)² under a MAC check; a lying hospital triggers an abort.

## When to Use It

- To see why "the parties follow the protocol" is a real assumption with a real price, and what removing it costs.
- To understand Beaver triples: why multiplication needs preprocessing, why the openings d and e are safe, and why a triple is single-use.
- To learn what "abort" does and does not give you.
- **Do NOT use it** to run actual multi-party computations: there is one browser tab, one memory space, and a trusted dealer. Nothing here protects real secrets.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-spdz-forge/>**

Share and add secrets, step through a Beaver multiplication, reuse a triple to cause a genuine leak, tamper with your own share and watch semi-honest MPC swallow the lie while SPDZ aborts, compare bound and inconsistent MAC-key contexts, drain and refill the triple bank, and run a three-hospital variance.

## What's Real vs Modeled

**Real:** all field arithmetic (BigInt over p = 2⁶¹ − 1, uniform rejection sampling from `crypto.getRandomValues`); additive sharing; MAC shares and the check σᵢ = γ(y)ᵢ − αᵢ·y, Σσᵢ = 0; Beaver's identity; **authenticated openings for every opened value, including the intermediate d and e** (a lie in an opening produces an authenticated wrong product, so a final check alone cannot catch it — there is a regression test proving this); the commit-then-open ordering of the check-share exchange (real SHA-256 over random nonces); the triple-reuse leak; the σ-last-sender cancellation; the Off-Key residuals derived from actual authenticated shares; the abort logic. The tampering interactions run against the real verifier — no outcome is scripted.

**Modeled (stated in-page):** triples and shares come from a **trusted dealer** — the SHE/MASCOT offline phase is not built; opened values are checked individually rather than batched by random linear combination (the paper draws batch coefficients after the opened values are fixed); all parties share one tab, so the commitment round models *message ordering*, not a real network, and network adversaries (scheduling, replay) are out of scope. The Off-Key extension adapts the paper's two-party attack to this lab's three-party shares and one unbatched blind opening (λ=1). It computes z=μ·residual directly and samples μ from Fₚ*; the paper samples uniformly from Fₚ, so μ=0 gives a 1/p false-zero event that this bounded exact-predicate fixture removes. It does not implement the distributed multiplication triple that hides μ, the full private-affine MPC circuit, persistence, cross-process state, or any evaluated framework.

**What it does NOT prove:** SPDZ **detects that** someone cheated — it does not compute the correct answer despite cheating, and it does not identify **who** cheated (that stronger property, *identifiable abort*, is a different protocol and is not built here). A cheater whose messages are fixed before reveals passes the MAC check with probability exactly 1/p ≈ 4.3×10⁻¹⁹ — overwhelming, not absolute; without that ordering the bound does not hold at all, which the lab demonstrates rather than hides.

### MAC-key consistency and the bounded Off-Key extension — October 25, 2026

[Keller, Navot and Tyagi, *Off-Key: Inconsistent MAC Keys Compromise Privacy in SPDZ-Family MPC*, ePrint 2026/2533](https://eprint.iacr.org/2026/2533) is a **preprint with demonstrated, attack-model-conditional results**. All shares and preprocessing used together must be authenticated under the same reconstructed global MAC key. Individual parties' additive key shares normally differ; that is not the bug. The bug is mixing material under α with material under β=α+Δ. The authors report privacy attacks against evaluated implementations that violated this requirement across batches, threads or process runs: depending on the MAC check, a corrupt party can recover a shared secret or test guesses through selective failure. This does not break SPDZ's theoretical guarantees or establish that every current version of those frameworks is vulnerable.

The main lab already uses one in-memory key (`src/ui/state.ts`) for inputs and all triple-bank refills. The research extension deliberately isolates a second context and executes the paper's core blind-opening equations over the lab's real shares. Its same-context control computes Δ(g−d); its inconsistent context computes Δ(g−y). The attacker request is built without y or honest state, while a separately labeled omniscient view independently checks the deductions. With the original unmasked check the visible residue recovers y. With the bounded masked check, a fresh non-zero μ preserves only zero/non-zero; one query tests y=g, and the explicit bit promise makes that enough to infer y. For a general field secret, one failed guess only rules out that guess.

This remains a **three-party trusted-dealer algebraic adaptation**, not a framework reproduction. It does not implement the paper's two-party preprocessing protocols, distributed masked multiplication, batching coefficients, persistent key bindings, threads, restarts, or network behavior. The same-context comparison models the restored assumption by producing the blind mask under α; it is protocol state, not a client-side validation rule. A real fix preserves and reuses the preprocessing protocol's key-binding state and discards affected state after abort, as described in §5.

**Source record:** reviewed the CL079 manuscript copy created 2026-10-17, SHA-256 `578bda70467f3d658c0011a08c419c37d0f5a987d0e580705c9770c24d5ab0f3`, specifically §§3, 3.2, 4.1–4.5, 5 and 5.1. The paper itself, rather than its abstract, supplies the residual identities, attacker observations, private affine example, and key-binding mitigation used here.

### Threat-model matrix

| Property | This lab | Full SPDZ-family deployment |
| --- | --- | --- |
| Field / share / MAC algebra | Implemented (BigInt, CSPRNG) | Implemented |
| Corruption threshold | The SPDZ theorem allows up to n−1 corruptions; this page executes one designated cheater at a time | Up to n−1, per family variant and setup |
| Input protocol | Trusted dealer shares inputs | Authenticated input procedure |
| Triple generation | Trusted dealer | SHE- or OT-based preprocessing with sacrifice checks |
| Opening authentication | Implemented for every opening, incl. d and e | Required |
| MAC-key consistency | Main path: one in-memory key. Isolated research fixture: deliberate α/β mismatch plus a same-context control | Preserve key-binding state across all values and preprocessing used together |
| MAC-check ordering | Commit-then-open (SHA-256); single tab models the network order | Network protocol with commitments |
| Batched checking | Single-value checks (pedagogical case) | Random linear combination, amortized |
| Network, scheduling, replay | Not modeled (one browser tab) | Required |
| Fairness / guaranteed output | Not provided — abort only | Generally abort, not guaranteed output |
| Identifiable abort | Not provided (named, not built) | Separate stronger variants |

## What Can Go Wrong

- **Triple reuse** — the "d leaks nothing" argument requires a to be uniform *and single-use*; the break-it panel shows the wire leaking x − x′ the moment that's violated.
- **Skipping the MAC check** — the semi-honest column is exactly SPDZ without it: a single bad share silently corrupts the output for everyone.
- **Trusting the dealer** — in this demo the dealer is honest by fiat; a malicious dealer could deal c ≠ a·b or leak α. Real SPDZ replaces the dealer with heavy cryptography (SHE + ZK proofs, or OT à la MASCOT).
- **Mixing authentication contexts** — a check can still detect incorrect arithmetic while its success/failure leaks a private predicate. Preserve the preprocessing protocol's key-binding state across every batch, thread and restart whose material may be combined; plaintext key shares alone do not provide that binding.

## Real-World Usage

SPDZ-family protocols are implemented in research and production-grade frameworks — [MP-SPDZ](https://github.com/data61/MP-SPDZ) (whose Mersenne61 backend uses this exact field) and [SCALE-MAMBA](https://github.com/KULeuven-COSIC/SCALE-MAMBA) implement them directly — and the offline/online architecture (bank expensive input-independent material, keep the input-dependent phase cheap) is the standard shape of maliciously secure arithmetic MPC in settings where participants are competitors and semi-honest trust is not on the table. No throughput numbers are quoted here on purpose: performance claims are meaningless without hardware, network, security parameters, party count, and preprocessing backend, so consult the papers below for benchmarks in context.

## References

- Damgård, Pastro, Smart, Zakarias — [Multiparty Computation from Somewhat Homomorphic Encryption](https://eprint.iacr.org/2011/535) (CRYPTO 2012). The SPDZ protocol: information-theoretic MACs, offline/online split, active security with up to n−1 corruptions.
- Beaver — [Efficient Multiparty Protocols Using Circuit Randomization](https://link.springer.com/chapter/10.1007/3-540-46766-1_34) (CRYPTO 1991). The multiplication triple.
- Keller, Orsini, Scholl — [MASCOT](https://eprint.iacr.org/2016/505) (CCS 2016). OT-based triple generation (named in-page, not built).
- Keller, Pastro, Rotaru — [Overdrive](https://eprint.iacr.org/2017/1230) (EUROCRYPT 2018). Faster SHE-based preprocessing (named in-page, not built).
- [MP-SPDZ](https://github.com/data61/MP-SPDZ) — corroborating implementation: its `MAC_Check` performs the commit-then-open, batched check this lab teaches the single-value case of.
- Keller, Navot, Tyagi — [Off-Key: Inconsistent MAC Keys Compromise Privacy in SPDZ-Family MPC](https://eprint.iacr.org/2026/2533) (2026 preprint). The inconsistent-key residuals, selective-failure attack, private affine example, and key-binding mitigation adapted in the research extension.

Original SPDZ (2012) is distinguished throughout from later SPDZ-family work — MASCOT and Overdrive are separate constructions, named where relevant and explicitly out of scope.

## How to Run Locally

```bash
npm ci
npm run dev        # Vite dev server
npm test           # Vitest unit tests + KATs
npm run build      # typecheck + production build
npm run test:a11y  # behavior + dark-theme WCAG 2.1 AA gate at desktop/380px (port 4352)
npm run test:mutations # replay three focused Off-Key mutations; each owning test must fail
```

## Related Demos

- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — the semi-honest, addition-only predecessor.
- [crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/) — polynomial secret sharing, honest majority.
- [crypto-lab-garbled-gate](https://systemslibrarian.github.io/crypto-lab-garbled-gate/) — Yao's two-party boolean circuits.
- [crypto-lab-ot-gate](https://systemslibrarian.github.io/crypto-lab-ot-gate/) — oblivious transfer.

## Build & Verify

- **76 Vitest unit tests** across 8 files (`src/**/*.test.ts`), covering field arithmetic, share/open round trips, MAC accept/reject for every party and delta, the exact identity the MAC panel reports (Σσᵢ = macΔ − α·Δ, so only the precise forgery passes and a MAC-only edit still aborts), Beaver correctness on typical/boundary/randomized operands, single-use enforcement, the triple-reuse leak, the semi-honest vulnerable path *exhibiting* the flaw, the y = 0 case where the opening lie is absorbed and the product stays correct (SPDZ aborts anyway), the session-key consistency control, and the variance circuit incl. fail-closed edge cases — plus the adversarial message boundaries: tampered d and e openings abort; a regression test proves a final-only check would miss the opening attack (z′ = xy + δy verifies); the σ-last-sender cancellation succeeds against the unordered check and fails against commit-then-open; equivocation after commitment is caught; commitments are binding on value and nonce. Eleven Off-Key tests independently verify both residual formulas, same-context/non-leakage controls, unmasked recovery, masked bit inference, the private affine view, ordinary corruption, all bit/guess combinations, and fail-closed input bounds.
- **16 known-answer assertions** in `src/spdz/kats.test.ts`. SPDZ is a paper, not an RFC — it publishes no test vectors — so the KATs are (a) closed-form Mersenne-61 field identities derived independently on paper, and (b) fixed-randomness protocol vectors with every share, MAC, and transcript value hand-computed from the SPDZ equations and pinned as literals.
- **16 functional browser tests** (`e2e/behavior.spec.ts`) assert the real arithmetic, abort semantics, the no-attribution rule for aborts, triple-bank accounting, fail-closed behavior, Off-Key attacker/teaching view separation, matching and rejected selective-failure guesses, the same-context repair, and evidence retirement after editable controls change against the production build.
- **3 focused mutations** (`scripts/mutations.mjs`) remove the β-authenticated attack mask, move the repaired mask into β, or omit Δ·g from the attack request. Each named owning test must turn red, and the script restores the source byte-for-byte and reruns the clean control.
- **Accessibility gate:** `@axe-core/playwright` scans the dark-only production build at desktop and 380px widths, scanning the ALARM/ABORT variants *while they are rendered* and then the accepted variants that replace them; zero WCAG 2.1 A/AA violations required. Pull requests run the same gate (`ci.yml`); the GitHub Pages deploy is blocked if unit tests, the typechecked build, or the browser gate fail.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
