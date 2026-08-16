# `equiv` — scope and technical plan
### The behavioral differential engine for the Rust ecosystem

**Date:** 2026-08-09
**Reads with:** [`docs/CLAIMS.md`](docs/CLAIMS.md), for what is actually implemented today.

The technique has not changed across revisions of this plan. The deployment model has. An ecosystem scan produces results before it has users; a PR checker needs users before it produces a single result. That is the change that turns a tool into infrastructure.

## Implementation status (current repository)

The shipped repository is a complete, validated local pre-alpha slice:

- `equiv-gate` performs the conservative syntactic eligibility analysis;
- `equiv-harness` generates a deterministic two-artifact probe;
- `equiv-harness::runner::decide_checked` performs find → replay, verifies the
  versioned protocol, fingerprints path-backed artifacts, and emits only
  replay-confirmed `DIVERGES` or explicit `UNKNOWN`;
- `equiv-probe` measures the gate over a caller-provided source tree.

The crates.io batch scanner, `cargo-equiv` CLI, external sandbox, Bolero/
libFuzzer integration, Kani proof engine, and public index described below are
planned work. They are not silently treated as complete. The evidence and
acceptance criteria for the shipped slice are recorded in
[`docs/CLAIMS.md`](docs/CLAIMS.md).

---

## 0. The scope decision, in one page

The instinct is to build a PR checker and hope it grows. That is the wrong shape, and I can now say why with evidence rather than taste.

**One primitive, four altitudes, launched where you need no users.**

```
        core primitive
        ──────────────
        (impl_old, impl_new, domain D, observation O)
              → EQUIVALENT | DIVERGES(witness) | UNKNOWN(reason)

        deployed at four altitudes
        ──────────────────────────
  1. FUNCTION        a changed fn in a PR              cargo equiv diff
  2. PACKAGE VERSION v1.2.3 → v1.2.4                   cargo equiv upgrade   ← LAUNCH HERE
  3. SERVICE         old build vs new build            (later; Diffy's grave)
  4. MODEL           fp16 vs quantized                 (research; not this project)
```

**Launch at altitude 2 — package version pairs — not altitude 1.** Eight reasons, each independently checkable:

1. **Zero users required (planned deployment).** crates.io exposes published versions and metadata, so an offline batch experiment can be run without an adoption funnel. Exact population size and storage cost are operational measurements, not fixed design facts, and must be recorded at scan time.
2. **The infrastructure precedent already exists and is run by the Rust project itself.** `rust-lang/crater` builds thousands of crates in Docker and diffs results across two compiler versions. Same shape. **But crater's oracle is the crate's own test suite** — and the whole premise of this project is that test suites miss ~21% of behavioral divergences. Replace the oracle with differential fuzzing and you get a strictly more sensitive instrument on infrastructure that is already known to work at ecosystem scale.
3. **The latency budget changes — and that is the lesson from the prior art.** `cargo-vouch`'s published validation exposed Kani timeouts and returned 6/6 INCONCLUSIVE on its small sample. Offline batch analysis can use a larger per-function budget than an interactive tool, while still treating timeout as `UNKNOWN`. **Deployment changes the operational trade-off; it does not remove verification difficulty.**
4. **Eligibility is measurable, not assumed.** A crate's public API is well-typed, but it is not automatically `Arbitrary`-able; the current gate and harness report separate conservative eligibility and generation limits.
5. **There is a prior API-level signal.** A 2023 study of the 1,000 most-downloaded crates reported SemVer violations in 172 crates and 464 releases; those are historical API-level findings, not a current behavioral base rate. **The behavioral rate remains an empirical question.**
6. **There is a useful neighbor.** `cargo-semver-checks` analyzes API compatibility, while this project's research question is runtime behavior. The tools should be treated as complementary; neither tool's scope is evidence that the other is easy.
7. **The output is a public good that distributes itself.** "`crate X` 1.2.3 → 1.2.4 changes behavior on input `Y`" is indexable, citable, and shareable. The findings *are* the marketing. Compare: a PR checker requires every user to install something before it produces a single result.
8. **Potential dual-use.** A behavioral difference can be relevant to correctness or supply-chain review, but intent cannot be inferred from a witness. Security use requires a separate sandbox, disclosure policy, and independent triage; those are not shipped in this repository.

**Therefore the project is not a linter. It is a behavioral index of an ecosystem, with a CLI attached.**

---

## 1. What "covers all" actually means here

The temptation is to widen by adding *features*. That kills tools. The correct way to widen is to keep one question and change **where you ask it**.

| Surface | Command | Who it serves | Ships |
|---|---|---|---|
| Ecosystem scan | `equiv scan` (batch runner) | the whole Rust community, security researchers | **Phase 1** |
| Dependency upgrade | `cargo equiv upgrade serde 1.0.219 → 1.0.220` | every Rust consumer | Phase 2 |
| Pre-publish check | `cargo equiv release` | every crate maintainer | Phase 2 |
| PR diff | `cargo equiv diff` | teams with AI-authored PRs | Phase 3 |
| Public index | `equiv.rs` / queryable DB | everyone, permanently | Phase 3 |

Same engine underneath, five surfaces. That is coverage without scope creep, because **every one of them asks the identical question**: did behavior change, and on which inputs?

### The artifact that makes it infrastructure

> **The Behavioral Change Index** — a public, queryable record of observed behavioral divergences between adjacent published versions of Rust crates, each with a replayable witness.

Think RustSec advisory DB, but for behavior instead of vulnerabilities. That is the thing that outlives the CLI, that other tools build on, that gets cited, and that no competitor can copy without redoing the compute.

---

## 2. Why the technique still works — the part v3 got right

Unchanged from v3, and load-bearing:

- **The naive design is refuted.** `cargo-vouch`'s published `REAL_WORLD_VALIDATION.md`: 6/6 INCONCLUSIVE on `roman` and `levenshtein`, every failure a data-dependent loop, `.iter().max().unwrap()` alone costing 116 s. A harness that calls `old(x)` and `new(x)` and asserts equality inherits that fate exactly.
- **The escape is relational abstraction.** Godlin & Strichman's Regression Verification (VSTTE 2005 / DAC 2009): rewrite loops as recursion, replace *matching* recursive calls on both sides with **the same uninterpreted function**, prove the bodies equivalent. *"By assuming that the program states are equal after each loop iteration, RVT avoids the need for user-specified or inferred loop invariants."* You never unroll.
- **CBMC has the primitive natively**: `__CPROVER_uninterpreted_*` — nondeterministic but consistent for identical arguments, discharged by congruence closure.
- **The finding/proving asymmetry decides the roadmap.** Concrete execution does not care about loop depth. Witnesses reach essentially all deterministic code; proofs reach a tiered subset. **Lead with witnesses.**

What v4 adds: batch deployment removes the latency constraint that made the proving tier look hopeless. Tier A proofs that time out at 30 s frequently succeed at 10 min.

---

## 3. Architecture

### 3.1 The core primitive

```rust
struct Query {
    old: Impl,            // built artifact + entry point
    new: Impl,
    domain: Domain,       // from types (Arbitrary) + declared constraints
    observe: Observation, // return value | panic | Err variant
    budget: Budget,       // interactive (30s) | batch (10min) | deep (1h)
}

enum Verdict {
    Equivalent { tier: Tier, bound: Bound },
    Diverges   { witnesses: Vec<Witness>, impact: Option<Impact> },
    Unknown    { reason: Reason },   // always specific, never apologetic
}
```

Every surface in §1 constructs a `Query` and renders a `Verdict`. Nothing else is shared, and nothing else needs to be.

### 3.2 Pipeline

```
  input (diff | version pair | traffic)
     │
  0  SLICE + ELIGIBILITY GATE ......... static, conservative, no LLM
     │                                   fail → UNKNOWN(specific reason)
  1  ALIGN ........................... mechanical path/name/signature match
     │                                   LLM breaks ties only; ambiguity → UNKNOWN
  2  BUILD BOTH ...................... two crates as deps of a generated probe crate
     │                                   (rust-semverver / cargo-semver-checks pattern)
  3  HARNESS ......................... current local generator is
     │                                   `arbitrary::Unstructured`; Bolero/Kani integration is future work
  4  FIND ............................ seeds (tests, doctests, proptest corpora)
     │                                   → libFuzzer coverage-guided on the union
     │                                   → shrink to minimal witness
  5  REPLAY .......................... execute witness on BOTH unmodified artifacts
     │                                   fails to replay → discard silently
     │                                   ⇒ zero false DIVERGES by construction
  6  PROVE (tiered, batch budget) .... same harness, --engine kani
     │                                   unwinding assertions ON, no stubs in Tier A
  7  QUANTIFY (only after DIVERGES) .. exact | Clopper-Pearson | lower bound
     │
  8  PUBLISH ......................... signed record → Behavioral Change Index
```

Stages 4–5 produce only `DIVERGES`. Only stage 6 produces `EQUIVALENT`. Invariant.

### 3.3 Proof tiers

| Tier | Technique | Reaches | Work |
|---|---|---|---|
| **A** | coupled harness, `assert_eq!(old(x), new(x))` under Kani | loop-free/loop-light arithmetic, indexing, guards | none — bolero+Kani today |
| **B** | shared-callee hoisting: call each unchanged callee once, feed both sides | functions whose complexity lives in unchanged helpers | source transform |
| **C** | RVT loop coupling: loops → recursion, matching calls → same UF | `roman::to`, `levenshtein`, real parsers | **the research contribution** |

### 3.4 The uninterpreted-function gap — unchanged and honest

Kani does not expose CBMC's UFs. `#[kani::stub]` is a MIR swap, and a stub returning `kani::any()` gives a **fresh** value per call — breaking equivalence with spurious counterexamples. Three routes: **hoisting** (v0, no toolchain change) → **bounded memo stub** → **reach CBMC directly** (highest reach, deepest yak-shave; not before Tier A ships).

---

## 4. Phases

### Phase 0 — days 1–3: the eligibility probe *(no verifier, no LLM, no solver)*

Build only the static gate. The future batch worker should run it over
**crates.io version pairs**, not repo history. The current command accepts a
caller-provided local source tree; it does not implement registry discovery.

The future batch CLI is specified as:

```text
equiv-probe --top 1000 --pairs adjacent --out probe.json   # not shipped yet
```

The current local command is:

```text
cargo run -p equiv-probe -- path/to/crate/src
```

| Metric | Meaning | Go |
|---|---|---|
| **E1** | % of public API fns passing the gate | ≥ 5% |
| **E2** | % of adjacent version pairs with ≥1 eligible changed fn | ≥ 20% |
| **E3** | median eligible fns per crate | ≥ 3 |

**E1 < 5% → stop and redesign the gate.** This is the cargo-vouch failure mode; `cargo-vouch` already showed how badly it can go.

*Ship `equiv-gate` standalone regardless of outcome.* "What fraction of this codebase admits sound differential analysis" is useful alone and is a free paper (§6).

### Phase 1 — days 4–30: the scan, and the first public findings

Future Phase 1 build: two-version builder → alignment → Bolero/libFuzzer
harness codegen → differential fuzz → shrink → **replay**. The shipped local
slice already covers generated probing, shrinking, and replay, but not the
batch worker or coverage-guided engine. **No `EQUIVALENT` claim ships in this
phase.**

The future target is the top 1,000 crates × adjacent version pairs in a
Docker-isolated, crater-style worker. The current implementation accepts a
caller-provided local source tree and does not perform this batch scan.

| Day-30 gate | Threshold |
|---|---|
| Version pairs successfully built (both sides) | ≥ 60% |
| Eligible fns auto-harnessed | ≥ 80% |
| Witnesses replaying on both unmodified artifacts | **100%** |
| **Confirmed behavioral divergences in non-major releases** | **≥ 10** |
| False `DIVERGES` | **0** |

**Deliverable: a findings page.** Ten real, replayable, previously-unknown behavioral changes in published patch/minor releases of crates people depend on. That is the launch. Nobody needs to install anything to find it valuable.

### Phase 2 — days 31–60: the CLI surfaces + Tier A proofs

- `cargo equiv upgrade` — check a dependency bump *before* taking it
- `cargo equiv release` — maintainer pre-publish check
- Tier A `EQUIVALENT` via Kani at batch budget. Unwinding assertions always on, no stubs, full discharge-obligation table enforced by `ProofLedger`, red-team corpus in CI.
- Report the three-bucket distribution as the headline maturity metric.

**Acceptable false-`EQUIVALENT` count: zero, permanently.**

### Phase 3 — days 61–120: the index, Tier B/C, the benchmark

- Public queryable Behavioral Change Index
- `cargo equiv diff` (PR mode) — now that the engine is proven
- Tier B hoisting; Tier C loop coupling prototype ← the paper
- Quantification: exact (Ganak/ApproxMC), estimate (Clopper–Pearson), lower bound
- **Publish the benchmark**: silent semantic regressions in real published releases. EqBench is C/Java at ~16 LOC; SWE-Refactor grades generators; EquiBench grades LLM reasoning. Nothing grades a *verifier* on real ecosystem diffs.

---

## 5. Repository layout

```
equiv/
├── crates/
│   ├── equiv-core/        # Query/Verdict primitive — everything else is a surface
│   ├── equiv-gate/        # eligibility predicate    ← Phase 0, ships standalone
│   ├── equiv-align/       # old↔new correspondence (mechanical; LLM tie-break only)
│   ├── equiv-build/       # two-version probe crate; worktrees & crates.io tarballs
│   ├── equiv-harness/     # current generator/runner; Bolero is future work
│   ├── equiv-run/         # fuzz driver, shrink, replay sandbox
│   ├── equiv-prove/       # Kani engine, tiers A/B/C
│   ├── equiv-quant/       # measure, model counting, confidence intervals
│   ├── equiv-scan/        # crater-style ecosystem batch runner
│   └── cargo-equiv/       # CLI: upgrade | release | diff
├── index/                 # Behavioral Change Index — schema, records, site
├── bench/                 # probe corpus, silent-regression benchmark
├── redteam/               # must-never-prove-equivalent corpus
└── docs/
```

---

## 6. Research output

1. **Eligibility characterization of the Rust ecosystem** — what fraction of public API admits sound differential analysis. *Never measured.* Phase 0 produces it. → MSR / ISSTA
2. **An empirical study of behavioral semver violations** — how often do non-major releases actually change behavior, with witnesses? The API-level rate is known (~1 in 31 releases); **the behavioral rate is unknown.** Phase 1 produces it. → ICSE / FSE
3. **Relational abstraction beats functional verification on real code** — head-to-head against cargo-vouch's `roman`/`levenshtein` 6/6 INCONCLUSIVE. If `equiv` returns verdicts there, that one table is the paper. → CAV / NFM tool track
4. **LLM artifacts under strict discharge obligations** — direct comparison against *Partial Contracts Suffice* (102–106/272 on ~16 LOC C). → ICSE / FSE
5. **Differential semantics as a supply-chain signal** — can behavioral divergence detect malicious releases that pattern-matching misses? → USENIX Security / NDSS
6. **The silent-regression benchmark.** → MSR data showcase

Items 1, 2 and 6 need **no novel technique** and *are* the de-risking. Do them regardless.

---

## 7. Risk register

| Risk | Sev | Prob | Mitigation |
|---|---|---|---|
| Eligibility rate ~2% | Fatal | Med | Phase 0, 3 days. cargo-vouch is the warning shot. |
| **Bulk-building crates is hard** (build scripts, feature matrices, sys deps, platform) | High | **High** | **New top-3 risk under v4.** Gate rejects `build.rs`/`links=`/`*-sys` anyway. Reuse crater's Docker approach. Report build-success rate as a first-class metric; 60% is a pass. |
| `EQUIVALENT` reach collapses to loop-free only | High | Med | Batch budget removes the timeout cause; witnesses ship first; tiers B/C |
| False `EQUIVALENT` ships | Fatal to credibility | Low | Discharge obligations; no stubs in Tier A; unwinding assertions on; red-team CI |
| Kani has no true UF | Med | **Confirmed** | Hoisting → memo stub → CBMC direct |
| Two crate versions in one dep graph collide | Med | Med | Gate rejects `#[no_mangle]`, `links=`, `static mut`, ctors |
| **Publishing "your crate broke behavior" causes blowback** | High | **Med-high** | **See §8. Non-negotiable policy, written before the first finding is published.** |
| `UNKNOWN` dominates | Med | High | Witnesses first; specific reasons; publish the honest distribution like cargo-vouch did |
| Scope creep into "AI code review" | High | High | One-question rule in `CONTRIBUTING.md` day one |
| Someone ships first | Low | Low | GitHub returns *zero* for Rust equivalence verification; SymDiff's repo is gone; Diffy is archived; diffsense is heuristics |

---

## 8. Disclosure policy — write this before the first finding

Phase 1 publishes claims about other people's published code. That is a social act, and getting it wrong ends the project faster than any technical failure.

**Non-negotiable rules:**

1. **Every published finding carries a replayable witness.** No finding ships on a heuristic, ever.
2. **Maintainer first.** Private notification with the witness, minimum 30 days before public listing.
3. **Neutral language.** "Behavior differs on input X" — never "bug", "broken", "violation". Behavior changes are often deliberate; the tool cannot know intent and must not imply it.
4. **Suspected-malicious findings never go public first.** They go to the maintainer, the crates.io team, and RustSec. The supply-chain angle is exactly where irresponsible publication does real damage.
5. **Correction path.** A visible, fast way for maintainers to mark a finding intended-behavior, with the record kept rather than deleted.
6. **The index states its own limits on every page**: bounded domain, stated measure, `UNKNOWN` counted honestly.

---

## 9. Prerequisites

The current development environment has Rust 1.97.1 and Cargo 1.97.1. The
future Kani/CBMC and ecosystem-worker prerequisites below are separate from
the shipped local slice.

```bash
rustc --version
cargo --version
cargo install cargo-mutants cargo-bolero              # optional roadmap tools
cargo install --locked kani-verifier && cargo kani setup   # future Phase 2
```

**Verify `cargo kani setup` actually runs on this Mac early** — Phase 2 depends on it entirely, and Kani pulls a CBMC toolchain with platform constraints. Crater itself is Linux-only; the Phase 1 scanner will likely want a Linux box or Docker.

---

## 10. Reading list — priority order

**Before writing code:**
1. `ss1738/cargo-vouch` — source, then `REAL_WORLD_VALIDATION.md`. Your negative specification.
2. Godlin & Strichman, *Regression Verification* (VSTTE 2005 / DAC 2009). **The core idea.**
3. `camshaft/bolero` — `bolero-generator`, `bolero-kani`. Do not rewrite this.
4. `rust-lang/crater` — README + Rust Forge triage guide. Your Phase 1 infrastructure pattern.
5. `obi1kenobi/cargo-semver-checks` + predr.ag "Four challenges" — your neighbor, its gap, its UX conventions.

**Then:**
- *Partial Contracts Suffice* — arXiv 2607.10291 (nearest live competitor)
- Dristi & Dwyer — arXiv 2602.15761 (19–35% non-equivalent; 21% escape tests)
- *Kani: A Model Checker for Rust* — arXiv 2607.01504, plus the Kani book on stubbing/unwinding
- Lahiri et al., *SymDiff* (CAV 2012) — why sitting above the source killed it
- Testora (ICSE 2026) — previous version as oracle
- ARDiff (FSE 2020) — the 86% / 53–55% asymmetry justifying the cascade
- *Breaking Bad? Semantic Versioning in Maven Central* — arXiv 2110.07889
- *Breaking Changes in Software Ecosystems: A Systematic Literature Review* — arXiv 2605.24397
- `twitter-archive/diffy` — the altitude-3 grave

**Reuse, don't rebuild:** `bolero`, `cargo-mutants`, `arbitrary`, `crates-index`, crater's Docker pattern, Ganak/ApproxMC.

---

## 11. Bottom line

The technique did not change. The **deployment model** did, and that is what makes it big.

- A PR checker needs users before it produces one result. **An ecosystem scan produces results before it has users.**
- The timeout problem that killed `cargo-vouch` is an *interactivity* problem. Batch deployment dissolves it without a single algorithmic improvement.
- `crater` already proved this infrastructure runs at ecosystem scale — with a weaker oracle. Swapping the test suite for differential fuzzing is the whole upgrade.
- `cargo-semver-checks` covers the API axis. **The behavioral axis is open, adjacent, and wanted.**
- A historical top-1,000-crate study reported API-level SemVer violations in
  464 releases. **Nobody knows the behavioral rate.** Phase 1 is intended to
  measure it, subject to the implemented eligibility, build, and sandbox
  limits.

Still true: build the eligibility gate first, in three days, with no verifier. Everything downstream is worthless if real code isn't analyzable — and one repo already showed exactly how that ends.

> **`git diff` shows what text changed. `cargo update` shows what version changed.**
> **Neither tells you what *behavior* changed. That's the gap.**
