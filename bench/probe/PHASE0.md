# Phase 0 — eligibility probe: first results

**Date:** 2026-08-09
**Tool:** `equiv-probe` (this repo)
**Question:** what fraction of real Rust public API is admissible to sound differential analysis?

Raw output: `run-14-crates.json`, `run-13-crates-no-itertools.json`.

---

## Why this ran before any verifier was built

`cargo-vouch` — a tool that auto-generates Kani proof harnesses for Rust functions — published its own validation against two randomly chosen crates.io crates and reported **6/6 INCONCLUSIVE**. Separately, *Teralizer* (arXiv 2512.14475) completed its pipeline on **1.7% of 632 real Java projects**.

Both are *eligibility* failures, not verifier failures. Eligibility is measurable with a static gate and no solver, in days rather than months. That is what this is.

---

## Result

| Sample | Functions | Fuzz-admissible (find a witness) | Prove-admissible (Tier A) |
|---|---:|---:|---:|
| 14 pure-computation crates | 368 | **20 (5.4%)** | 9 (2.4%) |
| Same, excluding `itertools` | 198 | **20 (10.1%)** | 9 (4.5%) |
| 3 CLI/tooling crates *(off-target)* | 430 | 6 (1.4%) | 5 (1.2%) |

Crates: `base64 bytecount byteorder crc32fast glob hex humantime itertools levenshtein roman semver textwrap unicode-width urlencoding`. Tooling sample: `cargo-mutants`, `bolero`, `cargo-semver-checks`.

`itertools` is reported separately because it is a genuine outlier: 41% of its public functions are generic, which is the point of the crate. Both numbers are given rather than the flattering one.

**Verdict against the `PLAN.md` §4 go/no-go (E1 ≥ 5%): PASS**, but only just on the full sample.

---

## How it got there — the gate improved three times under measurement

The first run measured **1.4%**, almost exactly Teralizer's 1.7%. Each subsequent number came from acting on what the probe's *blocking-alone* column named as the binding constraint.

| Iteration | Change | Fuzz-admissible |
|---|---|---:|
| v1 | initial predicate | 2.2% |
| v2 | resolve crate-local `struct`/`enum` types; accept `&self` receivers | 3.3% |
| v3 | support `str`; resolve `Self`; stop misattributing generic params to `unsupported_type` | **5.4%** |

Two of the v3 items were outright bugs — `str` was missing from the primitive list, and `Self` never resolved. The probe found them because it reports *which concrete types* it failed on, not just a count.

**This is the loop the probe exists to drive**, and it more than doubled the measured surface in one sitting without weakening a single soundness rule.

---

## What is binding now

`unsupported_type` remains the largest single blocker. The remaining tail is short and specific:

```
Options(17)  Error·no-PartialEq(14)  Cow(6)  Encoded(6)  Rfc3339Timestamp(6)
GeneralPurposeConfig·no-PartialEq(5)  Hasher·no-PartialEq(5)  State·no-PartialEq(5)
Version(5)  Word(4)  WrapAlgorithm(4)  BuildMetadata(3)          — 36 distinct
```

Roughly a third of that tail is **`no PartialEq`**: types that are structurally supported and generatable, but whose values cannot currently be compared. That is a *comparison* problem with a clean fix — derive a structural comparator, or compare `Debug` output — and it is the next thing to do.

After that: `Cow`, then generics (41% of functions in the `itertools`-style tail, and much harder).

---

## Honest limitations

- **Small, hand-picked sample.** 14 crates chosen for being pure-computation. The real Phase 0 target is the top 1,000 crates by downloads, sampled without preselection.
- **Syntactic analysis.** The gate cannot see through type aliases, macros, trait resolution, or into callee bodies, and rejects on every blind spot. **The reported rate is a lower bound on the true rate.**
- **Public API only** (`--all` includes private functions).
- **Nothing here has been fuzzed or proved.** This measures admissibility, not results. A function counted as fuzz-admissible has not yet been shown to yield a witness.

---

## Reproduce

```bash
cargo build --release
./target/release/equiv-probe <path-to-crate-sources>...
./target/release/equiv-probe --json <paths> > out.json   # machine-readable
./target/release/equiv-probe --all <paths>               # include private fns
```

---

## Reading

The number that directs work is not the histogram — it is **blocking-alone**: how many functions would be admitted if exactly one constraint were relaxed and nothing else changed. A function blocked by six things is not evidence against any one of them. The probe prints this column, and every gate improvement above was chosen from it.

---

## Addendum, 2026-08-09 — admissible was not the binding number

The numbers above stand as *admissibility* rates. What they did not measure is
whether an admitted function can actually be probed, and two later measurements
showed that gap was the binding one.

### 1. Every admitted function was uncallable at the path reported

The gate reported functions by name. Real crates use the facade pattern —
`mod imp;` plus `pub use imp::{…}` — so the path where a function is *written*
does not compile from outside the crate. Re-measured over a 7-crate sample with
the path resolution the gate now performs:

| | before `pub use` resolution | after |
|---|---:|---:|
| Functions callable at the reported path | **0 / 8** | **8 / 8** |

`textwrap::dedent` is written at `indentation::dedent`;
`bytecount::naive_count` at `naive::naive_count`;
`textwrap::wrap_algorithms::Penalties::new` at
`wrap_algorithms::optimal_fit::Penalties::new`. All eight resolved paths were
verified by compiling a call to each.

Current sample (101 public functions across `bytecount 0.6.8`, `hex 0.4.3`,
`levenshtein 1.0.5`, `roman 0.2.0`, `semver 1.0.23`, `textwrap 0.16.1`,
`urlencoding 2.1.3`):

| | count | rate |
|---|---:|---:|
| fuzz-admissible | 8 | 7.9% |
| …callable at the reported path | 8 | 7.9% |
| prove-admissible (Tier A) | 1 | 1.0% |

### 2. The generator could not reach the admitted functions' inputs

Admissibility says a witness *may* exist to be found. It says nothing about
whether the search finds it. Measured over 20 000 draws of the original
`arbitrary`-backed generator:

```
&str    47% empty string, mean length 1.11 characters
i32      0 draws inside roman::to's valid range 1..=3999
```

`roman::to` accepts `1..=3999`, which is 9.3e-7 of `i32`. Every "no divergence
found" this probe had produced on a string- or range-guarded function was
uninformative — the search had not reached the function's domain at all.

Replacing it with a dictionary mined from the crate under test (string and
integer literals, `±1` neighbours, quoted spans from doc examples), on a
divergence guarded by `n > 3999` — one input in 2³²:

| generator | 200 000 draws |
|---|---|
| mined dictionary | witness `n = 3999`, shrunk to 2 bytes, found in < 30 000 |
| empty dictionary | nothing |

### What this means for the go/no-go

The §4 gate (E1 ≥ 5%) still passes. But **E1 was never sufficient on its own**:
a function is only a probe target if it is admissible *and* callable *and*
reachable by the generator. A future measurement should report all three, and
the honest reading of the original 5.4% is that it was an upper bound on a
smaller usable number.
