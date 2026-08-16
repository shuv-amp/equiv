# equiv

> `git diff` shows what text changed. `cargo update` shows what version changed.
> Neither tells you what **behaviour** changed.

`equiv` answers exactly one question about a pair of program versions:

**Did behaviour change, and on which inputs?**

It returns one of exactly three things — never a fourth, never a confidence score:

| | |
|---|---|
| ❌ **DIVERGES** | a concrete input, replayed against both unmodified artifacts |
| ✅ **EQUIVALENT** | proven, relative to a stated bound |
| ❓ **UNKNOWN** | and precisely why |

Point it at a source tree and it reports what fraction of the public API is
even admissible to that question, and what is blocking the rest:

```
cargo build --release
./target/release/equiv-probe crates/equiv-gate/src
```

```
  E1  fuzz-admissible (can hunt a witness)        8 / 29       27.6%
      prove-admissible (Tier A equivalence)       0 / 29        0.0%

  BLOCKS FUZZING — functions affected
  reason                   affected       %  blocking alone
  unsupported_type               16   55.2%               7
  unresolved_call                 7   24.1%               2
```

The rightmost column is the one that matters. See [below](#the-column-that-directs-the-work).

---

## Status

**Pre-alpha. The local Phase 0 gate and a replay-confirmed Phase 1 probe slice
are implemented.** The ecosystem scanner, formal verifier, and public index are
roadmap work, not shipped features; see [`docs/CLAIMS.md`](docs/CLAIMS.md).
There is still no verifier — deliberately — but generated probes can now be
executed through a typed decision boundary that returns only replay-confirmed
`DIVERGES` or explicit `UNKNOWN` outcomes.

Before building one, the project measured whether real code is even analysable. See [`bench/probe/PHASE0.md`](bench/probe/PHASE0.md): **5.4%** of public functions across 14 pure-computation crates are admissible to differential fuzzing (10.1% excluding one generics-heavy outlier). That cleared the go/no-go bar in [`PLAN.md`](PLAN.md) §4.

This mattered: [`cargo-vouch`](https://github.com/ss1738/cargo-vouch), which auto-generates Kani harnesses for Rust functions, published **6/6 INCONCLUSIVE** on two randomly chosen crates.io crates. That sample exposes an eligibility/timeout risk; it is evidence about that tool and sample, not a universal Rust rate.

### Three things measurement changed since

**Admissible is not callable.** The gate reported functions by name. Real crates
are built as a facade — `mod imp;` plus `pub use imp::*;` — so the path where a
function is *written* does not compile from outside the crate. Across `textwrap`,
`bytecount`, `semver`, `hex`, `urlencoding`, `levenshtein` and `roman`, **every**
admissible function was written inside a private module. Resolving `pub use`
chains turned 0 usable probe targets into 8 of 8.

**Uniform random input finds nothing.** Measured over 20 000 draws of the
original `arbitrary`-backed generator:

```
&str    47% empty string, mean length 1.11 characters
i32      0 draws inside roman::to's valid range 1..=3999
```

So a probe now mines a dictionary from the crate under test — string literals,
integer literals and their `±1` neighbours, and the quoted spans inside doc
examples — as AFL's `-x` and libFuzzer's `-dict=` do. On a divergence guarded by
`n > 3999`, one input in 2³²:

| generator | result |
|---|---|
| mined dictionary | witness `n = 3999` in < 30 000 draws, shrunk to 2 bytes |
| empty dictionary | nothing in 200 000 draws |

A test pins that gap, because a generator regression does not fail loudly — it
quietly finds nothing.

**Cargo will not resolve a patch pair.** Cargo unifies semver-compatible
versions, and dependency renaming aliases a package rather than duplicating it.
So `=1.0.4` alongside `=1.0.5` does not resolve at all — and patch/minor pairs
are the entire population worth scanning. Both sides must be vendored and
retagged to deliberately incompatible versions; `equiv-harness` does this, and
`Source::Version` is documented as the narrow path it actually is.

---

## Why this can work when the obvious version cannot

A harness that calls `old(x)` and `new(x)` and asserts equality inherits `cargo-vouch`'s fate exactly: both loops must unroll, and bounded model checking dies. `roman::to` iterates ~3999 times; `.iter().max().unwrap()` alone costs 116 s under Kani.

The escape is 20 years old. Godlin & Strichman's **Regression Verification**: rewrite loops as recursion, replace *matching* recursive calls on both sides with **the same uninterpreted function**, then prove the bodies equivalent. You never unroll. Equivalence is a claim about the *relationship* between two programs, and that is tractable exactly where verifying either one alone is not.

CBMC supports the primitive natively (`__CPROVER_uninterpreted_*` — nondeterministic but consistent for identical arguments). Nobody has wired it to `git diff`.

---

## The two safe-construction rules

The safe construction APIs enforce the two key invariants in normal use. The
current repository does not ship a proof engine, so it intentionally exposes
no public way to construct a `Certificate`; a future verifier must add that
trusted integration. The executor is still responsible for truthfully
recording a successful replay.

**1. No LLM output may be an axiom.**
An `EQUIVALENT` verdict requires a `Certificate`, and the only way to obtain one is `ProofLedger::seal()`, which fails while any artifact from an untrusted origin remains undischarged.

```rust,ignore
let mut ledger = ProofLedger::new(Tier::A, bound, tcb); // core-internal/future prover
let id = ledger.record_untrusted("loop unwind bound = 8", "llm:scaffold");
ledger.seal().unwrap_err();                       // blocked
ledger.discharge(id, "kani: unwinding assertion held");
let cert = ledger.seal().unwrap();                // now, and only now
```

**2. Zero false `DIVERGES`.**
`Verdict::diverges` requires at least one witness *replayed against both unmodified artifacts*. Unconfirmed witnesses are dropped silently — they may be harness artifacts.

```rust
let w = Witness::candidate("retries = -1", "3", "0");
Verdict::diverges(vec![w], None)                  // Err(NoConfirmedWitness)
```

And the rule that matters most: **"fuzzing found nothing" is `UNKNOWN`, never `EQUIVALENT`.**

---

## Crates

| crate | what it does |
|---|---|
| `equiv-core` | `Verdict`, `Witness`, `ProofLedger`, `Impact` — the primitives above, plus a self-contained Clopper–Pearson implementation |
| `equiv-gate` | the eligibility predicate: is this function admissible, and what is its callable path? |
| `equiv-harness` | mines a dictionary, generates two-version probes, runs find → shrink → replay before producing a verdict |
| `equiv-probe` | Phase 0 CLI: measure eligibility across a codebase |

```bash
cargo build --release
./target/release/equiv-probe path/to/crate/src        # eligibility summary
./target/release/equiv-probe --list path/to/crate/src # call paths to probe
```

The probe reports two admissions separately, because the reachable surface differs enormously:

- **fuzz-admissible** — can we hunt for a witness? Concrete execution ignores loop depth, so this surface is large.
- **prove-admissible** — can we prove equivalence? Bounded model checking does not, so this surface is small.

Leading with witnesses is the whole roadmap, and that split is where the decision is encoded.

`--list` prints the path a probe would have to call, which is not the same as
where the function is written:

```
fuzz     pub    dedent                              # written at indentation::dedent
fuzz     pub    naive_count                         # written at naive::naive_count
fuzz+prove pub  wrap_algorithms::Penalties::new     # written at …::optimal_fit::Penalties::new
```

Paths marked `hidden` are behind a private module or type with no `pub use`
reaching them; a probe built against one would not compile, so a scanner filters
them out. Every path above was checked by compiling a call to it.

The harness runner treats probe build failures, timeouts, malformed protocol
output, artifact mutations, and replay mismatches as `UNKNOWN`. Checked local
runs fingerprint path-backed artifacts and kill the Cargo process group on Unix
timeouts. This is process cleanup, not a security sandbox: do not execute
untrusted crates without external isolation. A successful fuzz budget never
becomes `EQUIVALENT`; only a future proof engine can create that verdict.

### The column that directs the work

Not the histogram — **blocking-alone**: how many functions would be admitted if exactly one constraint were relaxed. A function blocked by six things is not evidence against any one of them. Every gate improvement so far (1.4% → 2.2% → 3.3% → 5.4%) was chosen from that column.

---

## Never a bare percentage

`retries < 0` is ~50% of `i32` and ~2.9% of `[-3, 100]`. A proportion without a stated domain and measure is a marketing number. Every `Impact` carries its provenance:

```
DIVERGES — 3 / 65536 inputs (0.004578%), exact over D
DIVERGES — 0.7800% (95% CI: 0.6180%–0.9707%, n = 10000, 78 diverging)
DIVERGES — >= 1 input (lower bound from witnesses; domain size unknown)
```

A single witness does not license a proportion, and `Impact::point_estimate()` returns `None` for a lower bound so callers cannot obtain one by accident.

---

## Documents

- [`docs/FINDINGS.md`](docs/FINDINGS.md) — behavioural differences found between published patch releases
- [`docs/CLAIMS.md`](docs/CLAIMS.md) — what is implemented, what is not, and the evidence for each
- [`bench/probe/PHASE0.md`](bench/probe/PHASE0.md) — measured eligibility results
- [`PLAN.md`](PLAN.md) — scope, phases, go/no-go criteria, risk register

## Licence

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT licence ([`LICENSE-MIT`](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option. This covers everything in the repository, including the measured
results under `bench/`.

### Contribution

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this work, as defined in Apache-2.0, shall be dual licensed as
above, without any additional terms.

A verification tool nobody can audit is not a verification tool.
