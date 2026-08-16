# Evidence ledger

This file separates claims that are implemented and tested in this repository
from claims that belong to the research roadmap. It is intentionally dated:
tool behavior, paper results, and ecosystem measurements can change.

## Implemented claims

| Claim | Evidence |
|---|---|
| A run can return only `DIVERGES` or `UNKNOWN` in the shipped probe path. | `equiv-harness::runner::decide` requires a replay-confirmed witness; no-divergence, build failures, timeouts, malformed protocol output, and replay mismatches become `UNKNOWN`. |
| The shipped workspace has no public proof path. | `equiv-core::Certificate` has private fields and the proof-ledger constructor/seal path is crate-private until a real verifier supplies trusted evidence. |
| Path-backed checked runs bind the witness to source contents. | `decide_checked` fingerprints both source trees before the run and before replay; mutation produces `Reason::ArtifactChanged`. Symlinks are rejected because following them would weaken the identity boundary. |
| Generated probes compare one byte-derived input on both sides and observe return `Debug` output or panic. | `crates/equiv-harness/src/codegen.rs`; replay uses the exact witness bytes. This is an observation contract, not a claim of full semantic equivalence. |
| Probe output is bounded and versioned. | The runner accepts only `EQUIV_PROBE_V1`, requires the protocol version and exit code to agree, rejects unknown fields, and caps captured stdout/stderr at 1 MiB. |
| The local gate is conservative by design, but syntactic. | `equiv-gate` rejects unresolved effects, types, calls, macros, and unsupported shapes. It does not replace rustc name/type resolution. |

## Explicitly not shipped

The following are roadmap items, not current capabilities:

- an ecosystem-wide crates.io scan or public Behavioral Change Index;
- `cargo equiv` upgrade/release/diff commands;
- a Kani/CBMC proof engine or any shipped `EQUIVALENT` producer;
- Bolero/libFuzzer coverage-guided execution (the current local probe uses a
  deterministic xorshift generator and `arbitrary::Unstructured`);
- a security sandbox for arbitrary third-party build scripts and binaries;
- automatic construction of user-defined crate types. The harness currently
  supports the `GenType` subset documented in `equiv-harness::gentype`.

Because the runner invokes Cargo and the compared code can execute build
scripts, checked local runs are not a security boundary. Do not use them on
untrusted artifacts without an external OS/container sandbox. A timeout kills
the Cargo process group on Unix, but process-group cleanup is not equivalent to
resource isolation.

## External evidence used for design decisions

- [Cargo Book: renaming dependencies](https://doc.rust-lang.org/stable/cargo/reference/specifying-dependencies.html)
  documents the `package` key and using aliases for multiple versions.
- [`arbitrary::Arbitrary`](https://docs.rs/arbitrary/latest/arbitrary/trait.Arbitrary.html)
  documents derived structured generation, while
  [`Unstructured`](https://docs.rs/arbitrary/latest/arbitrary/struct.Unstructured.html)
  documents deterministic interpretation of the same bytes and explicitly
  does not promise a particular distribution.
- [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) is the established
  libFuzzer frontend; the current project does not claim to implement it.
- [Kani loop unwinding](https://model-checking.github.io/kani/reference/attributes.html)
  and [Kani verification results](https://model-checking.github.io/kani/verification-results.html)
  support the rule that insufficient unwinding is a failed/undetermined proof,
  never equivalence.
- [`cargo-vouch`](https://github.com/ss1738/cargo-vouch) and its
  [real-world validation](https://github.com/ss1738/cargo-vouch/blob/main/REAL_WORLD_VALIDATION.md)
  motivate measuring eligibility before building a verifier; their reported
  results are evidence about that tool and sample, not a universal Rust rate.
- [`rust-lang/crater`](https://github.com/rust-lang/crater) is an ecosystem-scale
  build/test experiment and a useful infrastructure precedent. It is not a
  security sandbox specification for this project.
- [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks)
  checks API compatibility; this repository treats runtime behavior as a
  separate, future axis.
- [Regression verification of unbalanced recursive functions](https://arxiv.org/abs/2207.14364),
  [EquiBench](https://arxiv.org/abs/2502.12466),
  [Dristi & Dwyer](https://arxiv.org/abs/2602.15761), and
  [Partial Contracts Suffice](https://arxiv.org/abs/2607.10291) inform the
  research roadmap. Their benchmark results are not current performance claims
  about `equiv`.

## Reproducible local proof record

The completion checks for the shipped slice are:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo test -p equiv-harness --test e2e -- --ignored --nocapture --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
git diff --check
```

The commands above are the acceptance criteria for the current repository
scope. They do not certify arbitrary third-party code, universal equivalence,
or absence of defects outside the tested domains.
