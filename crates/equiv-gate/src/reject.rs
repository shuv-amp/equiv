//! Reasons a function is not admissible.
//!
//! Two design rules, both load-bearing for Phase 0:
//!
//! 1. **Collect every reason, never short-circuit.** If we stopped at the
//!    first failing check, the rejection histogram would be biased by check
//!    order and would not tell us which constraint is actually binding.
//!
//! 2. **Every variant carries a stable [`code`](Reject::code).** Phase 0's
//!    output is a histogram over these codes, and the codes have to survive
//!    refactoring for the numbers to stay comparable across runs.

use serde::{Deserialize, Serialize};

/// A single reason a function was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum Reject {
    // ---- signature shape -------------------------------------------------
    /// Generic parameters. Kani verifies per monomorphization; v0 skips these.
    Generic(String),
    /// `async fn` — futures are not a value we can compare.
    Async,
    /// `unsafe fn`.
    UnsafeFn,
    /// Takes `self` in any form. v0 handles free functions only.
    SelfParam,
    /// A `&mut` parameter: output is not confined to the return value.
    MutRefParam(String),
    /// `impl Trait` in argument or return position.
    ImplTrait,
    /// `dyn Trait` — Kani does not support dynamic dispatch.
    TraitObject,
    /// Raw pointer in the signature.
    RawPointer,
    /// Floating point. Excluded in v0: NaN != NaN, -0.0 == 0.0, and legal
    /// reassociation all make naive equality the wrong comparison.
    FloatType(String),
    /// A type we cannot confirm implements `Arbitrary + PartialEq`.
    UnsupportedType(String),
    /// Returns `()`. There is no observable to compare.
    UnitReturn,

    // ---- effects (reject for both fuzzing and proving) -------------------
    /// An `unsafe { .. }` block in the body.
    UnsafeBlock,
    /// Interior mutability: `Cell`, `RefCell`, `Mutex`, `Atomic*`, `OnceLock`…
    InteriorMutability(String),
    /// Filesystem, network, process or stdio.
    IoEffect(String),
    /// Reads the clock. Non-deterministic.
    TimeEffect(String),
    /// Randomness. Non-deterministic.
    RandEffect(String),
    /// Threads or concurrency.
    ConcurrencyEffect(String),
    /// Environment access.
    EnvEffect(String),
    /// A printing macro — stdio is an unmodelled output channel.
    PrintMacro(String),
    /// `.await` in the body.
    Await,
    /// Refers to a `static` item: shared state outside the arguments.
    StaticAccess(String),
    /// Calls a free function we cannot confirm is pure and deterministic.
    ///
    /// Expected to dominate the histogram. That is the point: Phase 0 measures
    /// how much this single constraint costs before we invest in resolving it.
    UnresolvedCall(String),
    /// Calls a method not on the known-pure allowlist.
    UnresolvedMethod(String),
    /// Invokes a macro we cannot see through.
    UnresolvedMacro(String),

    // ---- proof tier only (fuzzing handles these fine) --------------------
    /// A loop whose trip count depends on the input. This is what produced
    /// `cargo-vouch`'s 6/6 INCONCLUSIVE, and what Tier C exists to defeat.
    DataDependentLoop,
    /// Direct recursion.
    Recursion,
    /// An input whose size is unbounded (`Vec`, `String`, slices) — fine to
    /// fuzz, but needs a declared bound before it can be proved.
    UnboundedInput(String),
}

impl Reject {
    /// Stable identifier used for histogramming. Must not change casually.
    pub fn code(&self) -> &'static str {
        use Reject::*;
        match self {
            Generic(_) => "generic",
            Async => "async",
            UnsafeFn => "unsafe_fn",
            SelfParam => "self_param",
            MutRefParam(_) => "mut_ref_param",
            ImplTrait => "impl_trait",
            TraitObject => "trait_object",
            RawPointer => "raw_pointer",
            FloatType(_) => "float_type",
            UnsupportedType(_) => "unsupported_type",
            UnitReturn => "unit_return",
            UnsafeBlock => "unsafe_block",
            InteriorMutability(_) => "interior_mutability",
            IoEffect(_) => "io_effect",
            TimeEffect(_) => "time_effect",
            RandEffect(_) => "rand_effect",
            ConcurrencyEffect(_) => "concurrency_effect",
            EnvEffect(_) => "env_effect",
            PrintMacro(_) => "print_macro",
            Await => "await",
            StaticAccess(_) => "static_access",
            UnresolvedCall(_) => "unresolved_call",
            UnresolvedMethod(_) => "unresolved_method",
            UnresolvedMacro(_) => "unresolved_macro",
            DataDependentLoop => "data_dependent_loop",
            Recursion => "recursion",
            UnboundedInput(_) => "unbounded_input",
        }
    }

    /// Whether this reason blocks *fuzzing* (finding divergence), as opposed to
    /// only blocking *proving* equivalence.
    ///
    /// This split is the whole architecture: concrete execution does not care
    /// about loop depth, so the surface we can find witnesses on is much larger
    /// than the surface we can prove equivalence on.
    pub fn blocks_fuzzing(&self) -> bool {
        !matches!(
            self,
            Reject::DataDependentLoop | Reject::Recursion | Reject::UnboundedInput(_)
        )
    }
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Reject::*;
        match self {
            Generic(d) => write!(f, "generic parameter `{d}`"),
            Async => f.write_str("async fn"),
            UnsafeFn => f.write_str("unsafe fn"),
            SelfParam => f.write_str("takes self"),
            MutRefParam(d) => write!(f, "`&mut` parameter `{d}`"),
            ImplTrait => f.write_str("`impl Trait`"),
            TraitObject => f.write_str("`dyn Trait`"),
            RawPointer => f.write_str("raw pointer"),
            FloatType(d) => write!(f, "floating point type `{d}`"),
            UnsupportedType(d) => write!(f, "unsupported type `{d}`"),
            UnitReturn => f.write_str("returns `()` — nothing to compare"),
            UnsafeBlock => f.write_str("`unsafe` block"),
            InteriorMutability(d) => write!(f, "interior mutability `{d}`"),
            IoEffect(d) => write!(f, "I/O `{d}`"),
            TimeEffect(d) => write!(f, "clock access `{d}`"),
            RandEffect(d) => write!(f, "randomness `{d}`"),
            ConcurrencyEffect(d) => write!(f, "concurrency `{d}`"),
            EnvEffect(d) => write!(f, "environment access `{d}`"),
            PrintMacro(d) => write!(f, "printing macro `{d}!`"),
            Await => f.write_str("`.await`"),
            StaticAccess(d) => write!(f, "static item `{d}`"),
            UnresolvedCall(d) => write!(f, "call to unresolved `{d}`"),
            UnresolvedMethod(d) => write!(f, "method `.{d}()` not on the pure allowlist"),
            UnresolvedMacro(d) => write!(f, "opaque macro `{d}!`"),
            DataDependentLoop => f.write_str("data-dependent loop"),
            Recursion => f.write_str("recursion"),
            UnboundedInput(d) => write!(f, "unbounded input `{d}`"),
        }
    }
}
