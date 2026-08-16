//! Verdicts, and the safe-construction machinery for the two central rules.
//!
//! Rule 1 — **No LLM output may be an axiom.**
//!   An [`Equivalent`] verdict requires a [`Certificate`], and a `Certificate`
//!   can only be produced by `ProofLedger::seal`, which fails if any artifact
//!   from an untrusted origin is still undischarged.
//!
//! Rule 2 — **Zero false `DIVERGES`.**
//!   A [`Verdict::diverges`] requires at least one witness that has been
//!   *replayed against both unmodified artifacts*. A witness produced by a
//!   harness but never replayed cannot reach a verdict.
//!
//! The safe constructors enforce the local invariants: sampled runs cannot
//! become `EQUIVALENT`, and the `DIVERGES` constructor accepts only confirmed
//! witnesses with distinct observations. The shipped workspace has no public
//! proof engine; a future verifier must provide the trusted certificate path.
//!
//! [`Equivalent`]: Verdict::Equivalent

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Proof tiers and bounds
// ---------------------------------------------------------------------------

/// Which relational technique earned the proof. See `PLAN.md` §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Coupled harness: `assert_eq!(old(x), new(x))`. Loop-free / loop-light only.
    A,
    /// Shared-callee hoisting: each unchanged callee invoked once, result fed to both sides.
    B,
    /// RVT-style loop coupling: loops as recursion, matching calls as one uninterpreted function.
    C,
}

/// The bound an `EQUIVALENT` verdict is relative to. Always printed.
///
/// There is no such thing as an unqualified equivalence claim in this system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bound {
    /// Loop unwinding depth, when bounded model checking was used.
    pub loop_unwind: Option<u32>,
    /// Maximum recursion depth explored.
    pub recursion_depth: Option<u32>,
    /// Rendered description of the input domain, e.g. `"i32 x [0,16] Vec<u8>"`.
    pub domain: String,
}

/// The trusted computing base that produced a verdict.
///
/// Recorded so a verdict can be re-checked, and so a soundness bug in a
/// specific solver version can be traced to every verdict it touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tcb {
    pub rustc: String,
    pub equiv: String,
    pub prover: Option<String>,
}

// ---------------------------------------------------------------------------
// Rule 1: the proof ledger
// ---------------------------------------------------------------------------

/// Where an artifact used in a proof came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    /// Produced by something in the TCB: rustc, the solver, the eligibility
    /// gate, the replay executor.
    Trusted(String),
    /// Produced by something outside the TCB: an LLM proposal, a heuristic.
    /// Must be discharged before it can contribute to an `EQUIVALENT`.
    Untrusted(String),
}

/// Opaque handle to a recorded untrusted proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalId(usize);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// What the artifact is, e.g. `"loop unwind bound = 8"`.
    pub what: String,
    pub origin: Origin,
    /// How the obligation was mechanically discharged. `None` = outstanding.
    pub discharged_by: Option<String>,
}

/// Accumulates every artifact a proof attempt relied on.
///
/// The ledger is the mechanism behind Rule 1: untrusted entries must be
/// explicitly discharged, and `seal` refuses otherwise.
#[allow(dead_code)] // reserved for the future proof-engine crate
#[derive(Debug, Clone)]
pub struct ProofLedger {
    tier: Tier,
    bound: Bound,
    tcb: Tcb,
    entries: Vec<Entry>,
}

#[allow(dead_code)] // reserved for the future proof-engine crate
impl ProofLedger {
    pub(crate) fn new(tier: Tier, bound: Bound, tcb: Tcb) -> Self {
        Self {
            tier,
            bound,
            tcb,
            entries: Vec::new(),
        }
    }

    /// Record an artifact from inside the TCB. Needs no discharge.
    pub(crate) fn record_trusted(&mut self, what: impl Into<String>, by: impl Into<String>) {
        self.entries.push(Entry {
            what: what.into(),
            origin: Origin::Trusted(by.into()),
            discharged_by: None,
        });
    }

    /// Record an artifact from outside the TCB — an LLM proposal, a guess.
    ///
    /// Until [`discharge`](Self::discharge) is called with the returned id,
    /// [`seal`](Self::seal) will fail.
    #[must_use = "an untrusted proposal must be discharged or the proof cannot be sealed"]
    pub(crate) fn record_untrusted(
        &mut self,
        what: impl Into<String>,
        from: impl Into<String>,
    ) -> ProposalId {
        self.entries.push(Entry {
            what: what.into(),
            origin: Origin::Untrusted(from.into()),
            discharged_by: None,
        });
        ProposalId(self.entries.len() - 1)
    }

    /// Discharge a proposal by recording the mechanical check that validated it.
    ///
    /// `how` should name a real check — `"kani: unwinding assertion held"`,
    /// `"solver: invariant proved inductive"` — not a rationalisation.
    pub(crate) fn discharge(&mut self, id: ProposalId, how: impl Into<String>) {
        if let Some(e) = self.entries.get_mut(id.0) {
            e.discharged_by = Some(how.into());
        }
    }

    /// Entries that are untrusted and still outstanding.
    pub(crate) fn outstanding(&self) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.origin, Origin::Untrusted(_)) && e.discharged_by.is_none())
            .collect()
    }

    /// Seal the ledger into a [`Certificate`].
    ///
    /// This is the **only** way to obtain a `Certificate`, and therefore the
    /// only route to [`Verdict::Equivalent`].
    ///
    /// # Errors
    /// Returns every outstanding untrusted artifact. The caller's correct
    /// response is to emit [`Verdict::unknown`] — never to force the proof.
    pub(crate) fn seal(self) -> Result<Certificate, Undischarged> {
        let outstanding: Vec<String> = self
            .entries
            .iter()
            .filter(|e| matches!(e.origin, Origin::Untrusted(_)) && e.discharged_by.is_none())
            .map(|e| e.what.clone())
            .collect();

        if !outstanding.is_empty() {
            return Err(Undischarged { outstanding });
        }

        Ok(Certificate {
            tier: self.tier,
            bound: self.bound,
            tcb: self.tcb,
            entries: self.entries,
        })
    }
}

/// Returned when a proof was attempted while untrusted artifacts remained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undischarged {
    pub outstanding: Vec<String>,
}

impl std::fmt::Display for Undischarged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot seal proof: {} undischarged untrusted artifact(s): {}",
            self.outstanding.len(),
            self.outstanding.join("; ")
        )
    }
}

impl std::error::Error for Undischarged {}

/// Evidence that an `EQUIVALENT` verdict is legitimate.
///
/// Fields are private and there is no public constructor: the only way to
/// build one is `ProofLedger::seal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    tier: Tier,
    bound: Bound,
    tcb: Tcb,
    entries: Vec<Entry>,
}

impl Certificate {
    pub fn tier(&self) -> Tier {
        self.tier
    }
    pub fn bound(&self) -> &Bound {
        &self.bound
    }
    pub fn tcb(&self) -> &Tcb {
        &self.tcb
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// Rule 2: witnesses must replay
// ---------------------------------------------------------------------------

/// A concrete input on which the two versions were observed to differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    /// Rendered input, e.g. `"retries = -1"`.
    pub input: String,
    pub old_output: String,
    pub new_output: String,
    /// `None` until the witness has been replayed on both unmodified artifacts.
    replay: Option<Replay>,
}

/// Proof that a witness was re-executed against both untouched artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replay {
    pub old_ref: String,
    pub new_ref: String,
}

impl Witness {
    /// A candidate witness, as produced by a fuzzer or solver. Not yet usable.
    pub fn candidate(
        input: impl Into<String>,
        old_output: impl Into<String>,
        new_output: impl Into<String>,
    ) -> Self {
        Self {
            input: input.into(),
            old_output: old_output.into(),
            new_output: new_output.into(),
            replay: None,
        }
    }

    /// Record a successful replay against both unmodified artifacts.
    ///
    /// The replay executor is responsible for calling this only after it has
    /// actually rerun both artifacts. The core type records that evidence and
    /// validates its shape; it cannot inspect another process by itself.
    pub fn confirm(mut self, old_ref: impl Into<String>, new_ref: impl Into<String>) -> Self {
        self.replay = Some(Replay {
            old_ref: old_ref.into(),
            new_ref: new_ref.into(),
        });
        self
    }

    pub fn is_confirmed(&self) -> bool {
        self.replay.is_some()
    }

    pub fn replay(&self) -> Option<&Replay> {
        self.replay.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Why no decision could be reached. Always specific — never apologetic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum Reason {
    /// The eligibility gate rejected the function.
    Ineligible(String),
    /// Old and new could not be put into correspondence unambiguously.
    AmbiguousAlignment(String),
    /// One or both revisions failed to build.
    BuildFailed(String),
    /// The prover ran out of time.
    Timeout { seconds: u64 },
    /// Bounded model checking could not reach a sufficient unwinding depth.
    UnwindBoundInsufficient { at: String },
    /// A language or toolchain feature the analysis does not support.
    Unsupported(String),
    /// A proof was attempted but untrusted artifacts remained outstanding.
    UndischargedObligations(Vec<String>),
    /// Fuzzing found nothing; this is *not* evidence of equivalence.
    NoDivergenceFound { samples: u64 },
    /// A generated probe did not produce the machine-readable result required
    /// to make a sound decision.
    ProbeOutputInvalid { stage: String, detail: String },
    /// A candidate witness did not reproduce byte-for-byte on replay.
    ReplayMismatch { detail: String },
    /// One of the artifacts changed while a checked probe was running.
    ArtifactChanged { side: String, detail: String },
    /// The runner configuration was invalid before execution began.
    InvalidRunOptions(String),
}

/// The answer to the one question this system asks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Proven equivalent, relative to the certificate's bound.
    Equivalent { certificate: Certificate },
    /// Behaviour differs, with at least one replay-confirmed witness.
    Diverges {
        witnesses: Vec<Witness>,
        impact: Option<crate::impact::Impact>,
    },
    /// No decision. A first-class, respectable outcome.
    Unknown { reason: Reason },
}

/// Rejected attempt to build a `Diverges` verdict without confirmed evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoConfirmedWitness;

impl std::fmt::Display for NoConfirmedWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cannot report DIVERGES: no confirmed witness with distinct observations")
    }
}

impl std::error::Error for NoConfirmedWitness {}

impl Verdict {
    /// Build an `EQUIVALENT` verdict. Requires a sealed certificate, so this
    /// cannot be reached while untrusted artifacts are outstanding.
    pub fn equivalent(certificate: Certificate) -> Self {
        Verdict::Equivalent { certificate }
    }

    /// Build a `DIVERGES` verdict.
    ///
    /// Unconfirmed witnesses and confirmed witnesses with identical
    /// observations are **dropped silently** — they may be artifacts of an
    /// imperfect harness. If nothing survives, this fails and the caller must
    /// emit [`Verdict::unknown`].
    pub fn diverges(
        witnesses: Vec<Witness>,
        impact: Option<crate::impact::Impact>,
    ) -> Result<Self, NoConfirmedWitness> {
        let confirmed: Vec<Witness> = witnesses
            .into_iter()
            .filter(|witness| {
                witness.is_confirmed()
                    && witness.old_output != witness.new_output
                    && witness.replay.as_ref().is_some_and(|replay| {
                        !replay.old_ref.is_empty() && !replay.new_ref.is_empty()
                    })
            })
            .collect();
        if confirmed.is_empty() {
            return Err(NoConfirmedWitness);
        }
        Ok(Verdict::Diverges {
            witnesses: confirmed,
            impact,
        })
    }

    pub fn unknown(reason: Reason) -> Self {
        Verdict::Unknown { reason }
    }

    /// Short label for terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Equivalent { .. } => "EQUIVALENT",
            Verdict::Diverges { .. } => "DIVERGES",
            Verdict::Unknown { .. } => "UNKNOWN",
        }
    }

    pub fn is_equivalent(&self) -> bool {
        matches!(self, Verdict::Equivalent { .. })
    }
    pub fn is_diverges(&self) -> bool {
        matches!(self, Verdict::Diverges { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> Bound {
        Bound {
            loop_unwind: Some(8),
            recursion_depth: None,
            domain: "i32".into(),
        }
    }

    fn tcb() -> Tcb {
        Tcb {
            rustc: "1.90.0".into(),
            equiv: "0.1.0".into(),
            prover: Some("kani 0.60".into()),
        }
    }

    fn ledger() -> ProofLedger {
        ProofLedger::new(Tier::A, bound(), tcb())
    }

    #[test]
    fn trusted_only_ledger_seals() {
        let mut l = ledger();
        l.record_trusted("domain from Arbitrary bounds", "equiv-gate");
        assert!(l.seal().is_ok());
    }

    #[test]
    fn undischarged_llm_proposal_blocks_the_proof() {
        let mut l = ledger();
        let _id = l.record_untrusted("loop unwind bound = 8", "llm:scaffold");
        let err = l.seal().unwrap_err();
        assert_eq!(err.outstanding.len(), 1);
        assert!(err.to_string().contains("undischarged"));
    }

    #[test]
    fn discharged_proposal_unblocks_the_proof() {
        let mut l = ledger();
        let id = l.record_untrusted("loop unwind bound = 8", "llm:scaffold");
        l.discharge(id, "kani: unwinding assertion held");
        let cert = l.seal().expect("should seal once discharged");
        assert_eq!(cert.tier(), Tier::A);
        assert_eq!(cert.entries().len(), 1);
    }

    #[test]
    fn partially_discharged_still_blocks() {
        let mut l = ledger();
        let a = l.record_untrusted("alignment: old::f -> new::f", "llm:align");
        let _b = l.record_untrusted("stub for io::read", "llm:scaffold");
        l.discharge(a, "checker: signatures match structurally");
        assert_eq!(l.outstanding().len(), 1);
        assert!(l.seal().is_err());
    }

    #[test]
    fn unconfirmed_witness_cannot_produce_a_verdict() {
        let w = Witness::candidate("retries = -1", "3", "0");
        assert!(!w.is_confirmed());
        assert_eq!(Verdict::diverges(vec![w], None), Err(NoConfirmedWitness));
    }

    #[test]
    fn unconfirmed_witnesses_are_dropped_not_reported() {
        let good = Witness::candidate("retries = -1", "3", "0").confirm("a821f3c", "c192dd8");
        let bad = Witness::candidate("retries = 7", "7", "7");
        let v = Verdict::diverges(vec![bad, good], None).unwrap();
        match v {
            Verdict::Diverges { witnesses, .. } => {
                assert_eq!(witnesses.len(), 1, "harness artifact must not be reported");
                assert_eq!(witnesses[0].input, "retries = -1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn identical_observations_cannot_be_reported_as_divergence() {
        let w = Witness::candidate("x", "same", "same").confirm("old", "new");
        assert_eq!(Verdict::diverges(vec![w], None), Err(NoConfirmedWitness));
    }

    #[test]
    fn no_divergence_found_is_not_equivalence() {
        // The single most important thing this type system must not permit:
        // "fuzzing found nothing" is UNKNOWN, never EQUIVALENT.
        let v = Verdict::unknown(Reason::NoDivergenceFound { samples: 1_000_000 });
        assert!(!v.is_equivalent());
        assert_eq!(v.label(), "UNKNOWN");
    }

    #[test]
    fn verdict_roundtrips_through_json() {
        let mut l = ledger();
        l.record_trusted("domain", "equiv-gate");
        let v = Verdict::equivalent(l.seal().unwrap());
        let s = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }
}
