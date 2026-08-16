//! Core types for `equiv`.
//!
//! `equiv` answers exactly one question about a pair of program versions:
//!
//! > **Did behaviour change, and on which inputs?**
//!
//! Everything in this crate exists to make the two safety rules impossible to
//! violate by accident:
//!
//! 1. **No LLM output may be an axiom.** See [`verdict::ProofLedger`].
//! 2. **Zero false `DIVERGES`.** See [`verdict::Witness`].
//!
//! Both are enforced with private constructors, so a violation is a compile
//! error rather than a review comment.

pub mod impact;
pub mod stats;
pub mod verdict;

pub use impact::Impact;
pub use verdict::{
    Bound, Certificate, NoConfirmedWitness, Origin, ProofLedger, ProposalId, Reason, Tcb, Tier,
    Undischarged, Verdict, Witness,
};
