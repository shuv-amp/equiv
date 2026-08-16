//! Impact = "how much of the input domain diverges".
//!
//! The rule this module exists to enforce:
//!
//! > **Never emit a bare percentage.**
//!
//! `retries < 0` is ~50% of `i32` and ~2.9% of `[-3, 100]`. A proportion with
//! no stated domain and no stated measure is a marketing number. Every value
//! here therefore carries its provenance, and [`Impact::render`] always prints
//! how the number was obtained.

use serde::{Deserialize, Serialize};

use crate::stats::clopper_pearson;

/// How the divergence proportion was established.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Impact {
    /// The domain was small enough to count exhaustively, or a model counter
    /// gave an exact answer.
    Exact { diverging: u128, total: u128 },

    /// The domain was sampled. Reported with a conservative (Clopper–Pearson)
    /// interval, never a bare point estimate.
    Estimated {
        diverging: u64,
        samples: u64,
        /// Confidence level, e.g. `0.95`.
        confidence: f64,
        lower: f64,
        upper: f64,
    },

    /// All we have is witnesses. This is a sound lower bound and nothing more.
    ///
    /// This is the *default* and most common case: finding one input where the
    /// two versions differ tells you the divergence set is non-empty. It does
    /// not tell you how big it is.
    LowerBound {
        witnesses: u64,
        /// Size of the declared domain, when known.
        domain_size: Option<u128>,
    },
}

impl Impact {
    /// Build an estimate from a sample, computing a conservative interval.
    ///
    /// # Panics
    /// If `samples == 0`, if `diverging > samples`, or if `confidence` is not
    /// strictly between 0 and 1.
    pub fn from_sample(diverging: u64, samples: u64, confidence: f64) -> Self {
        let alpha = 1.0 - confidence;
        let (lower, upper) = clopper_pearson(diverging, samples, alpha);
        Impact::Estimated {
            diverging,
            samples,
            confidence,
            lower,
            upper,
        }
    }

    /// Build a lower bound from witnesses alone.
    pub fn from_witnesses(witnesses: u64, domain_size: Option<u128>) -> Self {
        Impact::LowerBound {
            witnesses,
            domain_size,
        }
    }

    /// The point estimate, where one is meaningful.
    ///
    /// Returns `None` for [`Impact::LowerBound`] — deliberately. A single
    /// witness does not license a proportion, and callers must not be able to
    /// obtain one by accident.
    pub fn point_estimate(&self) -> Option<f64> {
        match *self {
            Impact::Exact { diverging, total } if total > 0 => {
                Some(diverging as f64 / total as f64)
            }
            Impact::Exact { .. } => None,
            Impact::Estimated {
                diverging, samples, ..
            } if samples > 0 => Some(diverging as f64 / samples as f64),
            Impact::Estimated { .. } => None,
            Impact::LowerBound { .. } => None,
        }
    }

    /// A sound lower bound on the divergence proportion, if one can be stated.
    pub fn sound_lower_bound(&self) -> Option<f64> {
        match *self {
            Impact::Exact { diverging, total } if total > 0 => {
                Some(diverging as f64 / total as f64)
            }
            Impact::Exact { .. } => None,
            Impact::Estimated { lower, .. } => Some(lower),
            Impact::LowerBound {
                witnesses,
                domain_size: Some(size),
            } if size > 0 => Some(witnesses as f64 / size as f64),
            Impact::LowerBound { .. } => None,
        }
    }

    /// Human-readable rendering that always discloses the method.
    pub fn render(&self) -> String {
        match *self {
            Impact::Exact { diverging, total } => {
                let pct = if total > 0 {
                    format!(" ({:.6}%)", 100.0 * diverging as f64 / total as f64)
                } else {
                    String::new()
                };
                format!("{diverging} / {total} inputs{pct}, exact over D")
            }
            Impact::Estimated {
                diverging,
                samples,
                confidence,
                lower,
                upper,
            } => format!(
                "{:.4}% ({:.0}% CI: {:.4}%–{:.4}%, n = {}, {} diverging)",
                100.0 * diverging as f64 / samples as f64,
                100.0 * confidence,
                100.0 * lower,
                100.0 * upper,
                samples,
                diverging
            ),
            Impact::LowerBound {
                witnesses,
                domain_size,
            } => match domain_size {
                Some(size) if size > 0 => format!(
                    ">= {witnesses} / {size} (lower bound from {witnesses} witness{})",
                    if witnesses == 1 { "" } else { "es" }
                ),
                _ => format!(
                    ">= {witnesses} input{} (lower bound from witnesses; domain size unknown)",
                    if witnesses == 1 { "" } else { "s" }
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_bound_refuses_to_produce_a_percentage() {
        let i = Impact::from_witnesses(1, None);
        assert_eq!(i.point_estimate(), None);
        assert_eq!(i.sound_lower_bound(), None);
        assert!(i.render().contains("lower bound"));
        assert!(!i.render().contains('%'));
    }

    #[test]
    fn lower_bound_with_domain_gives_a_bound_but_no_estimate() {
        let i = Impact::from_witnesses(3, Some(65_536));
        assert_eq!(i.point_estimate(), None);
        let lb = i.sound_lower_bound().unwrap();
        assert!((lb - 3.0 / 65_536.0).abs() < 1e-12);
    }

    #[test]
    fn estimate_interval_brackets_the_point() {
        let i = Impact::from_sample(78, 10_000, 0.95);
        let p = i.point_estimate().unwrap();
        if let Impact::Estimated { lower, upper, .. } = i {
            assert!(lower <= p && p <= upper);
            // 78/10000 = 0.78%
            assert!((p - 0.0078).abs() < 1e-12);
            assert!(lower > 0.006 && upper < 0.010);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn zero_divergence_sample_still_has_an_upper_bound() {
        // Seeing no divergence in 1000 samples does NOT mean zero divergence.
        let i = Impact::from_sample(0, 1000, 0.95);
        if let Impact::Estimated { lower, upper, .. } = i {
            assert_eq!(lower, 0.0);
            assert!(upper > 0.0, "must not claim the rate is provably zero");
            assert!(upper < 0.01);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn exact_renders_with_method() {
        let i = Impact::Exact {
            diverging: 3,
            total: 65_536,
        };
        let s = i.render();
        assert!(s.contains("3 / 65536"));
        assert!(s.contains("exact"));
    }

    #[test]
    fn render_always_states_provenance() {
        for i in [
            Impact::Exact {
                diverging: 1,
                total: 2,
            },
            Impact::from_sample(1, 100, 0.95),
            Impact::from_witnesses(1, None),
        ] {
            let s = i.render();
            let discloses = s.contains("exact") || s.contains("CI") || s.contains("lower bound");
            assert!(discloses, "impact rendered without provenance: {s}");
        }
    }
}
