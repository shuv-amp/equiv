//! Self-contained statistics needed for impact reporting.
//!
//! We implement Clopper–Pearson ("exact") binomial confidence intervals rather
//! than the normal approximation. Clopper–Pearson is *conservative*: its true
//! coverage is always at least the nominal level. That is the right bias for
//! this project — we would rather overstate our uncertainty than understate it.
//!
//! No external dependencies: the regularized incomplete beta function is
//! implemented directly so the numerics are auditable.

/// Lanczos approximation to `ln(Γ(x))`, valid for `x > 0`.
pub fn ln_gamma(x: f64) -> f64 {
    // Published Lanczos coefficients for g = 7, n = 9. Reproduced verbatim:
    // rounding them changes the approximation, so the lints are silenced
    // rather than the digits edited.
    #[allow(clippy::excessive_precision, clippy::inconsistent_digit_grouping)]
    const C: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    if x < 0.5 {
        // Reflection: Γ(x)Γ(1-x) = π / sin(πx)
        let pi = std::f64::consts::PI;
        return (pi / (pi * x).sin()).abs().ln() - ln_gamma(1.0 - x);
    }

    let x = x - 1.0;
    let mut a = C[0];
    let t = x + 7.5;
    for (i, &c) in C.iter().enumerate().skip(1) {
        a += c / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// Continued-fraction expansion used by [`reg_inc_beta`] (Lentz's method).
fn beta_cf(a: f64, b: f64, x: f64) -> f64 {
    const MAX_ITER: usize = 300;
    const EPS: f64 = 3.0e-14;
    const TINY: f64 = 1.0e-300;

    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;

    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < TINY {
        d = TINY;
    }
    d = 1.0 / d;
    let mut h = d;

    for m in 1..=MAX_ITER {
        let m_f = m as f64;
        let m2 = 2.0 * m_f;

        // Even step.
        let aa = m_f * (b - m_f) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        h *= d * c;

        // Odd step.
        let aa = -(a + m_f) * (qab + m_f) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;

        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Regularized incomplete beta function `I_x(a, b)`.
///
/// Equals the CDF of a Beta(a, b) distribution evaluated at `x`.
pub fn reg_inc_beta(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_bt = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln();
    let bt = ln_bt.exp();

    if x < (a + 1.0) / (a + b + 2.0) {
        bt * beta_cf(a, b, x) / a
    } else {
        1.0 - bt * beta_cf(b, a, 1.0 - x) / b
    }
}

/// Inverse of [`reg_inc_beta`] in `x`, found by bisection.
///
/// `I_x(a, b)` is continuous and strictly increasing in `x` on `(0, 1)`, so
/// bisection is guaranteed to converge. We prefer it over Newton's method
/// because it cannot overshoot, and precision here is cheap.
pub fn inv_reg_inc_beta(a: f64, b: f64, p: f64) -> f64 {
    if p <= 0.0 {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if reg_inc_beta(a, b, mid) < p {
            lo = mid;
        } else {
            hi = mid;
        }
        if hi - lo < 1e-15 {
            break;
        }
    }
    0.5 * (lo + hi)
}

/// Clopper–Pearson confidence interval for a binomial proportion.
///
/// `k` successes out of `n` trials at confidence `1 - alpha`. Returns
/// `(lower, upper)`, both in `[0, 1]`.
///
/// The interval is *conservative*: actual coverage is >= `1 - alpha`.
pub fn clopper_pearson(k: u64, n: u64, alpha: f64) -> (f64, f64) {
    assert!(n > 0, "clopper_pearson requires n > 0");
    assert!(k <= n, "successes cannot exceed trials");
    assert!(alpha > 0.0 && alpha < 1.0, "alpha must be in (0, 1)");

    let (k_f, n_f) = (k as f64, n as f64);

    let lower = if k == 0 {
        0.0
    } else {
        inv_reg_inc_beta(k_f, n_f - k_f + 1.0, alpha / 2.0)
    };
    let upper = if k == n {
        1.0
    } else {
        inv_reg_inc_beta(k_f + 1.0, n_f - k_f, 1.0 - alpha / 2.0)
    };

    (lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    #[test]
    fn ln_gamma_known_values() {
        // Γ(1) = 1, Γ(2) = 1, Γ(5) = 24, Γ(0.5) = sqrt(pi)
        assert!(close(ln_gamma(1.0), 0.0, 1e-10));
        assert!(close(ln_gamma(2.0), 0.0, 1e-10));
        assert!(close(ln_gamma(5.0), 24.0_f64.ln(), 1e-10));
        assert!(close(
            ln_gamma(0.5),
            std::f64::consts::PI.sqrt().ln(),
            1e-10
        ));
    }

    #[test]
    fn reg_inc_beta_is_a_cdf() {
        assert!(close(reg_inc_beta(2.0, 3.0, 0.0), 0.0, 1e-12));
        assert!(close(reg_inc_beta(2.0, 3.0, 1.0), 1.0, 1e-12));
        // I_x(1,1) is the uniform CDF, i.e. the identity.
        for x in [0.1, 0.25, 0.5, 0.75, 0.9] {
            assert!(close(reg_inc_beta(1.0, 1.0, x), x, 1e-10));
        }
        // Monotone increasing.
        let mut prev = 0.0;
        for i in 0..=20 {
            let v = reg_inc_beta(3.0, 7.0, i as f64 / 20.0);
            assert!(v >= prev - 1e-12);
            prev = v;
        }
    }

    #[test]
    fn inverse_round_trips() {
        for &(a, b) in &[(2.0, 5.0), (1.0, 1.0), (7.5, 0.5)] {
            for p in [0.025, 0.5, 0.975] {
                let x = inv_reg_inc_beta(a, b, p);
                assert!(close(reg_inc_beta(a, b, x), p, 1e-9), "a={a} b={b} p={p}");
            }
        }
    }

    #[test]
    fn clopper_pearson_matches_reference() {
        // Reference values derived independently from the *defining* equations
        // via exact binomial tails (see `agrees_with_binomial_definition`),
        // not from the beta formulation used by the implementation.
        let (lo, hi) = clopper_pearson(1, 10, 0.05);
        assert!(close(lo, 0.002_528_578_544, 1e-9), "lo={lo}");
        assert!(close(hi, 0.445_016_117_028, 1e-9), "hi={hi}");

        let (lo, hi) = clopper_pearson(5, 100, 0.05);
        assert!(close(lo, 0.016_431_879_182, 1e-9), "lo={lo}");
        assert!(close(hi, 0.112_834_911_105, 1e-9), "hi={hi}");
    }

    /// The strongest check available: the beta-function implementation must
    /// satisfy the *definition* of a Clopper–Pearson interval, computed here
    /// from binomial tail sums by an entirely separate code path.
    ///
    ///   lower solves  P(X >= k | n, p) = alpha/2
    ///   upper solves  P(X <= k | n, p) = alpha/2
    #[test]
    fn agrees_with_binomial_definition() {
        fn ln_choose(n: u64, k: u64) -> f64 {
            ln_gamma(n as f64 + 1.0) - ln_gamma(k as f64 + 1.0) - ln_gamma((n - k) as f64 + 1.0)
        }
        fn pmf(p: f64, i: u64, n: u64) -> f64 {
            if p <= 0.0 {
                return if i == 0 { 1.0 } else { 0.0 };
            }
            if p >= 1.0 {
                return if i == n { 1.0 } else { 0.0 };
            }
            (ln_choose(n, i) + i as f64 * p.ln() + (n - i) as f64 * (1.0 - p).ln()).exp()
        }
        let tail_ge = |p: f64, k: u64, n: u64| (k..=n).map(|i| pmf(p, i, n)).sum::<f64>();
        let tail_le = |p: f64, k: u64, n: u64| (0..=k).map(|i| pmf(p, i, n)).sum::<f64>();

        let alpha = 0.05;
        for n in [5_u64, 10, 23, 100] {
            for k in 0..=n {
                let (lo, hi) = clopper_pearson(k, n, alpha);
                if k > 0 {
                    assert!(
                        close(tail_ge(lo, k, n), alpha / 2.0, 1e-9),
                        "lower bound violates definition: n={n} k={k} lo={lo}"
                    );
                }
                if k < n {
                    assert!(
                        close(tail_le(hi, k, n), alpha / 2.0, 1e-9),
                        "upper bound violates definition: n={n} k={k} hi={hi}"
                    );
                }
            }
        }
    }

    #[test]
    fn clopper_pearson_edges_are_saturated() {
        let (lo, hi) = clopper_pearson(0, 50, 0.05);
        assert_eq!(lo, 0.0);
        assert!(hi > 0.0 && hi < 0.1);

        let (lo, hi) = clopper_pearson(50, 50, 0.05);
        assert!(lo > 0.9 && lo < 1.0);
        assert_eq!(hi, 1.0);
    }

    #[test]
    fn interval_always_contains_point_estimate() {
        for n in [1_u64, 7, 50, 1000] {
            for k in 0..=n {
                let (lo, hi) = clopper_pearson(k, n, 0.05);
                let p = k as f64 / n as f64;
                assert!(lo <= p + 1e-9 && p <= hi + 1e-9, "n={n} k={k}");
            }
        }
    }
}
