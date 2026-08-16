//! End-to-end: generate a probe against two real crates, find a witness,
//! then replay it.
//!
//! This is the Phase 1 loop in miniature and the only test that proves the
//! generated code actually compiles and runs. It invokes `cargo`, so it is
//! slow and needs a network on first run; run it explicitly:
//!
//! ```text
//! cargo test -p equiv-harness --test e2e -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use equiv_core::Verdict;
use equiv_harness::project::{retag_version, NEW_VERSION, OLD_VERSION};
use equiv_harness::runner::{decide_checked, RunOptions};
use equiv_harness::{spec_from_signature, Corpus, ProbeCrate, Source};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("equiv-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write a minimal library crate at `version`, containing `body`.
fn write_crate(root: &Path, name: &str, version: &str, body: &str) {
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n\n[workspace]\n"
        ),
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), body).unwrap();
}

/// Vendor one side of a comparison: write the published crate, then retag it.
///
/// # Why the retag is load-bearing
///
/// Cargo **unifies semver-compatible versions** of a package. A probe that asks
/// for `=1.0.4` and `=1.0.5` of the same crate does not resolve at all:
///
/// ```text
/// error: failed to select a version for `levenshtein`.
/// versions that meet the requirements `=1.0.4` are: 1.0.4
/// all possible versions conflict with previously selected packages
///   previously selected package `levenshtein v1.0.5`
/// ```
///
/// Patch and minor pairs are exactly the population this project exists to
/// scan, so that is not an edge case — it is the target. Vendoring both sides
/// and stamping deliberately *in*compatible pre-release versions onto them is
/// what makes the population reachable, and it is why these tests use path
/// sources rather than registry ones.
fn vendor(root: &Path, name: &str, published: &str, tag: &str, body: &str) {
    write_crate(root, name, published, body);
    retag_version(root, tag).unwrap();
}

fn cargo_run(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO"))
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(dir.join("Cargo.toml"))
        .arg("--")
        .args(args)
        .output()
        .expect("cargo run failed to start");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        panic!(
            "probe build/run failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Exit code 1 means a divergence was found, which is a success for us.
    (out.status.code() == Some(1), stdout)
}

fn json_field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let start = s.find(&pat)? + pat.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[test]
#[ignore = "invokes cargo; run with --ignored"]
fn finds_and_replays_a_real_divergence() {
    let dir = workdir("diverge");

    // A behaviour change of exactly the shape this project exists to catch:
    // both versions compile, both look reasonable, the signature is identical,
    // and they differ only on negative input. Note the version pair — 1.0.4 to
    // 1.0.5 is a patch release, which is where the interesting findings are and
    // which cargo will not resolve without the retag.
    vendor(
        &dir.join("old"),
        "budget",
        "1.0.4",
        OLD_VERSION,
        "pub fn retry_budget(retries: i32) -> u32 {\n\
         \x20   if retries < 0 { 3 } else { retries as u32 }\n}\n",
    );
    vendor(
        &dir.join("new"),
        "budget",
        "1.0.5",
        NEW_VERSION,
        "pub fn retry_budget(retries: i32) -> u32 {\n\
         \x20   if retries <= 0 { 0 } else { retries as u32 }\n}\n",
    );

    let sig: syn::ItemFn =
        syn::parse_str("fn retry_budget(retries: i32) -> u32 { unimplemented!() }").unwrap();
    let spec = spec_from_signature(&sig.sig, "retry_budget", 16).unwrap();
    assert_eq!(spec.domain(), "retries: i32");

    let probe = ProbeCrate {
        package: "budget".into(),
        old: Source::old_path(dir.join("old")),
        new: Source::new_path(dir.join("new")),
        spec,
        corpus: Corpus::default(),
    };
    let probe_dir = dir.join("probe");
    probe.write_to(&probe_dir).unwrap();

    // --- find ------------------------------------------------------------
    let (diverged, out) = cargo_run(&probe_dir, &["--iters", "5000"]);
    assert!(diverged, "expected a divergence, got: {out}");
    assert!(out.contains("\"diverges\":true"), "{out}");

    let input = json_field(&out, "input").expect("input in output");
    let old = json_field(&out, "old").expect("old in output");
    let new = json_field(&out, "new").expect("new in output");
    let hex = json_field(&out, "witness_hex").expect("witness_hex in output");
    println!("witness: {input}  old={old}  new={new}  hex={hex}");

    // Shrinking should land on a small negative value, not a random i32.
    let value: i64 = input
        .trim_start_matches("retries = ")
        .parse()
        .unwrap_or_else(|_| panic!("unexpected input rendering: {input}"));
    assert!(
        value < 0,
        "divergence should require a negative input, got {value}"
    );
    assert_eq!(old, "3");
    assert_eq!(new, "0");

    // --- replay ----------------------------------------------------------
    // This is the confirmation step: a witness only counts once it has been
    // re-executed against both unmodified artifacts.
    let (replayed, out2) = cargo_run(&probe_dir, &["--replay", hex]);
    assert!(replayed, "witness failed to replay: {out2}");
    assert_eq!(
        json_field(&out2, "input"),
        Some(input),
        "replay must reproduce the same input"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "invokes cargo; run with --ignored"]
fn identical_versions_report_no_divergence_not_equivalence() {
    let dir = workdir("same");

    let body = "pub fn clamp_page(p: i32, max: i32) -> i32 {\n\
                \x20   if p < 0 { 0 } else if p > max { max } else { p }\n}\n";
    vendor(&dir.join("old"), "pager", "2.1.0", OLD_VERSION, body);
    vendor(&dir.join("new"), "pager", "2.1.1", NEW_VERSION, body);

    let sig: syn::ItemFn =
        syn::parse_str("fn clamp_page(p: i32, max: i32) -> i32 { unimplemented!() }").unwrap();
    let spec = spec_from_signature(&sig.sig, "clamp_page", 16).unwrap();

    let probe_dir = dir.join("probe");
    let probe = ProbeCrate {
        package: "pager".into(),
        old: Source::old_path(dir.join("old")),
        new: Source::new_path(dir.join("new")),
        spec,
        corpus: Corpus::default(),
    };
    probe.write_to(&probe_dir).unwrap();

    let (diverged, out) = cargo_run(&probe_dir, &["--iters", "3000"]);
    assert!(!diverged, "identical code must not diverge: {out}");
    assert!(out.contains("\"diverges\":false"), "{out}");
    assert!(out.contains("\"samples\":3000"), "{out}");

    // The whole point: exhausting the budget is not evidence of equivalence.
    assert!(
        !out.to_lowercase().contains("equivalent"),
        "probe must not claim equivalence: {out}"
    );

    let verdict = decide_checked(
        &probe,
        &probe_dir,
        &RunOptions {
            iterations: 3_000,
            seed: 0,
            width: 64,
            timeout: Duration::from_secs(120),
        },
    );
    assert!(matches!(
        verdict,
        Verdict::Unknown {
            reason: equiv_core::Reason::NoDivergenceFound { samples: 3_000 }
        }
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "invokes cargo; run with --ignored"]
fn a_panic_is_an_observable_difference() {
    let dir = workdir("panic");

    vendor(
        &dir.join("old"),
        "stats",
        "0.3.0",
        OLD_VERSION,
        "pub fn mean(xs: &[i32]) -> i32 {\n\
         \x20   xs.iter().sum::<i32>() / xs.len() as i32\n}\n",
    );
    vendor(
        &dir.join("new"),
        "stats",
        "0.3.1",
        NEW_VERSION,
        "pub fn mean(xs: &[i32]) -> i32 {\n\
         \x20   if xs.is_empty() { return 0; }\n\
         \x20   xs.iter().sum::<i32>() / xs.len() as i32\n}\n",
    );

    let sig: syn::ItemFn =
        syn::parse_str("fn mean(xs: &[i32]) -> i32 { unimplemented!() }").unwrap();
    let spec = spec_from_signature(&sig.sig, "mean", 8).unwrap();

    let probe_dir = dir.join("probe");
    ProbeCrate {
        package: "stats".into(),
        old: Source::old_path(dir.join("old")),
        new: Source::new_path(dir.join("new")),
        spec,
        corpus: Corpus::default(),
    }
    .write_to(&probe_dir)
    .unwrap();

    let (diverged, out) = cargo_run(&probe_dir, &["--iters", "5000"]);
    assert!(diverged, "empty-slice guard should be visible: {out}");
    assert_eq!(
        json_field(&out, "old"),
        Some("<panic>"),
        "old divides by zero on an empty slice: {out}"
    );
    assert_eq!(json_field(&out, "new"), Some("0"), "{out}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The property the whole search rests on: a divergence guarded by a constant
/// is reachable *only* through the mined dictionary.
///
/// Both versions here agree everywhere except `n == 3999`, one input out of
/// 2^32. Uniform sampling reaches it with probability 2.3e-10 — measured, an
/// empty dictionary found nothing in 200 000 draws while the mined one produced
/// a witness in under 30 000. This test pins the difference so a regression in
/// [`Corpus`] shows up as a failure rather than as a scan that quietly finds
/// nothing.
#[test]
#[ignore = "invokes cargo twice; run with --ignored"]
fn a_boundary_guarded_divergence_needs_the_mined_dictionary() {
    let dir = workdir("dict");

    // `MAX` and the guard are written in the source, so they are exactly what
    // `Corpus::mine` picks up — as they would be in any real crate.
    let old = "pub const MAX: i32 = 3999;\n\
               pub fn to(n: i32) -> Option<i32> {\n\
               \x20   if n <= 0 || n > MAX { return None; }\n\
               \x20   Some(n)\n}\n";
    let new = "pub const MAX: i32 = 3999;\n\
               pub fn to(n: i32) -> Option<i32> {\n\
               \x20   if n <= 0 || n >= MAX { return None; }\n\
               \x20   Some(n)\n}\n";
    vendor(&dir.join("old"), "numeral", "0.1.0", OLD_VERSION, old);
    vendor(&dir.join("new"), "numeral", "0.1.1", NEW_VERSION, new);

    let sig: syn::ItemFn =
        syn::parse_str("fn to(n: i32) -> Option<i32> { unimplemented!() }").unwrap();
    let spec = spec_from_signature(&sig.sig, "to", 16).unwrap();

    let source = std::fs::read_to_string(dir.join("new/src/lib.rs")).unwrap();
    let parsed = syn::parse_file(&source).unwrap();
    let corpus = Corpus::mine([&parsed]);
    assert!(
        corpus.ints.contains(&3999),
        "mining failed: {:?}",
        corpus.ints
    );

    let probe_dir = dir.join("probe");
    ProbeCrate {
        package: "numeral".into(),
        old: Source::old_path(dir.join("old")),
        new: Source::new_path(dir.join("new")),
        spec: spec.clone(),
        corpus,
    }
    .write_to(&probe_dir)
    .unwrap();

    let (diverged, out) = cargo_run(&probe_dir, &["--iters", "40000"]);
    assert!(diverged, "dictionary should reach the guard: {out}");
    assert_eq!(json_field(&out, "input"), Some("n = 3999"), "{out}");

    // And the control: same probe, no dictionary, far more draws.
    let bare_dir = dir.join("bare");
    ProbeCrate {
        package: "numeral".into(),
        old: Source::old_path(dir.join("old")),
        new: Source::new_path(dir.join("new")),
        spec,
        corpus: Corpus::default(),
    }
    .write_to(&bare_dir)
    .unwrap();

    let (found, out) = cargo_run(&bare_dir, &["--iters", "200000"]);
    assert!(
        !found,
        "if an empty dictionary finds this, the experiment no longer measures \
         what it claims and the numbers in codegen's docs need redoing: {out}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "invokes cargo twice; run with --ignored"]
fn runner_only_reports_a_replay_confirmed_witness() {
    let dir = workdir("runner");
    let body_old = "pub fn retry_budget(retries: i32) -> u32 {\n\
         \x20   if retries < 0 { 3 } else { retries as u32 }\n}\n";
    let body_new = "pub fn retry_budget(retries: i32) -> u32 {\n\
         \x20   if retries <= 0 { 0 } else { retries as u32 }\n}\n";
    vendor(&dir.join("old"), "budget", "1.0.4", OLD_VERSION, body_old);
    vendor(&dir.join("new"), "budget", "1.0.5", NEW_VERSION, body_new);

    let sig: syn::ItemFn =
        syn::parse_str("fn retry_budget(retries: i32) -> u32 { unimplemented!() }").unwrap();
    let spec = spec_from_signature(&sig.sig, "retry_budget", 16).unwrap();
    let probe_dir = dir.join("probe");
    let probe = ProbeCrate {
        package: "budget".into(),
        old: Source::old_path(dir.join("old")),
        new: Source::new_path(dir.join("new")),
        spec,
        corpus: Corpus::default(),
    };
    probe.write_to(&probe_dir).unwrap();

    let verdict = decide_checked(
        &probe,
        &probe_dir,
        &RunOptions {
            iterations: 5_000,
            seed: 0,
            width: 64,
            timeout: Duration::from_secs(120),
        },
    );

    match verdict {
        Verdict::Diverges { witnesses, .. } => {
            assert_eq!(witnesses.len(), 1);
            assert!(witnesses[0].is_confirmed());
            let replay = witnesses[0].replay().unwrap();
            assert_eq!(replay.old_ref, probe.old.fingerprint("budget").unwrap());
            assert_eq!(replay.new_ref, probe.new.fingerprint("budget").unwrap());
        }
        other => panic!("expected replay-confirmed divergence, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
