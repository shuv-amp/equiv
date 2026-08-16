//! Phase 0 probe: measure the eligibility rate of real Rust code.
//!
//! Build no verifier. Answer one question:
//!
//! > What fraction of functions are even admissible to sound differential
//! > analysis, and **which single constraint is costing us the most**?
//!
//! The second half is the point. A raw rejection histogram is misleading,
//! because a function blocked by six things is not evidence against any one of
//! them. What actually directs engineering effort is the *marginal* number:
//! how many functions would be admitted if we relaxed exactly one constraint
//! and changed nothing else. That is the `blocking_alone` marginal.
//!
//! Usage:
//!   equiv-probe [--all] [--json] [--list] `path`...

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use equiv_gate::{Admission, Config, FnReport};
use serde::Serialize;

/// One admitted function, named the way a probe would have to call it.
#[derive(Debug, Clone, Serialize)]
struct Admitted {
    path: String,
    /// False when the function is `pub` but sits behind a private module or
    /// type. A probe cannot call it at `path`; a `pub use` elsewhere may still
    /// expose it under a different one.
    reachable: bool,
    prove: bool,
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    files_scanned: usize,
    files_unparseable: usize,
    functions: usize,
    /// Crate-local `struct`/`enum` definitions the gate could resolve.
    local_types_resolved: usize,

    fuzz_admitted: usize,
    prove_admitted: usize,

    /// How many functions each reason blocks, counted once per function.
    fuzz_histogram: BTreeMap<String, usize>,
    prove_histogram: BTreeMap<String, usize>,

    /// The actionable number: functions rejected by *this reason alone*.
    /// Relaxing one of these admits exactly this many more functions.
    fuzz_blocking_alone: BTreeMap<String, usize>,
    prove_blocking_alone: BTreeMap<String, usize>,

    with_loop: usize,
    with_recursion: usize,

    /// Which concrete types the gate could not resolve. This is the actionable
    /// tail of `unsupported_type`: it names exactly what to support next.
    unresolved_types: BTreeMap<String, usize>,
    /// Which callees the gate could not confirm pure.
    unresolved_callees: BTreeMap<String, usize>,

    /// Every fuzz-admissible function, by call path. This is the handoff to
    /// everything downstream: a scanner needs the path, not the count.
    fuzz_admitted_fns: Vec<Admitted>,
}

impl Summary {
    fn rate(n: usize, d: usize) -> f64 {
        if d == 0 {
            0.0
        } else {
            100.0 * n as f64 / d as f64
        }
    }

    fn ingest(&mut self, r: &FnReport) {
        self.functions += 1;
        if r.fuzz.is_admitted() {
            self.fuzz_admitted_fns.push(Admitted {
                path: r.path.clone(),
                reachable: r.reachable,
                prove: r.prove.is_admitted(),
            });
        }
        if r.facts.has_loop {
            self.with_loop += 1;
        }
        if r.facts.has_recursion {
            self.with_recursion += 1;
        }

        for reason in r.fuzz.reasons() {
            match reason {
                equiv_gate::Reject::UnsupportedType(t) => {
                    *self.unresolved_types.entry(t.clone()).or_default() += 1;
                }
                equiv_gate::Reject::UnresolvedCall(c) | equiv_gate::Reject::UnresolvedMethod(c) => {
                    *self.unresolved_callees.entry(c.clone()).or_default() += 1;
                }
                _ => {}
            }
        }

        for (adm, hist, alone, admitted) in [
            (
                &r.fuzz,
                &mut self.fuzz_histogram,
                &mut self.fuzz_blocking_alone,
                &mut self.fuzz_admitted,
            ),
            (
                &r.prove,
                &mut self.prove_histogram,
                &mut self.prove_blocking_alone,
                &mut self.prove_admitted,
            ),
        ] {
            match adm {
                Admission::Admitted => *admitted += 1,
                Admission::Rejected { reasons } => {
                    let mut codes: Vec<&str> = reasons.iter().map(|x| x.code()).collect();
                    codes.sort_unstable();
                    codes.dedup();
                    for c in &codes {
                        *hist.entry((*c).to_string()).or_default() += 1;
                    }
                    if codes.len() == 1 {
                        *alone.entry(codes[0].to_string()).or_default() += 1;
                    }
                }
            }
        }
    }
}

fn collect_rs(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        if root.extension().is_some_and(|e| e == "rs") {
            out.push(root.to_path_buf());
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Skip vendored, generated and test-only trees: they are not the
        // public surface we are measuring.
        if p.is_dir() && matches!(name, "target" | ".git" | "tests" | "benches" | "examples") {
            continue;
        }
        collect_rs(&p, out);
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let all = args.iter().any(|a| a == "--all");
    let list = args.iter().any(|a| a == "--list");
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    if paths.is_empty() {
        eprintln!("usage: equiv-probe [--all] [--json] [--list] <path>...");
        eprintln!("  --all   include private functions (default: public API only)");
        eprintln!("  --json  emit machine-readable summary");
        eprintln!("  --list  print the call path of every fuzz-admissible function");
        return ExitCode::from(2);
    }

    let cfg = Config { public_only: !all };
    let mut files = Vec::new();
    for p in &paths {
        collect_rs(Path::new(p), &mut files);
    }

    // Parse everything first, then analyse as one unit: crate-local type
    // resolution and module visibility both need every definition in hand
    // before any single function can be judged.
    let mut s = Summary::default();
    let mut parsed = Vec::new();
    for f in &files {
        let Ok(src) = std::fs::read_to_string(f) else {
            continue;
        };
        s.files_scanned += 1;
        match equiv_gate::parse(&src) {
            // A file with no `src` component in its path tells us nothing about
            // its module, so it is treated as the crate root rather than given
            // an invented prefix.
            Ok(file) => parsed.push((equiv_gate::module_path_of(f).unwrap_or_default(), file)),
            Err(_) => s.files_unparseable += 1,
        }
    }
    let sources: Vec<equiv_gate::SourceFile> = parsed
        .iter()
        .map(|(m, f)| equiv_gate::SourceFile::in_module(m.clone(), f))
        .collect();
    for r in &equiv_gate::analyze_files(&sources, &cfg) {
        s.ingest(r);
    }
    s.local_types_resolved = equiv_gate::TypeEnv::from_files(parsed.iter().map(|(_, f)| f)).len();
    s.fuzz_admitted_fns.sort_by(|a, b| a.path.cmp(&b.path));

    if json {
        println!("{}", serde_json::to_string_pretty(&s).unwrap());
        return ExitCode::SUCCESS;
    }

    if list {
        list_admitted(&s);
        return ExitCode::SUCCESS;
    }

    report(&s, cfg.public_only);
    ExitCode::SUCCESS
}

/// Print the call path of every fuzz-admissible function.
///
/// This is the output a scanner consumes: the count says whether the project is
/// viable, the paths say what to actually probe.
fn list_admitted(s: &Summary) {
    for a in &s.fuzz_admitted_fns {
        println!(
            "{:<8} {:<6} {}",
            if a.prove { "fuzz+prove" } else { "fuzz" },
            if a.reachable { "pub" } else { "hidden" },
            a.path
        );
    }
    let hidden = s.fuzz_admitted_fns.iter().filter(|a| !a.reachable).count();
    eprintln!(
        "\n  {} fuzz-admissible, {} of them not callable at that path \
         (private module or type; a `pub use` may still expose them elsewhere)",
        s.fuzz_admitted_fns.len(),
        hidden
    );
}

fn report(s: &Summary, public_only: bool) {
    println!();
    println!("  equiv-probe — eligibility of {} functions", s.functions);
    println!(
        "  {} files scanned ({} unparseable), {} local types resolved, scope: {}",
        s.files_scanned,
        s.files_unparseable,
        s.local_types_resolved,
        if public_only {
            "public API"
        } else {
            "all functions"
        }
    );
    println!();

    println!(
        "  E1  fuzz-admissible (can hunt a witness)   {:>6} / {:<6}  {:>5.1}%",
        s.fuzz_admitted,
        s.functions,
        Summary::rate(s.fuzz_admitted, s.functions)
    );
    println!(
        "      prove-admissible (Tier A equivalence)  {:>6} / {:<6}  {:>5.1}%",
        s.prove_admitted,
        s.functions,
        Summary::rate(s.prove_admitted, s.functions)
    );
    println!();
    println!(
        "      contains a loop {:>5}   recursive {:>5}",
        s.with_loop, s.with_recursion
    );
    println!();

    print_table(
        "BLOCKS FUZZING — functions affected",
        &s.fuzz_histogram,
        &s.fuzz_blocking_alone,
        s.functions,
    );
    print_table(
        "BLOCKS PROVING — functions affected",
        &s.prove_histogram,
        &s.prove_blocking_alone,
        s.functions,
    );

    let best = s
        .fuzz_blocking_alone
        .iter()
        .max_by_key(|(_, v)| **v)
        .map(|(k, v)| (k.clone(), *v));

    print_top(
        "TOP UNRESOLVED TYPES — what to support next",
        &s.unresolved_types,
    );
    print_top("TOP UNRESOLVED CALLEES", &s.unresolved_callees);

    println!("  ── read this ──────────────────────────────────────────────");
    match best {
        Some((code, n)) if n > 0 => println!(
            "  Relaxing `{code}` alone would admit {n} more function(s) to\n  \
             fuzzing (+{:.1} points). That is where the next engineering effort\n  \
             belongs — nothing else buys as much.",
            Summary::rate(n, s.functions)
        ),
        _ => println!(
            "  No single constraint dominates: rejected functions are blocked\n  \
             by several reasons at once, so relaxing any one changes little."
        ),
    }
    println!();
    println!(
        "  Go/no-go: PLAN.md sets E1 >= 5% to continue. Currently {:.1}%.  {}",
        Summary::rate(s.fuzz_admitted, s.functions),
        if Summary::rate(s.fuzz_admitted, s.functions) >= 5.0 {
            "PASS"
        } else {
            "FAIL — redesign the gate before building a verifier"
        }
    );
    println!();
}

fn print_top(title: &str, m: &BTreeMap<String, usize>) {
    if m.is_empty() {
        return;
    }
    let mut rows: Vec<(&String, &usize)> = m.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    println!("  {title}");
    let line = rows
        .iter()
        .take(12)
        .map(|(k, v)| format!("{k}({v})"))
        .collect::<Vec<_>>()
        .join("  ");
    println!("    {line}");
    println!("    ({} distinct)", rows.len());
    println!();
}

fn print_table(
    title: &str,
    hist: &BTreeMap<String, usize>,
    alone: &BTreeMap<String, usize>,
    total: usize,
) {
    if hist.is_empty() {
        return;
    }
    println!("  {title}");
    println!(
        "  {:<24} {:>8} {:>7}  {:>14}",
        "reason", "affected", "%", "blocking alone"
    );
    println!("  {}", "-".repeat(58));

    let mut rows: Vec<(&String, &usize)> = hist.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1));
    for (code, n) in rows.iter().take(14) {
        println!(
            "  {:<24} {:>8} {:>6.1}%  {:>14}",
            code,
            n,
            Summary::rate(**n, total),
            alone.get(*code).copied().unwrap_or(0)
        );
    }
    println!();
}
