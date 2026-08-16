//! The eligibility predicate.
//!
//! > Is this function admissible to sound differential analysis?
//!
//! This is Phase 0 of the project and the cheapest way to kill it. Before
//! building any verifier we need to know what fraction of real code is even
//! analysable — because `cargo-vouch`, which auto-generated Kani harnesses for
//! Rust functions, returned **6/6 INCONCLUSIVE** on two randomly chosen
//! crates.io crates. That failure was an eligibility failure, and it is
//! measurable without writing a single line of verifier.
//!
//! # Two admissions, not one
//!
//! The gate answers *two* questions, because the reachable surface differs
//! enormously between them:
//!
//! - [`FnReport::fuzz`] — can we look for a divergence *witness*? Concrete
//!   execution does not care about loop depth, so this surface is large.
//! - [`FnReport::prove`] — can we prove *equivalence*? Bounded model checking
//!   does care, so this surface is small.
//!
//! Leading with witnesses is the whole roadmap, and this split is where that
//! decision is encoded.
//!
//! # Conservatism
//!
//! The analysis is syntactic. It cannot see through type aliases, macros,
//! trait resolution, or into callee bodies. Every blind spot resolves to
//! *reject*, so the eligibility rate reported here is a **lower bound**.

pub mod exports;
pub mod reject;
pub mod rules;
pub mod typeenv;
pub mod visit;

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use syn::spanned::Spanned;

pub use reject::Reject;
use rules::{check_type, Position};
pub use typeenv::TypeEnv;

/// Tuning for the gate.
#[derive(Debug, Clone)]
pub struct Config {
    /// Only consider `pub` functions. For the crates.io use case this is the
    /// right filter: a crate's public API is its behavioural contract.
    pub public_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { public_only: true }
    }
}

/// Whether a function is admitted for a given purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Admission {
    Admitted,
    Rejected { reasons: Vec<Reject> },
}

impl Admission {
    pub fn is_admitted(&self) -> bool {
        matches!(self, Admission::Admitted)
    }
    pub fn reasons(&self) -> &[Reject] {
        match self {
            Admission::Admitted => &[],
            Admission::Rejected { reasons } => reasons,
        }
    }
}

/// Shape facts, recorded whether or not the function is admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub params: usize,
    pub has_loop: bool,
    pub has_recursion: bool,
    pub call_sites: usize,
}

/// The gate's verdict on one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FnReport {
    pub name: String,
    /// How to *call* this function from outside the crate: the module path,
    /// then the `impl` type for an associated function, then the name —
    /// `parse`, `Version::parse`, `parser::tokenize`.
    ///
    /// This is what a differential probe needs; `name` alone is ambiguous the
    /// moment a crate has two `parse` functions, and is not callable at all for
    /// an associated function.
    ///
    /// # What this path is, and is not
    ///
    /// Where an item is *written* and where it is *callable* differ in almost
    /// every published crate, because of the facade pattern (`mod imp;` plus
    /// `pub use imp::*;`). [`exports`] resolves `pub use` chains, so this is the
    /// **exported** path where one could be found, and the written path
    /// otherwise:
    ///
    /// - [`reachable`](FnReport::reachable) true — this path is callable from
    ///   outside the crate, and is the shortest such path.
    /// - false — the item is written behind a private module or type, and no
    ///   `pub use` was found that exposes it. The written path is reported
    ///   instead, since that is at least where the code lives.
    ///
    /// Re-export resolution is syntactic like the rest of the gate, so it does
    /// not see through `#[cfg]` or macro-generated `use` items. The probe build
    /// is the final check either way: a wrong path is a compile error, never a
    /// wrong verdict.
    pub path: String,
    /// Whether the function is callable at exactly [`path`](FnReport::path)
    /// from outside the crate — it is `pub`, and every enclosing module and the
    /// `impl` type are too, after `pub use` resolution.
    ///
    /// This is the flag a scanner filters on: false means building a probe
    /// against that path would not compile.
    pub reachable: bool,
    pub line: usize,
    pub is_pub: bool,
    pub facts: Facts,
    /// Admissible to differential fuzzing — i.e. can we hunt for a witness?
    pub fuzz: Admission,
    /// Admissible to a Tier-A equivalence proof.
    pub prove: Admission,
}

impl FnReport {
    /// Every distinct reason across both admissions.
    pub fn all_reasons(&self) -> Vec<&Reject> {
        let mut v: Vec<&Reject> = self.prove.reasons().iter().collect();
        for r in self.fuzz.reasons() {
            if !v.contains(&r) {
                v.push(r);
            }
        }
        v
    }
}

/// Parse one source file. Exposed so callers can count parse failures.
pub fn parse(src: &str) -> syn::Result<syn::File> {
    syn::parse_file(src)
}

/// A parsed source file together with the module it defines.
///
/// A crate's modules are spread across files, and a `syn::File` on its own does
/// not know which one it is. Supplying that lets the gate report a callable
/// [`FnReport::path`] instead of a bare function name.
#[derive(Debug, Clone)]
pub struct SourceFile<'a> {
    /// `::`-separated module path this file defines, empty for the crate root.
    /// Derive it from a file path with [`module_path_of`].
    pub module: String,
    pub file: &'a syn::File,
}

impl<'a> SourceFile<'a> {
    /// A file defining the crate root (`src/lib.rs`).
    pub fn root(file: &'a syn::File) -> Self {
        Self {
            module: String::new(),
            file,
        }
    }

    /// A file defining the module at `module`.
    pub fn in_module(module: impl Into<String>, file: &'a syn::File) -> Self {
        Self {
            module: module.into(),
            file,
        }
    }
}

/// Derive a module path from a source file's location, by cargo's conventions.
///
/// ```text
/// src/lib.rs        ->  ""             (the crate root)
/// src/foo.rs        ->  "foo"
/// src/foo/mod.rs    ->  "foo"
/// src/foo/bar.rs    ->  "foo::bar"
/// ```
///
/// Everything up to and including the last `src` component is discarded, so
/// absolute and relative paths behave the same. Returns `None` for a path with
/// no `src` component, where the layout gives us nothing to go on — callers
/// should fall back to the crate root rather than invent a module.
///
/// This reads the *conventional* layout only. A `#[path = "…"]` attribute
/// relocates a module and is not visible from the file path; such a module gets
/// the wrong prefix here, and the probe build catches it.
pub fn module_path_of(file: &Path) -> Option<String> {
    let comps: Vec<&str> = file
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let src = comps.iter().rposition(|c| *c == "src")?;
    let mut segs: Vec<String> = comps[src + 1..].iter().map(|s| s.to_string()).collect();

    let last = segs.pop()?;
    let stem = last.strip_suffix(".rs")?;
    if !matches!(stem, "lib" | "main" | "mod") {
        segs.push(stem.to_string());
    }
    Some(segs.join("::"))
}

/// Analyse a whole crate at once.
///
/// Analysing the crate together — rather than file by file — is what lets the
/// gate resolve crate-local `struct` and `enum` definitions. That single change
/// is worth more than every other rule here combined; see [`typeenv`].
///
/// Every file is treated as the crate root, so [`FnReport::path`] carries no
/// module prefix. Use [`analyze_files`] when the file layout is known.
pub fn analyze_crate(files: &[syn::File], cfg: &Config) -> Vec<FnReport> {
    let roots: Vec<SourceFile> = files.iter().map(SourceFile::root).collect();
    analyze_files(&roots, cfg)
}

/// Analyse a crate whose files are each attributed to a module.
///
/// This is [`analyze_crate`] plus the information needed to report a callable
/// path rather than a bare name.
pub fn analyze_files(files: &[SourceFile<'_>], cfg: &Config) -> Vec<FnReport> {
    let env = TypeEnv::from_files(files.iter().map(|f| f.file));
    let index = CrateIndex::of(files.iter().map(|f| f.file));
    let cx = Cx {
        cfg,
        env: &env,
        index: &index,
    };
    let mut out = Vec::new();
    for sf in files {
        // A file-derived prefix has no visibility of its own: the `mod` item
        // that pulls it in lives in the parent file. `private` is that lookup.
        let reachable = sf
            .module
            .split("::")
            .all(|seg| seg.is_empty() || !index.private_modules.contains(seg));
        let scope = Scope {
            module: sf.module.clone(),
            reachable,
        };
        for item in &sf.file.items {
            walk_item(item, &cx, &scope, &mut out);
        }
    }

    // Where an item is written and where it is callable are different places in
    // almost every published crate. Resolve `pub use` last, over finished
    // reports, so the rewrite sees the complete path including the impl type.
    let exports = exports::Exports::of(files);
    for r in &mut out {
        if r.reachable || !r.is_pub {
            continue;
        }
        // A rewrite that lands somewhere equally private is no improvement, and
        // reporting it would replace one uncallable path with another. Keep the
        // path as written in that case — it is at least where the code lives.
        match exports.resolve(&r.path) {
            Some(public) if exports::path_is_public(&public, &index) => {
                r.path = public;
                r.reachable = true;
            }
            _ => {}
        }
    }
    out
}

/// Analyse a single source string. Convenience wrapper over [`analyze_crate`].
pub fn analyze_str(src: &str, cfg: &Config) -> syn::Result<Vec<FnReport>> {
    let file = parse(src)?;
    Ok(analyze_crate(std::slice::from_ref(&file), cfg))
}

/// Names declared without `pub` anywhere in the crate.
///
/// Crate-wide facts that no single function or file can supply.
///
/// Two questions need the whole crate in hand:
///
/// - **Is a path callable?** That depends on the modules it passes through and,
///   for an associated function, on the `impl` type. `pub fn new` inside
///   `impl Config` is not callable as `Config::new` if `Config` is private.
/// - **Is a bare identifier a local or a global?** `LIMIT` reads identically
///   either way, and only a crate-level `static` makes it state outside the
///   arguments.
///
/// Names are bare, because a file path gives us nothing finer, so two items
/// sharing a name are conflated. The conflation is deliberately one-directional:
/// one private `foo` marks every `foo` unreachable, and one `static LIMIT`
/// makes every bare `LIMIT` suspect. Both under-claim and never over-claim.
#[derive(Debug, Default)]
struct CrateIndex {
    private_modules: BTreeSet<String>,
    private_types: BTreeSet<String>,
    /// Statics that carry *state*, and so make a function that reads one
    /// depend on something other than its arguments.
    ///
    /// An immutable `static TABLE: &[(char, u32)]` is not one of these. It is a
    /// constant with an address, reading it is pure, and rejecting it costs
    /// real targets — `roman`, the crate this whole project benchmarks
    /// against, holds its numeral table in exactly that form.
    statics: BTreeSet<String>,
}

impl CrateIndex {
    fn of<'a>(files: impl IntoIterator<Item = &'a syn::File>) -> Self {
        fn walk(item: &syn::Item, out: &mut CrateIndex) {
            if let syn::Item::Static(s) = item {
                if is_stateful_static(s) {
                    out.statics.insert(s.ident.to_string());
                }
                return;
            }
            let (vis, ident, inner) = match item {
                syn::Item::Mod(m) => (&m.vis, &m.ident, Some(&m.content)),
                syn::Item::Struct(s) => (&s.vis, &s.ident, None),
                syn::Item::Enum(e) => (&e.vis, &e.ident, None),
                syn::Item::Union(u) => (&u.vis, &u.ident, None),
                syn::Item::Type(t) => (&t.vis, &t.ident, None),
                _ => return,
            };
            if !matches!(vis, syn::Visibility::Public(_)) {
                let set = if matches!(item, syn::Item::Mod(_)) {
                    &mut out.private_modules
                } else {
                    &mut out.private_types
                };
                set.insert(ident.to_string());
            }
            if let Some(Some((_, items))) = inner {
                for it in items {
                    walk(it, out);
                }
            }
        }
        let mut out = CrateIndex::default();
        for f in files {
            for item in &f.items {
                walk(item, &mut out);
            }
        }
        out
    }
}

/// Whether reading this `static` can observe anything but a fixed value.
///
/// Two ways it can: `static mut`, and a type with interior mutability
/// (`Mutex`, `OnceLock`, `Atomic*`, `Cell`). Everything else is a constant with
/// an address — pure to read, and rejecting it would throw away lookup tables,
/// which are one of the most analysable shapes there is.
fn is_stateful_static(item: &syn::ItemStatic) -> bool {
    if !matches!(item.mutability, syn::StaticMutability::None) {
        return true;
    }

    struct Scan<'a>(&'a mut bool);
    impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
        fn visit_path_segment(&mut self, n: &'ast syn::PathSegment) {
            let name = n.ident.to_string();
            if matches!(
                rules::classify_type_name(&name, &name),
                Some(Reject::InteriorMutability(_))
            ) {
                *self.0 = true;
            }
            syn::visit::visit_path_segment(self, n);
        }
    }

    let mut found = false;
    syn::visit::Visit::visit_type(&mut Scan(&mut found), &item.ty);
    found
}

/// Where in the module tree we currently are, and whether it is externally
/// visible.
struct Scope {
    module: String,
    reachable: bool,
}

impl Scope {
    /// `self.module::tail`, skipping the separator at the crate root.
    fn join(&self, tail: &str) -> String {
        if self.module.is_empty() {
            tail.to_string()
        } else {
            format!("{}::{tail}", self.module)
        }
    }
}

/// Name an `impl` block's self type, for use in a call path.
///
/// `impl Version` and `impl Wrapper<T>` both yield the bare identifier, which is
/// what a call site writes. Anything not written as a path — `impl [T]`,
/// `impl (A, B)` — has no such spelling, and yields `None`.
fn self_ty_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(tp) => tp.path.segments.last().map(|s| s.ident.to_string()),
        syn::Type::Paren(p) => self_ty_name(&p.elem),
        syn::Type::Group(g) => self_ty_name(&g.elem),
        _ => None,
    }
}

/// Everything the per-function analysis needs from the crate as a whole.
///
/// Bundled rather than threaded as separate parameters: each of these is
/// derived once per crate and read by every function, and passing them
/// individually pushed `analyze_fn` past nine arguments.
struct Cx<'a> {
    cfg: &'a Config,
    env: &'a TypeEnv,
    index: &'a CrateIndex,
}

fn walk_item(item: &syn::Item, cx: &Cx<'_>, scope: &Scope, out: &mut Vec<FnReport>) {
    match item {
        syn::Item::Fn(f) => {
            let is_pub = matches!(f.vis, syn::Visibility::Public(_));
            if !cx.cfg.public_only || is_pub {
                let name = f.sig.ident.to_string();
                out.push(analyze_fn(
                    &f.sig,
                    Some(&f.block),
                    is_pub,
                    f.span(),
                    None,
                    &[],
                    cx,
                    scope.join(&name),
                    scope.reachable && is_pub,
                ));
            }
        }
        syn::Item::Mod(m) => {
            if let Some((_, items)) = &m.content {
                let inner = Scope {
                    module: scope.join(&m.ident.to_string()),
                    reachable: scope.reachable && matches!(m.vis, syn::Visibility::Public(_)),
                };
                for it in items {
                    walk_item(it, cx, &inner, out);
                }
            }
        }
        syn::Item::Impl(i) => {
            // Trait impls are excluded: their signatures are fixed by the trait
            // and they are rarely the unit a caller reasons about.
            if i.trait_.is_some() {
                return;
            }
            let impl_generics: Vec<String> = i
                .generics
                .params
                .iter()
                .filter_map(|p| match p {
                    syn::GenericParam::Type(t) => Some(t.ident.to_string()),
                    syn::GenericParam::Const(c) => Some(c.ident.to_string()),
                    syn::GenericParam::Lifetime(_) => None,
                })
                .collect();
            let ty_name = self_ty_name(&i.self_ty);
            for it in &i.items {
                if let syn::ImplItem::Fn(f) = it {
                    let is_pub = matches!(f.vis, syn::Visibility::Public(_));
                    if !cx.cfg.public_only || is_pub {
                        let name = f.sig.ident.to_string();
                        // Without a nameable self type there is no call path,
                        // so the report says so instead of emitting a path that
                        // would not compile.
                        let (path, reachable) = match &ty_name {
                            Some(t) => (
                                scope.join(&format!("{t}::{name}")),
                                scope.reachable && is_pub && !cx.index.private_types.contains(t),
                            ),
                            None => (scope.join(&name), false),
                        };
                        out.push(analyze_fn(
                            &f.sig,
                            Some(&f.block),
                            is_pub,
                            f.span(),
                            Some(&i.self_ty),
                            &impl_generics,
                            cx,
                            path,
                            reachable,
                        ));
                    }
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_fn(
    sig: &syn::Signature,
    body: Option<&syn::Block>,
    is_pub: bool,
    span: proc_macro2::Span,
    self_ty: Option<&syn::Type>,
    impl_generics: &[String],
    cx: &Cx<'_>,
    path: String,
    reachable: bool,
) -> FnReport {
    let name = sig.ident.to_string();
    let mut rejects: Vec<Reject> = Vec::new();
    let mut unbounded: Vec<String> = Vec::new();
    let ctx = rules::Ctx {
        env: cx.env,
        self_ty,
    };

    // Generic parameters in scope, from the fn and from the enclosing impl.
    // Uses of these show up as `unsupported_type`, which is a misattribution:
    // the real reason is `generic`, and counting both inflates the type
    // histogram and hides what actually needs supporting.
    let mut generic_names: Vec<String> = sig
        .generics
        .params
        .iter()
        .filter_map(|p| match p {
            syn::GenericParam::Type(t) => Some(t.ident.to_string()),
            syn::GenericParam::Const(c) => Some(c.ident.to_string()),
            syn::GenericParam::Lifetime(_) => None,
        })
        .collect();
    generic_names.extend(impl_generics.iter().cloned());
    if !impl_generics.is_empty() {
        // The enclosing impl is generic, so there is no single monomorphization.
        for g in impl_generics {
            rejects.push(Reject::Generic(g.clone()));
        }
    }

    // ---- signature ------------------------------------------------------
    if sig.asyncness.is_some() {
        rejects.push(Reject::Async);
    }
    if sig.unsafety.is_some() {
        rejects.push(Reject::UnsafeFn);
    }

    // Lifetime parameters are harmless; type and const parameters are not,
    // because Kani verifies per monomorphization and we have no call site yet.
    for p in &sig.generics.params {
        match p {
            syn::GenericParam::Type(t) => rejects.push(Reject::Generic(t.ident.to_string())),
            syn::GenericParam::Const(c) => rejects.push(Reject::Generic(c.ident.to_string())),
            syn::GenericParam::Lifetime(_) => {}
        }
    }
    if sig.generics.where_clause.is_some() {
        rejects.push(Reject::Generic("where clause".into()));
    }

    let mut params = 0usize;
    for arg in &sig.inputs {
        match arg {
            // A `&self` or `self` receiver is exactly as analysable as a free
            // function taking the receiver as its first parameter — the value
            // is an input and the output stays in the return value. Only
            // `&mut self` escapes that, because it is an extra output channel.
            syn::FnArg::Receiver(r) => {
                let by_mut_ref = r.reference.is_some() && r.mutability.is_some();
                match self_ty {
                    Some(ty) if !by_mut_ref => {
                        params += 1;
                        check_type(ty, Position::Param, &mut rejects, &mut unbounded, ctx);
                    }
                    Some(_) => rejects.push(Reject::MutRefParam("self".into())),
                    None => rejects.push(Reject::SelfParam),
                }
            }
            syn::FnArg::Typed(pt) => {
                params += 1;
                check_type(&pt.ty, Position::Param, &mut rejects, &mut unbounded, ctx);
            }
        }
    }

    match &sig.output {
        syn::ReturnType::Default => rejects.push(Reject::UnitReturn),
        syn::ReturnType::Type(_, ty) => {
            check_type(ty, Position::Return, &mut rejects, &mut unbounded, ctx)
        }
    }

    // Drop `unsupported_type` entries that merely name a generic parameter in
    // scope: `Generic` already covers those, and double-counting would make the
    // type histogram point at the wrong fix.
    rejects.retain(|r| match r {
        Reject::UnsupportedType(t) => !generic_names.iter().any(|g| g == t),
        _ => true,
    });
    rejects.dedup();

    // ---- body -----------------------------------------------------------
    let body_facts = body
        .map(|b| visit::scan_body(b, &name, &cx.index.statics))
        .unwrap_or_default();
    rejects.extend(body_facts.rejects.iter().cloned());

    // ---- split into the two admissions ----------------------------------
    // Fuzzing tolerates loops, recursion and unbounded inputs. Proving does not.
    let fuzz_blockers: Vec<Reject> = rejects
        .iter()
        .filter(|r| r.blocks_fuzzing())
        .cloned()
        .collect();

    let mut prove_blockers = rejects.clone();
    if body_facts.has_loop {
        prove_blockers.push(Reject::DataDependentLoop);
    }
    if body_facts.has_recursion {
        prove_blockers.push(Reject::Recursion);
    }
    for u in dedup(unbounded) {
        prove_blockers.push(Reject::UnboundedInput(u));
    }

    FnReport {
        name,
        path,
        reachable,
        line: span.start().line,
        is_pub,
        facts: Facts {
            params,
            has_loop: body_facts.has_loop,
            has_recursion: body_facts.has_recursion,
            call_sites: body_facts.call_sites,
        },
        fuzz: admission(fuzz_blockers),
        prove: admission(prove_blockers),
    }
}

fn admission(reasons: Vec<Reject>) -> Admission {
    if reasons.is_empty() {
        Admission::Admitted
    } else {
        Admission::Rejected { reasons }
    }
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(src: &str) -> FnReport {
        let mut r = analyze_str(src, &Config { public_only: false }).expect("parse");
        assert_eq!(r.len(), 1, "expected exactly one function");
        r.pop().unwrap()
    }

    fn codes(a: &Admission) -> Vec<&'static str> {
        let mut c: Vec<_> = a.reasons().iter().map(|r| r.code()).collect();
        c.sort_unstable();
        c.dedup();
        c
    }

    #[test]
    fn clean_arithmetic_is_admitted_for_both() {
        let r = one("pub fn clamp_page(p: i32, max: i32) -> i32 { if p < 0 { 0 } else if p > max { max } else { p } }");
        assert!(r.fuzz.is_admitted(), "{:?}", r.fuzz);
        assert!(r.prove.is_admitted(), "{:?}", r.prove);
        assert_eq!(r.facts.params, 2);
    }

    #[test]
    fn a_loop_blocks_proving_but_not_fuzzing() {
        // This is the cargo-vouch case: `roman::to` style iteration.
        let r = one(
            "pub fn to_roman(mut n: i32) -> u32 { let mut c = 0; while n >= 1000 { n -= 1000; c += 1; } c }",
        );
        assert!(
            r.fuzz.is_admitted(),
            "loops must not block fuzzing: {:?}",
            r.fuzz
        );
        assert!(!r.prove.is_admitted());
        assert!(codes(&r.prove).contains(&"data_dependent_loop"));
        assert!(r.facts.has_loop);
    }

    #[test]
    fn unbounded_input_blocks_proving_only() {
        let r = one("pub fn total(xs: Vec<i32>) -> i32 { let mut s = 0; s }");
        assert!(r.fuzz.is_admitted(), "{:?}", r.fuzz);
        assert!(codes(&r.prove).contains(&"unbounded_input"));
    }

    #[test]
    fn effects_block_everything() {
        for (src, code) in [
            (
                "pub fn f(a: i32) -> i32 { std::fs::read(\"x\").unwrap(); a }",
                "io_effect",
            ),
            (
                "pub fn f(a: i32) -> i32 { let t = std::time::Instant::now(); a }",
                "time_effect",
            ),
            (
                "pub fn f(a: i32) -> i32 { let r = rand::random::<i32>(); a }",
                "rand_effect",
            ),
            (
                "pub fn f(a: i32) -> i32 { println!(\"{}\", a); a }",
                "print_macro",
            ),
            (
                "pub fn f(a: i32) -> i32 { unsafe { *(&a as *const i32) } }",
                "unsafe_block",
            ),
            (
                "pub fn f(a: i32) -> i32 { std::env::var(\"X\").ok(); a }",
                "env_effect",
            ),
        ] {
            let r = one(src);
            assert!(!r.fuzz.is_admitted(), "should be blocked: {src}");
            assert!(
                codes(&r.fuzz).contains(&code),
                "expected {code}, got {:?} for {src}",
                codes(&r.fuzz)
            );
        }
    }

    #[test]
    fn signature_shapes_are_rejected() {
        for (src, code) in [
            ("pub async fn f(a: i32) -> i32 { a }", "async"),
            ("pub unsafe fn f(a: i32) -> i32 { a }", "unsafe_fn"),
            ("pub fn f<T>(a: T) -> T { a }", "generic"),
            ("pub fn f(a: &mut i32) -> i32 { *a }", "mut_ref_param"),
            ("pub fn f(a: f64) -> f64 { a }", "float_type"),
            ("pub fn f(a: i32) {}", "unit_return"),
            ("pub fn f(a: *const i32) -> i32 { 0 }", "raw_pointer"),
            (
                "pub fn f(a: i32) -> impl Iterator<Item = i32> { std::iter::once(a) }",
                "impl_trait",
            ),
            (
                "pub fn f(a: Box<dyn Fn() -> i32>) -> i32 { 0 }",
                "trait_object",
            ),
        ] {
            let r = one(src);
            assert!(
                codes(&r.fuzz).contains(&code),
                "expected {code}, got {:?} for {src}",
                codes(&r.fuzz)
            );
        }
    }

    #[test]
    fn lifetimes_alone_are_fine() {
        let r = one("pub fn first<'a>(s: &'a str) -> u32 { s.len() as u32 }");
        assert!(!codes(&r.fuzz).contains(&"generic"), "{:?}", codes(&r.fuzz));
    }

    #[test]
    fn recursion_is_detected_and_blocks_proving_only() {
        let r =
            one("pub fn fib(n: u32) -> u32 { if n < 2 { n } else { fib(n - 1) + fib(n - 2) } }");
        assert!(r.facts.has_recursion);
        assert!(r.fuzz.is_admitted(), "{:?}", r.fuzz);
        assert!(codes(&r.prove).contains(&"recursion"));
    }

    #[test]
    fn unknown_free_call_is_rejected_conservatively() {
        let r = one("pub fn f(a: i32) -> i32 { helper(a) }");
        assert!(codes(&r.fuzz).contains(&"unresolved_call"));
    }

    #[test]
    fn enum_constructors_are_not_unresolved_calls() {
        let r = one("pub fn f(a: i32) -> Option<i32> { Some(a) }");
        assert!(
            !codes(&r.fuzz).contains(&"unresolved_call"),
            "Some(..) must not count as a call: {:?}",
            codes(&r.fuzz)
        );
        assert!(r.fuzz.is_admitted(), "{:?}", r.fuzz);
    }

    #[test]
    fn all_reasons_are_collected_not_short_circuited() {
        // Phase 0's histogram depends on this: if we stopped at the first
        // failure the numbers would be biased by check order.
        let r = one("pub async unsafe fn f<T>(a: f64, b: *const T) {}");
        let c = codes(&r.fuzz);
        for expected in [
            "async",
            "unsafe_fn",
            "generic",
            "float_type",
            "raw_pointer",
            "unit_return",
        ] {
            assert!(c.contains(&expected), "missing {expected} in {c:?}");
        }
    }

    #[test]
    fn public_only_filter_works() {
        let src = "pub fn a(x: i32) -> i32 { x } fn b(x: i32) -> i32 { x }";
        let pub_only = analyze_str(src, &Config { public_only: true }).unwrap();
        assert_eq!(pub_only.len(), 1);
        assert_eq!(pub_only[0].name, "a");
        let all = analyze_str(src, &Config { public_only: false }).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn inherent_impl_associated_fns_are_analysed() {
        let src = "pub struct S; impl S { pub fn make(x: i32) -> i32 { x } pub fn m(&self) -> i32 { 0 } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r
            .iter()
            .find(|f| f.name == "make")
            .unwrap()
            .fuzz
            .is_admitted());
        // `&self` is now an input like any other, so this is admissible.
        let m = r.iter().find(|f| f.name == "m").unwrap();
        assert!(m.fuzz.is_admitted(), "{:?}", codes(&m.fuzz));
        assert_eq!(m.facts.params, 1, "the receiver counts as a parameter");
    }

    #[test]
    fn mut_self_receiver_is_still_rejected() {
        // `&mut self` is a second output channel, so the return value is no
        // longer the whole observable.
        let src = "pub struct S; impl S { pub fn bump(&mut self) -> i32 { 0 } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert!(codes(&r[0].fuzz).contains(&"mut_ref_param"));
    }

    #[test]
    fn receiver_of_an_unsupported_type_is_rejected() {
        let src = "pub struct S { x: f64 } impl S { pub fn get(&self) -> i32 { 0 } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert!(codes(&r[0].fuzz).contains(&"unsupported_type"));
    }

    #[test]
    fn crate_local_struct_is_resolved_not_rejected() {
        // The single change that mattered most: before type resolution this
        // was `unsupported_type`, which blocked 80% of real public functions.
        let src = "#[derive(PartialEq)] pub struct P { pub x: i32, pub y: i32 }
                   pub fn flip(p: P) -> P { P { x: p.y, y: p.x } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        let flip = r.iter().find(|f| f.name == "flip").unwrap();
        assert!(flip.fuzz.is_admitted(), "{:?}", codes(&flip.fuzz));
        assert!(flip.prove.is_admitted(), "{:?}", codes(&flip.prove));
    }

    #[test]
    fn returned_local_type_must_be_comparable() {
        // No `PartialEq` derive: we could generate the input but could not
        // compare the output, so there is no observable.
        let src = "pub struct P { pub x: i32 }
                   pub fn make(x: i32) -> P { P { x } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        let make = r.iter().find(|f| f.name == "make").unwrap();
        assert!(
            codes(&make.fuzz).contains(&"unsupported_type"),
            "{:?}",
            codes(&make.fuzz)
        );
    }

    #[test]
    fn local_type_carrying_a_vec_is_unbounded_for_proving_only() {
        let src = "#[derive(PartialEq)] pub struct B { pub v: Vec<u8> }
                   pub fn head(b: B) -> u32 { b.v.len() as u32 }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        let head = r.iter().find(|f| f.name == "head").unwrap();
        assert!(head.fuzz.is_admitted(), "{:?}", codes(&head.fuzz));
        assert!(codes(&head.prove).contains(&"unbounded_input"));
    }

    // ---- call paths -----------------------------------------------------
    //
    // A bare name is not enough to build a probe with: `equiv_old::parse(..)`
    // does not compile for an associated function, and is ambiguous the moment
    // a crate has two functions called `parse`.

    fn paths(src: &str) -> Vec<(String, bool)> {
        let mut v: Vec<(String, bool)> = analyze_str(src, &Config { public_only: true })
            .unwrap()
            .into_iter()
            .map(|r| (r.path, r.reachable))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_free_function_is_its_own_path() {
        assert_eq!(
            paths("pub fn parse(s: &str) -> u32 { 0 }"),
            [("parse".to_string(), true)]
        );
    }

    #[test]
    fn an_associated_function_is_qualified_by_its_type() {
        let src = "pub struct Version; impl Version { pub fn parse(s: &str) -> u32 { 0 } }";
        assert_eq!(paths(src), [("Version::parse".to_string(), true)]);
    }

    #[test]
    fn a_generic_self_type_keeps_the_bare_type_name() {
        // `Wrapper<T>::get` is not how a call site spells it, and the turbofish
        // is inferred, so the bare name is the callable path. (The function is
        // rejected for being generic; the path still has to be right.)
        let src = "pub struct Wrapper<T>(T); impl<T> Wrapper<T> { pub fn get(x: u8) -> u8 { x } }";
        assert_eq!(paths(src), [("Wrapper::get".to_string(), true)]);
    }

    #[test]
    fn inline_modules_prefix_the_path() {
        let src = "pub mod parser { pub fn tokenize(s: &str) -> u32 { 0 }
                       pub mod inner { pub fn deep(a: u8) -> u8 { a } } }";
        assert_eq!(
            paths(src),
            [
                ("parser::inner::deep".to_string(), true),
                ("parser::tokenize".to_string(), true),
            ]
        );
    }

    #[test]
    fn a_pub_fn_in_a_private_module_is_not_reachable_at_that_path() {
        // `imp::helper` does not compile from outside the crate. It may still
        // be callable elsewhere via `pub use`, which is why this is a flag on
        // the path rather than a rejection.
        assert_eq!(
            paths("mod imp { pub fn helper(a: u8) -> u8 { a } }"),
            [("imp::helper".to_string(), false)]
        );
    }

    #[test]
    fn a_pub_fn_on_a_private_type_is_not_reachable() {
        let src = "struct Config; impl Config { pub fn new(a: u8) -> u8 { a } }";
        assert_eq!(paths(src), [("Config::new".to_string(), false)]);
    }

    #[test]
    fn an_unnameable_self_type_is_not_reachable() {
        // There is no path that spells this, so no path is claimed.
        let src = "impl (u8, u8) { pub fn f(a: u8) -> u8 { a } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert_eq!(r.len(), 1);
        assert!(!r[0].reachable, "no nameable type means no callable path");
    }

    #[test]
    fn private_functions_are_never_reachable() {
        let r = analyze_str(
            "fn helper(a: u8) -> u8 { a }",
            &Config { public_only: false },
        )
        .unwrap();
        assert_eq!(r[0].path, "helper");
        assert!(!r[0].reachable);
    }

    #[test]
    fn analyze_files_prefixes_with_the_files_module() {
        let root = parse("pub mod parser;").unwrap();
        let parser = parse("pub fn tokenize(s: &str) -> u32 { 0 }").unwrap();
        let r = analyze_files(
            &[
                SourceFile::root(&root),
                SourceFile::in_module("parser", &parser),
            ],
            &Config::default(),
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].path, "parser::tokenize");
        assert!(r[0].reachable);
    }

    #[test]
    fn a_file_module_declared_private_makes_its_contents_unreachable() {
        // The `mod` item lives in the parent file, so this can only be resolved
        // by looking at the whole crate — which is why it is done here and not
        // per file.
        let root = parse("mod imp;").unwrap();
        let imp = parse("pub fn helper(a: u8) -> u8 { a }").unwrap();
        let r = analyze_files(
            &[SourceFile::root(&root), SourceFile::in_module("imp", &imp)],
            &Config::default(),
        );
        assert_eq!(r[0].path, "imp::helper");
        assert!(!r[0].reachable);
    }

    #[test]
    fn module_paths_follow_cargo_layout() {
        let p = |s: &str| module_path_of(std::path::Path::new(s));
        assert_eq!(p("src/lib.rs").as_deref(), Some(""));
        assert_eq!(p("src/main.rs").as_deref(), Some(""));
        assert_eq!(p("src/foo.rs").as_deref(), Some("foo"));
        assert_eq!(p("src/foo/mod.rs").as_deref(), Some("foo"));
        assert_eq!(p("src/foo/bar.rs").as_deref(), Some("foo::bar"));
        assert_eq!(
            p("/abs/semver-1.0.23/src/parse.rs").as_deref(),
            Some("parse")
        );
        // Nothing to go on: the caller must fall back to the crate root rather
        // than have a module invented for it.
        assert_eq!(p("lib.rs"), None);
        assert_eq!(p("src/notrust.txt"), None);
    }

    // ---- effects that only the whole crate can reveal ---------------------

    #[test]
    fn reading_a_stateful_static_is_an_effect() {
        // The read is spelled exactly like a local variable. Only the crate-wide
        // index distinguishes them, which is why this cannot be decided per
        // function — and why it was invisible while `StaticAccess` fired solely
        // on statics declared *inside* a body.
        let src = "static CACHE: Mutex<i32> = Mutex::new(0);
                   pub fn peek(x: i32) -> i32 { CACHE.load() + x }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        let f = r.iter().find(|f| f.name == "peek").unwrap();
        assert!(
            codes(&f.fuzz).contains(&"static_access"),
            "{:?}",
            codes(&f.fuzz)
        );
    }

    #[test]
    fn an_immutable_lookup_table_is_not_an_effect() {
        // `roman` — the crate this project benchmarks against — holds its
        // numeral table exactly like this. Rejecting it would cost the single
        // most valuable target in the corpus for no soundness gain: reading a
        // constant is pure.
        let src = "static NUMERALS: &[(char, i32)] = &[('I', 1)];
                   pub fn value(i: usize) -> i32 { NUMERALS[i].1 }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        let f = r.iter().find(|f| f.name == "value").unwrap();
        assert!(
            !codes(&f.fuzz).contains(&"static_access"),
            "immutable table must stay admissible: {:?}",
            codes(&f.fuzz)
        );
    }

    #[test]
    fn a_local_shadowing_a_static_is_not_an_effect() {
        let src = "static CACHE: OnceLock<i32> = OnceLock::new();
                   pub fn clamp(x: i32) -> i32 { let CACHE = x; CACHE }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        let f = r.iter().find(|f| f.name == "clamp").unwrap();
        assert!(
            !codes(&f.fuzz).contains(&"static_access"),
            "{:?}",
            codes(&f.fuzz)
        );
    }

    #[test]
    fn a_static_read_in_its_own_initialiser_position_still_counts() {
        // `let x = x + 1;` reads the outer `x`. Binding the name before
        // visiting the initialiser would hide that read.
        let src = "static SEED: AtomicU32 = AtomicU32::new(0);
                   pub fn go(a: u32) -> u32 { let SEED = SEED.load() + a; SEED }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert!(
            codes(&r[0].fuzz).contains(&"static_access"),
            "{:?}",
            codes(&r[0].fuzz)
        );
    }

    #[test]
    fn a_static_mut_is_always_stateful() {
        let src = "static mut COUNT: i32 = 0;
                   pub fn bump(a: i32) -> i32 { COUNT + a }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert!(
            codes(&r[0].fuzz).contains(&"static_access"),
            "{:?}",
            codes(&r[0].fuzz)
        );
    }

    #[test]
    fn a_same_named_call_in_another_module_is_not_recursion() {
        // Matching on the last path segment read this as recursion, and
        // recursion does not block fuzzing — so an unresolved callee that
        // happened to share the function's name was waved through.
        let r = one("pub fn parse(s: u8) -> u8 { other::parse(s) }");
        assert!(!r.facts.has_recursion, "`other::parse` is not a self-call");
        assert!(
            codes(&r.fuzz).contains(&"unresolved_call"),
            "{:?}",
            codes(&r.fuzz)
        );
    }

    #[test]
    fn self_qualified_recursion_is_still_recursion() {
        let src = "pub struct S; impl S { pub fn fact(n: u32) -> u32 {
                       if n < 2 { 1 } else { n * Self::fact(n - 1) } } }";
        let r = analyze_str(src, &Config { public_only: true }).unwrap();
        assert!(r[0].facts.has_recursion);
        assert!(r[0].fuzz.is_admitted(), "{:?}", codes(&r[0].fuzz));
    }

    #[test]
    fn a_method_sharing_the_fn_name_is_still_purity_checked() {
        // `xs.spawn()` inside `fn spawn` is not necessarily recursion, and
        // treating it as such skipped the allowlist entirely.
        let r = one("pub fn spawn(xs: Vec<u8>) -> u8 { xs.spawn() }");
        assert!(
            codes(&r.fuzz).contains(&"unresolved_method"),
            "{:?}",
            codes(&r.fuzz)
        );
    }

    #[test]
    fn a_pure_method_sharing_the_fn_name_is_not_rejected() {
        let r = one("pub fn len(xs: Vec<u8>) -> usize { xs.len() }");
        assert!(r.fuzz.is_admitted(), "{:?}", codes(&r.fuzz));
    }

    #[test]
    fn reports_serialize() {
        let r = one("pub fn f(a: i32) -> i32 { a }");
        let s = serde_json::to_string(&r).unwrap();
        let back: FnReport = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}
