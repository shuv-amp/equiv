//! Public re-export resolution: `pub use`.
//!
//! # Why this is not optional
//!
//! Where an item is *written* and where it is *callable* are different places
//! in almost every published crate. The facade pattern is near-universal:
//!
//! ```text
//! // textwrap/src/lib.rs
//! mod indentation;                          // private
//! pub use indentation::{dedent, indent};    // public at the crate root
//! ```
//!
//! `dedent` is written at `indentation::dedent`, which does not compile from
//! outside the crate, and is callable at `textwrap::dedent`, which does.
//! Measured over `textwrap`, `bytecount`, `semver`, `hex` and `urlencoding`,
//! **every** admissible function was written inside a private module. A gate
//! that reports only the syntactic path yields zero usable probe targets on
//! real code.
//!
//! # Method
//!
//! Collect every `pub use`, resolve its target to a crate-root-relative path,
//! and record `written path -> public path`. Apply by longest-prefix match, and
//! iterate to a fixed point so that chains (`pub use a::b;` where `a` itself
//! re-exports) resolve.
//!
//! # Limits
//!
//! Syntactic, like the rest of the gate. It does not resolve `use` targets that
//! leave the crate, `#[cfg]`-gated re-exports, or macro-generated ones. Every
//! blind spot leaves the path as written and [`FnReport::reachable`] false —
//! never a path asserted to work that does not.
//!
//! [`FnReport::reachable`]: crate::FnReport::reachable

use std::collections::BTreeMap;

use crate::{CrateIndex, SourceFile};

/// What a `pub use` binds.
enum Leaf {
    /// `pub use a::b;` and `pub use a::b as c;`
    Name { item: String, alias: String },
    /// `pub use a::*;`
    Glob,
}

/// Crate-root-relative re-export map.
#[derive(Debug, Default)]
pub struct Exports {
    /// Written path -> public path.
    direct: BTreeMap<String, String>,
    /// `pub use a::*;` in module `m` -> (`a`, `m`). Everything under `a` is
    /// reachable under `m`.
    globs: Vec<(String, String)>,
}

impl Exports {
    /// Build the map from every `pub use` in the crate.
    ///
    /// Every one is collected, including those inside private modules. Such a
    /// re-export does not reach outside the crate on its own, but it does
    /// establish an alias that an outer `pub use` can chain from:
    ///
    /// ```text
    /// mod mid;                       // private
    /// pub use mid::go;               // root: mid::go     -> go
    /// //   mid/mod.rs
    /// mod inner;
    /// pub use inner::go;             // mid:  mid::inner::go -> mid::go
    /// ```
    ///
    /// Dropping the inner entry loses the chain. Whether the *final* path is
    /// externally visible is decided by [`path_is_public`], after resolution.
    pub(crate) fn of<'a>(files: &'a [SourceFile<'a>]) -> Self {
        let mut out = Exports::default();
        for sf in files {
            for item in sf.file.items.iter() {
                collect(item, &sf.module, &mut out);
            }
        }
        // `direct` is a BTreeMap and so already ordered; globs are collected in
        // file order, which is not a property of the crate. Sort them so two
        // runs over the same crate cannot disagree.
        out.globs.sort();
        out.globs.dedup();
        out
    }

    fn insert(&mut self, written: String, public: String) {
        // An item can be re-exported at several paths. The shortest is the one
        // a caller is meant to use; ties break lexicographically so the result
        // does not depend on the order files were handed to us.
        match self.direct.get(&written) {
            Some(existing) if !better(&public, existing) => {}
            _ => {
                self.direct.insert(written, public);
            }
        }
    }

    /// Rewrite a written path to the path it is publicly callable at.
    ///
    /// Returns `None` when no re-export applies, in which case the caller keeps
    /// the written path and reports it as unreachable.
    pub fn resolve(&self, path: &str) -> Option<String> {
        let mut cur = path.to_string();
        let mut changed = false;
        // Chains are short in practice; the cap is what makes a cyclic
        // `pub use` terminate rather than hang.
        for _ in 0..8 {
            match self.step(&cur) {
                Some(next) if next != cur => {
                    cur = next;
                    changed = true;
                }
                _ => break,
            }
        }
        changed.then_some(cur)
    }

    /// One rewrite, by longest matching prefix.
    fn step(&self, path: &str) -> Option<String> {
        let mut best: Option<(usize, String)> = None;
        let mut consider = |key: &str, target: &str| {
            let Some(rest) = strip_prefix_path(path, key) else {
                return;
            };
            if best.as_ref().is_some_and(|(len, _)| *len >= key.len()) {
                return;
            }
            best = Some((key.len(), join(target, rest)));
        };
        for (written, public) in &self.direct {
            consider(written, public);
        }
        for (from, to) in &self.globs {
            consider(from, to);
        }
        best.map(|(_, p)| p)
    }
}

/// Whether a resolved item path is callable from outside the crate.
///
/// Only the qualifying segments are checked; the last is the item itself, whose
/// own visibility the caller already knows.
pub(crate) fn path_is_public(path: &str, index: &CrateIndex) -> bool {
    let segs: Vec<&str> = path.split("::").collect();
    segs[..segs.len().saturating_sub(1)]
        .iter()
        .all(|s| !s.is_empty() && !index.private_modules.contains(*s))
}

/// `a::b::c` with prefix `a::b` -> `Some("c")`; exact match -> `Some("")`.
/// Segment-aware, so `ab` is not a prefix of `abc`.
fn strip_prefix_path<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        return None;
    }
    if path == prefix {
        return Some("");
    }
    path.strip_prefix(prefix)?.strip_prefix("::")
}

fn join(base: &str, rest: &str) -> String {
    match (base.is_empty(), rest.is_empty()) {
        (true, _) => rest.to_string(),
        (_, true) => base.to_string(),
        _ => format!("{base}::{rest}"),
    }
}

/// Ordering key for "which public path should we report".
///
/// Fewest segments first — that is the path a caller reaches for, and the one
/// crate docs lead with. Then shortest, then lexicographic, so the winner is a
/// total order and never depends on the order files were handed to us.
fn rank(path: &str) -> (usize, usize, &str) {
    (path.split("::").count(), path.len(), path)
}

fn better(candidate: &str, existing: &str) -> bool {
    rank(candidate) < rank(existing)
}

fn collect(item: &syn::Item, module: &str, out: &mut Exports) {
    match item {
        syn::Item::Use(u) => {
            if !matches!(u.vis, syn::Visibility::Public(_)) {
                return;
            }
            let mut leaves = Vec::new();
            flatten(&u.tree, &mut Vec::new(), &mut leaves);
            for (prefix, leaf) in leaves {
                let Some(target) = resolve_use_prefix(&prefix, module) else {
                    continue;
                };
                match leaf {
                    Leaf::Name { item, alias } => {
                        out.insert(join(&target, &item), join(module, &alias));
                    }
                    Leaf::Glob => out.globs.push((target, module.to_string())),
                }
            }
        }
        syn::Item::Mod(m) => {
            if let Some((_, items)) = &m.content {
                let inner = join(module, &m.ident.to_string());
                for it in items {
                    collect(it, &inner, out);
                }
            }
        }
        _ => {}
    }
}

/// Turn a `use` path's leading segments into a crate-root-relative module path.
///
/// Rust 2018 uniform paths mean a bare first segment may name an item in the
/// current module *or* an external crate. We resolve it against the current
/// module; if that names nothing local, the resulting map entry simply never
/// matches a function path, which is the harmless outcome.
fn resolve_use_prefix(segments: &[String], module: &str) -> Option<String> {
    let mut base: Vec<String> = module
        .split("::")
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let mut rest = segments;

    loop {
        match rest.first().map(String::as_str) {
            Some("crate") => {
                base.clear();
                rest = &rest[1..];
            }
            Some("self") => {
                rest = &rest[1..];
            }
            Some("super") => {
                base.pop()?;
                rest = &rest[1..];
            }
            // A `use` leaving the crate cannot re-export anything we analyse.
            Some("std" | "core" | "alloc") => return None,
            _ => break,
        }
    }

    base.extend(rest.iter().cloned());
    Some(base.join("::"))
}

fn flatten(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, Leaf)>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => out.push((
            prefix.clone(),
            Leaf::Name {
                item: n.ident.to_string(),
                alias: n.ident.to_string(),
            },
        )),
        syn::UseTree::Rename(r) => out.push((
            prefix.clone(),
            Leaf::Name {
                item: r.ident.to_string(),
                alias: r.rename.to_string(),
            },
        )),
        syn::UseTree::Glob(_) => out.push((prefix.clone(), Leaf::Glob)),
        syn::UseTree::Group(g) => {
            for t in &g.items {
                flatten(t, prefix, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze_files, parse, Config, SourceFile};

    /// Resolve paths for a crate given as `(module, source)` pairs.
    fn paths(files: &[(&str, &str)]) -> Vec<(String, bool)> {
        let parsed: Vec<syn::File> = files.iter().map(|(_, s)| parse(s).unwrap()).collect();
        let sources: Vec<SourceFile> = files
            .iter()
            .zip(&parsed)
            .map(|((m, _), f)| SourceFile::in_module(*m, f))
            .collect();
        let mut v: Vec<(String, bool)> = analyze_files(&sources, &Config::default())
            .into_iter()
            .map(|r| (r.path, r.reachable))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn the_facade_pattern_resolves() {
        // Exactly textwrap's shape, which is the shape of most published crates.
        assert_eq!(
            paths(&[
                (
                    "",
                    "mod indentation; pub use indentation::{dedent, indent};"
                ),
                (
                    "indentation",
                    "pub fn dedent(s: &str) -> String { String::new() }"
                ),
            ]),
            [("dedent".to_string(), true)]
        );
    }

    #[test]
    fn a_glob_reexport_resolves() {
        // bytecount's shape: `mod naive; pub use naive::*;`
        assert_eq!(
            paths(&[
                ("", "mod naive; pub use naive::*;"),
                (
                    "naive",
                    "pub fn naive_count(h: &[u8], n: u8) -> usize { 0 }"
                ),
            ]),
            [("naive_count".to_string(), true)]
        );
    }

    #[test]
    fn a_reexported_type_carries_its_associated_functions() {
        // The `pub use` names the type; the function hangs off it and has to be
        // rewritten by prefix, not by exact match.
        assert_eq!(
            paths(&[
                ("", "mod line_ending; pub use line_ending::LineEnding;"),
                (
                    "line_ending",
                    "pub struct LineEnding; impl LineEnding { pub fn as_str(x: u8) -> u8 { x } }"
                ),
            ]),
            [("LineEnding::as_str".to_string(), true)]
        );
    }

    #[test]
    fn crate_qualified_reexports_resolve() {
        // semver's shape: `pub use crate::parse::Error;`
        assert_eq!(
            paths(&[
                ("", "mod parse; pub use crate::parse::parse_version;"),
                ("parse", "pub fn parse_version(s: &str) -> u32 { 0 }"),
            ]),
            [("parse_version".to_string(), true)]
        );
    }

    #[test]
    fn renamed_reexports_use_the_new_name() {
        assert_eq!(
            paths(&[
                ("", "mod imp; pub use imp::go as run;"),
                ("imp", "pub fn go(a: u8) -> u8 { a }"),
            ]),
            [("run".to_string(), true)]
        );
    }

    #[test]
    fn reexport_into_a_public_module_keeps_the_prefix() {
        assert_eq!(
            paths(&[
                ("", "pub mod api; mod imp;"),
                ("api", "pub use crate::imp::go;"),
                ("imp", "pub fn go(a: u8) -> u8 { a }"),
            ]),
            [("api::go".to_string(), true)]
        );
    }

    #[test]
    fn a_private_reexport_does_not_make_anything_public() {
        // `use` without `pub` is not a re-export, so the path stays as written.
        assert_eq!(
            paths(&[
                ("", "mod imp; use imp::go;"),
                ("imp", "pub fn go(a: u8) -> u8 { a }"),
            ]),
            [("imp::go".to_string(), false)]
        );
    }

    #[test]
    fn a_reexport_inside_a_private_module_does_not_escape() {
        assert_eq!(
            paths(&[
                ("", "mod hidden; mod imp;"),
                ("hidden", "pub use crate::imp::go;"),
                ("imp", "pub fn go(a: u8) -> u8 { a }"),
            ]),
            [("imp::go".to_string(), false)]
        );
    }

    #[test]
    fn chained_reexports_resolve_to_the_outermost_path() {
        assert_eq!(
            paths(&[
                ("", "mod mid; pub use mid::go;"),
                ("mid", "mod inner; pub use inner::go;"),
                ("mid::inner", "pub fn go(a: u8) -> u8 { a }"),
            ]),
            [("go".to_string(), true)]
        );
    }

    #[test]
    fn a_cyclic_reexport_terminates() {
        // Not valid Rust, but the resolver must not hang on it.
        let e = Exports {
            direct: [
                ("a::f".to_string(), "b::f".to_string()),
                ("b::f".to_string(), "a::f".to_string()),
            ]
            .into_iter()
            .collect(),
            globs: Vec::new(),
        };
        let _ = e.resolve("a::f");
    }

    #[test]
    fn paths_without_a_reexport_are_left_alone() {
        let e = Exports::default();
        assert_eq!(e.resolve("imp::go"), None);
    }

    #[test]
    fn prefix_matching_respects_segment_boundaries() {
        assert_eq!(strip_prefix_path("ab::c", "ab"), Some("c"));
        assert_eq!(strip_prefix_path("abc::d", "ab"), None);
        assert_eq!(strip_prefix_path("ab", "ab"), Some(""));
    }
}
