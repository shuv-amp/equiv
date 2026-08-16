//! Allowlists and the supported-type predicate.
//!
//! Everything here is deliberately conservative: when the analysis cannot
//! resolve something, it rejects. The gate over-rejects and never
//! under-rejects, so the eligibility rate it reports is a **lower bound** on
//! the true rate. That is the correct bias — a Phase 0 number that is too
//! pessimistic costs us effort, a number that is too optimistic costs us the
//! whole project.

use syn::Type;

use crate::reject::Reject;
use crate::typeenv::TypeEnv;

// ---------------------------------------------------------------------------
// Effect classification by path
// ---------------------------------------------------------------------------

/// Classify a fully-rendered path (e.g. `std::fs::read`, `Instant::now`).
///
/// Returns `None` when the path looks inert.
pub fn classify_path(path: &str) -> Option<Reject> {
    let segs: Vec<&str> = path.split("::").filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return None;
    }
    let head = segs[0];
    let last = *segs.last().unwrap();

    // std/core/alloc module heads that imply an effect.
    if matches!(head, "std" | "core" | "alloc") && segs.len() >= 2 {
        match segs[1] {
            "fs" | "net" | "io" | "process" => return Some(Reject::IoEffect(path.to_string())),
            "time" => return Some(Reject::TimeEffect(path.to_string())),
            "thread" | "sync" => return Some(Reject::ConcurrencyEffect(path.to_string())),
            "env" => return Some(Reject::EnvEffect(path.to_string())),
            _ => {}
        }
    }

    // Bare module heads, as they appear after a `use`.
    match head {
        "fs" | "net" | "process" => return Some(Reject::IoEffect(path.to_string())),
        "rand" | "getrandom" | "fastrand" => return Some(Reject::RandEffect(path.to_string())),
        "thread" | "rayon" | "tokio" | "async_std" => {
            return Some(Reject::ConcurrencyEffect(path.to_string()))
        }
        _ => {}
    }

    // Type names that imply an effect wherever they appear.
    for seg in &segs {
        if let Some(r) = classify_type_name(seg, path) {
            return Some(r);
        }
    }

    // Randomness by function name.
    if matches!(last, "random" | "thread_rng" | "rng" | "gen_range") {
        return Some(Reject::RandEffect(path.to_string()));
    }

    None
}

/// Classify a bare type name for effectfulness.
pub fn classify_type_name(name: &str, ctx: &str) -> Option<Reject> {
    if name.starts_with("Atomic") {
        return Some(Reject::InteriorMutability(ctx.to_string()));
    }
    match name {
        "Cell" | "RefCell" | "UnsafeCell" | "Mutex" | "RwLock" | "OnceCell" | "OnceLock"
        | "LazyLock" | "LazyCell" | "SyncUnsafeCell" => {
            Some(Reject::InteriorMutability(ctx.to_string()))
        }
        "File" | "Stdin" | "Stdout" | "Stderr" | "TcpStream" | "TcpListener" | "UdpSocket"
        | "Command" | "Child" => Some(Reject::IoEffect(ctx.to_string())),
        // NB: `Path`, `PathBuf` and `Duration` are pure data types. They fall
        // through to `UnsupportedType`, which is the accurate reason — treating
        // them as effects would inflate the effect histogram misleadingly.
        "Instant" | "SystemTime" => Some(Reject::TimeEffect(ctx.to_string())),
        "JoinHandle" | "Thread" => Some(Reject::ConcurrencyEffect(ctx.to_string())),
        _ => None,
    }
}

/// Macros that write to an output channel we do not model.
pub fn classify_macro(name: &str) -> Option<Reject> {
    match name {
        "println" | "print" | "eprintln" | "eprint" | "dbg" => {
            Some(Reject::PrintMacro(name.to_string()))
        }
        // Control flow and diagnostics we can see through: a panic is an
        // observable outcome we compare, not an unmodelled effect.
        "panic" | "assert" | "assert_eq" | "assert_ne" | "debug_assert" | "debug_assert_eq"
        | "debug_assert_ne" | "unreachable" | "todo" | "unimplemented" | "matches" | "vec"
        | "format" | "write" | "writeln" | "concat" | "stringify" => None,
        other => Some(Reject::UnresolvedMacro(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Pure-function and pure-method allowlists
// ---------------------------------------------------------------------------

/// Free functions known to be pure and deterministic.
pub fn is_pure_fn(path: &str) -> bool {
    let last = path.rsplit("::").next().unwrap_or(path);
    matches!(
        last,
        "min"
            | "max"
            | "abs"
            | "signum"
            | "swap"
            | "replace"
            | "take"
            | "size_of"
            | "align_of"
            | "from"
            | "into"
            | "try_from"
            | "try_into"
            | "default"
            | "identity"
            | "from_str"
            | "from_utf8"
            | "from_utf8_lossy"
            | "new"
            | "with_capacity"
            | "repeat"
            | "once"
            | "empty"
            | "from_fn"
    )
}

/// Methods known to be pure and deterministic on supported types.
///
/// Anything not listed is rejected as [`Reject::UnresolvedMethod`]. This will
/// over-reject; Phase 0 measures by exactly how much.
pub fn is_pure_method(name: &str) -> bool {
    // Arithmetic families, matched by prefix.
    for p in [
        "wrapping_",
        "checked_",
        "saturating_",
        "overflowing_",
        "carrying_",
        "borrowing_",
        "unbounded_",
        "to_",
        "as_",
        "is_",
        "trailing_",
        "leading_",
        "count_",
        "rotate_",
        "from_",
        "try_",
    ] {
        if name.starts_with(p) {
            return true;
        }
    }

    matches!(
        name,
        // sizing / access
        "len" | "get" | "first" | "last" | "iter" | "into_iter" | "chars" | "bytes"
            | "char_indices" | "lines" | "split" | "splitn" | "rsplit" | "split_whitespace"
            | "split_at" | "chunks" | "windows" | "elem" | "index" | "get_mut"
        // transformation
            | "map" | "map_err" | "and_then" | "or_else" | "filter" | "filter_map" | "flat_map"
            | "flatten" | "fold" | "reduce" | "scan" | "zip" | "chain" | "enumerate" | "rev"
            | "take_while" | "skip_while" | "skip" | "step_by" | "peekable" | "cloned" | "copied"
            | "collect" | "extend" | "sum" | "product" | "count" | "position" | "find" | "find_map"
            | "any" | "all" | "min_by" | "max_by" | "min_by_key" | "max_by_key" | "partition"
        // strings
            | "trim" | "trim_start" | "trim_end" | "trim_matches" | "starts_with" | "ends_with"
            | "contains" | "replace" | "replacen" | "repeat" | "parse" | "join" | "concat"
            | "chars_rev" | "escape_debug" | "escape_default" | "strip_prefix" | "strip_suffix"
        // collections (owned mutation of a local is fine: the effect stays inside)
            | "push" | "pop" | "push_str" | "insert" | "remove" | "clear" | "truncate"
            | "sort" | "sort_by" | "sort_by_key" | "sort_unstable" | "dedup" | "reverse"
            | "append" | "split_off" | "retain" | "resize" | "fill" | "swap" | "swap_remove"
            | "binary_search" | "binary_search_by" | "contains_key" | "entry" | "keys" | "values"
        // option / result
            | "unwrap" | "expect" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default"
            | "ok" | "err" | "ok_or" | "ok_or_else" | "some" | "take" | "replace_with"
        // comparison / conversion
            | "clone" | "cmp" | "partial_cmp" | "eq" | "ne" | "lt" | "le" | "gt" | "ge"
            | "min" | "max" | "clamp" | "abs" | "signum" | "pow" | "rem_euclid" | "div_euclid"
            | "next" | "next_back" | "into" | "borrow" | "as_ref" | "deref"
    )
}

// ---------------------------------------------------------------------------
// Supported types
// ---------------------------------------------------------------------------

/// Where a type appears. Only affects which reject variants make sense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Param,
    Return,
}

/// Check whether a type is admissible, collecting every problem found.
///
/// `unbounded` accumulates types that are fine to fuzz but need a declared
/// bound before they can be proved (`Vec`, `String`, slices).
/// Context a type is checked in.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    pub env: &'a TypeEnv,
    /// The `impl` self type, so `Self` can be resolved.
    pub self_ty: Option<&'a Type>,
}

impl<'a> Ctx<'a> {
    pub fn new(env: &'a TypeEnv) -> Self {
        Self { env, self_ty: None }
    }
    fn without_self(self) -> Self {
        Self {
            env: self.env,
            self_ty: None,
        }
    }
}

pub fn check_type(
    ty: &Type,
    pos: Position,
    out: &mut Vec<Reject>,
    unbounded: &mut Vec<String>,
    ctx: Ctx<'_>,
) {
    let env = ctx.env;
    match ty {
        Type::Path(tp) => {
            if tp.qself.is_some() {
                out.push(Reject::UnsupportedType("qualified path".into()));
                return;
            }
            let Some(seg) = tp.path.segments.last() else {
                out.push(Reject::UnsupportedType("empty path".into()));
                return;
            };
            let name = seg.ident.to_string();

            if let Some(r) = classify_type_name(&name, &name) {
                out.push(r);
                return;
            }

            match name.as_str() {
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "usize" | "bool" | "char" => {}
                "f32" | "f64" => out.push(Reject::FloatType(name)),
                "String" | "str" => unbounded.push(name.clone()),
                // `Self` in an inherent impl denotes the impl type.
                "Self" => match ctx.self_ty {
                    Some(t) => check_type(t, pos, out, unbounded, ctx.without_self()),
                    None => out.push(Reject::UnsupportedType("Self".into())),
                },
                "Vec" | "VecDeque" => {
                    unbounded.push(name.clone());
                    for inner in generic_types(seg) {
                        check_type(inner, pos, out, unbounded, ctx);
                    }
                }
                "Option" | "Result" | "Box" | "Wrapping" | "Reverse" => {
                    for inner in generic_types(seg) {
                        check_type(inner, pos, out, unbounded, ctx);
                    }
                }
                // A crate-local type is supported when all of its fields are.
                other => match env.lookup(other) {
                    Some(lt) if lt.supported => {
                        if lt.unbounded {
                            unbounded.push(other.to_string());
                        }
                        // Only the returned value has to be comparable.
                        if pos == Position::Return && !lt.has_partial_eq {
                            out.push(Reject::UnsupportedType(format!("{other} (no PartialEq)")));
                        }
                    }
                    _ => out.push(Reject::UnsupportedType(other.to_string())),
                },
            }
        }
        Type::Reference(r) => {
            if r.mutability.is_some() && pos == Position::Param {
                out.push(Reject::MutRefParam(render_type(&r.elem)));
                return;
            }
            check_type(&r.elem, pos, out, unbounded, ctx);
        }
        Type::Slice(s) => {
            unbounded.push("slice".into());
            check_type(&s.elem, pos, out, unbounded, ctx);
        }
        Type::Array(a) => check_type(&a.elem, pos, out, unbounded, ctx),
        Type::Tuple(t) => {
            if t.elems.is_empty() && pos == Position::Return {
                out.push(Reject::UnitReturn);
                return;
            }
            for e in &t.elems {
                check_type(e, pos, out, unbounded, ctx);
            }
        }
        Type::Paren(p) => check_type(&p.elem, pos, out, unbounded, ctx),
        Type::Group(g) => check_type(&g.elem, pos, out, unbounded, ctx),
        Type::Ptr(_) => out.push(Reject::RawPointer),
        Type::ImplTrait(_) => out.push(Reject::ImplTrait),
        Type::TraitObject(_) => out.push(Reject::TraitObject),
        Type::BareFn(_) => out.push(Reject::UnsupportedType("fn pointer".into())),
        Type::Never(_) => out.push(Reject::UnsupportedType("!".into())),
        Type::Infer(_) => out.push(Reject::UnsupportedType("_".into())),
        Type::Macro(_) => out.push(Reject::UnsupportedType("macro type".into())),
        _ => out.push(Reject::UnsupportedType("unknown".into())),
    }
}

fn generic_types(seg: &syn::PathSegment) -> Vec<&Type> {
    match &seg.arguments {
        syn::PathArguments::AngleBracketed(ab) => ab
            .args
            .iter()
            .filter_map(|a| match a {
                syn::GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Render a type compactly for diagnostics.
pub fn render_type(ty: &Type) -> String {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Type::Reference(r) => format!(
            "&{}{}",
            if r.mutability.is_some() { "mut " } else { "" },
            render_type(&r.elem)
        ),
        Type::Slice(s) => format!("[{}]", render_type(&s.elem)),
        Type::Array(a) => format!("[{}; _]", render_type(&a.elem)),
        Type::Tuple(t) => format!(
            "({})",
            t.elems
                .iter()
                .map(render_type)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Type::Ptr(_) => "*ptr".into(),
        Type::ImplTrait(_) => "impl Trait".into(),
        Type::TraitObject(_) => "dyn Trait".into(),
        _ => "?".into(),
    }
}

/// Render a `syn::Path` as `a::b::c`.
pub fn render_path(p: &syn::Path) -> String {
    let mut s = String::new();
    if p.leading_colon.is_some() {
        s.push_str("::");
    }
    for (i, seg) in p.segments.iter().enumerate() {
        if i > 0 {
            s.push_str("::");
        }
        s.push_str(&seg.ident.to_string());
    }
    s
}
