//! Crate-local type resolution.
//!
//! # Why this exists
//!
//! The first Phase 0 run rejected 80.4% of public functions with
//! `unsupported_type`, and it was the single largest *blocking-alone* reason.
//! Nearly all of those were the crate's own structs and enums.
//!
//! But a user-defined type whose fields are all supported **is** supported: it
//! is `#[derive(Arbitrary)]`-able and comparable. Rejecting it was a limitation
//! of the analysis, not a property of the code. This module resolves local type
//! definitions so the gate can see that.
//!
//! # Method
//!
//! Two passes. Collect every `struct`/`enum` in the crate, then compute a
//! least fixed point: a type is supported once all of its field types are
//! supported. Types that never stabilise — because they are generic, recursive
//! through an unsupported path, or reference something we cannot see — stay
//! unsupported. The fixed point starts empty and only ever adds, so the result
//! is conservative by construction.

use std::collections::BTreeMap;

/// What we know about one crate-local type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalType {
    pub supported: bool,
    /// Derives `PartialEq`, so values can be compared. Required in return
    /// position; unnecessary for parameters.
    pub has_partial_eq: bool,
    /// Contains a `Vec`, `String` or slice, so inputs need a declared bound
    /// before an equivalence proof can be attempted.
    pub unbounded: bool,
}

/// Crate-local type definitions, resolved.
#[derive(Debug, Default, Clone)]
pub struct TypeEnv {
    types: BTreeMap<String, LocalType>,
}

/// Resolution outcome for one type expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Supported; `unbounded` if it carries a variable-length component.
    Supported {
        unbounded: bool,
    },
    Unsupported,
}

struct Def {
    generic: bool,
    has_partial_eq: bool,
    fields: Vec<syn::Type>,
}

impl TypeEnv {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn lookup(&self, name: &str) -> Option<&LocalType> {
        self.types.get(name)
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Build from parsed sources across a whole crate.
    pub fn from_files<'a>(files: impl IntoIterator<Item = &'a syn::File>) -> Self {
        let mut defs: BTreeMap<String, Def> = BTreeMap::new();
        for f in files {
            for item in &f.items {
                collect_item(item, &mut defs);
            }
        }

        // Least fixed point: repeatedly admit types whose fields all resolve.
        let mut env = TypeEnv::default();
        loop {
            let mut changed = false;
            for (name, def) in &defs {
                if env.types.contains_key(name) || def.generic {
                    continue;
                }
                let mut unbounded = false;
                let mut all_ok = true;
                for ty in &def.fields {
                    match resolve(ty, &env) {
                        Status::Supported { unbounded: u } => unbounded |= u,
                        Status::Unsupported => {
                            all_ok = false;
                            break;
                        }
                    }
                }
                if all_ok {
                    env.types.insert(
                        name.clone(),
                        LocalType {
                            supported: true,
                            has_partial_eq: def.has_partial_eq,
                            unbounded,
                        },
                    );
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        env
    }
}

fn collect_item(item: &syn::Item, out: &mut BTreeMap<String, Def>) {
    match item {
        syn::Item::Struct(s) => {
            out.insert(
                s.ident.to_string(),
                Def {
                    generic: has_type_params(&s.generics),
                    has_partial_eq: derives(&s.attrs, "PartialEq"),
                    fields: s.fields.iter().map(|f| f.ty.clone()).collect(),
                },
            );
        }
        syn::Item::Enum(e) => {
            let fields = e
                .variants
                .iter()
                .flat_map(|v| v.fields.iter().map(|f| f.ty.clone()))
                .collect();
            out.insert(
                e.ident.to_string(),
                Def {
                    generic: has_type_params(&e.generics),
                    has_partial_eq: derives(&e.attrs, "PartialEq"),
                    fields,
                },
            );
        }
        syn::Item::Mod(m) => {
            if let Some((_, items)) = &m.content {
                for it in items {
                    collect_item(it, out);
                }
            }
        }
        _ => {}
    }
}

fn has_type_params(g: &syn::Generics) -> bool {
    g.params
        .iter()
        .any(|p| matches!(p, syn::GenericParam::Type(_) | syn::GenericParam::Const(_)))
}

fn derives(attrs: &[syn::Attribute], want: &str) -> bool {
    for a in attrs {
        if !a.path().is_ident("derive") {
            continue;
        }
        let mut found = false;
        let _ = a.parse_nested_meta(|meta| {
            if meta.path.is_ident(want) {
                found = true;
            }
            Ok(())
        });
        if found {
            return true;
        }
    }
    false
}

/// Resolve a type expression against the environment built so far.
///
/// Shared with [`crate::rules`] so the two never disagree about what counts as
/// supported.
pub fn resolve(ty: &syn::Type, env: &TypeEnv) -> Status {
    use syn::Type as T;
    match ty {
        T::Path(tp) => {
            if tp.qself.is_some() {
                return Status::Unsupported;
            }
            let Some(seg) = tp.path.segments.last() else {
                return Status::Unsupported;
            };
            let name = seg.ident.to_string();
            let args: Vec<&syn::Type> = match &seg.arguments {
                syn::PathArguments::AngleBracketed(ab) => ab
                    .args
                    .iter()
                    .filter_map(|a| match a {
                        syn::GenericArgument::Type(t) => Some(t),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };

            match name.as_str() {
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "usize" | "bool" | "char" => Status::Supported { unbounded: false },
                "f32" | "f64" => Status::Unsupported,
                "String" | "str" => Status::Supported { unbounded: true },
                "Vec" | "VecDeque" => match args.first() {
                    Some(inner) => match resolve(inner, env) {
                        Status::Supported { .. } => Status::Supported { unbounded: true },
                        Status::Unsupported => Status::Unsupported,
                    },
                    None => Status::Unsupported,
                },
                "Option" | "Box" | "Wrapping" | "Reverse" | "Result" => {
                    let mut unbounded = false;
                    if args.is_empty() {
                        return Status::Unsupported;
                    }
                    for a in args {
                        match resolve(a, env) {
                            Status::Supported { unbounded: u } => unbounded |= u,
                            Status::Unsupported => return Status::Unsupported,
                        }
                    }
                    Status::Supported { unbounded }
                }
                other => match env.lookup(other) {
                    Some(lt) if lt.supported => Status::Supported {
                        unbounded: lt.unbounded,
                    },
                    _ => Status::Unsupported,
                },
            }
        }
        T::Reference(r) => {
            if r.mutability.is_some() {
                Status::Unsupported
            } else {
                resolve(&r.elem, env)
            }
        }
        T::Slice(s) => match resolve(&s.elem, env) {
            Status::Supported { .. } => Status::Supported { unbounded: true },
            Status::Unsupported => Status::Unsupported,
        },
        T::Array(a) => resolve(&a.elem, env),
        T::Tuple(t) => {
            let mut unbounded = false;
            for e in &t.elems {
                match resolve(e, env) {
                    Status::Supported { unbounded: u } => unbounded |= u,
                    Status::Unsupported => return Status::Unsupported,
                }
            }
            Status::Supported { unbounded }
        }
        T::Paren(p) => resolve(&p.elem, env),
        T::Group(g) => resolve(&g.elem, env),
        _ => Status::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(src: &str) -> TypeEnv {
        let f = syn::parse_file(src).unwrap();
        TypeEnv::from_files([&f])
    }

    #[test]
    fn plain_struct_of_primitives_is_supported() {
        let e = env_of("#[derive(PartialEq)] pub struct P { pub x: i32, pub y: i32 }");
        let p = e.lookup("P").unwrap();
        assert!(p.supported);
        assert!(p.has_partial_eq);
        assert!(!p.unbounded);
    }

    #[test]
    fn struct_containing_a_vec_is_supported_but_unbounded() {
        let e = env_of("#[derive(PartialEq)] pub struct B { pub items: Vec<u8> }");
        let b = e.lookup("B").unwrap();
        assert!(b.supported && b.unbounded);
    }

    #[test]
    fn struct_with_a_float_is_not_supported() {
        let e = env_of("pub struct F { pub x: f64 }");
        assert!(e.lookup("F").is_none());
    }

    #[test]
    fn nesting_resolves_transitively() {
        let e = env_of(
            "pub struct Inner { a: u8 }
             pub struct Outer { i: Inner, n: u32 }",
        );
        assert!(e.lookup("Inner").unwrap().supported);
        assert!(e.lookup("Outer").unwrap().supported);
    }

    #[test]
    fn nesting_propagates_failure() {
        let e = env_of(
            "pub struct Bad { h: std::collections::HashMap<u8, u8> }
             pub struct Uses { b: Bad }",
        );
        assert!(e.lookup("Bad").is_none());
        assert!(
            e.lookup("Uses").is_none(),
            "must not admit via an unsupported field"
        );
    }

    #[test]
    fn generic_types_are_skipped() {
        let e = env_of("pub struct G<T> { v: T }");
        assert!(e.lookup("G").is_none());
    }

    #[test]
    fn enums_resolve_over_all_variants() {
        let e = env_of(
            "#[derive(PartialEq)] pub enum E { A, B(u32), C { x: i8 } }
             pub enum Bad2 { A(f32) }",
        );
        assert!(e.lookup("E").unwrap().supported);
        assert!(e.lookup("Bad2").is_none());
    }

    #[test]
    fn self_referential_type_does_not_hang_or_get_admitted() {
        // `Box<Tree>` is Arbitrary-able in principle but the fixed point
        // starts empty and only adds, so a cycle simply never stabilises.
        let e = env_of("pub enum Tree { Leaf, Node(Box<Tree>) }");
        assert!(e.lookup("Tree").is_none());
    }

    #[test]
    fn types_are_found_inside_modules() {
        let e = env_of("pub mod inner { #[derive(PartialEq)] pub struct T { a: u8 } }");
        assert!(e.lookup("T").unwrap().supported);
    }
}
