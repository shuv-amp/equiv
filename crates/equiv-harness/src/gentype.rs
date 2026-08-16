//! The subset of types we can *generate values for* in a probe.
//!
//! # Why this is narrower than the eligibility gate
//!
//! The gate asks "is this function analysable in principle". This module asks a
//! harder question: "can the probe crate actually construct a value of this
//! type". Two constraints bite here that do not bite in the gate:
//!
//! 1. **No way to build a foreign value.** The probe's generator knows how to
//!    decode bytes into std types, and nothing else. A struct belonging to the
//!    crate under test has no such decoder, even though the gate correctly
//!    considers it structurally supported: building one means going through the
//!    crate's own public constructors, which is future work.
//!
//! 2. **Two versions means two distinct types.** `old::Version` and
//!    `new::Version` are different types to the compiler even when they are
//!    character-identical in source. There is no `PartialEq` between them and
//!    there cannot be. See [`crate::codegen`] for how the observable is defined
//!    as a result.

use syn::Type;

/// A type the probe can construct a value of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenType {
    /// `u8`, `i32`, `bool`, `char`, …
    Prim(String),
    /// Owned `String`.
    String,
    /// `&str` — generated as an owned `String`, then borrowed.
    StrRef,
    /// `Vec<T>`.
    Vec(Box<GenType>),
    /// `&[T]` — generated as an owned `Vec<T>`, then borrowed.
    SliceRef(Box<GenType>),
    /// `Option<T>`.
    Option(Box<GenType>),
    /// `(A, B, …)`.
    Tuple(Vec<GenType>),
}

const PRIMS: &[&str] = &[
    "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize", "bool",
    "char",
];

impl GenType {
    /// Map a syntactic type onto something the probe can build.
    ///
    /// Returns `None` when the probe could not construct a value — which is a
    /// stricter test than the gate's, by design.
    pub fn from_syn(ty: &Type) -> Option<Self> {
        match ty {
            Type::Path(tp) => {
                if tp.qself.is_some() {
                    return None;
                }
                let seg = tp.path.segments.last()?;
                let name = seg.ident.to_string();
                let args = generic_args(seg);

                if PRIMS.contains(&name.as_str()) {
                    return Some(GenType::Prim(name));
                }
                match name.as_str() {
                    "String" => Some(GenType::String),
                    "str" => Some(GenType::StrRef),
                    "Vec" => Some(GenType::Vec(Box::new(Self::from_syn(args.first()?)?))),
                    "Option" => Some(GenType::Option(Box::new(Self::from_syn(args.first()?)?))),
                    _ => None,
                }
            }
            Type::Reference(r) => {
                if r.mutability.is_some() {
                    return None;
                }
                match &*r.elem {
                    // `&str` and `&[T]` need an owned backing value.
                    Type::Path(tp) if tp.path.segments.last().is_some_and(|s| s.ident == "str") => {
                        Some(GenType::StrRef)
                    }
                    Type::Slice(s) => Some(GenType::SliceRef(Box::new(Self::from_syn(&s.elem)?))),
                    other => Self::from_syn(other),
                }
            }
            Type::Tuple(t) => {
                if t.elems.is_empty() {
                    return None;
                }
                let mut v = Vec::with_capacity(t.elems.len());
                for e in &t.elems {
                    v.push(Self::from_syn(e)?);
                }
                Some(GenType::Tuple(v))
            }
            Type::Paren(p) => Self::from_syn(&p.elem),
            Type::Group(g) => Self::from_syn(&g.elem),
            _ => None,
        }
    }

    /// The owned Rust type the generator produces, before any reborrow.
    pub fn owned_rust_type(&self) -> String {
        match self {
            GenType::Prim(p) => p.clone(),
            GenType::String | GenType::StrRef => "String".into(),
            GenType::Vec(inner) | GenType::SliceRef(inner) => {
                format!("Vec<{}>", inner.owned_rust_type())
            }
            GenType::Option(inner) => format!("Option<{}>", inner.owned_rust_type()),
            GenType::Tuple(v) => format!(
                "({})",
                v.iter()
                    .map(|t| t.owned_rust_type())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Expression turning the owned local `name` into the argument value.
    pub fn borrow_expr(&self, name: &str) -> String {
        match self {
            GenType::StrRef => format!("{name}.as_str()"),
            GenType::SliceRef(_) => format!("{name}.as_slice()"),
            _ => name.to_string(),
        }
    }

    /// Expression that draws one value of this type from the generator `g`.
    ///
    /// The declared bound is applied *during* generation rather than by
    /// truncating afterwards. Truncating wastes draws — it spends entropy
    /// building a value it then throws most of away — and it skews the length
    /// distribution towards the cap. Generating within the bound keeps the
    /// domain statement in [`describe`](Self::describe) exactly true.
    pub fn gen_expr(&self, g: &str, max_len: usize) -> String {
        match self {
            GenType::Prim(p) => match p.as_str() {
                "bool" => format!("{g}.gen_bool()"),
                "char" => format!("{g}.gen_char()"),
                other => format!("{g}.gen_{other}()"),
            },
            GenType::String | GenType::StrRef => format!("{g}.gen_string({max_len})"),
            // A block rather than a closure: generated code is easier to read
            // back, and there is no borrow to reason about at the call site.
            GenType::Vec(inner) | GenType::SliceRef(inner) => format!(
                "{{ let n = {g}.gen_len({max_len}); let mut v = Vec::with_capacity(n); \
                 for _ in 0..n {{ v.push({}); }} v }}",
                inner.gen_expr(g, max_len)
            ),
            GenType::Option(inner) => format!(
                "if {g}.gen_none() {{ None }} else {{ Some({}) }}",
                inner.gen_expr(g, max_len)
            ),
            GenType::Tuple(v) => format!(
                "({})",
                v.iter()
                    .map(|t| t.gen_expr(g, max_len))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Human-readable domain description, printed with every verdict.
    pub fn describe(&self, max_len: usize) -> String {
        match self {
            GenType::Prim(p) => p.clone(),
            GenType::String => format!("String[len<={max_len}]"),
            GenType::StrRef => format!("&str[len<={max_len}]"),
            GenType::Vec(i) => format!("Vec<{}>[len<={max_len}]", i.describe(max_len)),
            GenType::SliceRef(i) => format!("&[{}][len<={max_len}]", i.describe(max_len)),
            GenType::Option(i) => format!("Option<{}>", i.describe(max_len)),
            GenType::Tuple(v) => format!(
                "({})",
                v.iter()
                    .map(|t| t.describe(max_len))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

fn generic_args(seg: &syn::PathSegment) -> Vec<&Type> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Type {
        syn::parse_str(s).unwrap()
    }
    fn g(s: &str) -> Option<GenType> {
        GenType::from_syn(&t(s))
    }

    #[test]
    fn primitives_map_directly() {
        for p in ["u8", "i64", "usize", "bool", "char"] {
            assert_eq!(g(p), Some(GenType::Prim(p.into())), "{p}");
        }
    }

    #[test]
    fn floats_are_not_generatable() {
        // Excluded upstream in the gate; enforced again here so the two
        // cannot drift apart silently.
        assert_eq!(g("f32"), None);
        assert_eq!(g("f64"), None);
    }

    #[test]
    fn string_forms() {
        assert_eq!(g("String"), Some(GenType::String));
        assert_eq!(g("&str"), Some(GenType::StrRef));
        assert_eq!(g("&'a str"), Some(GenType::StrRef));
    }

    #[test]
    fn containers_nest() {
        assert_eq!(
            g("Vec<u8>"),
            Some(GenType::Vec(Box::new(GenType::Prim("u8".into()))))
        );
        assert_eq!(
            g("&[i32]"),
            Some(GenType::SliceRef(Box::new(GenType::Prim("i32".into()))))
        );
        assert_eq!(
            g("Option<Vec<u8>>"),
            Some(GenType::Option(Box::new(GenType::Vec(Box::new(
                GenType::Prim("u8".into())
            )))))
        );
    }

    #[test]
    fn foreign_types_are_rejected_by_the_orphan_rule() {
        // The gate may consider these supported; the probe still cannot build
        // one, because it cannot implement Arbitrary for a foreign type.
        assert_eq!(g("Version"), None);
        assert_eq!(g("HashMap<u8, u8>"), None);
        assert_eq!(
            g("Vec<Version>"),
            None,
            "must not admit via the element type"
        );
    }

    #[test]
    fn mut_references_are_rejected() {
        assert_eq!(g("&mut u32"), None);
        assert_eq!(g("&mut [u8]"), None);
    }

    #[test]
    fn owned_types_are_rendered_for_unstructured() {
        assert_eq!(g("&str").unwrap().owned_rust_type(), "String");
        assert_eq!(g("&[u8]").unwrap().owned_rust_type(), "Vec<u8>");
        assert_eq!(g("Option<u32>").unwrap().owned_rust_type(), "Option<u32>");
    }

    #[test]
    fn borrows_are_reintroduced_at_the_call_site() {
        assert_eq!(g("&str").unwrap().borrow_expr("p0"), "p0.as_str()");
        assert_eq!(g("&[u8]").unwrap().borrow_expr("p0"), "p0.as_slice()");
        assert_eq!(g("u32").unwrap().borrow_expr("p0"), "p0");
    }

    #[test]
    fn generation_expressions_carry_the_bound() {
        assert_eq!(g("u32").unwrap().gen_expr("g", 16), "g.gen_u32()");
        assert_eq!(g("&str").unwrap().gen_expr("g", 32), "g.gen_string(32)");
        assert!(g("Vec<u8>")
            .unwrap()
            .gen_expr("g", 16)
            .contains("gen_len(16)"));
        // The bound reaches the element type too, so `Vec<String>` cannot
        // produce strings longer than the domain says.
        assert!(g("Vec<String>")
            .unwrap()
            .gen_expr("g", 12)
            .contains("gen_string(12)"));
    }

    #[test]
    fn bool_and_char_do_not_become_gen_bool_bool() {
        // `Prim("bool")` must not render as `gen_bool()` via the generic arm
        // and `gen_char()` must not render as `gen_char()` twice over.
        assert_eq!(g("bool").unwrap().gen_expr("g", 8), "g.gen_bool()");
        assert_eq!(g("char").unwrap().gen_expr("g", 8), "g.gen_char()");
        assert_eq!(g("i128").unwrap().gen_expr("g", 8), "g.gen_i128()");
    }

    #[test]
    fn domain_description_states_the_bound() {
        assert_eq!(g("&str").unwrap().describe(32), "&str[len<=32]");
        assert_eq!(g("u8").unwrap().describe(32), "u8");
    }
}
