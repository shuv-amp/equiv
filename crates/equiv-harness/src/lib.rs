//! Generates a differential probe: a standalone crate that links **both**
//! versions of the code under test and compares them on generated inputs.
//!
//! ```text
//!   syn::Signature ──▶ HarnessSpec ──▶ ProbeCrate ──▶ cargo run ──▶ witness
//! ```
//!
//! The probe only ever produces `DIVERGES` or "no divergence found". It cannot
//! produce `EQUIVALENT`, and the generated source is asserted not to claim it —
//! equivalence requires a proof, and fuzzing is not one.

pub mod codegen;
pub mod corpus;
pub mod gentype;
pub mod project;
pub mod runner;

pub use codegen::{generate, generate_with, HarnessSpec, Param, NEW, OLD};
pub use corpus::Corpus;
pub use gentype::GenType;
pub use project::{ProbeCrate, Source};

/// Why a function could not be harnessed, even though the gate admitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotHarnessable {
    /// A parameter type the probe cannot construct a value of. Usually the
    /// orphan rule: `Arbitrary` cannot be implemented for a foreign type.
    UngeneratableParam { name: String, ty: String },
    /// Takes `self`; the receiver would have to be constructed first.
    Receiver,
    /// Returns nothing, so there is no observable to compare.
    NoReturnValue,
}

impl std::fmt::Display for NotHarnessable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotHarnessable::UngeneratableParam { name, ty } => {
                write!(f, "cannot generate values for parameter `{name}: {ty}`")
            }
            NotHarnessable::Receiver => f.write_str("takes self"),
            NotHarnessable::NoReturnValue => f.write_str("returns () — nothing to compare"),
        }
    }
}

/// Build a [`HarnessSpec`] from a parsed signature.
///
/// `fn_path` is how the function is named *inside* each crate, e.g. `parse` or
/// `Version::parse`. Parameter names come from the signature where they are
/// plain identifiers, and are synthesised as `p0`, `p1`, … otherwise, so
/// pattern parameters do not produce invalid code.
pub fn spec_from_signature(
    sig: &syn::Signature,
    fn_path: impl Into<String>,
    max_len: usize,
) -> Result<HarnessSpec, NotHarnessable> {
    if matches!(sig.output, syn::ReturnType::Default) {
        return Err(NotHarnessable::NoReturnValue);
    }

    let mut params = Vec::new();
    for (i, arg) in sig.inputs.iter().enumerate() {
        match arg {
            syn::FnArg::Receiver(_) => return Err(NotHarnessable::Receiver),
            syn::FnArg::Typed(pt) => {
                let name = match &*pt.pat {
                    syn::Pat::Ident(id) => sanitize(&id.ident.to_string(), i),
                    _ => format!("p{i}"),
                };
                let ty = GenType::from_syn(&pt.ty).ok_or_else(|| {
                    NotHarnessable::UngeneratableParam {
                        name: name.clone(),
                        ty: quote_ty(&pt.ty),
                    }
                })?;
                params.push(Param { name, ty });
            }
        }
    }

    Ok(HarnessSpec {
        fn_path: fn_path.into(),
        params,
        max_len,
    })
}

/// Keep identifiers legal and non-colliding in generated code.
fn sanitize(name: &str, i: usize) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
        "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final",
        "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "u", "data",
        "out", "old", "new",
    ];
    if name.is_empty() || name == "_" || KEYWORDS.contains(&name) || name.starts_with('_') {
        format!("p{i}")
    } else {
        name.to_string()
    }
}

fn quote_ty(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(tp) => tp
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        syn::Type::Reference(r) => format!("&{}", quote_ty(&r.elem)),
        syn::Type::Slice(s) => format!("[{}]", quote_ty(&s.elem)),
        syn::Type::Tuple(t) => format!(
            "({})",
            t.elems.iter().map(quote_ty).collect::<Vec<_>>().join(", ")
        ),
        _ => "?".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(s: &str) -> syn::Signature {
        let f: syn::ItemFn = syn::parse_str(&format!("{s} {{ unimplemented!() }}")).unwrap();
        f.sig
    }

    #[test]
    fn simple_signature_maps_cleanly() {
        let s =
            spec_from_signature(&sig("fn parse(text: &str) -> Option<u32>"), "parse", 32).unwrap();
        assert_eq!(s.params.len(), 1);
        assert_eq!(s.params[0].name, "text");
        assert_eq!(s.params[0].ty, GenType::StrRef);
        assert_eq!(s.domain(), "text: &str[len<=32]");
    }

    #[test]
    fn unit_return_is_not_harnessable() {
        assert_eq!(
            spec_from_signature(&sig("fn go(a: u8)"), "go", 16),
            Err(NotHarnessable::NoReturnValue)
        );
    }

    #[test]
    fn foreign_param_reports_which_one() {
        let e = spec_from_signature(&sig("fn f(v: Version) -> u8"), "f", 16).unwrap_err();
        match e {
            NotHarnessable::UngeneratableParam { ref name, ref ty } => {
                assert_eq!(name, "v");
                assert_eq!(ty, "Version");
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert!(e.to_string().contains("v: Version"));
    }

    #[test]
    fn keywords_and_reserved_names_are_renamed() {
        // `data`, `u` and `out` are used by the generated runtime; a parameter
        // with one of those names would shadow it and produce broken code.
        // (Strict keywords like `match` cannot appear as parameter names in
        // parseable Rust at all, so they are not testable here — `sanitize`
        // still covers them for raw identifiers and synthesised signatures.)
        // (`self: T` parses as a receiver, not a named parameter, so it is
        // covered by `receivers_are_rejected_with_a_specific_reason`.)
        for bad in ["data", "u", "out", "old", "new", "_"] {
            let s = spec_from_signature(&sig(&format!("fn f({bad}: u8) -> u8")), "f", 16).unwrap();
            assert_eq!(s.params[0].name, "p0", "failed to rename `{bad}`");
        }
    }

    #[test]
    fn ordinary_names_are_preserved() {
        let s = spec_from_signature(&sig("fn f(width: u8, height: u8) -> u8"), "f", 16).unwrap();
        assert_eq!(s.params[0].name, "width");
        assert_eq!(s.params[1].name, "height");
    }

    #[test]
    fn pattern_parameters_get_synthetic_names() {
        let s = spec_from_signature(&sig("fn f((a, b): (u8, u8)) -> u8"), "f", 16).unwrap();
        assert_eq!(s.params[0].name, "p0");
    }

    #[test]
    fn receivers_are_rejected_with_a_specific_reason() {
        assert_eq!(
            spec_from_signature(&sig("fn m(&self) -> u8"), "m", 16),
            Err(NotHarnessable::Receiver)
        );
    }

    #[test]
    fn end_to_end_spec_produces_valid_rust() {
        let s = spec_from_signature(
            &sig("fn encode(input: &[u8], pad: bool) -> String"),
            "encode",
            16,
        )
        .unwrap();
        let src = generate(&s);
        syn::parse_file(&src).expect("valid Rust");
        assert!(src.contains("encode(input.as_slice(), pad)"));
    }
}
