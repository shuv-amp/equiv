//! Emits the differential probe.
//!
//! # What the observable is, and why
//!
//! When comparing two *versions* of a crate, `old::Version` and `new::Version`
//! are distinct types to the compiler even when their source is
//! character-identical. There is no `PartialEq` between them and there cannot
//! be, so the values cannot be compared directly.
//!
//! The probe therefore defines the observable as:
//!
//! > **the `Debug` rendering of the return value, plus whether the call
//! > panicked.**
//!
//! This is the same choice traffic-diffing tools make when they compare
//! serialised responses rather than in-memory objects. It is honest but not
//! free, and the limitations are real:
//!
//! - Types whose `Debug` is lossy can hide a genuine difference (false
//!   negative — we miss a divergence, we never invent one).
//! - Types whose `Debug` exposes non-deterministic ordering (`HashMap`) can
//!   show a difference that is not semantic. **This is the dangerous
//!   direction**, and it is why every witness must survive replay before it is
//!   ever reported.
//!
//! # Determinism
//!
//! Every input is a pure function of a byte string. The same bytes always decode
//! to the same values, so any witness replays from its hex alone via
//! `--replay <hex>`. That replay path *is* the confirmation step required by
//! `equiv_core::Witness::confirm`, and it is why the generator must stay a
//! *decoder* rather than a stateful sampler.
//!
//! # How inputs are drawn, and why not uniformly
//!
//! The obvious generator — uniform random bytes through `arbitrary` — cannot
//! reach the inputs real functions branch on. Measured over 20 000 draws:
//!
//! ```text
//! &str   47% empty string, mean length 1.11 characters
//! i32     0 draws inside roman::to's valid range 1..=3999
//! ```
//!
//! So `Gen` decodes bytes into values through three biases, all of them
//! standard fuzzing practice and all preserving replayability:
//!
//! 1. **A dictionary** mined from the crate under test ([`crate::corpus`]) —
//!    AFL's `-x`, libFuzzer's `-dict=`. Tokens beat random bytes on anything
//!    that parses.
//! 2. **Boundary values** — AFL's `INTERESTING_8/16/32` tables, plus the
//!    crate's own integer literals and their `±1` neighbours, because guards
//!    live at boundaries.
//! 3. **Short lengths** — collection and string sizes concentrated near zero,
//!    as in Hypothesis and QuickCheck. Most divergences need small inputs, and
//!    small witnesses are the readable ones.
//!
//! Selector bytes are read *before* payload bytes, so zeroing a byte — what
//! `shrink` in the emitted runtime does — moves an input towards the first
//! dictionary entry
//! and towards zero, rather than into unrelated parts of the space.

use crate::corpus::Corpus;
use crate::gentype::GenType;

/// One parameter of the function under test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: GenType,
}

/// Everything needed to emit a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessSpec {
    /// Path to the function *within* each crate, e.g. `parse` or `Version::parse`.
    pub fn_path: String,
    pub params: Vec<Param>,
    /// Cap on generated collection and string lengths.
    pub max_len: usize,
}

impl HarnessSpec {
    /// Rendered input domain, printed with every verdict.
    ///
    /// A verdict without its domain is not a verdict; see `equiv_core::impact`.
    pub fn domain(&self) -> String {
        if self.params.is_empty() {
            return "()".into();
        }
        self.params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.ty.describe(self.max_len)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Aliases the two versions are linked under in the probe crate.
pub const OLD: &str = "equiv_old";
pub const NEW: &str = "equiv_new";

/// Generate the probe's `main.rs`, with an empty dictionary.
///
/// Prefer [`generate_with`]: a probe with no dictionary is the uniform-random
/// generator this module exists to replace, and finds correspondingly little.
pub fn generate(spec: &HarnessSpec) -> String {
    generate_with(spec, &Corpus::default())
}

/// Generate the probe's `main.rs`, seeded with literals mined from the crate.
pub fn generate_with(spec: &HarnessSpec, corpus: &Corpus) -> String {
    let mut s = String::new();
    s.push_str(HEADER);
    s.push_str(&format!(
        "const DOMAIN: &str = {:?};\nconst FN_PATH: &str = {:?};\n\n",
        spec.domain(),
        spec.fn_path
    ));
    s.push_str(&emit_dictionary(corpus));
    s.push_str(&emit_side(spec, OLD, "call_old"));
    s.push_str(&emit_side(spec, NEW, "call_new"));
    s.push_str(&emit_render_input(spec));
    s.push_str(GEN);
    s.push_str(RUNTIME);
    s
}

/// Emit one side's call function.
///
/// Both sides rebuild their arguments from the same bytes rather than sharing
/// them. That avoids `Clone` bounds and borrow gymnastics entirely, and costs
/// only a second cheap construction.
fn emit_side(spec: &HarnessSpec, alias: &str, fn_name: &str) -> String {
    let mut s = format!(
        "fn {fn_name}(data: &[u8]) -> Option<Outcome> {{\n    \
         let mut g = Gen::new(data);\n"
    );
    s.push_str(&emit_bindings(spec));
    let args = spec
        .params
        .iter()
        .map(|p| p.ty.borrow_expr(&p.name))
        .collect::<Vec<_>>()
        .join(", ");
    s.push_str(&format!(
        "    let out = catch_unwind(AssertUnwindSafe(|| {alias}::{}({args})));\n    \
         Some(match out {{\n        \
         Ok(v) => Outcome::Value(format!(\"{{:?}}\", v)),\n        \
         Err(_) => Outcome::Panic,\n    }})\n}}\n\n",
        spec.fn_path
    ));
    s
}

fn emit_render_input(spec: &HarnessSpec) -> String {
    let mut s = String::from(
        "fn render_input(data: &[u8]) -> Option<String> {\n    \
         let mut g = Gen::new(data);\n",
    );
    s.push_str(&emit_bindings(spec));
    if spec.params.is_empty() {
        s.push_str("    Some(String::from(\"()\"))\n}\n\n");
        return s;
    }
    let parts = spec
        .params
        .iter()
        .map(|p| format!("format!(\"{} = {{:?}}\", {})", p.name, p.name))
        .collect::<Vec<_>>()
        .join(", ");
    s.push_str(&format!("    Some([{parts}].join(\", \"))\n}}\n\n"));
    s
}

fn emit_bindings(spec: &HarnessSpec) -> String {
    let mut s = String::new();
    for p in &spec.params {
        s.push_str(&format!(
            "    let mut {}: {} = {};\n",
            p.name,
            p.ty.owned_rust_type(),
            p.ty.gen_expr("g", spec.max_len)
        ));
    }
    s
}

/// Bake the mined dictionary into the probe as constants.
///
/// Baked rather than loaded at runtime so a probe is self-contained: the
/// witness bytes plus the probe source fully determine the input, with no
/// external file that could drift and silently change what a replay means.
fn emit_dictionary(corpus: &Corpus) -> String {
    let strings = corpus
        .strings
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let ints = corpus
        .ints
        .iter()
        .map(|i| format!("{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("const DICT: &[&str] = &[{strings}];\nconst MINED: &[i128] = &[{ints}];\n\n")
}

const HEADER: &str = r#"// @generated by equiv-harness. Do not edit.
//
// Differential probe: builds one input, calls both versions, compares.
#![allow(unused_imports, unused_mut, unused_variables, clippy::all)]

use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Value(String),
    Panic,
}

impl Outcome {
    fn render(&self) -> String {
        match self {
            Outcome::Value(v) => v.clone(),
            Outcome::Panic => "<panic>".to_string(),
        }
    }
}

"#;

/// The input decoder, emitted into every probe.
///
/// Kept separate from [`RUNTIME`] so the search loop and the value generator can
/// be read independently — they are the two halves that decide whether a probe
/// finds anything.
const GEN: &str = r##"/// Boundary values, in the spirit of AFL's `INTERESTING_8/16/32` tables.
///
/// Guards cluster here: at zero, at one either side of a power of two, and at
/// the limits of each width. Values are stored as `i128` and cast down with
/// `as`, which wraps — so `-1` becomes each unsigned type's maximum, which is
/// exactly the value wanted.
const BOUNDARY: &[i128] = &[
    0, 1, -1, 2, -2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100, 127, -128, 128,
    255, 256, 511, 512, 1000, 1023, 1024, 4095, 4096, 32767, -32768, 65535,
    65536, 16777216, 2147483647, -2147483648, 4294967295,
    9223372036854775807, -9223372036854775808,
];

/// Decodes a byte string into values.
///
/// Every draw is a pure function of the bytes, which is what makes a witness
/// replayable. The cursor wraps on exhaustion rather than failing, so a short
/// byte string is still a valid input — that is what lets shrinking cut a
/// witness down to a handful of bytes.
struct Gen<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Gen<'a> {
    fn new(data: &'a [u8]) -> Self {
        Gen { data, pos: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn raw(&mut self, n: usize) -> u128 {
        let mut x: u128 = 0;
        for k in 0..n {
            x |= (self.byte() as u128) << (8 * k);
        }
        x
    }

    /// Pick from the boundary table, then the crate's own literals.
    ///
    /// Mined literals sit second so that zeroed bytes — where shrinking ends up
    /// — land on `0`, the most readable witness value there is.
    fn interesting(&mut self) -> i128 {
        let i = self.byte() as usize;
        if MINED.is_empty() || (i as u8) < 160 {
            BOUNDARY[i % BOUNDARY.len()]
        } else {
            MINED[i % MINED.len()]
        }
    }

    fn gen_bool(&mut self) -> bool {
        self.byte() & 1 == 1
    }

    /// Sizes concentrated near zero, as in Hypothesis and QuickCheck.
    ///
    /// Bugs that need a long input are rare; witnesses that *are* long are
    /// unreadable. The tail still reaches `max`, just seldom.
    fn gen_len(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        let b = self.byte();
        let n = match b {
            0..=31 => 0,
            32..=127 => 1 + (self.byte() as usize % 3),
            128..=207 => 1 + (self.byte() as usize % 8),
            208..=247 => 1 + (self.byte() as usize % max),
            _ => max,
        };
        if n > max {
            max
        } else {
            n
        }
    }

    fn gen_none(&mut self) -> bool {
        self.byte() < 64
    }

    fn gen_char(&mut self) -> char {
        const ALPHA: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\n.-_/:,;=+*%()[]{}<>\"'\\!?@#$^&|~`";
        let b = self.byte();
        if b < 208 {
            ALPHA[self.byte() as usize % ALPHA.len()] as char
        } else if b < 240 {
            // Latin-1: one UTF-8 byte in, two out. Where byte-indexing and
            // char-indexing start to disagree.
            char::from_u32(0x80 + self.byte() as u32).unwrap_or('\u{80}')
        } else {
            // Beyond the BMP occasionally, for the same reason at four bytes.
            let v = 0x100 + (self.raw(3) as u32 % 0x10000);
            char::from_u32(v).unwrap_or('\u{fffd}')
        }
    }

    /// Draw a string: a dictionary token, a perturbed token, or fresh chars.
    ///
    /// The dictionary is what makes a parser reachable at all. The perturbation
    /// matters just as much: an exact token usually agrees across versions, and
    /// the near-misses are where two parsers disagree.
    fn gen_string(&mut self, max: usize) -> String {
        let sel = self.byte();
        let mut s = if !DICT.is_empty() && sel < 176 {
            let mut base = String::from(DICT[self.byte() as usize % DICT.len()]);
            match sel % 5 {
                0 => base.push(self.gen_char()),
                1 => {
                    base.pop();
                }
                2 => base.push_str(DICT[self.byte() as usize % DICT.len()]),
                3 => base.insert(0, self.gen_char()),
                _ => {}
            }
            base
        } else {
            let n = self.gen_len(max);
            (0..n).map(|_| self.gen_char()).collect()
        };
        truncate_chars(&mut s, max);
        s
    }
}

/// Cut a string to `max` **characters**, never splitting a code point.
fn truncate_chars(s: &mut String, max: usize) {
    if let Some((i, _)) = s.char_indices().nth(max) {
        s.truncate(i);
    }
}

macro_rules! gen_int {
    ($($name:ident => $t:ty),* $(,)?) => {
        impl<'a> Gen<'a> {
            $(
                fn $name(&mut self) -> $t {
                    // Selector first, payload second: zeroing a byte then walks
                    // an input towards the boundary table rather than into an
                    // unrelated part of the space, which is what makes the
                    // shrinker converge.
                    if self.byte() < 160 {
                        self.interesting() as $t
                    } else {
                        self.raw(core::mem::size_of::<$t>()) as $t
                    }
                }
            )*
        }
    };
}

gen_int! {
    gen_i8 => i8, gen_i16 => i16, gen_i32 => i32, gen_i64 => i64,
    gen_i128 => i128, gen_isize => isize,
    gen_u8 => u8, gen_u16 => u16, gen_u32 => u32, gen_u64 => u64,
    gen_u128 => u128, gen_usize => usize,
}

"##;

const RUNTIME: &str = r#"/// Run one case. `None` means the input could not be built from these bytes,
/// which is not evidence of anything.
fn check(data: &[u8]) -> Option<(String, Outcome, Outcome)> {
    let old = call_old(data)?;
    let new = call_new(data)?;
    if old == new {
        return None;
    }
    let repr = render_input(data)?;
    Some((repr, old, new))
}

/// Shrink a diverging input while it keeps diverging.
///
/// Halving first, then zeroing bytes. Crude but effective, and every candidate
/// is validated by `check`, so shrinking can never manufacture a divergence
/// that was not already there.
fn shrink(data: &[u8]) -> Vec<u8> {
    let mut best = data.to_vec();
    for _ in 0..32 {
        let mut improved = false;

        while best.len() > 1 {
            let cand = best[..best.len() / 2].to_vec();
            if check(&cand).is_some() {
                best = cand;
                improved = true;
            } else {
                break;
            }
        }

        for i in 0..best.len() {
            if best[i] == 0 {
                continue;
            }
            let mut cand = best.clone();
            cand[i] = 0;
            if check(&cand).is_some() {
                best = cand;
                improved = true;
            }
        }

        if !improved {
            break;
        }
    }
    best
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(if seed == 0 { 0x2545_F491_4F6C_DD1D } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn emit_finding(data: &[u8], repr: &str, old: &Outcome, new: &Outcome) {
    println!(
        "EQUIV_PROBE_V1 {{\"protocol\":1,\"diverges\":true,\"fn\":\"{}\",\"domain\":\"{}\",\"input\":\"{}\",\"old\":\"{}\",\"new\":\"{}\",\"witness_hex\":\"{}\"}}",
        esc(FN_PATH),
        esc(DOMAIN),
        esc(repr),
        esc(&old.render()),
        esc(&new.render()),
        to_hex(data)
    );
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn main() {
    // Silence panic output: panics are an observed outcome here, not an error.
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Replay mode. This is the confirmation step: a witness only counts once
    // it has been re-executed against both unmodified artifacts.
    if let Some(hex) = arg_value(&args, "--replay") {
        let Some(data) = from_hex(&hex) else {
            eprintln!("invalid witness hex");
            std::process::exit(2);
        };
        match check(&data) {
            Some((repr, old, new)) => {
                emit_finding(&data, &repr, &old, &new);
                std::process::exit(1);
            }
            None => {
                println!("EQUIV_PROBE_V1 {{\"protocol\":1,\"diverges\":false,\"replayed\":true}}");
                std::process::exit(0);
            }
        }
    }

    let iters: u64 = arg_value(&args, "--iters").and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let seed: u64 = arg_value(&args, "--seed").and_then(|v| v.parse().ok()).unwrap_or(0);
    let width: usize = arg_value(&args, "--width").and_then(|v| v.parse().ok()).unwrap_or(64);

    let mut rng = Rng::new(seed);
    for _ in 0..iters {
        let data = rng.bytes(width);
        if check(&data).is_some() {
            let small = shrink(&data);
            if let Some((repr, old, new)) = check(&small) {
                emit_finding(&small, &repr, &old, &new);
                std::process::exit(1);
            }
        }
    }

    // No divergence found is UNKNOWN, never EQUIVALENT.
    println!(
        "EQUIV_PROBE_V1 {{\"protocol\":1,\"diverges\":false,\"samples\":{},\"fn\":\"{}\",\"domain\":\"{}\"}}",
        iters,
        esc(FN_PATH),
        esc(DOMAIN)
    );
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> HarnessSpec {
        HarnessSpec {
            fn_path: "parse".into(),
            params: vec![Param {
                name: "p0".into(),
                ty: GenType::StrRef,
            }],
            max_len: 32,
        }
    }

    #[test]
    fn both_sides_are_emitted_and_differ_only_in_alias() {
        let src = generate(&spec());
        assert!(src.contains("fn call_old"));
        assert!(src.contains("fn call_new"));
        assert!(src.contains("equiv_old::parse("));
        assert!(src.contains("equiv_new::parse("));
    }

    #[test]
    fn str_params_get_an_owned_backing_and_are_reborrowed() {
        let src = generate(&spec());
        assert!(
            src.contains("let mut p0: String = g.gen_string(32);"),
            "{src}"
        );
        assert!(src.contains("parse(p0.as_str())"));
    }

    #[test]
    fn variable_length_inputs_are_bounded_at_generation_time() {
        // The bound is an argument to the draw, not a truncation afterwards.
        // Truncating spends entropy on a value it then discards, and piles
        // probability mass on exactly the cap.
        let src = generate(&spec());
        assert!(src.contains("g.gen_string(32)"), "{src}");
        assert!(
            !src.contains("p0.truncate("),
            "bounding must not be a post-hoc truncation: {src}"
        );
    }

    #[test]
    fn slice_params_are_backed_by_a_vec() {
        let s = HarnessSpec {
            fn_path: "sum".into(),
            params: vec![Param {
                name: "xs".into(),
                ty: GenType::SliceRef(Box::new(GenType::Prim("u8".into()))),
            }],
            max_len: 16,
        };
        let src = generate(&s);
        assert!(
            src.contains("let mut xs: Vec<u8> = { let n = g.gen_len(16);"),
            "{src}"
        );
        assert!(src.contains("v.push(g.gen_u8());"), "{src}");
        assert!(src.contains("sum(xs.as_slice())"));
    }

    #[test]
    fn multiple_params_are_ordered_and_comma_joined() {
        let s = HarnessSpec {
            fn_path: "clamp".into(),
            params: vec![
                Param {
                    name: "a".into(),
                    ty: GenType::Prim("i32".into()),
                },
                Param {
                    name: "b".into(),
                    ty: GenType::Prim("i32".into()),
                },
            ],
            max_len: 16,
        };
        let src = generate(&s);
        assert!(src.contains("clamp(a, b)"));
        // Bindings must be emitted in declaration order: the generator reads a
        // byte stream, so swapping them changes which bytes feed which param —
        // and therefore what a recorded witness decodes to.
        let ia = src.find("let mut a:").unwrap();
        let ib = src.find("let mut b:").unwrap();
        assert!(ia < ib);
    }

    #[test]
    fn zero_arg_functions_still_generate() {
        let s = HarnessSpec {
            fn_path: "version".into(),
            params: vec![],
            max_len: 16,
        };
        let src = generate(&s);
        assert!(src.contains("equiv_old::version()"));
        assert!(src.contains("\"()\""));
    }

    #[test]
    fn panics_are_an_outcome_not_a_crash() {
        let src = generate(&spec());
        assert!(src.contains("catch_unwind"));
        assert!(src.contains("Outcome::Panic"));
        assert!(src.contains("set_hook"));
    }

    #[test]
    fn no_divergence_never_claims_equivalence() {
        // Checked against the emitted *code*, with comments stripped, so a
        // doc comment mentioning the word cannot mask a real claim.
        let src = generate(&spec());
        let code: String = src
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(code.contains("\\\"diverges\\\":false"));
        // Substring matching would be wrong here ("proved" is inside
        // "improved"), so compare identifier-like tokens instead.
        let tokens: Vec<String> = code
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|t| t.to_ascii_lowercase())
            .collect();
        for forbidden in ["equivalent", "equiv_alent", "proven", "proved"] {
            assert!(
                !tokens.iter().any(|t| t == forbidden),
                "probe must never assert equivalence; found token {forbidden:?}"
            );
        }
    }

    #[test]
    fn replay_mode_exists_and_is_the_confirmation_path() {
        let src = generate(&spec());
        assert!(src.contains("--replay"));
        assert!(src.contains("witness_hex"));
    }

    #[test]
    fn domain_is_rendered_with_bounds() {
        assert_eq!(spec().domain(), "p0: &str[len<=32]");
        let s = HarnessSpec {
            fn_path: "f".into(),
            params: vec![Param {
                name: "n".into(),
                ty: GenType::Prim("u8".into()),
            }],
            max_len: 8,
        };
        assert_eq!(s.domain(), "n: u8");
    }

    #[test]
    fn generated_source_parses_as_rust() {
        // The strongest cheap check on a code generator: the output must at
        // least be syntactically valid Rust.
        let src = generate(&spec());
        syn::parse_file(&src).expect("generated probe must be valid Rust");
    }

    #[test]
    fn generated_source_parses_for_every_supported_shape() {
        let shapes = [
            GenType::Prim("u64".into()),
            GenType::String,
            GenType::StrRef,
            GenType::Vec(Box::new(GenType::Prim("i8".into()))),
            GenType::SliceRef(Box::new(GenType::Prim("u8".into()))),
            GenType::Option(Box::new(GenType::Prim("u32".into()))),
            GenType::Tuple(vec![GenType::Prim("u8".into()), GenType::String]),
        ];
        for (i, ty) in shapes.into_iter().enumerate() {
            let s = HarnessSpec {
                fn_path: "f".into(),
                params: vec![Param {
                    name: "p0".into(),
                    ty,
                }],
                max_len: 16,
            };
            let src = generate(&s);
            syn::parse_file(&src)
                .unwrap_or_else(|e| panic!("shape {i} produced invalid Rust: {e}"));
        }
    }
}
