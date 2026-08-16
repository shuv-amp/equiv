//! Mines a dictionary of literals from the crate under test.
//!
//! # Why a probe needs one
//!
//! Uniform random bytes do not reach the inputs a function branches on. Measured
//! against the previous `arbitrary`-backed generator, over 20 000 draws:
//!
//! ```text
//! &str   47% empty string, mean length 1.11 characters
//! i32     0 draws landed in roman::to's valid range 1..=3999
//! ```
//!
//! `roman::to` accepts `1..=3999`, which is 9.3e-7 of `i32`. No amount of
//! uniform sampling finds it. Neither does any amount of uniform sampling
//! produce `"1.0.0"` for a version parser.
//!
//! The fix is the oldest one in fuzzing: a **dictionary**. AFL's `-x` and
//! libFuzzer's `-dict=` both exist because tokens drawn from the target
//! dominate random bytes on anything that parses. The tokens are already in the
//! crate — in its constants, its tests, and its doc examples.
//!
//! # What is mined
//!
//! Every string, char, byte-string and integer literal in the source, plus
//! quoted spans lifted out of doc comments, because a doc comment arrives as
//! one long string literal and the useful part is inside the quotes:
//!
//! ```text
//! /// assert_eq!(dedent("  x\n  y"), "x\ny");
//!                        ^^^^^^^^^   ^^^^^     both mined
//! ```
//!
//! Entries are ranked by how often they occur — a literal written five times is
//! more likely to matter than one written once — and ties break
//! lexicographically so two runs over the same crate always agree.

use std::collections::HashMap;

use syn::visit::{self, Visit};

/// Literals worth feeding to a function under test.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Corpus {
    pub strings: Vec<String>,
    pub ints: Vec<i128>,
}

/// Caps on how much is baked into a generated probe.
///
/// The dictionary is indexed by a single byte, so entries past 256 are
/// unreachable; well below that the marginal token stops paying for itself.
const MAX_STRINGS: usize = 128;
const MAX_INTS: usize = 128;
/// Longer literals are prose, not tokens.
const MAX_STRING_LEN: usize = 96;

impl Corpus {
    /// Mine every literal in a parsed crate.
    pub fn mine<'a>(files: impl IntoIterator<Item = &'a syn::File>) -> Self {
        let mut m = Miner::default();
        for f in files {
            m.visit_file(f);
        }
        m.finish()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty() && self.ints.is_empty()
    }
}

#[derive(Default)]
struct Miner {
    strings: HashMap<String, usize>,
    ints: HashMap<i128, usize>,
}

impl Miner {
    fn add_string(&mut self, s: String) {
        if s.is_empty() || s.chars().count() > MAX_STRING_LEN {
            return;
        }
        *self.strings.entry(s).or_default() += 1;
    }

    fn finish(self) -> Corpus {
        Corpus {
            strings: rank(self.strings, MAX_STRINGS),
            ints: rank(self.ints, MAX_INTS),
        }
    }
}

/// Most frequent first, ties lexicographic, truncated to `cap`.
fn rank<T: Ord + Clone>(counts: HashMap<T, usize>, cap: usize) -> Vec<T> {
    let mut v: Vec<(T, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.into_iter().take(cap).map(|(k, _)| k).collect()
}

impl<'ast> Visit<'ast> for Miner {
    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        let raw = node.value();
        // A doc comment is one long string literal whose payload is the code
        // inside it. Pull the quoted spans out; keep the whole thing too when
        // it is short enough to plausibly be a token itself.
        for q in quoted_spans(&raw) {
            self.add_string(q);
        }
        self.add_string(raw);
        visit::visit_lit_str(self, node);
    }

    fn visit_lit_byte_str(&mut self, node: &'ast syn::LitByteStr) {
        if let Ok(s) = String::from_utf8(node.value()) {
            self.add_string(s);
        }
        visit::visit_lit_byte_str(self, node);
    }

    fn visit_lit_char(&mut self, node: &'ast syn::LitChar) {
        self.add_string(node.value().to_string());
        // A char is also a code point worth trying as an integer.
        *self.ints.entry(node.value() as i128).or_default() += 1;
        visit::visit_lit_char(self, node);
    }

    fn visit_lit_int(&mut self, node: &'ast syn::LitInt) {
        if let Ok(v) = node.base10_parse::<i128>() {
            *self.ints.entry(v).or_default() += 1;
            // Boundaries are where guards live: a literal `3999` makes `3998`
            // and `4000` worth trying, and one of the three is usually the
            // input that separates two versions.
            for d in [-1_i128, 1] {
                if let Some(n) = v.checked_add(d) {
                    *self.ints.entry(n).or_default() += 1;
                }
            }
        }
        visit::visit_lit_int(self, node);
    }

    fn visit_lit_byte(&mut self, node: &'ast syn::LitByte) {
        *self.ints.entry(node.value() as i128).or_default() += 1;
        visit::visit_lit_byte(self, node);
    }
}

/// Extract `"..."`-quoted spans from a string, honouring backslash escapes.
///
/// Used on doc comments, where the literal we want is written inside the text.
fn quoted_spans(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut escaped = false;

    for c in s.chars() {
        match &mut cur {
            None => {
                if c == '"' {
                    cur = Some(String::new());
                }
            }
            Some(buf) => {
                if escaped {
                    // Interpret the escapes that carry meaning for an input;
                    // anything else stands for itself.
                    buf.push(match c {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '0' => '\0',
                        other => other,
                    });
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    out.push(std::mem::take(buf));
                    cur = None;
                } else {
                    buf.push(c);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine(src: &str) -> Corpus {
        let f = syn::parse_file(src).unwrap();
        Corpus::mine([&f])
    }

    #[test]
    fn string_literals_are_mined() {
        let c = mine(r#"pub fn f() -> bool { "GET" == "POST" }"#);
        assert!(c.strings.contains(&"GET".to_string()), "{:?}", c.strings);
        assert!(c.strings.contains(&"POST".to_string()));
    }

    #[test]
    fn integer_literals_bring_their_neighbours() {
        // The whole point for `roman::to`, whose domain is 1..=3999 and which
        // uniform sampling of i32 reaches with probability 9.3e-7.
        let c = mine("pub fn to(n: i32) -> u32 { if n > 3999 { 0 } else { 1 } }");
        for want in [3998, 3999, 4000] {
            assert!(c.ints.contains(&want), "missing {want} in {:?}", c.ints);
        }
    }

    #[test]
    fn doc_comment_examples_are_mined() {
        // Doc examples are the highest-quality inputs a crate ships, and they
        // arrive as one long string literal.
        let c = mine(
            r#"
            /// assert_eq!(parse("1.0.0"), Some(1));
            pub fn parse(s: &str) -> Option<u32> { None }
            "#,
        );
        assert!(c.strings.contains(&"1.0.0".to_string()), "{:?}", c.strings);
    }

    #[test]
    fn escapes_inside_doc_examples_are_decoded() {
        let c = mine(
            r#"
            /// assert_eq!(dedent("  x\n  y"), "x\ny");
            pub fn dedent(s: &str) -> String { String::new() }
            "#,
        );
        assert!(
            c.strings.contains(&"  x\n  y".to_string()),
            "{:?}",
            c.strings
        );
        assert!(c.strings.contains(&"x\ny".to_string()));
    }

    #[test]
    fn prose_is_not_a_token() {
        let long = "x".repeat(MAX_STRING_LEN + 1);
        let c = mine(&format!("pub fn f() -> &'static str {{ \"{long}\" }}"));
        assert!(!c.strings.contains(&long));
    }

    #[test]
    fn frequency_ranks_and_order_is_stable() {
        let src = r#"pub fn f(s: &str) -> bool { s == "a" || s == "a" || s == "b" }"#;
        let c = mine(src);
        assert_eq!(c.strings.first().map(String::as_str), Some("a"));
        // Same input, same output: a probe built twice must be byte-identical.
        assert_eq!(c, mine(src));
    }

    #[test]
    fn char_and_byte_literals_are_mined_both_ways() {
        let c = mine("pub fn f(x: u8) -> bool { x == b'Z' }");
        assert!(c.ints.contains(&(b'Z' as i128)), "{:?}", c.ints);
    }

    #[test]
    fn an_empty_crate_yields_an_empty_corpus() {
        assert!(mine("pub fn f(a: u8) -> u8 { a }").is_empty());
    }

    #[test]
    fn quoted_span_scanner_handles_edges() {
        assert_eq!(quoted_spans(r#"a "b" c "d""#), ["b", "d"]);
        assert_eq!(quoted_spans(r#"unterminated "x"#), Vec::<String>::new());
        assert_eq!(quoted_spans(r#""esc \" inside""#), [r#"esc " inside"#]);
        assert_eq!(quoted_spans("no quotes"), Vec::<String>::new());
    }
}
