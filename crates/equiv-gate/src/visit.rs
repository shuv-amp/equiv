//! Body scanner: walks a function body collecting effects and shape facts.
//!
//! This is a *syntactic* analysis. It cannot see through type aliases, macro
//! expansion, trait resolution, or into callee bodies in other modules. Every
//! such blind spot is resolved by rejecting, so the analysis over-rejects and
//! does not under-reject.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};

use crate::reject::Reject;
use crate::rules::{classify_macro, classify_path, is_pure_fn, is_pure_method, render_path};

/// What the scanner learned about a function body.
#[derive(Debug, Default, Clone)]
pub struct BodyFacts {
    pub rejects: Vec<Reject>,
    pub has_loop: bool,
    pub has_recursion: bool,
    pub call_sites: usize,
}

/// Scan a function body.
///
/// `statics` names every `static` item in the crate, so a bare read of one can
/// be told apart from a local variable. Without it a function that reads global
/// mutable state looks pure, which is the one direction this analysis must
/// never err in.
pub fn scan_body(block: &syn::Block, fn_name: &str, statics: &BTreeSet<String>) -> BodyFacts {
    let mut v = BodyScanner {
        fn_name: fn_name.to_string(),
        statics,
        facts: BodyFacts::default(),
        seen: BTreeSet::new(),
        bound: BTreeSet::new(),
    };
    v.visit_block(block);
    v.facts
}

struct BodyScanner<'a> {
    fn_name: String,
    statics: &'a BTreeSet<String>,
    facts: BodyFacts,
    /// Deduplicates rejects so one repeated call does not dominate the
    /// histogram for a single function.
    seen: BTreeSet<String>,
    /// Names bound locally (`let`, parameters of nested closures). A local that
    /// shadows a static is not a read of that static.
    bound: BTreeSet<String>,
}

impl BodyScanner<'_> {
    fn push(&mut self, r: Reject) {
        let key = format!("{}:{}", r.code(), r);
        if self.seen.insert(key) {
            self.facts.rejects.push(r);
        }
    }

    /// Record every identifier a pattern binds, so later reads of that name are
    /// known to be local rather than global.
    fn bind_pattern(&mut self, pat: &syn::Pat) {
        if let syn::Pat::Ident(id) = pat {
            self.bound.insert(id.ident.to_string());
        }
        // Destructuring patterns bind through their sub-patterns; `syn`'s
        // visitor reaches those for us on the recursive walk, so only the
        // simple case needs handling here.
    }
}

impl<'ast> Visit<'ast> for BodyScanner<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        // Visit the initialiser *before* binding the name: `let x = x + 1;`
        // reads the outer `x`, which may be a static.
        if let Some(init) = &node.init {
            self.visit_expr(&init.expr);
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
        self.visit_pat(&node.pat);
        self.bind_pattern(&node.pat);
    }

    fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
        self.bound.insert(node.ident.to_string());
        visit::visit_pat_ident(self, node);
    }
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.push(Reject::UnsafeBlock);
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
        self.push(Reject::Await);
        visit::visit_expr_await(self, node);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.facts.has_loop = true;
        visit::visit_expr_loop(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.facts.has_loop = true;
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.facts.has_loop = true;
        visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.facts.call_sites += 1;
        if let syn::Expr::Path(p) = &*node.func {
            let rendered = render_path(&p.path);
            let segs: Vec<&str> = rendered.split("::").filter(|s| !s.is_empty()).collect();
            let last = *segs.last().unwrap_or(&rendered.as_str());

            // Recursion means *this* function calling itself, which is written
            // unqualified or as `Self::name`. Matching on the last segment
            // alone would read `other::parse(x)` inside `fn parse` as
            // recursion, and recursion does not block fuzzing — so an
            // unresolved, possibly effectful callee would be waved through.
            let is_self_call = match segs.as_slice() {
                [n] => *n == self.fn_name,
                ["Self", n] => *n == self.fn_name,
                _ => false,
            };

            if is_self_call {
                self.facts.has_recursion = true;
            } else if let Some(r) = classify_path(&rendered) {
                self.push(r);
            } else if !is_pure_fn(&rendered) && !is_enum_ctor(last) {
                self.push(Reject::UnresolvedCall(rendered));
            }
        } else {
            // Calling a closure or an expression result: not resolvable.
            self.push(Reject::UnresolvedCall("<dynamic callee>".into()));
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.facts.call_sites += 1;
        let name = node.method.to_string();
        // A method sharing the enclosing function's name *may* be recursion —
        // `self.foo()` inside `fn foo` — and we cannot tell without types, so
        // record it and block proving. The purity check still runs regardless:
        // `v.len()` inside `fn len` is not recursion, and skipping the check
        // there would admit whatever the method actually does.
        if name == self.fn_name {
            self.facts.has_recursion = true;
        }
        if !is_pure_method(&name) {
            self.push(Reject::UnresolvedMethod(name));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if let Some(r) = classify_macro(&name) {
            self.push(r);
        }
        visit::visit_macro(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        // Catches effectful paths used outside call position, e.g. a bare
        // `Instant::now` passed as a function value, or `std::io::stdin`.
        let rendered = render_path(node);
        if rendered.contains("::") {
            if let Some(r) = classify_path(&rendered) {
                self.push(r);
            }
        }

        // A read of a crate-level `static` is state outside the arguments, and
        // it is spelled exactly like a local variable. Only the crate-wide
        // index can tell the two apart, and a local of the same name shadows
        // the static, so bound names win.
        if let Some(id) = node.get_ident() {
            let name = id.to_string();
            if self.statics.contains(&name) && !self.bound.contains(&name) {
                self.push(Reject::StaticAccess(name));
            }
        }

        visit::visit_path(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        self.push(Reject::StaticAccess(node.ident.to_string()));
        visit::visit_item_static(self, node);
    }
}

/// Enum constructors and tuple-struct constructors look like calls but are
/// pure data construction.
fn is_enum_ctor(name: &str) -> bool {
    if matches!(name, "Some" | "Ok" | "Err") {
        return true;
    }
    // Heuristic: UpperCamelCase identifiers in call position are constructors.
    name.chars().next().is_some_and(char::is_uppercase)
}
