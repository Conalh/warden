//! # warden
//!
//! A from-scratch policy DSL engine. A policy file is a list of rules that
//! decide whether an agent's action is **allowed**, **denied**, or requires a
//! human to be **asked**. The pipeline is the classic interpreter shape:
//!
//! ```text
//! source ──▶ [lexer] ──▶ tokens ──▶ [parser] ──▶ AST (Policy) ──▶ [evaluator] ──▶ Verdict
//! ```
//!
//! Everything is hand-written with zero dependencies: the lexer, the Pratt
//! parser, the glob matcher, and the rustc-style diagnostics.
//!
//! ```
//! let policy = warden::parse(r#"
//!     default ask
//!     deny  tool("bash") when command contains "rm -rf"
//!     allow tool("read") when path matches "src/**"
//! "#).unwrap();
//!
//! let action = warden::Action::new("bash").with_command("rm -rf /");
//! let verdict = warden::evaluate(&policy, &action);
//! assert_eq!(verdict.effect, warden::Effect::Deny);
//! ```

pub mod ast;
pub mod diagnostics;
pub mod eval;

mod lexer;
mod matcher;
mod parser;
mod token;

pub use ast::{Effect, Expr, Field, Policy, Rule};
pub use diagnostics::{render_all, Diagnostic, Span};
pub use eval::{evaluate, Action, Verdict};

use lexer::Lexer;

/// Parse policy source into a [`Policy`], or collect every diagnostic.
///
/// Lexer and parser errors are merged so a single call reports all problems.
pub fn parse(source: &str) -> Result<Policy, Vec<Diagnostic>> {
    let (tokens, mut diagnostics) = Lexer::new(source).tokenize();
    let (policy, parse_diagnostics) = parser::parse_tokens(tokens);
    diagnostics.extend(parse_diagnostics);
    if diagnostics.is_empty() {
        Ok(policy)
    } else {
        Err(diagnostics)
    }
}
