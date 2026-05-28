//! Abstract syntax tree. The recursive `Expr` enum is the heart of the engine:
//! the parser builds it, the evaluator walks it.

use crate::diagnostics::Span;

/// What a rule decides when it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

impl Effect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Ask => "ask",
        }
    }
}

/// A field of the action context that a predicate can inspect. Keeping this a
/// closed enum (rather than an arbitrary string) is what lets the parser
/// reject `paht matches "..."` at parse time instead of silently never firing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Path,
    Command,
}

impl Field {
    pub fn from_ident(name: &str) -> Option<Field> {
        match name {
            "path" => Some(Field::Path),
            "command" => Some(Field::Command),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Field::Path => "path",
            Field::Command => "command",
        }
    }
}

/// A boolean condition. `And`/`Or`/`Not` nest arbitrarily; the leaves are
/// predicates over the action context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// `<field> matches "<glob>"`
    Match { field: Field, pattern: String, span: Span },
    /// `<field> contains "<substring>"`
    Contains { field: Field, needle: String, span: Span },
}

/// `<effect> tool("<glob>") [when <expr>]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub effect: Effect,
    pub tool: String,
    pub condition: Option<Expr>,
    pub span: Span,
}

/// A whole policy file: an ordered list of rules plus the fallback effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub default: Effect,
    pub rules: Vec<Rule>,
}
