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

/// How matching rules are combined into a verdict.
///
/// `FirstMatch` walks rules top-to-bottom and the first match wins — order
/// *is* the priority. `DenyOverrides` instead collects every matching rule and
/// lets the most restrictive effect win (`deny` > `ask` > `allow`), regardless
/// of order; this is the conservative combining algorithm familiar from
/// XACML / AWS Cedar's `forbid` precedence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    FirstMatch,
    DenyOverrides,
}

impl Mode {
    pub fn from_ident(name: &str) -> Option<Mode> {
        match name {
            "first_match" => Some(Mode::FirstMatch),
            "deny_overrides" => Some(Mode::DenyOverrides),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::FirstMatch => "first_match",
            Mode::DenyOverrides => "deny_overrides",
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
    Match {
        field: Field,
        pattern: String,
        span: Span,
    },
    /// `<field> contains "<substring>"`
    Contains {
        field: Field,
        needle: String,
        span: Span,
    },
}

/// `<effect> tool("<glob>") [when <expr>]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub effect: Effect,
    pub tool: String,
    pub condition: Option<Expr>,
    pub span: Span,
}

/// An inline self-test: a concrete action and the verdict the author expects
/// the policy to reach for it. Checked at validate time, so a policy can assert
/// its own behavior and catch a regression the moment a rule changes.
///
/// `test <effect> tool("<name>") [path "<p>"] [command "<c>"]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    pub expected: Effect,
    pub tool: String,
    pub path: Option<String>,
    pub command: Option<String>,
    pub span: Span,
}

impl Test {
    /// One-line rendering of the action under test, e.g.
    /// `tool("bash") command "rm -rf /tmp"`.
    pub fn describe(&self) -> String {
        let mut out = format!("tool(\"{}\")", self.tool);
        if let Some(path) = &self.path {
            out.push_str(&format!(" path \"{path}\""));
        }
        if let Some(command) = &self.command {
            out.push_str(&format!(" command \"{command}\""));
        }
        out
    }
}

/// A whole policy file: an ordered list of rules, the fallback effect, the
/// combining [`Mode`] that decides how matching rules resolve to a verdict, and
/// any inline self-[`Test`]s declared alongside the rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub default: Effect,
    pub mode: Mode,
    pub rules: Vec<Rule>,
    pub tests: Vec<Test>,
}
