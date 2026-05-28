//! Tree-walking evaluator. Walks the rule list in order, returns the first
//! rule whose tool pattern and condition both match; otherwise the policy
//! default. This is first-match-wins resolution — the simplest semantics that
//! is still predictable. (`deny`-overrides is a planned v1 toggle.)

use crate::ast::{Effect, Expr, Field, Policy, Rule};
use crate::matcher::glob_match;

/// The action an agent wants to take, evaluated against a policy.
#[derive(Clone, Debug, Default)]
pub struct Action {
    pub tool: String,
    pub path: Option<String>,
    pub command: Option<String>,
}

impl Action {
    pub fn new(tool: impl Into<String>) -> Self {
        Action { tool: tool.into(), path: None, command: None }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    fn field(&self, field: Field) -> Option<&str> {
        match field {
            Field::Path => self.path.as_deref(),
            Field::Command => self.command.as_deref(),
        }
    }
}

/// The outcome of evaluating an action: the decided effect, which rule (if
/// any) produced it, and a one-line explanation suitable for an audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub effect: Effect,
    pub matched_rule: Option<usize>,
    pub explanation: String,
}

pub fn evaluate(policy: &Policy, action: &Action) -> Verdict {
    for (index, rule) in policy.rules.iter().enumerate() {
        if !glob_match(&rule.tool, &action.tool) {
            continue;
        }
        let condition_holds = match &rule.condition {
            None => true,
            Some(expr) => eval_expr(expr, action),
        };
        if condition_holds {
            return Verdict {
                effect: rule.effect,
                matched_rule: Some(index),
                explanation: explain(index, rule, action),
            };
        }
    }
    Verdict {
        effect: policy.default,
        matched_rule: None,
        explanation: format!("no rule matched; applied default `{}`", policy.default.as_str()),
    }
}

fn eval_expr(expr: &Expr, action: &Action) -> bool {
    match expr {
        Expr::And(lhs, rhs) => eval_expr(lhs, action) && eval_expr(rhs, action),
        Expr::Or(lhs, rhs) => eval_expr(lhs, action) || eval_expr(rhs, action),
        Expr::Not(inner) => !eval_expr(inner, action),
        Expr::Match { field, pattern, .. } => {
            action.field(*field).is_some_and(|value| glob_match(pattern, value))
        }
        Expr::Contains { field, needle, .. } => {
            action.field(*field).is_some_and(|value| value.contains(needle.as_str()))
        }
    }
}

fn explain(index: usize, rule: &Rule, action: &Action) -> String {
    let because = match &rule.condition {
        Some(expr) => format!(" because {}", why_true(expr, action)),
        None => String::new(),
    };
    format!(
        "matched rule {} (line {}): {} tool(\"{}\"){}",
        index + 1,
        rule.span.line,
        rule.effect.as_str(),
        rule.tool,
        because
    )
}

fn show(action: &Action, field: Field) -> String {
    action.field(field).map_or_else(|| "(unset)".to_string(), |v| format!("\"{v}\""))
}

/// Explain why a condition that evaluated **true** held, naming the deciding
/// leaf predicates with the concrete values that satisfied them.
fn why_true(expr: &Expr, action: &Action) -> String {
    match expr {
        Expr::And(lhs, rhs) => {
            format!("{} and {}", why_true(lhs, action), why_true(rhs, action))
        }
        // Report the branch that actually carried the `or`.
        Expr::Or(lhs, rhs) => {
            if eval_expr(lhs, action) {
                why_true(lhs, action)
            } else {
                why_true(rhs, action)
            }
        }
        // A satisfied `not P` simply means P did not hold; state that directly
        // rather than wrapping a double negative.
        Expr::Not(inner) => why_false(inner, action),
        Expr::Match { field, pattern, .. } => {
            format!("{} {} matches \"{}\"", field.as_str(), show(action, *field), pattern)
        }
        Expr::Contains { field, needle, .. } => {
            format!("{} {} contains \"{}\"", field.as_str(), show(action, *field), needle)
        }
    }
}

/// Mirror of [`why_true`] for a condition that evaluated **false**, used to
/// explain the negated branch under a `not`.
fn why_false(expr: &Expr, action: &Action) -> String {
    match expr {
        // An `and` is false because at least one side is; report a false one.
        Expr::And(lhs, rhs) => {
            if !eval_expr(lhs, action) {
                why_false(lhs, action)
            } else {
                why_false(rhs, action)
            }
        }
        Expr::Or(lhs, rhs) => {
            format!("{} and {}", why_false(lhs, action), why_false(rhs, action))
        }
        Expr::Not(inner) => why_true(inner, action),
        Expr::Match { field, pattern, .. } => {
            format!("{} {} does not match \"{}\"", field.as_str(), show(action, *field), pattern)
        }
        Expr::Contains { field, needle, .. } => {
            format!("{} {} does not contain \"{}\"", field.as_str(), show(action, *field), needle)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    fn policy(src: &str) -> Policy {
        parse(src).expect("policy should parse")
    }

    #[test]
    fn first_match_wins() {
        let p = policy(
            r#"
            deny  tool("bash") when command contains "rm -rf"
            allow tool("bash")
        "#,
        );
        let danger = Action::new("bash").with_command("rm -rf /");
        assert_eq!(evaluate(&p, &danger).effect, Effect::Deny);

        let safe = Action::new("bash").with_command("ls -la");
        assert_eq!(evaluate(&p, &safe).effect, Effect::Allow);
    }

    #[test]
    fn falls_through_to_default() {
        let p = policy(
            r#"
            default ask
            allow tool("read") when path matches "src/**"
        "#,
        );
        let outside = Action::new("read").with_path("secrets/key.pem");
        let verdict = evaluate(&p, &outside);
        assert_eq!(verdict.effect, Effect::Ask);
        assert_eq!(verdict.matched_rule, None);
    }

    #[test]
    fn tool_glob_acts_as_catch_all() {
        let p = policy(r#"deny tool("*") when path matches "**/.env*""#);
        let action = Action::new("write").with_path("config/.env.local");
        assert_eq!(evaluate(&p, &action).effect, Effect::Deny);
    }

    #[test]
    fn boolean_logic() {
        let p = policy(
            r#"ask tool("write") when path matches "**/*.json" and not path matches "package.json""#,
        );
        let pkg = Action::new("write").with_path("package.json");
        assert_eq!(evaluate(&p, &pkg).matched_rule, None);

        let other = Action::new("write").with_path("tsconfig.json");
        assert_eq!(evaluate(&p, &other).effect, Effect::Ask);
    }

    #[test]
    fn trace_names_the_deciding_predicate() {
        let p = policy(r#"deny tool("bash") when command contains "rm -rf""#);
        let v = evaluate(&p, &Action::new("bash").with_command("rm -rf /tmp"));
        assert!(
            v.explanation.contains(r#"command "rm -rf /tmp" contains "rm -rf""#),
            "got: {}",
            v.explanation
        );
    }

    #[test]
    fn trace_reports_the_firing_or_branch() {
        let p = policy(
            r#"deny tool("bash") when command contains "mkfs" or command contains "rm -rf""#,
        );
        let v = evaluate(&p, &Action::new("bash").with_command("sudo rm -rf /"));
        assert!(v.explanation.contains(r#"contains "rm -rf""#), "got: {}", v.explanation);
        assert!(!v.explanation.contains("mkfs"), "got: {}", v.explanation);
    }

    #[test]
    fn trace_explains_negation() {
        let p = policy(r#"ask tool("write") when not path matches "package.json""#);
        let v = evaluate(&p, &Action::new("write").with_path("tsconfig.json"));
        assert!(
            v.explanation.contains(r#"path "tsconfig.json" does not match "package.json""#),
            "got: {}",
            v.explanation
        );
    }
}
