//! Static analysis: find rules that can never fire.
//!
//! Because resolution is first-match-wins, a rule is **unreachable** if some
//! earlier rule always matches whenever it would. We check this *pairwise*: a
//! later rule `R` is shadowed if there is an earlier rule `E` whose match-set
//! is a superset of `R`'s.
//!
//! The analysis is deliberately **sound, not complete**: every reported rule
//! is genuinely dead (no false positives), but some dead rules may go
//! unreported. In particular we only reason about a single covering rule, not
//! the union of several, and tool-glob subsumption is decided conservatively.
//! A false "this rule is dead" claim would be far worse in a policy linter
//! than a missed one, so we err toward silence.

use crate::ast::{Expr, Policy, Rule};
use crate::diagnostics::{Diagnostic, Span};

/// One unreachable rule and the earlier rule that shadows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lint {
    /// Index of the dead rule in `Policy::rules`.
    pub rule: usize,
    /// Index of the earlier rule that always matches first.
    pub covered_by: usize,
    pub message: String,
    pub span: Span,
}

impl Lint {
    pub fn to_diagnostic(&self) -> Diagnostic {
        Diagnostic::new(self.message.clone(), self.span)
    }
}

/// Return every unreachable rule, in source order.
pub fn find_shadowed(policy: &Policy) -> Vec<Lint> {
    let mut lints = Vec::new();
    for (j, later) in policy.rules.iter().enumerate() {
        for (i, earlier) in policy.rules[..j].iter().enumerate() {
            if subsumes(earlier, later) {
                lints.push(Lint {
                    rule: j,
                    covered_by: i,
                    message: explain(i, earlier),
                    span: later.span,
                });
                break; // one covering rule is enough to prove deadness
            }
        }
    }
    lints
}

/// Does `earlier` match every action `later` would?
fn subsumes(earlier: &Rule, later: &Rule) -> bool {
    tool_subsumes(&earlier.tool, &later.tool)
        && condition_subsumes(&earlier.condition, &later.condition)
}

/// Sound check: does glob `a` match every tool string that glob `b` matches?
///
/// Handles the cases we can prove: identical patterns, the `*` catch-all, and
/// a literal-prefix-then-`*` pattern (`git*`) against any pattern whose own
/// literal prefix starts with it. Everything else is conservatively `false`.
fn tool_subsumes(a: &str, b: &str) -> bool {
    if a == b || a == "*" {
        return true;
    }
    // Every string `b` matches begins with `prefix`'s literal chars, and
    // `prefix*` matches anything beginning with them.
    if let Some(prefix) = a.strip_suffix('*')
        && is_literal(prefix)
        && b.starts_with(prefix)
    {
        return true;
    }
    false
}

fn is_literal(s: &str) -> bool {
    !s.contains('*') && !s.contains('?')
}

/// Sound check: whenever `later`'s condition holds, does `earlier`'s also hold?
///
/// `earlier == None` matches unconditionally, so it subsumes anything. A
/// structurally identical condition subsumes too. We do not attempt general
/// implication between different conditions.
fn condition_subsumes(earlier: &Option<Expr>, later: &Option<Expr>) -> bool {
    match earlier {
        None => true,
        Some(e) => matches!(later, Some(l) if expr_eq(e, l)),
    }
}

/// Structural equality that ignores spans (the derived `PartialEq` does not).
fn expr_eq(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (Expr::And(a1, a2), Expr::And(b1, b2)) => expr_eq(a1, b1) && expr_eq(a2, b2),
        (Expr::Or(a1, a2), Expr::Or(b1, b2)) => expr_eq(a1, b1) && expr_eq(a2, b2),
        (Expr::Not(a1), Expr::Not(b1)) => expr_eq(a1, b1),
        (
            Expr::Match { field: f1, pattern: p1, .. },
            Expr::Match { field: f2, pattern: p2, .. },
        ) => f1 == f2 && p1 == p2,
        (
            Expr::Contains { field: f1, needle: n1, .. },
            Expr::Contains { field: f2, needle: n2, .. },
        ) => f1 == f2 && n1 == n2,
        _ => false,
    }
}

fn explain(index: usize, earlier: &Rule) -> String {
    let kind = if earlier.condition.is_none() {
        if earlier.tool == "*" {
            format!("an unconditional catch-all `{} tool(\"*\")`", earlier.effect.as_str())
        } else {
            format!("an unconditional `{} tool(\"{}\")`", earlier.effect.as_str(), earlier.tool)
        }
    } else {
        format!("a rule with the same condition (`{} tool(\"{}\")`)", earlier.effect.as_str(), earlier.tool)
    };
    format!(
        "unreachable rule: rule {} at line {} ({}) always matches first",
        index + 1,
        earlier.span.line,
        kind
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    fn shadowed_indices(src: &str) -> Vec<usize> {
        let policy = parse(src).expect("policy should parse");
        find_shadowed(&policy).into_iter().map(|l| l.rule).collect()
    }

    #[test]
    fn unconditional_rule_shadows_later_conditional() {
        let dead = shadowed_indices(
            r#"
            allow tool("read")
            deny  tool("read") when path matches "**/.env*"
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn catch_all_shadows_everything_after_it() {
        let dead = shadowed_indices(
            r#"
            ask   tool("*")
            allow tool("read")
            deny  tool("bash") when command contains "rm"
        "#,
        );
        assert_eq!(dead, vec![1, 2]);
    }

    #[test]
    fn exact_duplicate_is_flagged() {
        let dead = shadowed_indices(
            r#"
            deny tool("bash") when command contains "rm -rf"
            deny tool("bash") when command contains "rm -rf"
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn prefix_glob_subsumes() {
        let dead = shadowed_indices(
            r#"
            allow tool("git*")
            allow tool("git status")
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn distinct_conditions_are_not_shadowed() {
        // Different conditions: the second rule can still fire.
        let dead = shadowed_indices(
            r#"
            deny tool("read") when path matches "a"
            deny tool("read") when path matches "b"
        "#,
        );
        assert!(dead.is_empty(), "unexpected shadows: {dead:?}");
    }

    #[test]
    fn narrower_earlier_does_not_shadow_broader_later() {
        // Earlier rule is conditional; later is unconditional and reachable
        // whenever the earlier condition is false.
        let dead = shadowed_indices(
            r#"
            deny  tool("bash") when command contains "rm"
            allow tool("bash")
        "#,
        );
        assert!(dead.is_empty(), "unexpected shadows: {dead:?}");
    }

    #[test]
    fn different_tools_are_independent() {
        let dead = shadowed_indices(
            r#"
            allow tool("read")
            allow tool("write")
        "#,
        );
        assert!(dead.is_empty(), "unexpected shadows: {dead:?}");
    }
}
