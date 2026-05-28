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
use crate::matcher::glob_subsumes;

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
///
/// This is a **first-match** notion of deadness: it assumes order is priority.
/// It is *not* valid under [`Mode::DenyOverrides`](crate::Mode), where a later
/// `deny` can override an earlier subsuming `allow` and so stays reachable —
/// callers should only run this on `first_match` policies.
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
/// Delegates to the glob language-inclusion decision in [`crate::matcher`].
fn tool_subsumes(a: &str, b: &str) -> bool {
    glob_subsumes(a, b)
}

/// Sound check: whenever `later`'s condition holds, does `earlier`'s also hold?
///
/// `earlier == None` matches unconditionally, so it subsumes anything.
/// Otherwise we ask whether `earlier`'s condition is *implied by* `later`'s —
/// see [`expr_subsumes`].
fn condition_subsumes(earlier: &Option<Expr>, later: &Option<Expr>) -> bool {
    match earlier {
        None => true,
        Some(e) => matches!(later, Some(l) if expr_subsumes(e, l)),
    }
}

/// Sound check: does `earlier` hold whenever `later` holds (`later` ⟹
/// `earlier`)? Conservative — every `true` is provable, but some true
/// implications go unrecognized.
///
/// Beyond structural equality we exploit:
/// - a conjunction is implied if *all* its parts are (`earlier` an `and`), and
///   implies anything one of its parts does (`later` an `and`);
/// - a disjunction implies a goal only if *both* arms do (`later` an `or`), and
///   is implied if *either* of its arms is (`earlier` an `or`);
/// - on leaves, `path matches A` is implied by `path matches B` when
///   [`glob_subsumes`]`(A, B)` holds, and `command contains X` by
///   `command contains Y` when `X` is a substring of `Y`.
///
/// `not` is only handled via the equality fast-path, which is always sound.
fn expr_subsumes(earlier: &Expr, later: &Expr) -> bool {
    if expr_eq(earlier, later) {
        return true;
    }
    match earlier {
        Expr::And(e1, e2) => expr_subsumes(e1, later) && expr_subsumes(e2, later),
        Expr::Or(e1, e2) => expr_subsumes(e1, later) || expr_subsumes(e2, later),
        _ => match later {
            Expr::And(l1, l2) => expr_subsumes(earlier, l1) || expr_subsumes(earlier, l2),
            Expr::Or(l1, l2) => expr_subsumes(earlier, l1) && expr_subsumes(earlier, l2),
            _ => leaf_subsumes(earlier, later),
        },
    }
}

/// Implication between two leaf predicates (no `and`/`or`/`not`).
fn leaf_subsumes(earlier: &Expr, later: &Expr) -> bool {
    match (earlier, later) {
        (
            Expr::Match { field: ef, pattern: ep, .. },
            Expr::Match { field: lf, pattern: lp, .. },
        ) => ef == lf && glob_subsumes(ep, lp),
        (
            Expr::Contains { field: ef, needle: en, .. },
            Expr::Contains { field: lf, needle: ln, .. },
        ) => ef == lf && ln.contains(en.as_str()),
        _ => false,
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
        format!("a broader rule (`{} tool(\"{}\")`)", earlier.effect.as_str(), earlier.tool)
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

    #[test]
    fn broader_glob_shadows_narrower() {
        // `path matches "**"` covers `path matches "src/**"`, so the second
        // rule is dead even though the effects differ.
        let dead = shadowed_indices(
            r#"
            allow tool("read") when path matches "**"
            deny  tool("read") when path matches "src/**"
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn narrower_glob_does_not_shadow_broader() {
        // The reverse must NOT be flagged: `src/**` leaves non-src paths for
        // the later `**` rule to handle.
        let dead = shadowed_indices(
            r#"
            deny tool("read") when path matches "src/**"
            deny tool("read") when path matches "**"
        "#,
        );
        assert!(dead.is_empty(), "unexpected shadows: {dead:?}");
    }

    #[test]
    fn shorter_substring_shadows_longer_contains() {
        // Anything containing "rm -rf" contains "rm", so the second is dead.
        let dead = shadowed_indices(
            r#"
            deny tool("bash") when command contains "rm"
            deny tool("bash") when command contains "rm -rf"
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn conjunction_is_shadowed_by_one_of_its_parts() {
        // The later `and` only fires when its `contains "rm -rf"` part holds,
        // which already implies the earlier `contains "rm"`.
        let dead = shadowed_indices(
            r#"
            deny tool("bash") when command contains "rm"
            deny tool("bash") when command contains "rm -rf" and path matches "src/**"
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn narrower_conjunction_does_not_shadow_broader() {
        // Earlier requires an extra `path` clause, so it does NOT cover the
        // later command-only rule — that rule still fires for non-src paths.
        let dead = shadowed_indices(
            r#"
            deny tool("bash") when command contains "rm" and path matches "src/**"
            deny tool("bash") when command contains "rm"
        "#,
        );
        assert!(dead.is_empty(), "unexpected shadows: {dead:?}");
    }

    #[test]
    fn different_field_does_not_shadow() {
        let dead = shadowed_indices(
            r#"
            deny tool("x") when path matches "**"
            deny tool("x") when command matches "y"
        "#,
        );
        assert!(dead.is_empty(), "unexpected shadows: {dead:?}");
    }
}
