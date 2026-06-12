//! Static analysis: find rules that can never affect a verdict.
//!
//! There are two notions of deadness, one per combining mode:
//!
//! - Under **first-match**, a rule is *unreachable* if some earlier rule always
//!   matches whenever it would ([`find_shadowed`]). We check this *pairwise*: a
//!   later rule `R` is shadowed if there is an earlier rule `E` whose match-set
//!   is a superset of `R`'s.
//! - Under **deny-overrides**, order is not priority, so instead a rule is
//!   *redundant* if some other rule *dominates* it — matches everything it does
//!   and is at least as restrictive ([`find_redundant`]).
//!
//! Each dead rule carries a [`Severity`]. The one that matters is the
//! first-match case where a stricter `deny`/`ask` is shadowed by a broader
//! `allow`: that is a control silently not enforced, flagged [`Severity::Dangerous`]
//! rather than as generic dead code.
//!
//! Both analyses are deliberately **sound, not complete**: every reported rule
//! is genuinely dead (no false positives), but some dead rules may go
//! unreported. In particular we only reason about a single covering/dominating
//! rule, not the union of several, and glob subsumption is decided
//! conservatively. A false "this rule is dead" claim would be far worse in a
//! policy linter than a missed one, so we err toward silence.

use crate::ast::{Expr, GlobScope, Policy, Rule};
use crate::diagnostics::{Diagnostic, Span};
use crate::matcher::glob_subsumes;

/// How much a dead rule actually matters.
///
/// A linter that prints one undifferentiated "unreachable" for every dead rule
/// buries the one case that is a security hole. We split them: a rule shadowed
/// by a cover that is *at least as restrictive* is merely [`Severity::Redundant`]
/// dead code, but a rule **more** restrictive than the rule eating it is
/// [`Severity::Dangerous`] — the author wrote a `deny`/`ask` control that a
/// broader `allow` silently makes inert, so a restriction they think they have
/// is not enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// The dead rule's effect is already covered by an at-least-as-restrictive
    /// rule, so removing it changes nothing.
    Redundant,
    /// The dead rule is stricter than the rule shadowing it: a control that is
    /// silently not enforced.
    Dangerous,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Redundant => "redundant",
            Severity::Dangerous => "dangerous",
        }
    }
}

/// One dead rule and the rule that makes it dead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lint {
    /// Index of the dead rule in `Policy::rules`.
    pub rule: usize,
    /// Index of the rule that covers it — under `first_match` the earlier rule
    /// that always matches first, under `deny_overrides` the rule that dominates
    /// it.
    pub covered_by: usize,
    /// Whether this dead rule is harmless redundancy or a silently-dropped
    /// control. See [`Severity`].
    pub severity: Severity,
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
                let severity = classify(earlier, later);
                lints.push(Lint {
                    rule: j,
                    covered_by: i,
                    severity,
                    message: explain_shadow(i, earlier, later, severity),
                    span: later.span,
                });
                break; // one covering rule is enough to prove deadness
            }
        }
    }
    lints
}

/// Find rules that can never change the verdict under [`Mode::DenyOverrides`](crate::Mode).
///
/// Order is not priority under deny-overrides, so the first-match shadow notion
/// does not apply. The analogous deadness is *domination*: a rule `R` is
/// redundant if some **other** rule `S` matches every action `R` does and is at
/// least as restrictive (`rank(S) >= rank(R)`). Then for every action `R`
/// matches, `S` already contributes an effect at least as strong, so the
/// most-restrictive-wins resolution lands on the same verdict whether or not `R`
/// is present — `R` is dead weight.
///
/// This stays **sound** the same way [`find_shadowed`] does: it only reasons
/// about a single dominating rule, never the union of several, so it may miss a
/// redundant rule but never wrongly flags one that matters. Mutually-dominating
/// duplicates (same match-set, same effect) are reported for all but the first,
/// so removing every flagged rule still leaves one in place.
pub fn find_redundant(policy: &Policy) -> Vec<Lint> {
    let mut lints = Vec::new();
    for (j, rule) in policy.rules.iter().enumerate() {
        if let Some(i) = dominator_of(policy, j) {
            let dom = &policy.rules[i];
            lints.push(Lint {
                rule: j,
                covered_by: i,
                // Domination requires `rank(dom) >= rank(rule)`, so the verdict
                // is already at least as restrictive — this is never a dropped
                // control, only dead weight.
                severity: Severity::Redundant,
                message: explain_dominated(dom),
                span: rule.span,
            });
        }
    }
    lints
}

/// Index of a rule that dominates rule `j` (matches everything it does, at least
/// as restrictive), or `None`. Excludes `j` itself, and breaks ties on
/// mutually-dominating equal-effect duplicates by keeping the earliest: a later
/// duplicate is dominated by an earlier one, but not vice versa.
fn dominator_of(policy: &Policy, j: usize) -> Option<usize> {
    let rule = &policy.rules[j];
    for (i, s) in policy.rules.iter().enumerate() {
        if i == j || !subsumes(s, rule) {
            continue;
        }
        if s.effect.restrictiveness() < rule.effect.restrictiveness() {
            continue;
        }
        // If they dominate each other with equal effect they are duplicates;
        // flag only the later one so the pair is never both called dead.
        let mutual =
            s.effect.restrictiveness() == rule.effect.restrictiveness() && subsumes(rule, s);
        if mutual && i > j {
            continue;
        }
        return Some(i);
    }
    None
}

/// Is the dead rule stricter than the rule shadowing it (a dropped control), or
/// merely covered by an at-least-as-restrictive one (harmless)?
fn classify(cover: &Rule, dead: &Rule) -> Severity {
    if dead.effect.restrictiveness() > cover.effect.restrictiveness() {
        Severity::Dangerous
    } else {
        Severity::Redundant
    }
}

/// Does `earlier` match every action `later` would?
fn subsumes(earlier: &Rule, later: &Rule) -> bool {
    tool_subsumes(&earlier.tool, &later.tool)
        && condition_subsumes(&earlier.condition, &later.condition)
}

/// Sound check: does glob `a` match every tool string that glob `b` matches?
/// Delegates to the glob language-inclusion decision in [`crate::matcher`]. Tool
/// names are flat identifiers, matched under segmented scope (no `/` to cross).
fn tool_subsumes(a: &str, b: &str) -> bool {
    glob_subsumes(a, b, GlobScope::Segmented)
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
            Expr::Match {
                field: ef,
                pattern: ep,
                ..
            },
            Expr::Match {
                field: lf,
                pattern: lp,
                ..
            },
            // Same field, so either field's glob scope is the right one to read
            // both patterns under (`command` flat, `path` segmented).
        ) => ef == lf && glob_subsumes(ep, lp, ef.glob_scope()),
        (
            Expr::Contains {
                field: ef,
                needle: en,
                ..
            },
            Expr::Contains {
                field: lf,
                needle: ln,
                ..
            },
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
            Expr::Match {
                field: f1,
                pattern: p1,
                ..
            },
            Expr::Match {
                field: f2,
                pattern: p2,
                ..
            },
        ) => f1 == f2 && p1 == p2,
        (
            Expr::Contains {
                field: f1,
                needle: n1,
                ..
            },
            Expr::Contains {
                field: f2,
                needle: n2,
                ..
            },
        ) => f1 == f2 && n1 == n2,
        _ => false,
    }
}

/// A short noun phrase naming the covering rule, e.g.
/// ``an unconditional catch-all `ask tool("*")` `` or ``a broader rule (`deny
/// tool("write")`)``.
fn describe(rule: &Rule) -> String {
    if rule.condition.is_none() {
        if rule.tool == "*" {
            format!(
                "an unconditional catch-all `{} tool(\"*\")`",
                rule.effect.as_str()
            )
        } else {
            format!(
                "an unconditional `{} tool(\"{}\")`",
                rule.effect.as_str(),
                rule.tool
            )
        }
    } else {
        format!(
            "a broader rule (`{} tool(\"{}\")`)",
            rule.effect.as_str(),
            rule.tool
        )
    }
}

/// Message for a first-match shadow. A redundant shadow reads as a plain
/// unreachable warning; a dangerous one spells out that a stricter control is
/// silently dropped, since that is the case a policy author most needs to see.
fn explain_shadow(index: usize, earlier: &Rule, later: &Rule, severity: Severity) -> String {
    let head = format!(
        "rule {} at line {} ({}) always matches first",
        index + 1,
        earlier.span.line,
        describe(earlier),
    );
    match severity {
        Severity::Redundant => format!("unreachable rule: {head}"),
        Severity::Dangerous => format!(
            "dangerous unreachable rule: {head}, so this stricter `{}` never fires \
             — the control it expresses is not enforced",
            later.effect.as_str(),
        ),
    }
}

/// Message for a rule dominated under `deny_overrides`. It is reachable but its
/// effect is always matched-or-beaten by another rule, so it cannot change any
/// verdict.
fn explain_dominated(dominator: &Rule) -> String {
    format!(
        "redundant rule: {} at line {} already decides every action this matches \
         (deny_overrides), so this rule never changes the verdict",
        describe(dominator),
        dominator.span.line,
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

    fn lints(src: &str) -> Vec<Lint> {
        find_shadowed(&parse(src).expect("policy should parse"))
    }

    fn redundant_indices(src: &str) -> Vec<usize> {
        let policy = parse(src).expect("policy should parse");
        find_redundant(&policy)
            .into_iter()
            .map(|l| l.rule)
            .collect()
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

    #[test]
    fn permissive_cover_over_stricter_rule_is_dangerous() {
        // A catch-all `allow` eats a later secrets `deny`: the denial is inert.
        let found = lints(
            r#"
            allow tool("read")
            deny  tool("read") when path matches "**/.env*"
        "#,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Dangerous);
        assert!(
            found[0].message.contains("not enforced"),
            "got: {}",
            found[0].message
        );
    }

    #[test]
    fn equal_or_stricter_cover_is_only_redundant() {
        // Same effect (pure duplicate) and a stricter cover over a looser rule
        // are both harmless — the verdict is already at least as restrictive.
        let same = lints(
            r#"
            deny tool("bash") when command contains "rm"
            deny tool("bash") when command contains "rm -rf"
        "#,
        );
        assert_eq!(same[0].severity, Severity::Redundant);

        let stricter_cover = lints(
            r#"
            deny  tool("read") when path matches "**"
            allow tool("read") when path matches "src/**"
        "#,
        );
        assert_eq!(stricter_cover[0].severity, Severity::Redundant);
    }

    #[test]
    fn command_glob_subsumption_is_flat() {
        // Under flat command scope `git *` covers `git status`, so the second
        // rule is dead — the `/`-free case already worked, but the point is the
        // scope used here is the flat one.
        let dead = shadowed_indices(
            r#"
            allow tool("bash") when command matches "git *"
            allow tool("bash") when command matches "git status"
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn redundant_flags_a_dominated_duplicate() {
        // deny-overrides: two identical allows — the later is redundant.
        let dead = redundant_indices(
            r#"
            mode deny_overrides
            allow tool("read")
            allow tool("read")
        "#,
        );
        assert_eq!(dead, vec![1]);
    }

    #[test]
    fn redundant_flags_allow_dominated_by_broader_deny() {
        // An `allow` whose whole match-set is covered by a `deny` can never be
        // the winning effect, regardless of order.
        let dead = redundant_indices(
            r#"
            mode deny_overrides
            allow tool("read") when path matches "src/**"
            deny  tool("read") when path matches "**"
        "#,
        );
        assert_eq!(dead, vec![0]);
    }

    #[test]
    fn redundant_spares_a_meaningful_deny() {
        // The `deny` is the most restrictive thing matching its paths; nothing
        // dominates it, so it must not be flagged.
        let dead = redundant_indices(
            r#"
            mode deny_overrides
            allow tool("read")
            deny  tool("read") when path matches "**/.env*"
        "#,
        );
        assert!(dead.is_empty(), "unexpected redundancies: {dead:?}");
    }

    #[test]
    fn redundant_keeps_one_of_three_duplicates() {
        // Three identical rules: all but the first are redundant, so removing
        // every flagged rule still leaves one standing.
        let dead = redundant_indices(
            r#"
            mode deny_overrides
            allow tool("read")
            allow tool("read")
            allow tool("read")
        "#,
        );
        assert_eq!(dead, vec![1, 2]);
    }
}
