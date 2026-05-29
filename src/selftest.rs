//! Runs a policy's inline `test` declarations against its own rules.
//!
//! Each [`Test`](crate::ast::Test) names a concrete action and the verdict its
//! author expects; [`run_tests`] evaluates every one and reports whether the
//! policy still agrees. This turns a policy file into something that can assert
//! its own behavior — a rule edit that breaks a documented expectation fails
//! loudly at validate time instead of silently changing a decision.

use crate::ast::{Effect, Policy};
use crate::diagnostics::Span;
use crate::eval::{Action, evaluate};

/// The result of checking one inline `test` against the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestOutcome {
    /// 1-based position of the test among the policy's tests.
    pub number: usize,
    pub passed: bool,
    pub expected: Effect,
    pub actual: Effect,
    /// The action under test, e.g. `tool("bash") command "rm -rf /tmp"`.
    pub action: String,
    /// The verdict's own explanation — names the rule (or default) responsible.
    pub explanation: String,
    /// Where the `test` was declared, for diagnostics.
    pub span: Span,
}

/// Evaluate every inline test in `policy` against the policy's rules.
pub fn run_tests(policy: &Policy) -> Vec<TestOutcome> {
    policy
        .tests
        .iter()
        .enumerate()
        .map(|(i, test)| {
            let mut action = Action::new(&test.tool);
            if let Some(path) = &test.path {
                action = action.with_path(path);
            }
            if let Some(command) = &test.command {
                action = action.with_command(command);
            }
            let verdict = evaluate(policy, &action);
            TestOutcome {
                number: i + 1,
                passed: verdict.effect == test.expected,
                expected: test.expected,
                actual: verdict.effect,
                action: test.describe(),
                explanation: verdict.explanation,
                span: test.span,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    #[test]
    fn passing_and_failing_tests_are_reported() {
        let policy = parse(
            r#"
            default ask
            deny  tool("bash") when command contains "rm -rf"
            allow tool("read") when path matches "src/**"

            test deny  tool("bash") command "rm -rf /tmp"
            test allow tool("read") path "src/main.rs"
            test allow tool("bash") command "rm -rf /tmp"
        "#,
        )
        .unwrap();

        let outcomes = run_tests(&policy);
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes[0].passed);
        assert!(outcomes[1].passed);
        // The third claims `allow` for a command the policy denies.
        assert!(!outcomes[2].passed);
        assert_eq!(outcomes[2].expected, Effect::Allow);
        assert_eq!(outcomes[2].actual, Effect::Deny);
        assert_eq!(outcomes[2].number, 3);
    }

    #[test]
    fn a_policy_without_tests_runs_none() {
        let policy = parse(r#"allow tool("read")"#).unwrap();
        assert!(run_tests(&policy).is_empty());
    }

    #[test]
    fn tests_see_the_combining_mode() {
        // Under deny_overrides the later deny wins, so the action denies even
        // though an earlier allow matched — the test must observe that.
        let policy = parse(
            r#"
            mode deny_overrides
            allow tool("read")
            deny  tool("read") when path matches "**/.env*"

            test deny tool("read") path "config/.env.local"
        "#,
        )
        .unwrap();
        assert!(run_tests(&policy)[0].passed);
    }
}
