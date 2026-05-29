//! End-to-end tests over the full pipeline (parse -> evaluate) and the
//! diagnostics surface, including the shipped example policy.

use warden::{Action, Effect, Mode, evaluate, parse};

const EXAMPLE: &str = include_str!("../examples/agent.warden");
const SHADOWED: &str = include_str!("../examples/shadowed.warden");
const DENY_OVERRIDES: &str = include_str!("../examples/deny_overrides.warden");
const TESTED: &str = include_str!("../examples/tested.warden");

fn decide(policy_src: &str, action: Action) -> Effect {
    let policy = parse(policy_src).expect("policy should parse");
    evaluate(&policy, &action).effect
}

#[test]
fn shipped_example_parses() {
    let policy = parse(EXAMPLE).expect("example policy must stay valid");
    assert_eq!(policy.default, Effect::Ask);
    assert_eq!(policy.rules.len(), 8);
}

#[test]
fn example_decisions() {
    let cases = [
        (
            Action::new("bash").with_command("rm -rf /tmp"),
            Effect::Deny,
        ),
        (
            Action::new("bash").with_command("git status -s"),
            Effect::Allow,
        ),
        (Action::new("read").with_path("src/main.rs"), Effect::Allow),
        (
            Action::new("read").with_path("config/.env.local"),
            Effect::Deny,
        ),
        (
            Action::new("write").with_path("app/tsconfig.json"),
            Effect::Ask,
        ),
        (Action::new("write").with_path("src/lib.rs"), Effect::Allow),
        // No rule matches an unknown tool -> default ask.
        (
            Action::new("browse").with_path("https://example.com"),
            Effect::Ask,
        ),
    ];
    for (action, expected) in cases {
        let policy = parse(EXAMPLE).unwrap();
        let verdict = evaluate(&policy, &action);
        assert_eq!(
            verdict.effect, expected,
            "action {action:?} -> {} (expected {expected:?})",
            verdict.explanation
        );
    }
}

#[test]
fn wildcard_tool_blocks_secrets_regardless_of_tool() {
    let src = r#"deny tool("*") when path matches "**/id_rsa*""#;
    assert_eq!(
        decide(src, Action::new("read").with_path("/home/me/.ssh/id_rsa")),
        Effect::Deny
    );
    assert_eq!(
        decide(
            src,
            Action::new("write").with_path("/home/me/.ssh/id_rsa.pub")
        ),
        Effect::Deny
    );
}

#[test]
fn precedence_and_negation_combine() {
    let src =
        r#"ask tool("write") when path matches "**/*.json" and not path matches "package.json""#;
    assert_eq!(
        decide(src, Action::new("write").with_path("tsconfig.json")),
        Effect::Ask
    );
    // package.json is excluded by the `not`, so it falls through to default ask...
    // here there is no default declared, so the implicit default `ask` applies too;
    // distinguish by checking the matched rule instead.
    let policy = parse(src).unwrap();
    let verdict = evaluate(&policy, &Action::new("write").with_path("package.json"));
    assert_eq!(verdict.matched_rule, None);
}

#[test]
fn errors_render_with_carets() {
    let src = "allow tool(\"read\") when paht matches \"x\"";
    let diags = parse(src).unwrap_err();
    assert_eq!(diags.len(), 1);
    let rendered = warden::render_all(src, &diags);
    assert!(rendered.contains("unknown field"));
    assert!(rendered.contains('^'));
    assert!(rendered.contains("line 1"));
}

#[test]
fn multiple_errors_in_one_pass() {
    let src = "banana tool(\"x\")\nallow tool(\"read\") when nope matches \"y\"";
    let diags = parse(src).unwrap_err();
    assert!(diags.len() >= 2, "expected >= 2 diagnostics, got {diags:?}");
}

#[test]
fn example_policy_has_no_unreachable_rules() {
    let policy = parse(EXAMPLE).unwrap();
    assert!(
        warden::find_shadowed(&policy).is_empty(),
        "the shipped example should have no dead rules"
    );
}

#[test]
fn deny_overrides_example_resolves_by_restrictiveness() {
    let policy = parse(DENY_OVERRIDES).expect("deny-overrides example must parse");
    assert_eq!(policy.mode, Mode::DenyOverrides);

    // The broad `allow tool("read")` is overridden wherever a deny matches.
    assert_eq!(
        evaluate(&policy, &Action::new("read").with_path("config/.env.local")).effect,
        Effect::Deny
    );
    assert_eq!(
        evaluate(&policy, &Action::new("read").with_path("keys/server.pem")).effect,
        Effect::Deny
    );
    // A plain read still resolves to allow.
    assert_eq!(
        evaluate(&policy, &Action::new("read").with_path("src/main.rs")).effect,
        Effect::Allow
    );
    // `ask` on json overrides the broad write allow.
    assert_eq!(
        evaluate(
            &policy,
            &Action::new("write").with_path("app/tsconfig.json")
        )
        .effect,
        Effect::Ask
    );
    // A plain write is just allowed.
    assert_eq!(
        evaluate(&policy, &Action::new("write").with_path("src/lib.rs")).effect,
        Effect::Allow
    );
}

#[test]
fn same_rules_differ_by_mode() {
    // Identical rule body; only the combining mode changes the verdict.
    let body = r#"
        allow tool("read")
        deny  tool("read") when path matches "**/.env*"
    "#;
    let first = parse(body).unwrap();
    let overrides = parse(&format!("mode deny_overrides\n{body}")).unwrap();
    let secret = Action::new("read").with_path("config/.env.local");
    assert_eq!(evaluate(&first, &secret).effect, Effect::Allow);
    assert_eq!(evaluate(&overrides, &secret).effect, Effect::Deny);
}

#[test]
fn tested_example_passes_its_own_self_tests() {
    let policy = parse(TESTED).expect("tested example must parse");
    let outcomes = warden::run_tests(&policy);
    assert!(
        !outcomes.is_empty(),
        "the example should declare self-tests"
    );
    assert!(
        outcomes.iter().all(|o| o.passed),
        "shipped self-tests must pass: {:?}",
        outcomes
            .iter()
            .filter(|o| !o.passed)
            .map(|o| &o.action)
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_broken_expectation_is_caught() {
    // Same rules, but a test now claims `allow` for a denied command.
    let src = r#"
        deny tool("bash") when command contains "rm -rf"
        test allow tool("bash") command "rm -rf /"
    "#;
    let policy = parse(src).unwrap();
    let outcomes = warden::run_tests(&policy);
    assert_eq!(outcomes.len(), 1);
    assert!(!outcomes[0].passed);
    assert_eq!(outcomes[0].expected, Effect::Allow);
    assert_eq!(outcomes[0].actual, Effect::Deny);
}

#[test]
fn shadowed_example_flags_dead_rules() {
    let policy = parse(SHADOWED).unwrap();
    let dead: Vec<usize> = warden::find_shadowed(&policy)
        .iter()
        .map(|l| l.rule)
        .collect();
    assert_eq!(dead, vec![1, 3, 5, 7]);
}
