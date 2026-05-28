//! End-to-end tests over the full pipeline (parse -> evaluate) and the
//! diagnostics surface, including the shipped example policy.

use warden::{evaluate, parse, Action, Effect};

const EXAMPLE: &str = include_str!("../examples/agent.warden");
const SHADOWED: &str = include_str!("../examples/shadowed.warden");

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
        (Action::new("bash").with_command("rm -rf /tmp"), Effect::Deny),
        (Action::new("bash").with_command("git status -s"), Effect::Allow),
        (Action::new("read").with_path("src/main.rs"), Effect::Allow),
        (Action::new("read").with_path("config/.env.local"), Effect::Deny),
        (Action::new("write").with_path("app/tsconfig.json"), Effect::Ask),
        (Action::new("write").with_path("src/lib.rs"), Effect::Allow),
        // No rule matches an unknown tool -> default ask.
        (Action::new("browse").with_path("https://example.com"), Effect::Ask),
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
        decide(src, Action::new("write").with_path("/home/me/.ssh/id_rsa.pub")),
        Effect::Deny
    );
}

#[test]
fn precedence_and_negation_combine() {
    let src = r#"ask tool("write") when path matches "**/*.json" and not path matches "package.json""#;
    assert_eq!(decide(src, Action::new("write").with_path("tsconfig.json")), Effect::Ask);
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
fn shadowed_example_flags_dead_rules() {
    let policy = parse(SHADOWED).unwrap();
    let dead: Vec<usize> = warden::find_shadowed(&policy).iter().map(|l| l.rule).collect();
    assert_eq!(dead, vec![1, 3]);
}
