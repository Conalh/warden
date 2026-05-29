//! `warden` CLI: load a policy file, optionally evaluate one action against it.
//!
//! Usage:
//!   warden <policy-file> [--json]                     validate the policy
//!   warden <policy-file> --tool <name> [--path P] [--command C] [--json]
//!
//! `--json` swaps the human-readable output for a single machine-readable JSON
//! object on stdout (nothing on stderr), so `warden` drops into a CI step or an
//! agent's tool-use loop. Exit codes are identical in both modes.
//!
//! Exit codes: 0 allow/ask, 1 deny, 2 parse error, 3 unreachable rules,
//! 4 self-test failed, 64 usage error.

use std::process::ExitCode;

use warden::{Action, Effect, Json, Mode, Policy, TestOutcome};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}\n");
            print_usage();
            ExitCode::from(64)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_usage();
        return Ok(ExitCode::SUCCESS);
    }

    let path = &args[0];
    let mut tool: Option<String> = None;
    let mut action_path: Option<String> = None;
    let mut command: Option<String> = None;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tool" => tool = Some(take_value(args, &mut i)?),
            "--path" => action_path = Some(take_value(args, &mut i)?),
            "--command" => command = Some(take_value(args, &mut i)?),
            "--json" => json = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }

    let source = std::fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;

    let policy = match warden::parse(&source) {
        Ok(policy) => policy,
        Err(diagnostics) => {
            if json {
                let errors = diagnostics
                    .iter()
                    .map(|d| {
                        Json::Object(vec![
                            ("message", d.message.as_str().into()),
                            ("line", Json::Int(d.span.line as i64)),
                            ("col", Json::Int(d.span.col as i64)),
                        ])
                    })
                    .collect();
                let report = Json::Object(vec![
                    ("status", "error".into()),
                    ("errors", Json::Array(errors)),
                ]);
                println!("{}", report.render());
            } else {
                eprintln!("{}", warden::render_all(&source, &diagnostics));
                eprintln!("\n{} error(s); policy not loaded.", diagnostics.len());
            }
            return Ok(ExitCode::from(2));
        }
    };

    let Some(tool) = tool else {
        return Ok(validate(&policy, &source, json));
    };

    let mut action = Action::new(tool);
    if let Some(p) = action_path {
        action = action.with_path(p);
    }
    if let Some(c) = command {
        action = action.with_command(c);
    }

    let verdict = warden::evaluate(&policy, &action);
    if json {
        let report = Json::Object(vec![
            ("effect", verdict.effect.as_str().into()),
            (
                "rule",
                verdict
                    .matched_rule
                    .map_or(Json::Null, |i| Json::Int(i as i64 + 1)),
            ),
            ("reason", verdict.explanation.as_str().into()),
        ]);
        println!("{}", report.render());
    } else {
        println!("decision: {}", verdict.effect.as_str().to_uppercase());
        println!("reason:   {}", verdict.explanation);
    }

    Ok(match verdict.effect {
        Effect::Deny => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

/// Validate mode (no action given): print the summary, run the unreachable-rule
/// lint (first-match policies only) and any inline self-tests, then return the
/// most serious exit code — `4` if a self-test failed, else `3` for unreachable
/// rules, else `0`.
fn validate(policy: &Policy, source: &str, json: bool) -> ExitCode {
    if json {
        return validate_json(policy);
    }

    println!(
        "{} rule(s), default `{}`, mode `{}`",
        policy.rules.len(),
        policy.default.as_str(),
        policy.mode.as_str()
    );

    let mut exit = 0u8;

    // Unreachable-rule analysis is a first-match notion; under deny-overrides a
    // later `deny` can still win, so we don't run it.
    if policy.mode == Mode::FirstMatch {
        let lints = warden::find_shadowed(policy);
        if lints.is_empty() {
            println!("policy ok: no unreachable rules.");
        } else {
            for lint in &lints {
                eprintln!(
                    "{}\n",
                    lint.to_diagnostic().render_labeled(source, "warning")
                );
            }
            eprintln!("{} unreachable rule(s) found.", lints.len());
            exit = 3;
        }
    } else {
        println!("policy ok: unreachable-rule analysis applies to `first_match` only; skipped.");
    }

    // Self-tests run in every mode — a deny_overrides policy benefits just as much.
    if !policy.tests.is_empty() && report_tests(&warden::run_tests(policy)) > 0 {
        // A broken behavioral expectation outranks a dead rule.
        exit = 4;
    }

    ExitCode::from(exit)
}

/// The `--json` counterpart of [`validate`]: emit one JSON object capturing the
/// summary, every unreachable-rule lint, and every self-test outcome. The exit
/// code and the `status` field follow the same precedence as the human path —
/// `4`/`"error"` if a self-test failed, else `3`/`"warning"` for unreachable
/// rules, else `0`/`"ok"`.
fn validate_json(policy: &Policy) -> ExitCode {
    let mut exit = 0u8;
    let mut status = "ok";

    // Unreachable analysis is first-match-only, same as the human path.
    let unreachable: Vec<Json> = if policy.mode == Mode::FirstMatch {
        let lints = warden::find_shadowed(policy);
        if !lints.is_empty() {
            exit = 3;
            status = "warning";
        }
        lints
            .iter()
            .map(|lint| {
                Json::Object(vec![
                    ("rule", Json::Int(lint.rule as i64 + 1)),
                    ("coveredBy", Json::Int(lint.covered_by as i64 + 1)),
                    ("message", lint.message.as_str().into()),
                    ("line", Json::Int(lint.span.line as i64)),
                ])
            })
            .collect()
    } else {
        Vec::new()
    };

    let outcomes = warden::run_tests(policy);
    if outcomes.iter().any(|o| !o.passed) {
        // A broken behavioral expectation outranks a dead rule.
        exit = 4;
        status = "error";
    }
    let tests: Vec<Json> = outcomes
        .iter()
        .map(|o| {
            Json::Object(vec![
                ("number", Json::Int(o.number as i64)),
                ("action", o.action.as_str().into()),
                ("expected", o.expected.as_str().into()),
                ("actual", o.actual.as_str().into()),
                ("passed", o.passed.into()),
                ("reason", o.explanation.as_str().into()),
            ])
        })
        .collect();

    let report = Json::Object(vec![
        ("rules", Json::Int(policy.rules.len() as i64)),
        ("default", policy.default.as_str().into()),
        ("mode", policy.mode.as_str().into()),
        ("status", status.into()),
        ("unreachable", Json::Array(unreachable)),
        ("tests", Json::Array(tests)),
    ]);
    println!("{}", report.render());
    ExitCode::from(exit)
}

/// Print one line per inline self-test (with a reason for each failure) plus a
/// summary; return how many failed.
fn report_tests(outcomes: &[TestOutcome]) -> usize {
    for outcome in outcomes {
        if outcome.passed {
            println!(
                "  ok   test {}: {} => {}",
                outcome.number,
                outcome.action,
                outcome.actual.as_str()
            );
        } else {
            println!(
                "  FAIL test {}: {} => expected {}, got {}",
                outcome.number,
                outcome.action,
                outcome.expected.as_str(),
                outcome.actual.as_str()
            );
            println!("         reason: {}", outcome.explanation);
        }
    }
    let failed = outcomes.iter().filter(|o| !o.passed).count();
    println!(
        "{} self-test(s): {} passed, {} failed.",
        outcomes.len(),
        outcomes.len() - failed,
        failed
    );
    failed
}

fn take_value(args: &[String], i: &mut usize) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("missing value for `{}`", args[*i - 1]))
}

fn print_usage() {
    eprintln!(
        "warden - a policy DSL engine\n\n\
         USAGE:\n\
         \x20 warden <policy-file> [--json]\n\
         \x20 warden <policy-file> --tool <name> [--path <p>] [--command <c>] [--json]\n\n\
         EXAMPLES:\n\
         \x20 warden policy.warden\n\
         \x20 warden policy.warden --tool bash --command \"rm -rf /\"\n\
         \x20 warden policy.warden --tool read --path src/main.rs\n\
         \x20 warden policy.warden --tool bash --command \"rm -rf /\" --json\n\n\
         EXIT CODES:\n\
         \x20 0  allow/ask   1  deny   2  parse error   3  unreachable rules   4  self-test failed   64  usage error"
    );
}
