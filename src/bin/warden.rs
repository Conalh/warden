//! `warden` CLI: load a policy file, optionally evaluate one action against it.
//!
//! Usage:
//!   warden <policy-file> [--json]                     validate the policy
//!   warden <policy-file> --tool <name> [--path P] [--command C] [--json]
//!   warden <policy-file> --stdin                       stream JSONL decisions
//!
//! `--json` swaps the human-readable output for a single machine-readable JSON
//! object on stdout (nothing on stderr), so `warden` drops into a CI step or an
//! agent's tool-use loop. Exit codes are identical in both modes.
//!
//! `--stdin` keeps one warden process alive and reads one JSON action object per
//! line, printing one JSON verdict per line — so a long-lived agent streams its
//! checks through a single process instead of paying spawn cost per action.
//!
//! Exit codes: 0 allow/ask, 1 deny, 2 parse error, 3 unreachable rules,
//! 4 self-test failed, 64 usage error. In `--stdin` mode the exit code is 1 if
//! any line was malformed, else 0 (per-line effects ride in each JSON verdict).

use std::process::ExitCode;

use warden::{Action, Effect, Json, Mode, Policy, TestOutcome, Verdict};

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
    let mut stdin = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tool" => tool = Some(take_value(args, &mut i)?),
            "--path" => action_path = Some(take_value(args, &mut i)?),
            "--command" => command = Some(take_value(args, &mut i)?),
            "--json" => json = true,
            "--stdin" => stdin = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }

    // Batch mode draws every action from stdin, so the one-shot action flags
    // are mutually exclusive with it.
    if stdin && (tool.is_some() || action_path.is_some() || command.is_some()) {
        return Err(
            "`--stdin` reads actions from stdin; do not also pass --tool/--path/--command"
                .to_string(),
        );
    }

    let source = std::fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;

    let policy = match warden::parse(&source) {
        Ok(policy) => policy,
        Err(diagnostics) => {
            if json {
                let errors = diagnostics
                    .iter()
                    .map(|d| {
                        Json::object(vec![
                            ("message", d.message.as_str().into()),
                            ("line", Json::Int(d.span.line as i64)),
                            ("col", Json::Int(d.span.col as i64)),
                        ])
                    })
                    .collect();
                let report = Json::object(vec![
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

    if stdin {
        if let Some(code) = validate_stdin_policy(&policy, &source) {
            return Ok(code);
        }
        return Ok(run_stdin(&policy));
    }

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
        println!("{}", verdict_to_json(&verdict).render());
    } else {
        println!("decision: {}", verdict.effect.as_str().to_uppercase());
        println!("reason:   {}", verdict.explanation);
    }

    Ok(match verdict.effect {
        Effect::Deny => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

/// The single JSON object a decision renders to: the effect, the 1-based number
/// of the rule that matched (or `null`), and the human-readable reason. Shared
/// by `--tool ... --json` and the `--stdin` batch loop so both speak the same
/// shape.
fn verdict_to_json(verdict: &Verdict) -> Json {
    Json::object(vec![
        ("effect", verdict.effect.as_str().into()),
        (
            "rule",
            verdict
                .matched_rule
                .map_or(Json::Null, |i| Json::Int(i as i64 + 1)),
        ),
        ("reason", verdict.explanation.as_str().into()),
    ])
}

/// Batch mode: read one JSON action object per line of stdin, evaluate each
/// against `policy`, and print one JSON verdict per line. A line that is blank
/// is skipped; a line that fails to parse or lacks a `tool` becomes an error
/// object instead of a verdict and flips the exit code to `1`, but never stops
/// the stream — a long-lived agent keeps getting decisions for its good lines.
fn run_stdin(policy: &Policy) -> ExitCode {
    use std::io::BufRead;

    let mut any_error = false;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                println!("{}", error_json(&format!("cannot read stdin: {e}")));
                return ExitCode::from(1);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match action_from_line(&line) {
            Ok(action) => {
                let verdict = warden::evaluate(policy, &action);
                println!("{}", verdict_to_json(&verdict).render());
            }
            Err(message) => {
                println!("{}", error_json(&message));
                any_error = true;
            }
        }
    }

    if any_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Before `--stdin` becomes a long-lived decision service, make sure the policy
/// is healthy. Keep success silent so stdout remains a pure verdict stream.
fn validate_stdin_policy(policy: &Policy, source: &str) -> Option<ExitCode> {
    let mut exit = 0u8;

    let (lints, noun) = match policy.mode {
        Mode::FirstMatch => (warden::find_shadowed(policy), "unreachable"),
        Mode::DenyOverrides => (warden::find_redundant(policy), "redundant"),
    };
    if !lints.is_empty() {
        eprintln!("policy validation failed before --stdin:\n");
        for lint in &lints {
            let label = match lint.severity {
                warden::Severity::Dangerous => "danger",
                warden::Severity::Redundant => "warning",
            };
            eprintln!("{}\n", lint.to_diagnostic().render_labeled(source, label));
        }
        let dangerous = lints
            .iter()
            .filter(|l| l.severity == warden::Severity::Dangerous)
            .count();
        if dangerous > 0 {
            eprintln!(
                "{} {noun} rule(s) found, {dangerous} of them dangerous (a stricter \
                 control silently not enforced).",
                lints.len()
            );
        } else {
            eprintln!("{} {noun} rule(s) found.", lints.len());
        }
        exit = 3;
    }

    let outcomes = warden::run_tests(policy);
    let failed = outcomes.iter().filter(|o| !o.passed).count();
    if failed > 0 {
        if exit == 0 {
            eprintln!("policy validation failed before --stdin:\n");
        } else {
            eprintln!();
        }
        for outcome in &outcomes {
            if outcome.passed {
                continue;
            }
            eprintln!(
                "FAIL self-test {}: {} => expected {}, got {}",
                outcome.number,
                outcome.action,
                outcome.expected.as_str(),
                outcome.actual.as_str()
            );
            eprintln!("     reason: {}", outcome.explanation);
        }
        eprintln!(
            "{} self-test(s): {} passed, {} failed.",
            outcomes.len(),
            outcomes.len() - failed,
            failed
        );
        exit = 4;
    }

    if exit == 0 {
        None
    } else {
        Some(ExitCode::from(exit))
    }
}

/// Parse one stdin line into an [`Action`]: it must be a JSON object with a
/// string `tool`, plus optional string `path` and `command`. Unknown fields are
/// ignored so callers can thread their own metadata through untouched.
fn action_from_line(line: &str) -> Result<Action, String> {
    let Json::Object(fields) = warden::json::parse(line)? else {
        return Err("each line must be a JSON object".to_string());
    };

    let mut tool = None;
    let mut path = None;
    let mut command = None;
    for (key, value) in fields {
        match key.as_str() {
            "tool" => tool = string_field("tool", value)?,
            "path" => path = string_field("path", value)?,
            "command" => command = string_field("command", value)?,
            _ => {}
        }
    }

    let mut action = Action::new(tool.ok_or("missing required string field `tool`")?);
    if let Some(p) = path {
        action = action.with_path(p);
    }
    if let Some(c) = command {
        action = action.with_command(c);
    }
    Ok(action)
}

/// Coerce a field value to an optional string: a JSON string is `Some`, `null`
/// is treated as absent, and anything else is a clean error.
fn string_field(field: &str, value: Json) -> Result<Option<String>, String> {
    match value {
        Json::Str(s) => Ok(Some(s)),
        Json::Null => Ok(None),
        _ => Err(format!("field `{field}` must be a string")),
    }
}

/// One-line error object for the batch stream, mirroring the parse-error shape.
fn error_json(message: &str) -> String {
    Json::object(vec![("status", "error".into()), ("error", message.into())]).render()
}

/// Validate mode (no action given): print the summary, run the deadness lint
/// (unreachable rules under `first_match`, dominated/redundant rules under
/// `deny_overrides`) and any inline self-tests, then return the most serious
/// exit code — `4` if a self-test failed, else `3` for a dead rule, else `0`.
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

    // Both modes get a deadness lint, but a different one: `first_match` order
    // *is* priority so a later rule can be shadowed, while `deny_overrides`
    // resolves by restrictiveness so the analogous dead rule is one dominated by
    // an at-least-as-restrictive match (see the two analysis entry points).
    let (lints, noun) = match policy.mode {
        Mode::FirstMatch => (warden::find_shadowed(policy), "unreachable"),
        Mode::DenyOverrides => (warden::find_redundant(policy), "redundant"),
    };
    if lints.is_empty() {
        println!("policy ok: no {noun} rules.");
    } else {
        for lint in &lints {
            // Surface a dropped control more loudly than dead code.
            let label = match lint.severity {
                warden::Severity::Dangerous => "danger",
                warden::Severity::Redundant => "warning",
            };
            eprintln!("{}\n", lint.to_diagnostic().render_labeled(source, label));
        }
        let dangerous = lints
            .iter()
            .filter(|l| l.severity == warden::Severity::Dangerous)
            .count();
        if dangerous > 0 {
            eprintln!(
                "{} {noun} rule(s) found, {dangerous} of them dangerous (a stricter \
                 control silently not enforced).",
                lints.len()
            );
        } else {
            eprintln!("{} {noun} rule(s) found.", lints.len());
        }
        exit = 3;
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

    // Same mode-aware deadness lint as the human path: shadow under first-match,
    // domination under deny-overrides. The JSON key stays `unreachable` for
    // backward compatibility; each entry carries a `severity` distinguishing a
    // dropped control (`dangerous`) from harmless dead code (`redundant`).
    let lints = match policy.mode {
        Mode::FirstMatch => warden::find_shadowed(policy),
        Mode::DenyOverrides => warden::find_redundant(policy),
    };
    if !lints.is_empty() {
        exit = 3;
        status = "warning";
    }
    let unreachable: Vec<Json> = lints
        .iter()
        .map(|lint| {
            Json::object(vec![
                ("rule", Json::Int(lint.rule as i64 + 1)),
                ("coveredBy", Json::Int(lint.covered_by as i64 + 1)),
                ("severity", lint.severity.as_str().into()),
                ("message", lint.message.as_str().into()),
                ("line", Json::Int(lint.span.line as i64)),
            ])
        })
        .collect();

    let outcomes = warden::run_tests(policy);
    if outcomes.iter().any(|o| !o.passed) {
        // A broken behavioral expectation outranks a dead rule.
        exit = 4;
        status = "error";
    }
    let tests: Vec<Json> = outcomes
        .iter()
        .map(|o| {
            Json::object(vec![
                ("number", Json::Int(o.number as i64)),
                ("action", o.action.as_str().into()),
                ("expected", o.expected.as_str().into()),
                ("actual", o.actual.as_str().into()),
                ("passed", o.passed.into()),
                ("reason", o.explanation.as_str().into()),
            ])
        })
        .collect();

    let report = Json::object(vec![
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
         \x20 warden <policy-file> --tool <name> [--path <p>] [--command <c>] [--json]\n\
         \x20 warden <policy-file> --stdin\n\n\
         EXAMPLES:\n\
         \x20 warden policy.warden\n\
         \x20 warden policy.warden --tool bash --command \"rm -rf /\"\n\
         \x20 warden policy.warden --tool read --path src/main.rs\n\
         \x20 warden policy.warden --tool bash --command \"rm -rf /\" --json\n\
         \x20 echo '{{\"tool\":\"read\",\"path\":\"src/main.rs\"}}' | warden policy.warden --stdin\n\n\
         EXIT CODES:\n\
         \x20 0  allow/ask   1  deny   2  parse error   3  unreachable rules   4  self-test failed   64  usage error"
    );
}
