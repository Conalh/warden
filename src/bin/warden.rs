//! `warden` CLI: load a policy file, optionally evaluate one action against it.
//!
//! Usage:
//!   warden <policy-file>                              validate the policy
//!   warden <policy-file> --tool <name> [--path P] [--command C]
//!
//! Exit codes: 0 allow/ask, 1 deny, 2 parse error, 3 unreachable rules, 64 usage error.

use std::process::ExitCode;

use warden::{Action, Effect};

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

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tool" => tool = Some(take_value(args, &mut i)?),
            "--path" => action_path = Some(take_value(args, &mut i)?),
            "--command" => command = Some(take_value(args, &mut i)?),
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }

    let source = std::fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;

    let policy = match warden::parse(&source) {
        Ok(policy) => policy,
        Err(diagnostics) => {
            eprintln!("{}", warden::render_all(&source, &diagnostics));
            eprintln!("\n{} error(s); policy not loaded.", diagnostics.len());
            return Ok(ExitCode::from(2));
        }
    };

    let Some(tool) = tool else {
        println!("{} rule(s), default `{}`", policy.rules.len(), policy.default.as_str());
        let lints = warden::find_shadowed(&policy);
        if lints.is_empty() {
            println!("policy ok: no unreachable rules.");
            return Ok(ExitCode::SUCCESS);
        }
        for lint in &lints {
            eprintln!("{}\n", lint.to_diagnostic().render_labeled(&source, "warning"));
        }
        eprintln!("{} unreachable rule(s) found.", lints.len());
        return Ok(ExitCode::from(3));
    };

    let mut action = Action::new(tool);
    if let Some(p) = action_path {
        action = action.with_path(p);
    }
    if let Some(c) = command {
        action = action.with_command(c);
    }

    let verdict = warden::evaluate(&policy, &action);
    println!("decision: {}", verdict.effect.as_str().to_uppercase());
    println!("reason:   {}", verdict.explanation);

    Ok(match verdict.effect {
        Effect::Deny => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

fn take_value(args: &[String], i: &mut usize) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("missing value for `{}`", args[*i - 1]))
}

fn print_usage() {
    eprintln!(
        "warden - a from-scratch policy DSL engine\n\n\
         USAGE:\n\
         \x20 warden <policy-file>\n\
         \x20 warden <policy-file> --tool <name> [--path <p>] [--command <c>]\n\n\
         EXAMPLES:\n\
         \x20 warden policy.warden\n\
         \x20 warden policy.warden --tool bash --command \"rm -rf /\"\n\
         \x20 warden policy.warden --tool read --path src/main.rs\n\n\
         EXIT CODES:\n\
         \x20 0  allow/ask   1  deny   2  parse error   3  unreachable rules   64  usage error"
    );
}
