//! `wasm-bindgen` glue exposing the warden engine to the in-browser playground.
//!
//! This crate sits *outside* the `warden` workspace (its Cargo.toml carries an
//! empty `[workspace]` table) so `wasm-bindgen` never enters the core crate's
//! dependency graph — `warden` itself stays zero-dependency. Everything here is
//! a thin wrapper over warden's public API, returning small structs that
//! wasm-bindgen turns into plain JS objects with string getters (no `serde`).

use warden::{Action, Mode};
use wasm_bindgen::prelude::*;

enum Status {
    Ok,
    Warning,
    Error,
}

impl Status {
    fn as_str(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warning => "warning",
            Status::Error => "error",
        }
    }
}

/// The result of validating a policy, mirroring what the CLI prints when run
/// with no action: a one-line summary, then parse errors (with carets),
/// unreachable-rule warnings, and any inline self-test results.
#[wasm_bindgen]
pub struct Report {
    status: Status,
    text: String,
}

#[wasm_bindgen]
impl Report {
    /// `"ok"`, `"warning"` (unreachable rules found), or `"error"` (parse failed
    /// or a self-test failed).
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.as_str().to_string()
    }

    /// The full human-readable report.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.text.clone()
    }
}

/// Validate `source` and produce a [`Report`].
#[wasm_bindgen]
pub fn validate(source: &str) -> Report {
    let policy = match warden::parse(source) {
        Ok(policy) => policy,
        Err(diagnostics) => {
            let text = format!(
                "{}\n\n{} error(s); policy not loaded.",
                warden::render_all(source, &diagnostics),
                diagnostics.len()
            );
            return Report {
                status: Status::Error,
                text,
            };
        }
    };

    let mut text = format!(
        "{} rule(s), default `{}`, mode `{}`",
        policy.rules.len(),
        policy.default.as_str(),
        policy.mode.as_str()
    );

    // A failed self-test (error) outranks an unreachable-rule warning, which
    // outranks a clean bill of health — same precedence as the CLI's exit code.
    let mut status = Status::Ok;

    // The unreachable-rule lint is a first-match notion; under deny-overrides a
    // later `deny` can still win, so we skip it — same as the CLI.
    if policy.mode == Mode::FirstMatch {
        let lints = warden::find_shadowed(&policy);
        if lints.is_empty() {
            text.push_str("\npolicy ok: no unreachable rules.");
        } else {
            for lint in &lints {
                text.push_str("\n\n");
                text.push_str(&lint.to_diagnostic().render_labeled(source, "warning"));
            }
            text.push_str(&format!("\n\n{} unreachable rule(s) found.", lints.len()));
            status = Status::Warning;
        }
    } else {
        text.push_str(
            "\npolicy ok: unreachable-rule analysis applies to `first_match` only; skipped.",
        );
    }

    // Self-tests run in every mode — a deny_overrides policy benefits just as much.
    let outcomes = warden::run_tests(&policy);
    if !outcomes.is_empty() {
        text.push('\n');
        for outcome in &outcomes {
            if outcome.passed {
                text.push_str(&format!(
                    "\n  ok   test {}: {} => {}",
                    outcome.number,
                    outcome.action,
                    outcome.actual.as_str()
                ));
            } else {
                text.push_str(&format!(
                    "\n  FAIL test {}: {} => expected {}, got {}\n         reason: {}",
                    outcome.number,
                    outcome.action,
                    outcome.expected.as_str(),
                    outcome.actual.as_str(),
                    outcome.explanation
                ));
            }
        }
        let failed = outcomes.iter().filter(|o| !o.passed).count();
        text.push_str(&format!(
            "\n{} self-test(s): {} passed, {} failed.",
            outcomes.len(),
            outcomes.len() - failed,
            failed
        ));
        if failed > 0 {
            status = Status::Error;
        }
    }

    Report { status, text }
}

/// The result of evaluating one action against the policy.
#[wasm_bindgen]
pub struct Decision {
    effect: String,
    reason: String,
    rule: Option<u32>,
}

#[wasm_bindgen]
impl Decision {
    /// `"allow"`, `"deny"`, `"ask"`, or `"invalid"` if the policy doesn't parse.
    #[wasm_bindgen(getter)]
    pub fn effect(&self) -> String {
        self.effect.clone()
    }

    /// One-line explanation naming the predicate that fired.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }

    /// 1-based number of the rule that decided the verdict, if any.
    #[wasm_bindgen(getter)]
    pub fn rule(&self) -> Option<u32> {
        self.rule
    }
}

/// Evaluate an action against `source`. Empty `path`/`command` are treated as
/// absent (matching the CLI's optional flags).
#[wasm_bindgen]
pub fn decide(source: &str, tool: &str, path: &str, command: &str) -> Decision {
    let policy = match warden::parse(source) {
        Ok(policy) => policy,
        Err(_) => {
            return Decision {
                effect: "invalid".to_string(),
                reason: "policy does not parse — fix the errors on the left first".to_string(),
                rule: None,
            };
        }
    };

    let mut action = Action::new(tool);
    if !path.is_empty() {
        action = action.with_path(path);
    }
    if !command.is_empty() {
        action = action.with_command(command);
    }

    let verdict = warden::evaluate(&policy, &action);
    Decision {
        effect: verdict.effect.as_str().to_string(),
        reason: verdict.explanation,
        rule: verdict.matched_rule.map(|i| i as u32 + 1),
    }
}
