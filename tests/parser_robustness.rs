//! Robustness smoke test: the parser must be *total* — on any input it returns
//! `Ok(Policy)` or `Err(diagnostics)` and never panics, overflows, or hangs.
//!
//! This is the same invariant the libFuzzer target in [`fuzz/`] checks
//! continuously. It's reproduced here as a fast, deterministic, zero-dependency
//! check that runs everywhere — including `windows-msvc`, whose target lacks the
//! `fuzzer` sanitizer, so `cargo fuzz` cannot run there.

use std::panic::catch_unwind;

fn assert_parse_does_not_panic(src: &str) {
    let result = catch_unwind(|| {
        let _ = warden::parse(src);
    });
    assert!(
        result.is_ok(),
        "parser panicked on input ({} bytes): {src:?}",
        src.len()
    );
}

/// Tiny deterministic xorshift64 PRNG — keeps the test reproducible without an
/// external `rand` dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

#[test]
fn handcrafted_adversarial_inputs_do_not_panic() {
    let cases = [
        "",
        " ",
        "\n\n\n",
        "\0",
        "allow",
        "allow tool",
        "allow tool(",
        "allow tool(\"",
        "allow tool(\"unterminated",
        "deny tool(\"x\") when",
        "deny tool(\"x\") when path",
        "deny tool(\"x\") when path matches",
        "deny tool(\"x\") when path matches \"",
        "when when when",
        "((((((((((",
        "not not not not path matches \"x\"",
        "allow tool(\"*********************\")",
        "mode",
        "mode banana",
        "default",
        "default default",
        "path matches \"**/**/**/**/**\"",
        "deny tool(\"x\") when a and b or c and not d",
        "🦀 tool(\"🔥\") when path matches \"💥\"",
    ];
    for case in cases {
        assert_parse_does_not_panic(case);
    }

    // Pathological nesting and a huge flat policy: depth-guarded, not stack-blown.
    let deep_parens = "(".repeat(50_000);
    assert_parse_does_not_panic(&format!("deny tool(\"x\") when {deep_parens}"));
    let deep_not = "not ".repeat(50_000);
    assert_parse_does_not_panic(&format!(
        "deny tool(\"x\") when {deep_not}path matches \"a\""
    ));
    let many_rules = "allow tool(\"x\")\n".repeat(20_000);
    assert_parse_does_not_panic(&many_rules);
}

#[test]
fn generated_token_soup_does_not_panic() {
    // Fragments biased toward real DSL tokens so the generator reaches deep
    // parser states, not just lexer rejections.
    const FRAGMENTS: &[&str] = &[
        "allow ",
        "deny ",
        "ask ",
        "tool",
        "when ",
        "path ",
        "command ",
        "matches ",
        "contains ",
        "and ",
        "or ",
        "not ",
        "default ",
        "mode ",
        "first_match",
        "deny_overrides",
        "(",
        ")",
        "\"",
        "*",
        "**",
        "?",
        "/",
        ".",
        "-",
        "\n",
        " ",
        "\t",
        "src",
        "env",
        "rm -rf",
        "\\",
        "#c\n",
        "tool(\"",
        "\")",
        "x",
        "0",
        "\0",
        "é",
        "漢",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut input = String::new();
    for _ in 0..20_000 {
        input.clear();
        let parts = rng.below(40) + 1;
        for _ in 0..parts {
            input.push_str(FRAGMENTS[rng.below(FRAGMENTS.len())]);
        }
        assert_parse_does_not_panic(&input);
    }
}

#[test]
fn random_ascii_does_not_panic() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let mut input = String::new();
    for _ in 0..20_000 {
        input.clear();
        let len = rng.below(64);
        for _ in 0..len {
            // Any ASCII byte is valid UTF-8 as a single `char`.
            input.push(rng.below(128) as u8 as char);
        }
        assert_parse_does_not_panic(&input);
    }
}
