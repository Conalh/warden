#![no_main]

use libfuzzer_sys::fuzz_target;

// The parser is meant to be *total*: it accumulates diagnostics and always
// returns `Ok(Policy)` or `Err(Vec<Diagnostic>)` — never panicking, indexing
// out of bounds, overflowing, or looping forever, on *any* input. This target
// asserts exactly that. Warden source is text, so we only forward the
// valid-UTF-8 inputs to `parse`; libFuzzer still gets credit for exploring the
// bytes that fail the UTF-8 check.
//
// libFuzzer can't run on `windows-msvc` (the target lacks the `fuzzer`
// sanitizer), so this runs in CI on Linux — see `.github/workflows/fuzz.yml`.
// `tests/parser_robustness.rs` exercises the same invariant on any platform.
fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let _ = warden::parse(src);
    }
});
