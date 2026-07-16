# Changelog

## [0.1.0] - 2026-07-16

- Ship the zero-dependency Rust policy engine, CLI, and WebAssembly playground.
- Support first-match and deny-overrides modes with allow, deny, and ask verdicts.
- Add field-aware globs, exact decision traces, unreachable and redundant rule
  analysis, inline policy self-tests, JSON output, and JSONL batch evaluation.
- Harden the hand-written lexer, Pratt parser, and JSON reader with depth bounds,
  adversarial regression tests, and a scheduled libFuzzer workflow.
- Add CI-built Windows, Linux, and macOS release binaries with SHA-256 checksums.

[0.1.0]: https://github.com/Conalh/warden/releases/tag/v0.1.0
