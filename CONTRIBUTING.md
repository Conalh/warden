# Contributing to Warden

Focused bug reports and pull requests are welcome. Please keep the policy engine
deterministic, explainable, and zero-dependency.

## Development setup

Warden requires Rust 1.85 or newer.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
cargo build --release --locked
cargo package --locked
```

Changes to `warden-wasm/` or `playground/` should also pass:

```sh
cargo install wasm-pack --version 0.15.0 --locked
wasm-pack test --node warden-wasm
wasm-pack build warden-wasm --release --target web --out-dir ../playground/pkg
```

The generated `playground/pkg/` directory is intentionally ignored; GitHub
Actions rebuilds it before deploying Pages.

## Pull requests

- Add regression tests for behavioral changes and bug fixes.
- Keep diagnostics and decision traces concrete enough to explain the result.
- Update the README and changelog when the language, CLI, or public API changes.
- Avoid new runtime dependencies in the core crate. A dependency proposal should
  explain why a small in-crate implementation is insufficient.

Parser changes should preserve totality: malformed or adversarial input must
return diagnostics instead of panicking, overflowing, or looping indefinitely.
The optional fuzz harness is documented in the README.
