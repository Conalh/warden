# warden

A **policy DSL engine** in Rust. You write a small declarative
policy; `warden` decides whether an agent's action should be **allowed**,
**denied**, or escalated to a human (**ask**).

It's the recognizable family of AWS Cedar / OPA-Rego / IAM / Claude Code's own
permission rules — but the lexer, the Pratt parser, the glob matcher, and the
compiler-style diagnostics are all implemented in-crate with **zero dependencies**. The
point is to demonstrate the fundamentals directly, not to wire up a crate.

```text
source ──▶ [lexer] ──▶ tokens ──▶ [parser] ──▶ AST (Policy) ──▶ [evaluator] ──▶ Verdict
```

## Quickstart

```sh
# Validate a policy
cargo run -- examples/agent.warden

# Evaluate an action against it — the reason names the exact predicate that fired
cargo run -- examples/agent.warden --tool bash --command "rm -rf /tmp"
#   decision: DENY
#   reason:   matched rule 5 (line 16): deny tool("bash") because command "rm -rf /tmp" contains "rm -rf"

cargo run -- examples/agent.warden --tool read --path src/main.rs
#   decision: ALLOW
```

Exit codes: `0` allow/ask · `1` deny · `2` parse error · `3` unreachable rules ·
`64` usage error — so `warden` drops straight into a shell guard or CI check.

## The language

A policy is an ordered list of rules and a fallback `default`. Rules are tried
top to bottom; **the first match wins**.

```warden
default ask

allow tool("read")  when path matches "src/**"
deny  tool("read")  when path matches "**/.env*"
deny  tool("*")     when path matches "**/id_rsa*"
deny  tool("bash")  when command contains "rm -rf" or command contains "mkfs"
allow tool("bash")  when command matches "git status*"
ask   tool("write") when path matches "**/*.json" and not path matches "package.json"
```

- **Effects:** `allow`, `deny`, `ask`.
- **Target:** `tool("<glob>")` — the tool name the rule applies to (`"*"` = any).
- **Condition (optional):** `when <expr>`, a boolean over predicates.
- **Predicates:** `<field> matches "<glob>"` and `<field> contains "<substring>"`,
  where `<field>` is `path` or `command`.
- **Operators:** `not` (tightest) → `and` → `or` (loosest); parenthesize to override.
- **Globs:** `/` is a segment boundary (gitignore-style): `*` matches a run
  within one segment, `**` spans `/`, `?` is one non-`/` char. So `src/*`
  matches `src/main.rs` but not `src/a/b.rs`, while `src/**` matches both.
  `#` starts a comment.
- **Combining mode (optional):** a top-level `mode first_match` (default) or
  `mode deny_overrides` directive — see below.

## Combining modes

How do *several* matching rules resolve to one verdict? `warden` ships two
combining algorithms, selected by a top-level `mode` directive:

- **`first_match`** (default) — rules are tried top to bottom and the first
  match wins. Order *is* the priority.
- **`deny_overrides`** — every matching rule is collected and the **most
  restrictive** effect wins (`deny` > `ask` > `allow`), regardless of order. A
  matching `deny` always beats a matching `allow`, even one written earlier.
  This is the conservative algorithm familiar from XACML and AWS Cedar's
  `forbid` precedence.

```warden
mode deny_overrides

allow tool("read")                              # broadly permit reads...
deny  tool("*") when path matches "**/.env*"    # ...but a matching deny wins
```

```sh
cargo run -- examples/deny_overrides.warden --tool read --path config/.env.local
#   decision: DENY
#   reason:   ... deny tool("*") because path "config/.env.local" matches "**/.env*";
#             under deny_overrides this beats rule 1 (allow tool("read"))
```

Because resolution no longer depends on order, the unreachable-rule lint below
(a *first-match* notion) does not apply under `deny_overrides`, and `warden`
skips it rather than report false positives.

## Linting: unreachable rules

Because resolution is first-match-wins, a rule is **dead** if an earlier rule
always matches first. `warden` finds these statically — running it on a policy
(no action) reports every shadowed rule and exits `3`:

```text
$ warden examples/shadowed.warden
8 rule(s), default `ask`, mode `first_match`
warning: unreachable rule: rule 1 at line 8 (an unconditional `allow tool("read")`) always matches first
   --> line 10, col 1
   |
10 | deny  tool("read") when path matches "**/.env*"
   | ^^^^

warning: unreachable rule: rule 3 at line 13 (a broader rule (`deny tool("write")`)) always matches first
   --> line 15, col 1
   |
15 | allow tool("write") when path matches "src/**"
   | ^^^^^

warning: unreachable rule: rule 5 at line 18 (a broader rule (`deny tool("bash")`)) always matches first
   --> line 20, col 1
   |
20 | deny  tool("bash") when command contains "rm -rf"
   | ^^^^

warning: unreachable rule: rule 7 at line 23 (an unconditional catch-all `ask tool("*")`) always matches first
   --> line 25, col 1
   |
25 | allow tool("browse") when path matches "**"
   | ^^^^^

4 unreachable rule(s) found.
```

[`examples/shadowed.warden`](examples/shadowed.warden) packs one of each shadow
mechanism the analysis understands: an unconditional rule swallowing a later
conditional one, a broad glob subsuming a narrower one (`**` over `src/**`), a
shorter `contains` substring covering a longer one (`"rm"` over `"rm -rf"`), and
a `tool("*")` catch-all killing everything after it.

The analysis is **sound, not complete**: every rule it flags is genuinely
unreachable (no false positives), but it reasons pairwise — about one covering
rule at a time, with conservative glob subsumption — so it may miss deadness
that only emerges from the *union* of several earlier rules. In a linter, a
false "this rule is dead" is far worse than a missed one. See
[`src/analysis.rs`](src/analysis.rs).

## Grammar (EBNF)

```ebnf
policy      = { statement } ;
statement   = mode | default | rule ;
mode        = "mode" , ( "first_match" | "deny_overrides" ) ;
default     = "default" , effect ;
rule        = effect , "tool" , "(" , string , ")" , [ "when" , expr ] ;
effect      = "allow" | "deny" | "ask" ;

expr        = or_expr ;
or_expr     = and_expr , { "or" , and_expr } ;
and_expr    = unary , { "and" , unary } ;
unary       = "not" , unary | primary ;
primary     = "(" , expr , ")" | predicate ;
predicate   = field , ( "matches" | "contains" ) , string ;
field       = "path" | "command" ;
```

The parser implements `or_expr`/`and_expr`/`unary` as a single **Pratt
(precedence-climbing) loop** driven by binding powers, rather than one function
per precedence level — see [`src/parser.rs`](src/parser.rs).

## Architecture

| Module | Responsibility |
| --- | --- |
| [`token.rs`](src/token.rs) | Token kinds + source spans |
| [`lexer.rs`](src/lexer.rs) | Single-pass scanner; collects errors, never panics |
| [`ast.rs`](src/ast.rs) | `Policy` / `Rule` / `Expr` — the recursive tree |
| [`parser.rs`](src/parser.rs) | Recursive descent + Pratt; error recovery |
| [`eval.rs`](src/eval.rs) | Tree-walking evaluator, first-match resolution |
| [`analysis.rs`](src/analysis.rs) | Static detection of unreachable (shadowed) rules |
| [`matcher.rs`](src/matcher.rs) | Backtracking glob matcher |
| [`diagnostics.rs`](src/diagnostics.rs) | Spans + rustc-style caret rendering |

## Design decisions

- **No parser generator.** No `nom`/`pest`/`lalrpop` — the lexer and parser
  are plain Rust over the token stream. The crate has zero dependencies.
- **First-match-wins by default, `deny`-overrides opt-in.** First-match is the
  simplest semantics that stays predictable as a policy grows; `deny`-overrides
  is the conservative alternative for security-critical policies, chosen per
  file with a `mode` directive rather than a build flag.
- **`Field` is a closed enum, not a free string.** This turns a typo like
  `paht matches "..."` into a *parse-time* error instead of a rule that silently
  never fires. Catching it early is the whole value of having a type system.
- **Collect diagnostics, don't throw.** Lexer and parser accumulate errors and
  resynchronize at rule boundaries, so one run reports every problem with a
  caret pointing at the offending span. The parser is **total** — even
  pathological input (thousands of nested `(`) yields a diagnostic, not a
  stack overflow — and a libFuzzer harness guards that property (see *Fuzzing*).

## Roadmap

- **Done:** **conflict/shadow detection** — static reachability analysis that
  flags rules an earlier rule already subsumes (see above). **Decision trace** —
  the verdict resolves `when <condition>` down to the leaf predicate that fired,
  with concrete values (`command "rm -rf /tmp" contains "rm -rf"`).
  **`deny`-overrides** — opt-in combining mode where the most restrictive
  matching rule wins, order-independent. **Segment-aware globs** — `/` is a
  hard boundary; `*` stays within a path segment while `**` spans them.
  **Richer glob subsumption** — the shadow analysis decides glob *language
  inclusion* with the same segment rules, so `**` is recognized as covering
  `src/**` while a single `*` is not. **Parser fuzzing** — a libFuzzer harness
  and a depth guard that make the parser provably total (see below).
- **Next:** a `wasm-bindgen` build powering an in-browser playground, keeping
  the core crate zero-dependency by isolating the wasm glue behind a feature.

## Tests

```sh
cargo test
```

Unit tests live beside each module; end-to-end policy scenarios are in
[`tests/integration.rs`](tests/integration.rs).

### Fuzzing

The parser is meant to be **total**: on *any* input it returns `Ok(Policy)` or
`Err(diagnostics)` — never panicking, overflowing, or looping forever. A
libFuzzer harness pins that down by throwing arbitrary bytes at
[`warden::parse`](src/lib.rs):

```sh
cargo +nightly fuzz run parse        # needs the nightly toolchain + cargo-fuzz
```

The fuzz crate lives in its own detached workspace
([`fuzz/`](fuzz/Cargo.toml)), so `libfuzzer-sys` never enters `warden`'s own
dependency graph — the core crate stays zero-dependency. libFuzzer's `fuzzer`
sanitizer ships only on Unix targets (not `windows-msvc`), so the harness runs
in CI on Linux ([`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml)); the
same invariant is checked on every platform by
[`tests/parser_robustness.rs`](tests/parser_robustness.rs), which feeds tens of
thousands of generated and adversarial inputs through the parser with no
external dependency.

The one input class that *could* defeat totality — thousands of nested `(` or
`not` overflowing the recursive-descent stack — is handled by a depth bound in
the parser, which emits a `condition nested too deeply` diagnostic instead of
recursing without limit.

## License

MIT
