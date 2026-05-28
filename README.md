# warden

A from-scratch **policy DSL engine** in Rust. You write a small declarative
policy; `warden` decides whether an agent's action should be **allowed**,
**denied**, or escalated to a human (**ask**).

It's the recognizable family of AWS Cedar / OPA-Rego / IAM / Claude Code's own
permission rules — but the lexer, the Pratt parser, the glob matcher, and the
compiler-style diagnostics are all hand-written with **zero dependencies**. The
point is to demonstrate the fundamentals directly, not to wire up a crate.

```text
source ──▶ [lexer] ──▶ tokens ──▶ [parser] ──▶ AST (Policy) ──▶ [evaluator] ──▶ Verdict
```

## Quickstart

```sh
# Validate a policy
cargo run -- examples/agent.warden

# Evaluate an action against it
cargo run -- examples/agent.warden --tool bash --command "rm -rf /tmp"
#   decision: DENY
#   reason:   matched rule 5 (line 16): deny tool("bash") when <condition>

cargo run -- examples/agent.warden --tool read --path src/main.rs
#   decision: ALLOW
```

Exit codes: `0` allow/ask · `1` deny · `2` parse error · `64` usage error — so
`warden` drops straight into a shell guard or CI check.

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
- **Globs:** `*` (any run), `?` (one char). `#` starts a comment.

## Grammar (EBNF)

```ebnf
policy      = { statement } ;
statement   = default | rule ;
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
| [`lexer.rs`](src/lexer.rs) | Hand-written scanner; collects errors, never panics |
| [`ast.rs`](src/ast.rs) | `Policy` / `Rule` / `Expr` — the recursive tree |
| [`parser.rs`](src/parser.rs) | Recursive descent + Pratt; error recovery |
| [`eval.rs`](src/eval.rs) | Tree-walking evaluator, first-match resolution |
| [`matcher.rs`](src/matcher.rs) | Backtracking glob matcher |
| [`diagnostics.rs`](src/diagnostics.rs) | Spans + rustc-style caret rendering |

## Design decisions

- **Hand-rolled, no parser generator.** No `nom`/`pest`/`lalrpop` — the lexer
  and parser exist to show the fundamentals. The crate has zero dependencies.
- **First-match-wins resolution.** The simplest semantics that stays
  predictable as a policy grows. `deny`-overrides is a planned opt-in (roadmap).
- **`Field` is a closed enum, not a free string.** This turns a typo like
  `paht matches "..."` into a *parse-time* error instead of a rule that silently
  never fires. Catching it early is the whole value of having a type system.
- **Collect diagnostics, don't throw.** Lexer and parser accumulate errors and
  resynchronize at rule boundaries, so one run reports every problem with a
  caret pointing at the offending span.

## Roadmap

- **v1:** `deny`-overrides combining mode; segment-aware `**` (not crossing `/`).
- **v2:** static validation pass and **conflict/shadow detection** ("rule 6 can
  never fire — rule 2 already subsumes it"), a reachability analysis over rules.
- **v3:** a full **decision trace** ("DENY because line 16: `command contains 'rm -rf'`"),
  a `wasm-bindgen` build powering an in-browser playground, and `cargo fuzz` on
  the parser.

## Tests

```sh
cargo test
```

Unit tests live beside each module; end-to-end policy scenarios are in
[`tests/integration.rs`](tests/integration.rs).

## License

MIT
