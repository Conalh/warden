# warden

[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](Cargo.toml) [![runtime deps](https://img.shields.io/badge/runtime%20deps-0-2ea44f)](Cargo.toml) [![wasm playground](https://img.shields.io/badge/wasm-live%20playground-654ff0?logo=webassembly&logoColor=white)](https://conalh.github.io/warden/) [![no LLM](https://img.shields.io/badge/decision%20path-no%20LLM-0c4a6e)](#where-this-fits) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**You write a small declarative policy; `warden` decides whether an agent's action is allowed, denied, or escalated to a human (ask)** — a from-scratch, zero-dependency engine with no LLM in the decision path.

<!-- TODO: add 10s demo GIF here -->

```sh
cargo run -- examples/agent.warden --tool bash --command "rm -rf /tmp"
#   decision: DENY
#   reason:   matched rule 5 (line 16): deny tool("bash") because command "rm -rf /tmp" contains "rm -rf"
```

▶ Try it in the browser, no install: **[live playground](https://conalh.github.io/warden/)**.

warden is a from-scratch policy language for agent tool-use, built to show the
fundamentals end to end: a hand-written lexer, a recursive-descent + Pratt
parser, a glob matcher, sound static unreachable-rule analysis, libFuzzer-proven
parser totality, and a zero-dependency core that also compiles to wasm. The
policy domain is the familiar Cedar / OPA-Rego / IAM family — the point is the
engine, implemented in-crate rather than wired up.

```text
source ──▶ [lexer] ──▶ tokens ──▶ [parser] ──▶ AST (Policy) ──▶ [evaluator] ──▶ Verdict
```

## Where this fits

warden is the suite's **decision** core — it answers allow / deny / ask for one tool action, and it is the only piece that makes that call.

| Tool | Input | Catches / decides | Output | Use when |
|---|---|---|---|---|
| **warden** | policy + tool action | allow / deny / ask | verdict | you need deterministic runtime policy decisions |
| [barbican](https://github.com/Conalh/barbican) | MCP tools/list + tools/call | denied calls, ask handling, tool poisoning | enforced MCP proxy + reports | you need MCP runtime enforcement |
| [ScopeTrail](https://github.com/Conalh/ScopeTrail) | PR base/head agent config | permission/config drift | annotations + report | a PR changes agent config |
| [PolicyMesh](https://github.com/Conalh/PolicyMesh) | current repo policy/config files | contradictory rules across agent surfaces | report / SARIF | current policy is inconsistent |
| [CapabilityEcho](https://github.com/Conalh/CapabilityEcho) | PR diff | new executable capability | annotations + report | code gains network/subprocess/eval/lifecycle/workflow power |
| [TaskBound](https://github.com/Conalh/TaskBound) | stated task + PR diff | scope creep | annotations + report | an agent may have gone off-task |
| [SessionTrail](https://github.com/Conalh/SessionTrail) | Cursor/Claude/Codex JSONL transcripts | risky runtime behavior | report / SARIF | an agent session already ran |
| [GovVerdict](https://github.com/Conalh/GovVerdict) | JSON reports | deduped suite verdict | merged report | you want one final review verdict |
| [AgentPulse](https://github.com/Conalh/AgentPulse) | live session events | trajectory state | terminal dashboard | you want live session observation |
| [agent-gov-core](https://github.com/Conalh/agent-gov-core) | shared schemas/parsers | common Finding/Report model | library | tools need shared report primitives |

## Cross-client policy — and what it doesn't cover

One ruleset, enforced across Claude Code, Cursor, and Codex on the MCP tool-call
surface. That portability isn't warden's — it comes from
[agent-gov-core](https://github.com/Conalh/agent-gov-core), which normalizes each
client's format (`parseAnthropicLine`, `parseCodexLine`, …) into the single shape
warden evaluates. Because Barbican interposes on the `tools/call` path, the same
policy applies no matter which client is driving.

**What this does not cover:** each client's *native* permission system. Claude
Code's own Bash/Read/Write allow-deny rules enforce inside the client and never
reach the proxy, so warden never sees them. Read it as two layers — native
built-ins gate the client's own tools; warden governs what crosses the MCP
surface. "One policy everywhere" is true for the MCP-call surface, not for
in-client tool permissions.

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
`4` self-test failed · `64` usage error — so `warden` drops straight into a
shell guard or CI check.

## Playground

The same engine compiles to WebAssembly and runs entirely in the browser: edit a
policy, fire an action, and watch the verdict and the lint report update live,
with no server round-trip. The page in [`playground/`](playground/) is plain
HTML/CSS/JS over two `wasm-bindgen` exports — `validate` and `decide`.

```sh
# Build the wasm bundle into playground/pkg/ (needs `cargo install wasm-pack`)
wasm-pack build warden-wasm --release --target web --out-dir ../playground/pkg

# Serve the folder — wasm must load over http://, not file://
python -m http.server --directory playground 8080
```

The glue crate ([`warden-wasm/`](warden-wasm/Cargo.toml)) is a detached
workspace, exactly like `fuzz/`, so `wasm-bindgen` never enters `warden`'s
dependency graph and the core crate stays zero-dependency. A
[GitHub Pages workflow](.github/workflows/pages.yml) builds and deploys the
playground on demand.

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

## Self-tests

A policy can carry its own expectations. A `test` statement names a concrete
action and the verdict it must reach; validating the policy (no action) runs
every test and fails with exit `4` if any expectation is broken — so a policy
guards itself against a careless edit, the way a unit test guards a function.

```warden
default ask

deny  tool("read")  when path matches "**/.env*"
allow tool("read")  when path matches "src/**"
deny  tool("bash")  when command contains "rm -rf"
allow tool("bash")  when command matches "git *"

test deny  tool("read")  path "config/.env.local"
test allow tool("read")  path "src/main.rs"
test deny  tool("bash")  command "rm -rf /tmp"
test allow tool("bash")  command "git status"
test ask   tool("write") path "notes.txt"        # nothing matches -> default ask
```

```text
$ warden examples/tested.warden
4 rule(s), default `ask`, mode `first_match`
policy ok: no unreachable rules.
  ok   test 1: tool("read") path "config/.env.local" => deny
  ok   test 2: tool("read") path "src/main.rs" => allow
  ok   test 3: tool("bash") command "rm -rf /tmp" => deny
  ok   test 4: tool("bash") command "git status" => allow
  ok   test 5: tool("write") path "notes.txt" => ask
5 self-test(s): 5 passed, 0 failed.
```

Tests run under whichever combining `mode` the policy declares, so the
expectation reflects the same resolution the engine uses in production. A
failing test prints the offending action, the expected and actual verdicts, and
the reason the engine reached the verdict it did. See
[`examples/tested.warden`](examples/tested.warden) and
[`src/selftest.rs`](src/selftest.rs).

## Structured output (`--json`)

Pass `--json` and `warden` swaps its human-readable output for a single JSON
object on stdout (and nothing on stderr), so it slots into a CI step or an
agent's tool-use loop without scraping text. The exit code is identical to the
default mode, so a shell guard can still branch on it.

```sh
$ warden examples/agent.warden --tool bash --command "rm -rf /tmp" --json
{"effect":"deny","rule":5,"reason":"matched rule 5 (line 16): deny tool(\"bash\") because command \"rm -rf /tmp\" contains \"rm -rf\""}

$ warden examples/tested.warden --json | jq '{status, passed: [.tests[].passed]}'
{ "status": "ok", "passed": [true, true, true, true, true] }
```

Validation reports `{rules, default, mode, status, unreachable, tests}`; a parse
failure reports `{status: "error", errors}` with the line and column of each
diagnostic. The JSON is hand-rolled in [`src/json.rs`](src/json.rs) — no `serde`,
so the core crate stays zero-dependency.

## Batch mode (`--stdin`)

A long-lived agent that checks many actions shouldn't pay process-spawn cost per
check. Pass `--stdin` and `warden` reads one JSON action object per line and
prints one JSON verdict per line, keeping a single process alive for the stream:

```sh
$ printf '%s\n' \
    '{"tool":"bash","command":"rm -rf /tmp"}' \
    '{"tool":"read","path":"src/main.rs"}' \
  | warden examples/agent.warden --stdin
{"effect":"deny","rule":5,"reason":"matched rule 5 (line 16): deny tool(\"bash\") because command \"rm -rf /tmp\" contains \"rm -rf\""}
{"effect":"allow","rule":1,"reason":"matched rule 1 (line 8): allow tool(\"read\") because path \"src/main.rs\" matches \"src/**\""}
```

Each line must be an object with a string `tool`, plus optional string `path`
and `command`; unknown fields are ignored, blank lines are skipped. A line that
won't parse, or lacks `tool`, becomes `{"status":"error","error":…}` and flips
the exit code to `1` — but never stops the stream, so the good lines still get
decisions. The per-line effect rides in each verdict, so a `deny` doesn't change
the process exit code the way it does for a single `--tool` check. Reading the
stream back into the value tree reuses the same [`src/json.rs`](src/json.rs); its
parser is **total** and depth-guarded, so a malformed or pathologically nested
line is a clean error, never a panic.

## Grammar (EBNF)

```ebnf
policy      = { statement } ;
statement   = mode | default | rule | test ;
mode        = "mode" , ( "first_match" | "deny_overrides" ) ;
default     = "default" , effect ;
rule        = effect , "tool" , "(" , string , ")" , [ "when" , expr ] ;
test        = "test" , effect , "tool" , "(" , string , ")" , { action_attr } ;
action_attr = ( "path" | "command" ) , string ;
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
| [`selftest.rs`](src/selftest.rs) | Runs inline `test` expectations against the policy |
| [`analysis.rs`](src/analysis.rs) | Static detection of unreachable (shadowed) rules |
| [`json.rs`](src/json.rs) | Minimal zero-dep JSON: writer for `--json`, total parser for `--stdin` |
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
  **In-browser playground** — a `wasm-bindgen` build of the engine, with the
  glue isolated in a detached crate so the core stays zero-dependency (see
  above). **Inline self-tests** — `test` statements that assert a concrete
  action's verdict, checked at validate time so a policy guards its own
  behavior (see above). **Structured output** — a `--json` mode for the verdict
  and the validation report, emitted from a hand-rolled zero-dep JSON writer, so
  `warden` slots into a CI step or an agent's tool-use loop (see above).
  **Batch mode** — a `--stdin` loop that reads one JSON action per line and
  streams one JSON verdict per line, so a long-lived agent checks many actions
  through a single process; it reuses the JSON module's total, depth-guarded
  parser (see above).
- **Possible next step:** a policy `include` directive, so shared baseline rules
  (a company-wide secrets denylist, say) live in one file and compose into
  per-project policies. Left unbuilt on purpose: it trades the engine's pure,
  no-I/O core for file resolution, cycle detection, and a read-access surface
  that deserves its own design pass before it earns a place here.

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
