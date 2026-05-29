import init, { validate, decide } from "./pkg/warden_wasm.js";

const EXAMPLES = {
  agent: `# Example policy for a coding agent.
# Rules are evaluated top to bottom; the first match wins.

default ask

# Reading source is fine; reading secrets is not.
allow tool("read")  when path matches "src/**"
deny  tool("read")  when path matches "**/.env*"
deny  tool("read")  when path matches "**/*.pem"

# Never let any tool touch a secret file.
deny  tool("*")     when path matches "**/.env*" or path matches "**/id_rsa*"

# Shell: block the obviously destructive, green-light the obviously safe.
deny  tool("bash")  when command contains "rm -rf" or command contains "mkfs"
allow tool("bash")  when command matches "git status*" or command matches "npm test*"

# Writing config is sensitive enough to confirm, except package.json churn.
ask   tool("write") when path matches "**/*.json" and not path matches "package.json"
allow tool("write") when path matches "src/**"
`,

  shadowed: `# A policy riddled with unreachable rules, to exercise the linter.
# Each pair shows a different way an earlier rule shadows a later one.

default ask

# (1) An unconditional rule matches every read...
allow tool("read")
# ...so this stricter rule can never fire.
deny  tool("read") when path matches "**/.env*"

# (2) A broad glob subsumes a narrower one.
deny  tool("write") when path matches "**"
allow tool("write") when path matches "src/**"

# (3) contains "rm" holds whenever contains "rm -rf" does.
deny  tool("bash") when command contains "rm"
deny  tool("bash") when command contains "rm -rf"

# (4) A catch-all matches every tool.
ask   tool("*")
allow tool("browse") when path matches "**"
`,

  denyOverrides: `# Same intent, combined with deny-overrides instead of first-match.
# Order stops being priority: the most restrictive matching effect wins
# (deny > ask > allow), so the broad allows below do NOT shadow the denies.

mode deny_overrides
default ask

allow tool("read")
allow tool("write")

deny  tool("*")     when path matches "**/.env*" or path matches "**/id_rsa*"
deny  tool("read")  when path matches "**/*.pem"

ask   tool("write") when path matches "**/*.json"
`,
};

const el = (id) => document.getElementById(id);
const policyEl = el("policy");
const reportBadge = el("report-badge");
const reportText = el("report-text");
const toolEl = el("tool");
const pathEl = el("path");
const commandEl = el("command");
const decisionBadge = el("decision-badge");
const decisionReason = el("decision-reason");
const decisionRule = el("decision-rule");

function runValidate() {
  const report = validate(policyEl.value);
  reportBadge.textContent = report.status;
  reportBadge.className = `badge ${report.status}`;
  reportText.textContent = report.text;
}

function runDecide() {
  const d = decide(
    policyEl.value,
    toolEl.value.trim(),
    pathEl.value.trim(),
    commandEl.value.trim(),
  );
  decisionBadge.textContent = d.effect.toUpperCase();
  decisionBadge.className = `verdict ${d.effect}`;
  decisionReason.textContent = d.reason;
  decisionRule.textContent =
    d.rule === undefined ? "" : `matched rule ${d.rule}`;
}

function refresh() {
  runValidate();
  runDecide();
}

function loadExample(name) {
  policyEl.value = EXAMPLES[name];
  refresh();
}

async function main() {
  await init();

  policyEl.addEventListener("input", refresh);
  for (const input of [toolEl, pathEl, commandEl]) {
    input.addEventListener("input", runDecide);
  }
  for (const button of document.querySelectorAll(".examples button")) {
    button.addEventListener("click", () => loadExample(button.dataset.example));
  }

  loadExample("agent");
}

main();
