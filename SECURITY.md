# Security Policy

## Supported versions

Security fixes are made on the latest release and the `main` branch. Older tags
do not receive backports while Warden is pre-1.0.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Email
`conal.hg@gmail.com` with the subject `Warden security report` and include:

- the affected version or commit;
- the policy or input needed to reproduce the behavior;
- the security impact you expect; and
- any suggested remediation, if available.

Reports involving parser crashes, policy bypasses, incorrect allow/deny
decisions, unsafe diagnostics, release artifacts, or the WebAssembly playground
are in scope. You should receive an acknowledgement within seven days.

Warden is a deterministic policy component, not a complete sandbox. Operators
must still enforce its verdict at the tool boundary and protect the policy file,
the executable, and the surrounding agent runtime from unauthorized changes.
