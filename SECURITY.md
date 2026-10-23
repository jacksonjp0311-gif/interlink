# Security policy

## Supported versions

Only the latest minor release receives security fixes.

## Reporting a vulnerability

Please report privately via GitHub's **"Report a vulnerability"** button on this
repository (Security → Advisories). Do not open a public issue. Include a description,
reproduction steps and the version. You should get a response within a week.

## Scope

Interlink's guarantees and non-guarantees are described in
[docs/safety.md](docs/safety.md). In particular, Interlink is **not an OS sandbox**:
a harness runs with the permissions of the user who started Interlink. Reports that
show a bypass of the env allow-list, redaction, path confinement, the idempotency
ledger, process-tree cleanup or the evidence chain are very welcome.

Peer connections (`interlink share` / `interlink peer`) have their own threat model in
[docs/SECURITY.md](docs/SECURITY.md). Reports of forged or replayed requests being
accepted, a revoked or unknown peer getting through, a peer task reading host env,
secrets or files outside its workspace, or a tampered result passing verification are
in scope and especially welcome.
