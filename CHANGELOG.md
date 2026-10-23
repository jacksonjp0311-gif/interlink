# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-23

Peer connections: hand a sandboxed task to a friend's Interlink and get signed,
verifiable evidence back. Off by default.

### Added
- `interlink share` (alias `interlink peer serve`): an HTTP(S) peer host that binds to
  loopback by default and requires TLS for any other address.
- `interlink peer` commands: `id`, `add`, `list`, `show`, `allow`, `policy`,
  `revoke`, `remove`, `ping`, `send`, `status`, `result`, `cancel`, `pending`,
  `approve`, `deny`, `audit`, `cert`.
- Ed25519 identities (via `cryptography`) with invite codes and fingerprints, pinned
  per peer. Every request and response is signed and bound to its method, path and
  body, with nonce and expiry replay protection. Revocation takes effect immediately.
- Per-peer policy: harness allow-list, `prompt` or `auto` approval, concurrency,
  hourly quota, request rate, timeout, prompt, file and result size limits.
- Inbound tasks run with a sanitized config: no host env, secrets or real HOME, and
  workspaces are discarded afterwards.
- Signed result statements (`interlink-peer-result/1`) bound to the exact task sent,
  carrying the task hash chain, file hashes and the evidence bundle. They are verified
  by the requester.
- Hash-chained, fsynced audit logs on both sides (`interlink peer audit --verify`).
- Opt-in MCP tools `interlink_peers`, `interlink_peer_send` and `interlink_peer_result`
  via `interlink serve --peer-tools`.
- Adversarial tests: forged signatures, replay, unknown and revoked peers, disallowed
  harnesses, oversized payloads, path traversal, env leaks and timeout abuse.
- Docs: [docs/peers.md](docs/peers.md) and the threat model in
  [docs/SECURITY.md](docs/SECURITY.md).

### Changed
- New dependency: `cryptography>=42`.
- Install instructions and client snippets now use a local install instead of an
  unpublished PyPI package.

## [0.1.0] - 2026-10-23

First standalone release, extracted from the Interlink layer of PEGASUS.

### Added
- stdio MCP server with nine tools: `interlink_harnesses`, `_launch`, `_prompt`,
  `_observe`, `_cancel`, `_files`, `_inspect`, `_evidence`, `_stop`, and a stable
  `interlink/1` reply envelope (`complete` / `held` / `refused` / `failed`).
- Throwaway instances: copied project, seeded files, private HOME/TMP, env allow-list,
  secret redaction, path confinement, per-run timeouts and process-tree kills.
- Idempotent request ledger (`request_id`), global instance/run limits, orphan recovery
  with process-identity checks.
- Hash-chained receipts and redacted evidence export.
- Adapters: `mock`, `command` (any CLI), `claude-code`, `codex`, `hermes`, `pegasus`,
  plus custom adapters by import path or `interlink.adapters` entry point.
- `interlink` CLI: `serve`, `run`, `doctor`, `harnesses`, `ls`, `cleanup`, `init`,
  `snippet`, `handshake`.
- Docs, examples, and CI for Linux, macOS and Windows.

### Ported from PEGASUS
- Disposable-profile launch, manifest/source digest, token-authenticated requests,
  leases and deadlines (now the `pegasus` adapter), env allow-list, request ledger,
  receipts and identity-checked orphan recovery.
