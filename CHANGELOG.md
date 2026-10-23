# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
