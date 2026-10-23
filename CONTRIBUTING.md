# Contributing to Interlink

Thanks for helping! Interlink is small on purpose; the bar is "boring, safe, tested".

## Dev setup

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                          # full suite, no keys or network needed
ruff check . && ruff format --check .
```

## Layout

```
src/interlink/
  server.py      MCP tools + reply envelope
  engine.py      instances, runs, limits, idempotency, orphan recovery
  sandbox.py     workspace copy/seed/snapshot/diff
  process.py     process trees, identity, kill
  security.py    env allow-list, redaction, path confinement, hashing
  ledger.py      idempotent request ledger
  events.py      normalized event log
  config.py      interlink.toml
  cli.py         the `interlink` command
  adapters/      mock, command, claude-code, codex, hermes, pegasus
  harnesses/     the scripted mock agent
tests/
  fakes/         fake Hermes CLI and fake PEGASUS host
  fixtures/      recorded Claude Code / Codex streams
```

## Adding an adapter

1. Prefer configuration: if the `command` adapter can drive it, document a TOML snippet
   instead of writing code.
2. Otherwise subclass `CommandAdapter` (process per prompt) or `HarnessAdapter`
   (long-lived host) in `src/interlink/adapters/`, register it in `adapters/__init__.py`.
3. Add a recorded fixture or a fake under `tests/fakes/` - CI must not need real
   credentials or network.
4. Test argv, environment (no un-allowed vars), session resume, failure classification,
   timeout and cancel.
5. Document it in `docs/adapters.md`, including what it was *actually* verified against.

## Rules of the road

* Never widen the default environment allow-list.
* Anything a harness prints is untrusted: bound it, redact it, don't execute it.
* New tool arguments need schema bounds (`max_length`, `le`, ...).
* Keep the reply envelope stable; add fields, don't rename them.
* Update `CHANGELOG.md` under "Unreleased".

## Reporting security issues

Please don't open a public issue - see [SECURITY.md](SECURITY.md).
