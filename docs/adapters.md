# Adapters

An **adapter** teaches Interlink how to drive one kind of harness. A **harness** is a
named, configured use of an adapter in `interlink.toml`:

```toml
[harness.reviewer]      # the name clients pass to interlink_launch
adapter = "claude-code" # which adapter drives it
permission_mode = "plan"
```

## Built-in adapters

| Adapter       | Drives | How |
|---------------|--------|-----|
| `mock`        | A scripted fake agent | Ships with Interlink. No network, no keys. |
| `command`     | Any CLI agent | One process per prompt; text or JSONL output. |
| `claude-code` | Claude Code | `claude -p --output-format stream-json --verbose`, `--resume` for follow-ups. |
| `codex`       | OpenAI Codex CLI | `codex exec --json`, `codex exec resume` for follow-ups; `CODEX_HOME` is per-instance when `isolate_home`. |
| `hermes`      | Hermes Agent | `hermes chat --oneshot --query-file ... --format stream-json`, per-instance `HERMES_HOME`. |
| `pegasus`     | PEGASUS desktop app | Boots a PEGASUS build with its Interlink host in a disposable profile and talks the `pegasus-interlink/1` protocol over its named pipe (leases, tokens, deadlines). |

## Options every harness accepts

| Key            | Default | Meaning |
|----------------|---------|---------|
| `description`  | `""`    | Shown by `interlink_harnesses`. |
| `pass_env`     | `[]`    | Extra env names to inherit (credential-looking names are refused; use `secrets`). |
| `secrets`      | adapter-specific | Env names passed through **and** redacted from everything Interlink records. |
| `env`          | `{}`    | Literal env values to set. |
| `timeout_s`    | `600`   | Default per-prompt timeout (capped by `server.max_run_timeout_s`). |
| `isolate_home` | `true`  | Give the harness a private HOME. Turn off for CLIs that keep their login under HOME (then they see your real config dir, read-only by convention, not by force). |

## The `command` adapter

```toml
[harness.my-agent]
adapter = "command"
argv = ["my-agent", "run", "--prompt-file", "{prompt_file}"]
resume_argv = ["my-agent", "run", "--resume", "{session_id}", "--prompt-file", "{prompt_file}"]
output = "jsonl"               # or "text"
session_id_field = "session_id"
success_exit_codes = [0]
```

Placeholders: `{prompt}` `{prompt_file}` `{workspace}` `{home}` `{run_id}` `{instance_id}`
`{session_id}`. If neither `{prompt}` nor `{prompt_file}` appears, the prompt goes to
stdin. No shell is ever involved; each token is substituted once, so a prompt that
contains `{workspace}` stays literal.

With `output = "jsonl"`, lines whose `type` is an Interlink event type are passed
through; anything else becomes a `raw` event.

## Writing your own adapter

Subclass `CommandAdapter` (process-per-prompt) or `HarnessAdapter` (long-lived hosts):

```python
from typing import ClassVar
from interlink.adapters.base import AdapterOptions, RunContext
from interlink.adapters.command import CommandAdapter, CommandOptions


class MyOptions(CommandOptions):
    argv: list[str] = ["my-agent", "--json"]
    output: str = "jsonl"


class MyAdapter(CommandAdapter):
    summary: ClassVar[str] = "My agent"
    Options: ClassVar[type[AdapterOptions]] = MyOptions

    def parse_line(
        self, line: str, ctx: RunContext
    ) -> None: ...  # ctx.emit("text", text=...), ctx.emit("tool_use", tool=...), ...
```

Use it with `adapter = "my_module:MyAdapter"`, or publish it as a plugin:

```toml
[project.entry-points."interlink.adapters"]
my-agent = "my_module:MyAdapter"
```

Hooks you can override: `doctor()`, `environment()`, `prepare()`, `start()`, `run()`,
`stop()`, and on `CommandAdapter`: `build_argv()`, `placeholders()`, `uses_stdin()`,
`parse_line()`, `remember_session()`, `classify()`. `examples/custom_adapter.py` is a
complete, tested example.

## Verification status (be honest about what was tested)

| Adapter | Tested against |
|---------|----------------|
| `mock`, `command` | Real processes, full suite, every platform in CI. |
| `claude-code` | Recorded stream fixtures + argv/env assertions; the real `claude` 2.1 CLI was exercised unauthenticated. `max_turns` maps to `--max-turns`, which current `claude --help` does not list - verify on your version. |
| `codex` | Recorded fixtures + argv assertions. **Live** (2026-10-23, Windows): a real logged-in `codex exec` turn with `isolate_home = false`, and Codex as the MCP client driving Interlink. See [the evidence](../evidence/live-2026-10-23/). |
| `hermes` | A faithful fake CLI in `tests/fakes/`. Flags follow Hermes docs; not yet run against a live Hermes. |
| `pegasus` | A fake PEGASUS host that enforces the real protocol (boot schema, source digest, tokens, leases, deadlines) over a Unix-socket test seam. The real host uses a Windows named pipe and isn't driven by CI. **Live** (2026-10-23): the real PEGASUS host booted from a disposable copy and refused a prompt with inference off, as designed. A full inference task hasn't been run yet. |
