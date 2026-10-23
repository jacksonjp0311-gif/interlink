# Interlink MCP protocol (`interlink/1`)

Interlink is an MCP server that speaks **stdio**. Any MCP client can connect; the
tools below are the whole surface.

## The reply envelope

Every tool returns the same shape as structured content:

```json
{ "schema": "interlink/1", "status": "complete", "data": { "...": "..." } }
```

| `status`   | Meaning                                                         | Payload |
|------------|-----------------------------------------------------------------|---------|
| `complete` | The call did what it says.                                       | `data`  |
| `held`     | Not now, try again (e.g. a run is still active on the instance). | `error` |
| `refused`  | Never, as asked (bad id, unknown harness, path escape, policy).  | `error` |
| `failed`   | Interlink itself hit an unexpected error.                        | `error` |

`error` is `{ "code": "...", "message": "...", ...extra }`. Codes are stable and meant for
programs: `unknown_harness`, `unknown_instance`, `unknown_run`, `instance_not_ready`,
`run_active`, `instance_limit`, `concurrency_limit`, `path_refused`, `not_owned`,
`prompt_too_long`, `empty_prompt`, `too_many_files`, `invalid_timeout`,
`invalid_instance_id`, `invalid_request_id`, `request_collision`, `launch_failed`,
`refused_by_policy`, `shutting_down`.

Arguments that fail JSON-schema validation (a malformed UUID, `limit` out of range) are
reported by MCP itself as a tool error (`isError: true`), before Interlink runs.

## Tools

| Tool                  | What it does |
|-----------------------|--------------|
| `interlink_harnesses` | Lists harnesses this server may launch, with cheap read-only readiness checks. |
| `interlink_launch`    | Creates a **throwaway instance**: fresh workspace (optionally a *copy* of `project`, plus seeded `files`), private HOME/TMP, env allow-list. |
| `interlink_prompt`    | Sends one prompt. Returns a `run_id` at once; `wait_s` (≤ 60) blocks for the result. |
| `interlink_observe`   | Reads normalized events for a run with `after_cursor` paging and `wait_ms` long-polling. |
| `interlink_cancel`    | Kills the active run's whole process tree. File changes stay. |
| `interlink_files`     | Lists files with `added`/`modified`/`unchanged`/`deleted` status, or reads one (bounded). |
| `interlink_inspect`   | One instance in detail, or the server, every instance and open requests. |
| `interlink_evidence`  | Writes a redacted, hash-chained evidence bundle to disk and returns its path and sha256. |
| `interlink_stop`      | Stops an instance (and its harness). `discard=true` also deletes the workspace. |

### Idempotency

`launch`, `prompt`, `cancel` and `stop` accept an optional `request_id` (a UUID). Repeating
a call with the same id and the same arguments **replays** the first answer (including
errors) instead of acting twice; reusing an id with *different* arguments is refused
with `request_collision`. Safe retries for flaky transports.

### Events

`observe` returns events like:

```json
{ "seq": 3, "at": 1792765646.094, "type": "text", "text": "hi" }
```

Types: `status`, `text`, `tool_use`, `tool_result`, `question`, `stderr`, `result`,
`error`, `raw` (anything an adapter could not classify) and `interlink` (lifecycle:
`spawn`, `finished`, ...). Every value is passed through the secret redactor before it is
stored. A run's terminal state is one of `complete`, `failed`, `cancelled`, `timed_out`,
`error`.

### Lifecycle

```
launch ──► ready ──prompt──► running ──► ready ──...──► stop ──► stopped ──(discard)──► gone
                                  │
                              cancel / timeout
```

One run at a time per instance; a second prompt while one is running is `held` with
`run_active` and the active `run_id`. Global limits (`max_instances`,
`max_concurrent_runs`) are enforced server-wide.

## State on disk

```
<state_root>/
  instances/<instance_id>/
    instance.json        # record, runs, receipts (atomic writes)
    work/                # the harness's cwd: the throwaway project copy
    home/  tmp/          # private HOME and TMP
    runs/<run_id>/       # events.jsonl (redacted), prompt file, raw logs
  requests/              # idempotency ledger
  exports/               # evidence bundles
```

A new server reads old instances read-only (`not_owned`) and reaps orphaned harness
processes it can positively identify as its own.

## Peer protocol

Peer connections between two Interlinks use a separate HTTP protocol,
`interlink-peer/1`, documented in [peers.md](peers.md#wire-protocol).
