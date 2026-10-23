# Peer connections

Peer connections let you hand a task to a friend's Interlink and get a **signed, verified
result** back. Neither of you can touch the other's machine, files or keys. This page is
the full guide and the wire protocol. The threat model is in [SECURITY.md](SECURITY.md).

- [Setup, step by step](#setup-step-by-step)
- [Reaching each other](#reaching-each-other)
- [Policies](#policies)
- [Approving tasks](#approving-tasks)
- [From an agent (MCP)](#from-an-agent-mcp)
- [Files on disk](#files-on-disk)
- [Wire protocol](#wire-protocol)

## Setup, step by step

**1. Both of you** print your identity:

```bash
interlink peer id
```

```text
Your fingerprint: SLEL-J7Q5-2ZJ2-SLRZ-FUIN-JU2H
Your invite code: IL1-...
```

Swap invite codes in any chat. Then **read the fingerprints to each other** over a call
(or another channel you trust). That check is what stops someone swapping in their own
code.

**2. Bob (the host)** adds Alice and decides what she may run:

```bash
interlink peer add alice IL1-...             # Alice's code; she can run nothing yet
interlink peer allow alice mock              # space separated: mock claude codex
interlink peer policy alice --max-timeout 120 --max-tasks-per-hour 5
interlink share                              # listens on 127.0.0.1:7464 until Ctrl-C
```

**3. Alice (the requester)** adds Bob with the address where she reaches his `share`:

```bash
interlink peer add bob IL1-... --url http://127.0.0.1:7464
interlink peer ping bob                      # checks his key, shows what you may run
interlink peer send bob mock "say hi
write answer.txt 42" --out ./from-bob
```

`send` waits while Bob approves, then prints the verified result:

```text
sent task 0ffe609c-97dc-4aaa-ae1b-1ed8289bfb33 (pending_approval)
waiting for your friend to approve...
wrote 1 file(s) to ./from-bob
state: complete   exit: 0
verified: signature OK, chain OK (4 entries), evidence dabf5a31711abb3f...

done turn 1
  added     answer.txt  3 B
```

`verified` means the host's signature, the digest of the task you sent, the hash chain,
the evidence digest and every file hash all checked out. If any of them fail, nothing
is written and the command exits with an error.

Send files with `--file dst=src` (repeatable). Use `--no-wait` to come back later with
`interlink peer status bob <task-id>` and `interlink peer result bob <task-id>`.

**4. When you're done:** stop `share` with Ctrl-C. To block someone for good, use
`interlink peer revoke alice` (it takes effect immediately, even while `share` runs)
or `interlink peer remove alice`.

## Reaching each other

`share` listens on loopback only by default. Pick one way to connect:

| Option | Bob runs | Alice's `--url` |
|--------|----------|-----------------|
| **Same machine** (testing) | `interlink share` | `http://127.0.0.1:7464` |
| **SSH tunnel** (recommended) | `interlink share` | Alice runs `ssh -N -L 7464:127.0.0.1:7464 bob-host`, then `http://127.0.0.1:7464` |
| **VPN** such as Tailscale or WireGuard | `interlink share --bind <vpn-ip> --tls-cert ... --tls-key ...` | `https://<vpn-ip>:7464` with `--ca share.crt` |
| **LAN with a self-signed cert** | see below | `https://<lan-ip>:7464` with `--ca share.crt` |

Any non-loopback `--bind` requires TLS. For a self-signed certificate:

```bash
interlink peer cert --host 192.168.1.20 --host bob-laptop.local
# certificate: .../peer/tls/share.crt  (give this file to your friend: --ca)
interlink share --bind 192.168.1.20 --tls-cert .../share.crt --tls-key .../share.key
```

Alice pins it with `interlink peer add bob IL1-... --url https://192.168.1.20:7464 --ca share.crt`.

Every request and response is signed whatever the transport, so a tunnel to a loopback
port is as safe as TLS against tampering and impersonation.

## Policies

`interlink peer show alice` prints a peer's policy, and `interlink peer policy alice --...`
changes it. The defaults are deliberately small:

| Setting | Default | Meaning |
|---------|---------|---------|
| `harnesses` | *(none)* | What they may run. Each must also be configured on your machine. |
| `approval` | `prompt` | `prompt`: each task waits for you. `auto`: runs immediately (`peer add --auto-approve` or `peer policy NAME --approval auto`). |
| `max_concurrent` | 1 | Their tasks running at once. |
| `max_tasks_per_hour` | 10 | New tasks per rolling hour. |
| `max_requests_per_minute` | 120 | Any request, including status polls. |
| `max_timeout_s` | 300 | Longest run allowed. Requests above it are refused. |
| `max_prompt_chars` | 20000 | Longest prompt. |
| `max_files` / `max_file_bytes` | 20 / 256 KiB | Files in a task, and files returned. |
| `max_result_bytes` | 1 MiB | Total size of returned files. |

Peer tasks run with a **sanitized copy of your config**: no `pass_env`, no `secrets`,
no `env`, a private HOME, and workspaces deleted afterwards. So a harness that needs your
API key or login won't work for peers. This is by design in 0.2.

## Approving tasks

With `approval = prompt`, the `share` window prints a notice for each incoming task:

```text
[approval needed] alice wants to run 'mock' (task 0ffe609c-97dc-4aaa-ae1b-1ed8289bfb33)
  prompt: 'say hi\nwrite answer.txt 42'
  files: -   timeout: 120s
  approve: interlink peer approve 0ffe609c-97dc-4aaa-ae1b-1ed8289bfb33
  deny:    interlink peer deny 0ffe609c-97dc-4aaa-ae1b-1ed8289bfb33
```

Decide from any terminal:

```bash
interlink peer pending            # task id, who, harness, prompt preview
interlink peer approve <task-id>
interlink peer deny <task-id>
```

Unanswered tasks expire after `share --approval-timeout` seconds (600 by default).
The requester gets a signed `denied` or `expired` result either way.

## From an agent (MCP)

Start the MCP server with `--peer-tools` to add three tools for the *requester* side:

| Tool | Does |
|------|------|
| `interlink_peers` | List paired peers and which ones can be sent to. |
| `interlink_peer_send` | Send a task. With `wait_s`, block up to 60 s for the result. |
| `interlink_peer_result` | Fetch and verify a result. Returns `held` while it's still running. |

```bash
claude mcp add interlink -- interlink serve --peer-tools
```

Pairing, allow-lists, approval and `share` stay CLI-only, so an agent can't grant
itself access to your machine.

## Files on disk

| Where | What |
|-------|------|
| `<peer home>/identity.key` | Your Ed25519 private key (0600). Back it up; never share it. |
| `<peer home>/peers.json` | Your peer book: keys, URLs, policies (0600). |
| `<peer home>/tls/` | Output of `peer cert`. |
| `<state root>/peer/audit.jsonl` | Host audit log, hash-chained. |
| `<state root>/peer/client-audit.jsonl` | Requester log of verified results. |
| `<state root>/peer/sent/`, `received/` | Tasks you sent (for verification) and verified results. |
| `<state root>/peer/tasks/`, `results/`, `decisions/` | Host-side task records, signed results, pending approvals. |

The peer home is `$INTERLINK_PEER_HOME`, or `peer/` next to your config file
(`~/.config/interlink/peer` on Linux). Interlink refuses a peer home that overlaps the
state root, so keys never sit where task data is written.

## Wire protocol

`interlink-peer/1` is JSON over HTTP(S). Every endpoint is `POST` with a JSON body:

| Path | Body | Returns |
|------|------|---------|
| `/v1/hello` | `{}` | Host fingerprint, your fingerprint, the harnesses you may run, approval mode, limits. |
| `/v1/tasks` | `{task_id, harness, prompt, files?, timeout_s?}` | `202` and the task status. |
| `/v1/tasks/status` | `{task_id}` | State, `result_ready`. |
| `/v1/tasks/result` | `{task_id}` | `{statement, signature}` once finished. |
| `/v1/tasks/cancel` | `{task_id}` | Status after cancelling. |

**Request authentication.** `X-Interlink-Auth` is the base64url of canonical JSON (sorted
keys, no spaces) claims:

```json
{"v": "interlink-peer/1", "from": "<requester fp>", "to": "<host fp>",
 "method": "POST", "path": "/v1/tasks", "nonce": "<32 hex>",
 "iat": 1761200000000, "exp": 1761200060000, "body_sha256": "<hex>"}
```

`X-Interlink-Signature` is the base64url Ed25519 signature over
`"interlink-peer/1 request\n" + <auth header bytes>`.

**Responses** are `{"ok": true, "data": ...}` or
`{"ok": false, "error": {"code", "message"}}`. They carry
`X-Interlink-Signature` over `"interlink-peer/1 response\n"` plus the canonical JSON of
`{v, from: host, to: requester, nonce, status, body_sha256}`.

**Results** are `{"statement": {...}, "signature": "..."}`. The signature covers
`"interlink-peer/1 result\n"` plus the canonical statement. The statement schema is
`interlink-peer-result/1`. `request_sha256` is the SHA-256 of the canonical task JSON
the requester sent.

Error codes include `unauthenticated`, `bad_signature`, `unknown_peer`, `revoked`,
`wrong_recipient`, `expired`, `clock_skew`, `replay`, `rate_limited`,
`harness_not_allowed`, `timeout_exceeds_policy`, `path_refused`, `file_too_large`,
`too_many_files`, `prompt_too_long`, `payload_too_large`, `quota_exceeded`,
`concurrency_limit`, `task_collision`, `unknown_task` and `not_found`.
