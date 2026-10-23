# Peer connections: threat model

This document covers **peer connections** (`interlink share` / `interlink peer ...`),
added in 0.2. Here one person's agent hands a task to a friend's Interlink and gets
signed evidence back. For the local MCP server's guarantees, see [safety.md](safety.md).
To report a vulnerability, see the [security policy](../SECURITY.md).

The design goal is narrow: **your friend may run a specific harness on a prompt and a
few text files you send. They get the answer, the output files and proof of what
happened. Neither of you gets anything else.**

## Terms

| Term | Meaning |
|------|---------|
| **Host** | The person running `interlink share`. Their machine does the work. |
| **Requester** | The person running `interlink peer send`. |
| **Peer book** | `peers.json` in the peer home: each friend's public key, URL and policy. |
| **Peer home** | Where `identity.key` and `peers.json` live: `$INTERLINK_PEER_HOME`, or `peer/` next to your config file. |
| **Peer state** | `<state root>/peer`: tasks, results, nonces, the audit log. |

## Assets

1. **The host's machine**: files, credentials, environment and other processes.
2. **The requester's inputs**: prompt and files. These are only shown to the host they chose.
3. **Identity keys**: each side's Ed25519 private key.
4. **Integrity of results**: a requester must be able to tell exactly what ran and what came back.
5. **The audit trail**: the host's record of who asked for what, and what they decided.

## Adversaries

| Adversary | Can |
|-----------|-----|
| **Network attacker** | See, drop, replay, reorder or modify traffic. Point a client at a fake host. |
| **Stranger** | Find an open port and send anything to it. |
| **Revoked or ex-friend** | Holds an old, previously valid key. |
| **Curious or malicious friend** (paired requester) | Send prompts and files designed to escape the sandbox, read host secrets, exhaust resources or spoof results. |
| **Malicious host** | Return made-up results, or results for a different task. |
| **Local tamperer** | Edit audit logs, results or the peer book on disk after the fact. |

## Mitigations

### Off unless you turn it on
- Nothing listens until you run `interlink share` (alias `interlink peer serve`). Stopping
  the process stops sharing.
- MCP peer tools are only exposed with `interlink serve --peer-tools`.
- A newly paired friend can run **nothing** until you `peer allow` a harness.
- New friends default to `approval = prompt`, so every task waits for `interlink peer approve`.

### Transport
- `share` binds to `127.0.0.1` by default. It refuses any non-loopback `--bind`
  without `--tls-cert`/`--tls-key`. TLS 1.2 is the minimum.
- The client refuses plain `http://` to anything that isn't loopback, and verifies
  `https://` against the system store or the pinned `--ca` certificate.
- TLS is defence in depth. Authentication does not depend on it: every request and
  response is signed (see below), so an SSH tunnel to a loopback port is also safe.

### Mutual authentication (Ed25519, via `cryptography`)
- Each side has one Ed25519 identity key, created with mode `0600` in a `0700`
  directory. Interlink refuses to load a key that other users can read, and refuses a
  peer home that sits inside (or contains) the state root.
- Pairing exchanges **invite codes** (`IL1-...`): a public key with a checksum. You
  compare **fingerprints** (24 base32 characters) over a channel you trust.
- Every request carries a signed claim set: protocol, sender, recipient fingerprint,
  method, path, a random 128-bit nonce, issue and expiry times (60 s by default,
  300 s at most), and the SHA-256 of the body. The host checks all of them.
- Every response is signed by the host over (protocol, host, requester, request nonce,
  HTTP status, body hash). The client verifies it against the **pinned** key in its peer
  book, so a fake host or a modified response is rejected (`bad_response_signature`).
- Signatures use domain separation (`interlink-peer/1 request|response|result`), so a
  signature made for one purpose can't be reused for another.
- `peer revoke` takes effect on the next request, even while `share` is running (the
  peer book is re-read when it changes on disk). Revoked peers get `403 revoked`.

### Replay protection
- Nonces are stored in SQLite until their expiry, and a repeated nonce is rejected
  (`replay`).
- Requests more than 120 s from the host's clock, or valid for longer than 300 s, are
  rejected.
- Task submission is idempotent by `task_id`. Resending the same task returns its
  status. A different task under the same id is refused (`task_collision`).

### Least privilege for inbound tasks
- **Allow-list:** a harness must be in the peer's policy *and* configured on the host.
  Requests may set only `task_id`, `harness`, `prompt`, `files` and `timeout_s`.
  Unknown fields are refused, so a requester can't pass a `project`, argv, env or
  adapter options.
- **Sanitized adapters:** for peer tasks the host clears `pass_env`, `secrets` and
  `env` from every adapter, forces a private HOME, discards workspaces afterwards and
  turns off auto-detection. Inbound tasks never see the host's environment variables,
  API keys or logins. (Consequence: harnesses that need a login or key can't be lent to
  peers in 0.2.)
- **Files in:** only the text files the requester sends are seeded into a fresh
  workspace. Paths are validated (relative, no `..`, no drive letters, no backslashes,
  no control characters), then confined again by the engine. No host project is copied.
- **Files out:** only files the harness created or changed in that workspace come
  back, within `max_files` / `max_file_bytes` / `max_result_bytes`. The requester's CLI
  re-checks every returned path before writing (`--out`).
- **The existing sandbox:** each task is a normal Interlink instance with its own
  limits, process-tree kills and timeouts. See [safety.md](safety.md).

### Resource limits
Each peer has its own: `max_concurrent`, `max_tasks_per_hour`,
`max_requests_per_minute`, `max_timeout_s` (a requested timeout above it is refused, not
clamped), `max_prompt_chars`, `max_files` and `max_file_bytes`. The host also has
global ones: `share --max-concurrent`, a hard 8 MiB request body cap that is enforced
before any parsing, a 15 s socket timeout, and a per-address limiter for failed
authentication.

### Evidence the requester can verify
When a task ends, the host signs a **result statement** (`interlink-peer-result/1`)
containing:
- the SHA-256 of the exact task that was approved;
- state, exit code and final text;
- returned files with their hashes;
- the redacted Interlink evidence bundle and its digest;
- the task's hash chain (`received → approved → started → finished`).

`peer result` verifies all of it against the host's pinned key *and* the copy of the
task you saved before sending. A result for a different prompt, from a different host,
or with an edited file, chain or bundle fails verification.

### Tamper-evident logs
The host's `audit.jsonl` records every accepted and rejected request, decision, start
and finish. The requester's `client-audit.jsonl` records every verified result. Each
entry is hash-chained and fsynced. Check them with `interlink peer audit --verify`
(and `--client`). Prompts appear only as a hash plus a short preview.

## Non-goals and known limits

- **Not an OS sandbox.** A peer task runs as the host user, with Interlink's
  workspace, env and HOME isolation. A harness with arbitrary code execution (a shell
  tool, say) can still read whatever the host user can read on disk. Only allow
  harnesses whose own sandbox you trust, or run `share` in a container or VM as a
  dedicated user.
- **Harness output is the harness's business.** `final_text` and output files are
  whatever the harness produced. They can mention sandbox paths (such as the temporary
  HOME), the OS, or anything the harness could read. The evidence bundle also names
  the host's OS and the *names* (not values) of the variables in the sandbox
  environment.
- **A malicious host can lie about running the model.** Signatures prove *who* said
  what and that nothing changed in transit, not that the computation was honest. Only
  pair with people you'd trust to run the job.
- **Prompts are visible to the host.** That is the point: they run them.
- **No key rotation or recovery.** Lose `identity.key` and you re-pair. A stolen key
  works until your friends revoke you.
- **Approval is out of band.** Pending tasks are approved with `interlink peer approve`
  (from any terminal), not an interactive prompt in the `share` window.
- **Availability:** limits make abuse expensive, not impossible. Don't expose `share`
  to the open internet; prefer an SSH tunnel, a VPN such as Tailscale, or a LAN with TLS.
- **Clock dependence:** the hosts' clocks must agree to within 2 minutes.
