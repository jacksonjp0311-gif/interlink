# Safety model

Interlink lets one agent run another. That is powerful, so the defaults are boring.

## What Interlink does

* **Throwaway workspaces.** Every instance gets its own directory. `project` is *copied*
  in (symlinks and junctions refused, size and count bounded); your original is never
  the harness's working directory and is never written.
* **Private HOME and TMP.** `HOME`, `USERPROFILE`, `TMP*` and `XDG_*` point inside the
  instance, so harness config, caches and sessions don't touch yours.
* **Environment allow-list.** A child process gets `PATH`, locale and a few
  platform essentials - nothing else - unless the harness config names it in
  `pass_env` or `secrets`. Credential-looking names (containing `TOKEN`, `SECRET`, `PASSWORD`,
  `CREDENTIAL`, `API_KEY`, `PRIVATE_KEY`) are refused in `pass_env`; they must be declared as `secrets`.
* **Redaction.** Values of declared secrets are scrubbed from events, logs and evidence
  before they hit disk.
* **Path confinement.** `interlink_files` and seed paths resolve inside the workspace and
  refuse `..`, absolute paths and links.
* **Process-tree control.** Each harness runs in its own process group (plus a Job object on
  Windows when the `windows` extra / pywin32 is installed). Cancel, timeout and stop kill the whole tree, grandchildren included.
  Orphans from a crashed server are reaped only when their recorded identity
  (pid + start time + executable) still matches.
* **Bounded everything.** Prompt size, seeded files, events per run, field sizes, file
  reads, evidence bytes, run time, live instances and concurrent runs.
* **Evidence.** Every launch, prompt and finish appends a hash-chained receipt.
  `interlink_evidence` exports runs, event hashes, the file diff and the chain, and
  verifies the chain as it goes. Prompt text is stored as a sha256 only.
* **Idempotent, replay-safe calls.** See [protocol.md](protocol.md).

## What Interlink does NOT do

* **It is not an OS sandbox.** A harness runs as *you*, with your file-system
  permissions. It is pointed at a copy and given a private HOME, but a determined or
  confused agent can still read `/etc` or write to absolute paths you can write to. For
  hostile code, run Interlink inside a container/VM, or use the harness's own sandbox
  (Codex `--sandbox`, Claude Code permission modes) on top.
* It does not make an agent's *actions* safe - an agent with network access can still
  call the network.
* `isolate_home = false` (needed by CLIs that keep their login under HOME) means the
  harness sees your real home directory.

## PEGASUS-specific protections (ported from PEGASUS Interlink)

The PEGASUS adapter refuses personal installs and real profiles, requires a disposable
source tree, links `data/` and `runtime/` into a disposable profile, verifies a manifest
digest of the source tree before boot, authenticates every request with a per-launch
token, enforces leases (1-60 s TTL) and request deadlines, and keeps inference off unless
`inference = true`.
