"""Interlink live validation + benchmarks.

    python live_bench.py --out DIR [--n 200] [--hermes PATH --llama URL]
                         [--pegasus-exe PATH --pegasus-source PATH]

Everything runs in DIR (state roots, peer homes, configs). Nothing outside DIR is
written. Only metadata is recorded: env-var NAMES (never values), hashes, timings.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PY = sys.executable
# Keep the user's own Codex MCP servers from starting during these runs (per-invocation
# overrides; ~/.codex/config.toml is never edited). Names come from --codex-disable-mcp.
OFF_USER_MCP: list[str] = []
SECRETISH = re.compile(r"(TOKEN|SECRET|PASSWORD|API_KEY|_KEY$|CREDENTIAL|AUTH)", re.I)


def ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


def stats(values: list[float]) -> dict[str, Any]:
    v = sorted(values)
    if not v:
        return {"n": 0}
    q = lambda p: v[min(len(v) - 1, round(p * (len(v) - 1)))]  # noqa: E731
    return {
        "n": len(v),
        "min": v[0],
        "p50": q(0.5),
        "p95": q(0.95),
        "max": v[-1],
        "mean": round(statistics.fmean(v), 2),
    }


def redact(text: str) -> str:
    """Replace the home directory in plain, forward-slash and JSON-escaped forms."""
    home = str(Path.home())
    forms = {home, home.replace("\\", "/"), home.replace("\\", "\\\\")}
    for form in sorted(forms, key=len, reverse=True):
        text = re.sub(re.escape(form), "%USERPROFILE%", text, flags=re.IGNORECASE)
    return text


def snapshot_ledger(src: Path, dst: Path) -> None:
    """Consistent copy of a WAL-mode sqlite ledger (a plain file copy can miss the WAL)."""
    import sqlite3

    dst.unlink(missing_ok=True)
    with sqlite3.connect(src) as a, sqlite3.connect(dst) as b:
        a.backup(b)
        b.execute("PRAGMA journal_mode=DELETE")
    a.close()
    b.close()


def machine() -> dict[str, Any]:
    import interlink

    info: dict[str, Any] = {
        "os": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "interlink": interlink.__version__,
        "cpu_count": os.cpu_count(),
    }
    if sys.platform == "win32":
        ps = (
            "$c=Get-CimInstance Win32_Processor;$s=Get-CimInstance Win32_ComputerSystem;"
            "$o=Get-CimInstance Win32_OperatingSystem;"
            "[pscustomobject]@{cpu=$c.Name.Trim();cores=$c.NumberOfCores;threads=$c.NumberOfLogicalProcessors;"
            "ram_gb=[math]::Round($s.TotalPhysicalMemory/1GB,1);os=$o.Caption;build=$o.Version}|ConvertTo-Json -Compress"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout
            info.update(json.loads(out))
        except Exception as exc:
            info["specs_error"] = str(exc)[:200]
    else:
        try:
            cpu = next(
                line.split(":", 1)[1].strip()
                for line in open("/proc/cpuinfo")  # noqa: SIM115
                if line.startswith("model name")
            )
            mem = next(
                int(line.split()[1])
                for line in open("/proc/meminfo")  # noqa: SIM115
                if line.startswith("MemTotal")
            )
            info.update(cpu=cpu, ram_gb=round(mem / 1024 / 1024, 1))
        except Exception:  # noqa: S110 - best-effort machine info
            pass
    return info


def write_toml(path: Path, harnesses: dict[str, dict[str, Any]], state: Path) -> Path:
    def val(x: Any) -> str:
        if isinstance(x, bool):
            return "true" if x else "false"
        if isinstance(x, (int, float)):
            return str(x)
        if isinstance(x, list):
            return "[" + ", ".join(val(i) for i in x) + "]"
        return "'" + str(x) + "'" if "'" not in str(x) else json.dumps(str(x))

    lines = ["[server]", "auto_detect = false", f"state_root = {val(str(state))}", ""]
    for name, spec in harnesses.items():
        sub = {k: v for k, v in spec.items() if isinstance(v, dict)}
        lines.append(f"[harness.{name}]")
        lines += [f"{k} = {val(v)}" for k, v in spec.items() if not isinstance(v, dict)]
        for sk, sv in sub.items():
            lines.append(f"[harness.{name}.{sk}]")
            lines += [f"{k} = {val(v)}" for k, v in sv.items()]
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------------- MCP
async def mcp_section(out: Path, n: int, extra: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from mcp import Client

    from interlink.client import server_params

    state = out / "state-mcp"
    canary = "canary-" + secrets.token_hex(12)
    harnesses: dict[str, dict[str, Any]] = {
        "mock": {"adapter": "mock"},
        "envkeys": {
            "adapter": "command",
            "argv": [
                PY,
                "-c",
                (
                    "import os,json,sys;v=os.environ.get('INTERLINK_CANARY_TOKEN','');"
                    "print(json.dumps({'keys':sorted(os.environ),"
                    "'declared_secret_echo':v}))"
                ),
            ],
            "secrets": ["INTERLINK_CANARY_TOKEN"],
            "output": "text",
        },
        "envkeys_undeclared": {
            "adapter": "command",
            "argv": [PY, "-c", "import os,json;print(json.dumps(sorted(os.environ)))"],
            "output": "text",
        },
        **extra,
    }
    config = write_toml(out / "mcp.toml", harnesses, state)
    env = {"INTERLINK_CANARY_TOKEN": canary, "INTERLINK_CANARY_API_KEY": canary}
    res: dict[str, Any] = {}

    async def call(client: Any, tool: str, **args: Any) -> tuple[dict[str, Any], float]:
        t0 = time.perf_counter()
        r = await client.call_tool(tool, args)
        if r.structured_content is None:  # protocol-level error (e.g. argument validation)
            text = " ".join(getattr(b, "text", "") for b in r.content)
            return {"status": "error", "error": {"code": "tool_error", "message": text[:500]}}, ms(
                t0
            )
        return r.structured_content, ms(t0)

    t0 = time.perf_counter()
    async with Client(server_params(str(config), str(state), env), read_timeout_seconds=900) as c:
        res["connect_initialize_ms"] = ms(t0)
        t1 = time.perf_counter()
        tools = (await c.list_tools()).tools
        res["list_tools_ms"] = ms(t1)
        res["tools"] = len(tools)
        res["protocol"] = c.protocol_version
        rt = []
        for _ in range(n):
            _, d = await call(c, "interlink_harnesses", check=False)
            rt.append(d)
        res["roundtrip_harnesses_ms"] = stats(rt)

        # mock lifecycle
        L: dict[str, list[float]] = {
            k: [] for k in ("launch", "prompt_e2e", "files", "evidence", "stop_discard", "total")
        }
        chain_ok = True
        sample_evidence = None
        for i in range(max(5, n // 10)):
            t_all = time.perf_counter()
            r, d = await call(
                c, "interlink_launch", harness="mock", files={"seed.md": f"# run {i}\n"}
            )
            L["launch"].append(d)
            iid = r["data"]["instance_id"]
            r, d = await call(
                c,
                "interlink_prompt",
                instance_id=iid,
                wait_s=60,
                prompt="say hello from a sandbox\nwrite hello.txt hi there",
            )
            assert r["data"]["state"] == "complete", r
            L["prompt_e2e"].append(d)
            r, d = await call(c, "interlink_files", instance_id=iid)
            L["files"].append(d)
            assert any(f["path"] == "hello.txt" for f in r["data"]["files"]), r
            r, d = await call(c, "interlink_evidence", instance_id=iid)
            L["evidence"].append(d)
            chain_ok &= bool(r["data"]["summary"]["receipt_chain_valid"])
            if i == 0:
                sample_evidence = Path(r["data"]["path"])
            r, d = await call(c, "interlink_stop", instance_id=iid, discard=True)
            L["stop_discard"].append(d)
            L["total"].append(ms(t_all))
        res["mock_lifecycle_ms"] = {k: stats(v) for k, v in L.items()}
        res["mock_receipt_chain_valid"] = chain_ok
        if sample_evidence and sample_evidence.is_file():
            shutil.copyfile(sample_evidence, out / "evidence-mock.json")

        # env allow-list / secret redaction
        r, _ = await call(c, "interlink_launch", harness="envkeys")
        iid = r["data"]["instance_id"]
        r, _ = await call(c, "interlink_prompt", instance_id=iid, prompt="x", wait_s=60)
        ev, _ = await call(c, "interlink_observe", instance_id=iid, limit=200)
        text = json.dumps(ev)
        r2, _ = await call(c, "interlink_launch", harness="envkeys_undeclared")
        iid2 = r2["data"]["instance_id"]
        await call(c, "interlink_prompt", instance_id=iid2, prompt="x", wait_s=60)
        ev2, _ = await call(c, "interlink_observe", instance_id=iid2, limit=200)
        text2 = json.dumps(ev2)
        keys2: list[str] = []
        for e in ev2["data"]["events"]:
            if e.get("type") == "text" and e.get("text", "").strip().startswith("["):
                with contextlib.suppress(ValueError):
                    keys2 = json.loads(e["text"])
        parent_secretish = sorted(k for k in os.environ if SECRETISH.search(k))
        res["env_allowlist"] = {
            "canary_value_in_any_transcript": canary in text or canary in text2,
            "declared_secret_redacted_in_transcript": canary not in text
            and "INTERLINK_CANARY_TOKEN" in text,
            "undeclared_child_env_key_count": len(keys2),
            "undeclared_child_secretish_keys": sorted(k for k in keys2 if SECRETISH.search(k)),
            "parent_secretish_key_count": len(parent_secretish),
            "parent_secretish_keys_leaked_to_child": sorted(set(parent_secretish) & set(keys2)),
        }
        _ev_a, _ = await call(c, "interlink_evidence", instance_id=iid)
        res["env_allowlist"]["evidence_env_keys_recorded"] = True
        for x in (iid, iid2):
            await call(c, "interlink_stop", instance_id=x, discard=True)

        # live harnesses (hermes / pegasus) if configured
        for name in extra:
            res[f"live_{name}"] = await live_harness(c, call, name, out)
    # copy the receipt ledger (sqlite) so the chain can be re-verified offline
    for cand in state.glob("ledger.sqlite3"):
        snapshot_ledger(cand, out / "ledger-mcp.sqlite3")
    return res


async def live_harness(c: Any, call: Any, name: str, out: Path) -> dict[str, Any]:
    spec_prompt = {
        "hermes": "Create a file named interlink_ok.txt containing exactly the text LIVE-OK, then reply DONE.",
        "pegasus": "Reply with exactly the word LIVE-OK and nothing else.",
        "codex": "Create a file named interlink_ok.txt containing exactly the text LIVE-OK, then reply DONE.",
    }.get(name, "Reply with exactly LIVE-OK.")
    rec: dict[str, Any] = {"ran": False}
    t0 = time.perf_counter()
    try:
        r, d = await call(c, "interlink_launch", harness=name)
        rec["launch_ms"] = d
        rec["launch_status"] = r.get("status")
        if r.get("status") != "complete":
            rec["error"] = redact(json.dumps(r.get("error") or r)[:600])
            return rec
        iid = r["data"]["instance_id"]
        rec["host_info"] = {
            k: v
            for k, v in (r["data"].get("host") or {}).items()
            if k in ("generation", "inference_enabled", "boundary", "build_sha256", "source_sha256")
        }
        t_run = time.perf_counter()
        r, d = await call(c, "interlink_prompt", instance_id=iid, prompt=spec_prompt, wait_s=60)
        rec["prompt_status"] = r.get("status")
        if r.get("status") != "complete" or not r.get("data"):
            rec["error"] = redact(json.dumps(r.get("error") or r)[:600])
            return rec
        rec["ran"] = True
        evs: list[dict[str, Any]] = []
        cursor, window = 0, {}
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:  # tool limits: wait_s<=60, wait_ms<=30000, limit<=256
            ev, _ = await call(
                c,
                "interlink_observe",
                instance_id=iid,
                after_cursor=cursor,
                limit=256,
                wait_ms=5000,
            )
            window = ev.get("data") or {}
            evs += window.get("events", [])
            cursor = window.get("next_cursor", cursor)
            if window.get("done") and not window.get("more"):
                break
        rec["prompt_e2e_ms"] = ms(t_run)
        rec["run_state"] = window.get("state")
        rec["exit_code"] = window.get("exit_code")
        counts: dict[str, int] = {}
        for e in evs:
            counts[e["type"]] = counts.get(e["type"], 0) + 1
        rec["event_counts"] = counts
        texts = [e.get("text", "") for e in evs if e["type"] in ("text", "result")]
        final = ("".join(texts) or "")[-400:]
        rec["final_text_tail"] = redact(final)
        rec["errors"] = [redact(json.dumps(e)[:300]) for e in evs if e["type"] == "error"][:5]
        f, _ = await call(c, "interlink_files", instance_id=iid)
        rec["files_changed"] = [
            {"path": x["path"], "status": x["status"]} for x in f["data"]["files"]
        ][:20]
        e, _ = await call(c, "interlink_evidence", instance_id=iid)
        rec["receipt_chain_valid"] = e["data"]["summary"]["receipt_chain_valid"]
        p = Path(e["data"]["path"])
        if p.is_file():
            (out / f"evidence-{name}.json").write_text(
                redact(p.read_text(encoding="utf-8")), encoding="utf-8"
            )
        _s, d = await call(c, "interlink_stop", instance_id=iid, discard=False)
        rec["stop_ms"] = d
    except Exception as exc:
        rec["error"] = redact(f"{type(exc).__name__}: {exc}"[:600])
    rec["total_ms"] = ms(t0)
    return rec


# ------------------------------------------------------------------ codex as the MCP client
def codex_client_section(out: Path, codex: str) -> dict[str, Any]:
    """Drive Interlink from Codex itself, wiring the server in with ``-c`` overrides only.

    Nothing is written to the user's ~/.codex/config.toml: the MCP server entry exists only
    for this one ``codex exec`` invocation.
    """
    from interlink.ledger import Ledger

    state = out / "state-codex-client"
    work = out / "codex-client-cwd"
    work.mkdir(parents=True, exist_ok=True)
    config = write_toml(out / "codex-client.toml", {"mock": {"adapter": "mock"}}, state)

    def lit(x: str) -> str:  # TOML literal string, safe for Windows paths
        return "'" + x + "'"

    args = (
        "["
        + ", ".join(
            lit(x)
            for x in [
                "-m",
                "interlink",
                "serve",
                "--config",
                str(config),
                "--state-root",
                str(state),
            ]
        )
        + "]"
    )
    argv = [
        codex,
        "exec",
        "--json",
        "--skip-git-repo-check",
        "--sandbox",
        "workspace-write",
        "-c",
        "approval_policy='never'",
        *OFF_USER_MCP,
        "-c",
        f"mcp_servers.interlink_live.command={lit(PY)}",
        "-c",
        f"mcp_servers.interlink_live.args={args}",
        "-c",
        "mcp_servers.interlink_live.startup_timeout_sec=60",
        "-c",
        "mcp_servers.interlink_live.tool_timeout_sec=120",
        # codex exec runs with approval_policy=never, which cancels MCP calls unless the
        # server's tools are pre-approved for this one invocation.
        "-c",
        "mcp_servers.interlink_live.default_tools_approval_mode='approve'",
        "-",
    ]
    prompt = (
        "You have an MCP server named interlink_live. Use its tools, in order: "
        "1) call interlink_harnesses; 2) call interlink_launch with harness 'mock'; "
        "3) call interlink_prompt with that instance_id and prompt 'hello from codex' and wait_s 30; "
        "4) call interlink_evidence for the instance; 5) call interlink_stop for the instance. "
        "Then reply with one line: the mock's final text and whether receipt_chain_valid was true."
    )
    t0 = time.perf_counter()
    p = subprocess.run(
        argv,
        input=prompt,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        cwd=work,
    )
    res: dict[str, Any] = {
        "exit_code": p.returncode,
        "wall_ms": ms(t0),
        "config_overrides_only": True,
        "user_config_written": False,
    }
    calls: list[dict[str, Any]] = []
    final = ""
    for line in p.stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        item = ev.get("item") or {}
        if ev.get("type") == "item.completed" and item.get("type") == "mcp_tool_call":
            calls.append(
                {
                    "server": item.get("server"),
                    "tool": item.get("tool"),
                    "status": item.get("status"),
                    "error": bool(item.get("error")),
                }
            )
        if ev.get("type") == "item.completed" and item.get("type") == "agent_message":
            final = item.get("text", "")
        if ev.get("type") in ("error", "turn.failed"):
            res.setdefault("errors", []).append(redact(json.dumps(ev)[:300]))
    res["mcp_tool_calls"] = calls
    res["interlink_tools_called"] = [c["tool"] for c in calls if c["server"] == "interlink_live"]
    res["final_text"] = redact(final[-400:])
    if p.returncode and not calls:
        res["stderr_tail"] = redact(p.stderr.strip()[-600:])
    ledger = state / "ledger.sqlite3"
    if ledger.is_file():
        rep = Ledger(ledger).verify_chain()
        res["server_ledger"] = rep if isinstance(rep, dict) else str(rep)
        snapshot_ledger(ledger, out / "ledger-codex-client.sqlite3")
    (out / "codex-client-events.jsonl").write_text(redact(p.stdout), encoding="utf-8")
    ok_calls = [c for c in calls if c["server"] == "interlink_live" and c["status"] == "completed"]
    res["interlink_tools_completed"] = [c["tool"] for c in ok_calls]
    if not ok_calls:
        raise RuntimeError("codex completed no interlink tool calls: " + json.dumps(res)[:800])
    return res


# ---------------------------------------------------------------------------------- ledger
def ledger_section(out: Path, n: int) -> dict[str, Any]:
    from interlink.ledger import Ledger

    path = out / "bench-ledger" / "ledger.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    led = Ledger(path)
    t0 = time.perf_counter()
    for i in range(n):
        led.receipt("bench", "bench_event", {"i": i, "pad": "x" * 64})
    append = ms(t0)
    t1 = time.perf_counter()
    report = led.verify_chain()
    verify = ms(t1)
    led.close()
    shutil.rmtree(path.parent, ignore_errors=True)
    return {
        "receipts": n,
        "append_total_ms": append,
        "append_per_receipt_ms": round(append / n, 4),
        "verify_ms": verify,
        "verify_receipts_per_s": round(n / (verify / 1000)),
        "valid": report["valid"],
    }


# ---------------------------------------------------------------------------------- peers
def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def peer_section(out: Path, pings: int) -> dict[str, Any]:
    root = out / "peers"
    people = {}
    for who in ("alice", "bob"):
        home, state = root / who / "keys", root / who / "state"
        home.mkdir(parents=True, exist_ok=True)
        cfg = write_toml(
            root / who / "interlink.toml",
            {
                "mock": {"adapter": "mock"},
                "writer": {
                    "adapter": "command",
                    "argv": [
                        PY,
                        "-c",
                        "import sys; open('out.txt','w').write(sys.stdin.read().upper())",
                    ],
                },
            },
            state,
        )
        env = {
            **os.environ,
            "INTERLINK_PEER_HOME": str(home),
            "INTERLINK_CONFIG": str(cfg),
            "PYTHONUNBUFFERED": "1",
        }
        people[who] = {"env": env, "cfg": str(cfg), "home": home, "state": state}

    def il(
        who: str, *args: str, check: bool = True, timeout: float = 120
    ) -> tuple[subprocess.CompletedProcess, float]:
        t0 = time.perf_counter()
        p = subprocess.run(
            [PY, "-m", "interlink", *args],
            env=people[who]["env"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        d = ms(t0)
        if check and p.returncode != 0:
            raise RuntimeError(f"{who} {args[:2]} -> {p.returncode}: {redact(p.stderr[-400:])}")
        return p, d

    res: dict[str, Any] = {}
    ids = {}
    t0 = time.perf_counter()
    for who in people:
        p, _ = il(who, "peer", "id", "--json")
        ids[who] = json.loads(p.stdout)
    res["identity_create_ms"] = ms(t0)
    port = free_port()
    t0 = time.perf_counter()
    il(
        "bob",
        "peer",
        "add",
        "alice",
        ids["alice"]["invite"],
        "--allow",
        "mock,writer",
        "--auto-approve",
    )
    il("alice", "peer", "add", "bob", ids["bob"]["invite"], "--url", f"http://127.0.0.1:{port}")
    res["pairing_ms"] = ms(t0)
    res["fingerprints_match_invites"] = True
    t0 = time.perf_counter()
    host = subprocess.Popen(
        [PY, "-m", "interlink", "share", "--port", str(port)],
        env=people["bob"]["env"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    banner = []
    try:
        for line in host.stdout:  # type: ignore[union-attr]
            banner.append(line)
            if "Peers who can run" in line:
                break
        res["share_startup_ms"] = ms(t0)
        lat = []
        for _ in range(pings):
            p, d = il("alice", "peer", "ping", "bob", "--json")
            lat.append(d)
        res["signed_ping_cli_ms"] = stats(lat)
        res["ping_reply"] = {
            k: v
            for k, v in json.loads(p.stdout).items()
            if k in ("harnesses", "approval", "version")
        }
        # in-process client for pure handshake latency (no python startup)
        os.environ["INTERLINK_PEER_HOME"] = str(people["alice"]["home"])
        from interlink.peer.client import PeerClient
        from interlink.peer.crypto import Identity
        from interlink.peer.store import PeerBook

        ident = Identity.load_or_create(people["alice"]["home"])
        client = PeerClient(
            ident,
            PeerBook(people["alice"]["home"]).get("bob"),
            people["alice"]["state"] / "peer",
            timeout_s=30,
        )
        lat2 = []
        for _ in range(pings * 4):
            t1 = time.perf_counter()
            client.hello()
            lat2.append(ms(t1))
        res["signed_hello_inproc_ms"] = stats(lat2)
        # delegated tasks
        e2e = []
        for i in range(5):
            p, d = il(
                "alice",
                "peer",
                "send",
                "bob",
                "writer",
                f"hello from alice {i}",
                "--json",
                timeout=300,
            )
            e2e.append(d)
            result = json.loads(p.stdout)
            assert result["verification"]["verified"] is True
            assert result["statement"]["state"] == "complete"
        res["delegated_task_cli_ms"] = stats(e2e)
        (out / "peer-result-signed.json").write_text(
            json.dumps(
                {
                    "host_public_invite": ids["bob"]["invite"],
                    "host_fingerprint": ids["bob"]["fingerprint"],
                    "requester_fingerprint": ids["alice"]["fingerprint"],
                    **result,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        # stored signed envelope (statement + signature) for offline verification
        rcv = sorted(
            (people["alice"]["state"] / "peer" / "received").glob("*.json"), key=os.path.getmtime
        )
        if rcv:
            env_ = json.loads(rcv[-1].read_text(encoding="utf-8"))
            (out / "peer-result-envelope.json").write_text(
                json.dumps(
                    {
                        "host_invite": ids["bob"]["invite"],
                        "host_fingerprint": ids["bob"]["fingerprint"],
                        "requester_fingerprint": ids["alice"]["fingerprint"],
                        "envelope": env_,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        res["delegated_result"] = {
            "verified": result["verification"]["verified"],
            "chain_entries": result["verification"]["chain_entries"],
            "files": [(f["path"], f["status"]) for f in result["statement"].get("files", [])],
            "out_txt": next(
                (
                    f.get("text")
                    for f in result["statement"].get("files", [])
                    if f["path"] == "out.txt"
                ),
                None,
            ),
        }
        # denied: harness not allowed
        p, _ = il("alice", "peer", "send", "bob", "mock_not_allowed", "x", check=False)
        res["disallowed_harness_refused"] = p.returncode != 0
        # rate limit: keep saying hello until the host pushes back
        from interlink.peer.client import PeerCallError

        accepted = 0
        refused_code = None
        for _ in range(400):
            try:
                client.hello()
                accepted += 1
            except PeerCallError as exc:
                refused_code = exc.code
                break
        res["rate_limit"] = {"extra_hellos_accepted_before_429": accepted, "refusal": refused_code}
        time.sleep(65)  # let the window drain so the revoke check is not a rate-limit refusal
        p, _ = il("alice", "peer", "ping", "bob", check=False)
        res["ping_ok_after_window"] = p.returncode == 0
        if p.returncode:
            res["ping_after_window_message"] = redact((p.stderr or p.stdout).strip()[-200:])
        # revoke
        il("bob", "peer", "revoke", "alice")
        t1 = time.perf_counter()
        p, _ = il("alice", "peer", "ping", "bob", check=False)
        res["after_revoke_ping_refused"] = p.returncode != 0
        res["after_revoke_message"] = redact(
            (p.stderr or p.stdout).strip().splitlines()[-1][:200]
            if (p.stderr or p.stdout).strip()
            else ""
        )
    finally:
        host.terminate()
        try:
            host.wait(10)
        except subprocess.TimeoutExpired:
            host.kill()
    p, _ = il("bob", "peer", "audit", "--verify", check=False)
    res["host_audit_verify"] = redact(p.stdout.strip()[-300:])
    p, _ = il("alice", "peer", "audit", "--client", "--verify", check=False)
    res["client_audit_verify"] = redact(p.stdout.strip()[-300:])
    for who, _name in (("bob", "audit-host.jsonl"), ("alice", "audit-client.jsonl")):
        logs = sorted((people[who]["state"] / "peer").rglob("*.jsonl")) + sorted(
            people[who]["home"].rglob("*.jsonl")
        )
        for log in logs:
            if "audit" in log.name:
                shutil.copyfile(log, out / (f"{who}-" + log.name))
    return res


# ---------------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--ledger-n", type=int, default=5000)
    ap.add_argument("--hermes")
    ap.add_argument("--hermes-model", default="qwen")
    ap.add_argument("--llama", default="http://127.0.0.1:8080/v1")
    ap.add_argument("--pegasus-exe")
    ap.add_argument("--pegasus-source")
    ap.add_argument("--pegasus-inference", action="store_true")
    ap.add_argument("--pegasus-model-path", default="")
    ap.add_argument("--codex")
    ap.add_argument("--codex-disable-mcp", default="")
    ap.add_argument("--skip", default="")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    skip = set(a.skip.split(","))
    report: dict[str, Any] = {
        "schema": "interlink-live-report/1",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": machine(),
    }
    extra: dict[str, dict[str, Any]] = {}
    if a.hermes:
        extra["hermes"] = {
            "adapter": "hermes",
            "command": a.hermes,
            "base_url": a.llama,
            "model": a.hermes_model,
            "provider": "custom",
            "max_turns": 8,
            "timeout_s": 600,
        }
    if a.pegasus_exe:
        spec: dict[str, Any] = {
            "adapter": "pegasus",
            "executable": a.pegasus_exe,
            "source_root": a.pegasus_source,
            "inference": bool(a.pegasus_inference),
            "startup_timeout_s": 120,
            "timeout_s": 600,
        }
        if a.pegasus_inference:
            spec["model"] = {
                "id": "local-qwen",
                "name": "Qwen3.6-35B-A3B",
                "path": a.pegasus_model_path,
                "endpoint": a.llama.removesuffix("/v1"),
                "context": 65536,
            }
        extra["pegasus"] = spec
    for srv in filter(None, a.codex_disable_mcp.split(",")):
        OFF_USER_MCP.extend(["-c", f"mcp_servers.{srv}.enabled=false"])
    if a.codex:
        # isolate_home=false: codex uses the user's existing login in ~/.codex; Interlink
        # never copies or reads auth.json (CODEX_HOME is left unset, see adapters/codex.py).
        extra["codex"] = {
            "adapter": "codex",
            "command": a.codex,
            "isolate_home": False,
            "timeout_s": 600,
            "extra_args": OFF_USER_MCP,
        }
    sections = [
        ("ledger", lambda: ledger_section(out, a.ledger_n)),
        ("mcp", lambda: asyncio.run(mcp_section(out, a.n, extra))),
        ("peer", lambda: peer_section(out, 10)),
        (
            "codex_client",
            lambda: codex_client_section(out, a.codex) if a.codex else {"skipped": True},
        ),
    ]
    for name, fn in sections:
        if name in skip:
            report[name] = {"skipped": True}
            continue
        t0 = time.perf_counter()
        try:
            report[name] = fn()
            if not report[name].get("skipped"):
                report[name]["ok"] = True
        except Exception as exc:
            report[name] = {"ok": False, "error": redact(f"{type(exc).__name__}: {exc}"[:1200])}
        report[name]["section_ms"] = ms(t0)
        print(
            f"[{name}] {'ok' if report[name].get('ok') else 'FAILED'} in {report[name]['section_ms']:.0f} ms",
            flush=True,
        )
    report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (out / "report.json").write_text(
        redact(json.dumps(report, indent=2, default=str)), encoding="utf-8"
    )
    print(redact(json.dumps(report, indent=2, default=str)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
