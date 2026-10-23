"""``interlink`` command line: serve, run, doctor and friends."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from interlink import __version__
from interlink.config import EXAMPLE, Config, ConfigError, load
from interlink.engine import Engine, InterlinkError
from interlink.security import platform_label

EXIT = {"complete": 0, "failed": 1, "error": 2, "timed_out": 124, "cancelled": 130}
COLORS = {
    "text": "",
    "tool_use": "36",
    "tool_result": "2",
    "stderr": "33",
    "error": "31",
    "status": "2",
}


def _color(code: str, text: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled and code else text


def _config(args: argparse.Namespace) -> Config:
    return load(args.config)


def _engine(args: argparse.Namespace) -> Engine:
    config = _config(args)
    return Engine(config, Path(args.state_root) if args.state_root else None)


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


# -- commands ----------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    from interlink.server import build_server

    config = _config(args)
    engine = Engine(config, Path(args.state_root) if args.state_root else None)
    server, _ = build_server(config, engine, peer_tools=args.peer_tools)
    server.run(transport="stdio")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    prompt = sys.stdin.read() if args.prompt == "-" else args.prompt
    if hasattr(sys.stdout, "reconfigure"):  # keep events and status lines in order
        sys.stdout.reconfigure(line_buffering=True)
    engine = _engine(args)
    color = sys.stdout.isatty() and not args.json
    files = {}
    for item in args.file or []:
        rel, sep, local = item.partition("=")
        if not sep:
            raise SystemExit(f"--file expects REL=LOCAL_PATH, got {item!r}")
        files[rel] = Path(local).read_bytes().decode("utf-8")
    try:
        launched = engine.launch(
            args.harness, project=args.project, files=files or None, label="cli run"
        )
        instance_id = launched["instance_id"]
        if not args.json:
            print(
                _color(
                    "2",
                    f"interlink: {args.harness} instance {instance_id[:8]} in {launched['workspace']}",
                    color,
                ),
                file=sys.stderr,
            )
        started = engine.prompt(instance_id, prompt, timeout_s=args.timeout)
        cursor, window = 0, {}
        while True:
            window = engine.observe(
                instance_id, started["run_id"], after=cursor, limit=256, wait_s=1.0
            )
            cursor = window["next_cursor"]
            for event in window["events"]:
                if args.json:
                    print(json.dumps(event, ensure_ascii=False))
                elif not args.quiet:
                    _render(event, color)
            if window["done"] and not window["more"]:
                break
        state = window["state"]
        if not args.json:
            final = window.get("final_text") or ""
            if args.quiet and final:
                print(final)
            print(
                _color("2", f"interlink: run {state} (exit {window['exit_code']})", color),
                file=sys.stderr,
            )
        if args.evidence:
            exported = engine.evidence(instance_id, include_transcript=True)
            print(f"evidence: {exported['path']}", file=sys.stderr)
        engine.stop(instance_id, discard=not (args.keep or args.evidence))
        if args.keep and not args.json:
            print(f"kept workspace: {launched['workspace']}", file=sys.stderr)
        return EXIT.get(state, 2)
    except InterlinkError as exc:
        print(f"interlink: {exc.status}: {exc.code}: {exc.message}", file=sys.stderr)
        return 2
    finally:
        engine.shutdown()


def _render(event: dict[str, Any], color: bool) -> None:
    kind = event["type"]
    if kind == "text":
        print(event.get("text", ""), end="" if event.get("partial") else "\n", flush=True)
    elif kind == "tool_use":
        detail = event.get("input")
        summary = json.dumps(detail, ensure_ascii=False)[:160] if detail is not None else ""
        print(_color(COLORS[kind], f"  -> {event.get('tool') or 'tool'} {summary}", color))
    elif kind == "tool_result":
        body = event.get("output") or event.get("text") or event.get("error") or ""
        status = "ok" if event.get("ok", not event.get("error")) else "failed"
        text = str(body)[:200].replace("\n", " ")
        print(
            _color(
                COLORS[kind], f"  <- {event.get('tool') or 'tool'} {status} {text}".rstrip(), color
            )
        )
    elif kind in ("stderr", "error"):
        print(
            _color(COLORS[kind], f"  ! {event.get('text') or event.get('message', '')}", color),
            file=sys.stderr,
        )
    elif kind == "question":
        print(_color("35", f"  ? {event.get('text', '')}", color))
    elif kind == "result" and event.get("text"):
        pass  # already streamed as text by most harnesses; shown via final_text with --quiet


def cmd_doctor(args: argparse.Namespace) -> int:
    import mcp

    checks: list[tuple[str, bool, str]] = []
    checks.append(("python", sys.version_info >= (3, 11), sys.version.split()[0]))
    checks.append(("platform", True, platform_label()))
    checks.append(("mcp sdk", True, getattr(mcp, "__version__", None) or _dist_version("mcp")))
    try:
        config = _config(args)
        checks.append(
            ("config", True, str(config.source) if config.source else "none (built-in defaults)")
        )
    except ConfigError as exc:
        checks.append(("config", False, str(exc)))
        _report(checks, args.json)
        return 1
    try:
        engine = Engine(config, Path(args.state_root) if args.state_root else None)
        checks.append(("state root", True, str(engine.root)))
    except Exception as exc:
        checks.append(("state root", False, str(exc)))
        _report(checks, args.json)
        return 1
    try:
        for item in engine.harnesses()["harnesses"]:
            doctor = item["doctor"]
            failing = [c for c in doctor["checks"] if not c["ok"]]
            detail = (
                "; ".join(f"{c['name']}: {c['detail']}" for c in failing) or item["description"]
            )
            checks.append((f"harness {item['name']} ({item['adapter']})", doctor["ok"], detail))
        for note in config.notes:
            checks.append(("note", True, note))
    finally:
        engine.shutdown()
    _report(checks, args.json)
    return 0 if all(ok for name, ok, _ in checks if not name.startswith("harness ")) else 1


def _dist_version(name: str) -> str:
    from importlib.metadata import version

    return version(name)


def _report(checks: list[tuple[str, bool, str]], as_json: bool) -> None:
    if as_json:
        core_ok = all(ok for name, ok, _ in checks if not name.startswith("harness "))
        _print_json(
            {
                "ok": core_ok,
                "checks": [{"check": n, "ok": ok, "detail": d} for n, ok, d in checks],
            }
        )
        return
    width = max(len(n) for n, _, _ in checks)
    for name, ok, detail in checks:
        print(f"  {'ok ' if ok else 'XX '} {name.ljust(width)}  {detail}")


def cmd_harnesses(args: argparse.Namespace) -> int:
    engine = _engine(args)
    try:
        listing = engine.harnesses(check=not args.no_check)
    finally:
        engine.shutdown()
    if args.json:
        _print_json(listing)
        return 0
    for item in listing["harnesses"]:
        ready = item.get("doctor", {}).get("ok", True)
        print(
            f"  {'ready' if ready else 'not ready':10} {item['name']:14} {item['adapter']:12} {item['description']}"
        )
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    engine = _engine(args)
    try:
        listing = engine.inspect()
    finally:
        engine.shutdown()
    if args.json:
        _print_json(listing)
        return 0
    if not listing["instances"]:
        print(f"no instances under {listing['server']['state_root']}")
    for item in listing["instances"]:
        print(
            f"  {item['instance_id']}  {item['state']:9} {item['harness']:12} runs={item['runs']}  {item['label']}"
        )
    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    engine = _engine(args)
    try:
        result = engine.cleanup(include_orphaned=True, older_than_s=args.older_than_hours * 3600)
    finally:
        engine.shutdown()
    print(f"removed {len(result['removed'])} workspace(s)")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    target.write_text(EXAMPLE, encoding="utf-8")
    print(f"wrote {target}")
    return 0


def snippet(kind: str, config_path: str | None = None) -> str:
    command = "interlink" if shutil.which("interlink") else sys.executable
    args = ["serve"] if command == "interlink" else ["-m", "interlink", "serve"]
    if config_path:
        args += ["--config", str(Path(config_path).resolve())]
    if kind == "claude-code":
        return json.dumps(
            {"mcpServers": {"interlink": {"command": command, "args": args}}}, indent=2
        )
    if kind == "claude-code-cli":
        return " ".join(["claude", "mcp", "add", "interlink", "--", command, *args])
    if kind == "codex":
        quoted = ", ".join(json.dumps(a) for a in args)
        return f"[mcp_servers.interlink]\ncommand = {json.dumps(command)}\nargs = [{quoted}]\nstartup_timeout_sec = 20\ntool_timeout_sec = 120\n"
    raise ValueError(kind)


def cmd_snippet(args: argparse.Namespace) -> int:
    print(snippet(args.client, args.config))
    return 0


def cmd_handshake(args: argparse.Namespace) -> int:
    from interlink.client import handshake

    try:
        result = asyncio.run(handshake(args.config, args.state_root))
    except Exception as exc:
        print(f"handshake failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.json:
        _print_json(result)
    else:
        print(
            f"ok: {result['server']} {result['version']} protocol {result['protocol']}, {len(result['tools'])} tools: {', '.join(result['tools'])}"
        )
    return 0


# -- parser ------------------------------------------------------------------------------


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="interlink",
        description="Drive any coding-agent harness from any other, over MCP.",
    )
    root.add_argument("--version", action="version", version=f"interlink {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="path to interlink.toml")
    common.add_argument("--state-root", help="where workspaces and the ledger live")
    sub = root.add_subparsers(dest="command", required=True, metavar="COMMAND")

    serve_p = sub.add_parser("serve", parents=[common], help="run the stdio MCP server")
    serve_p.add_argument(
        "--peer-tools",
        action="store_true",
        help="also expose interlink_peer_* tools for sending tasks to paired friends",
    )
    serve_p.set_defaults(func=cmd_serve)

    run = sub.add_parser(
        "run", parents=[common], help="one prompt, one throwaway instance, streamed"
    )
    run.add_argument("harness")
    run.add_argument("prompt", help="prompt text, or - to read stdin")
    run.add_argument("--project", help="directory to copy into the workspace")
    run.add_argument(
        "--file", action="append", metavar="REL=LOCAL", help="seed one file (repeatable)"
    )
    run.add_argument("--timeout", type=float, help="seconds before the run is killed")
    run.add_argument("--keep", action="store_true", help="keep the workspace afterwards")
    run.add_argument(
        "--evidence", action="store_true", help="export an evidence bundle (implies --keep)"
    )
    run.add_argument(
        "--json", action="store_true", help="print raw normalized events as JSON lines"
    )
    run.add_argument("-q", "--quiet", action="store_true", help="print only the final answer")
    run.set_defaults(func=cmd_run)

    doctor = sub.add_parser("doctor", parents=[common], help="check the install and each harness")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    harnesses = sub.add_parser("harnesses", parents=[common], help="list configured harnesses")
    harnesses.add_argument("--json", action="store_true")
    harnesses.add_argument("--no-check", action="store_true")
    harnesses.set_defaults(func=cmd_harnesses)

    ls = sub.add_parser("ls", parents=[common], help="list instances on disk")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=cmd_ls)

    cleanup = sub.add_parser("cleanup", parents=[common], help="delete stopped/orphaned workspaces")
    cleanup.add_argument("--older-than-hours", type=float, default=0)
    cleanup.set_defaults(func=cmd_cleanup)

    init = sub.add_parser("init", help="write a starter interlink.toml")
    init.add_argument("path", nargs="?", default="interlink.toml")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    snip = sub.add_parser("snippet", help="print MCP client config for Claude Code or Codex")
    snip.add_argument("client", choices=["claude-code", "claude-code-cli", "codex"])
    snip.add_argument("--config", help="bake a config path into the snippet")
    snip.set_defaults(func=cmd_snippet)

    shake = sub.add_parser("handshake", parents=[common], help="start a server and talk MCP to it")
    shake.add_argument("--json", action="store_true")
    shake.set_defaults(func=cmd_handshake)

    from interlink.peer.cli import register

    register(sub, common)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        print(f"interlink: config error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        from interlink.peer.cli import ERRORS
        from interlink.peer.client import PeerCallError

        if isinstance(exc, (*ERRORS, PeerCallError)):
            print(f"interlink: {exc}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    raise SystemExit(main())
