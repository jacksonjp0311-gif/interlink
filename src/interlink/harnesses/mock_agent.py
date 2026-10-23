"""A tiny scripted "agent" used for demos, tests and adapter development.

Reads a prompt and interprets each line as a command, emitting Interlink JSONL events.
Lines that are not commands are simply echoed back. Commands::

    say <text>              emit a text event
    write <path> <text>     write a file (relative to cwd) - shows up in the diff
    read <path>             emit a file's content
    delete <path>           delete a file
    ls                      list files in cwd
    sleep <seconds>         sleep (for timeout / cancel tests)
    env <NAME>              report whether NAME is set (never its value)
    printenv <NAME>         print NAME's value (for redaction tests)
    whereami                report cwd, HOME and TMP
    spawn <seconds>         start a grandchild that sleeps; writes grandchild.pid
    stderr <text>           write a line to stderr
    exit <code>             stop with that exit code

The agent remembers a session id and turn counter under $HOME/.mock-agent/, which
makes HOME isolation observable from tests.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path


def emit(kind: str, **fields: object) -> None:
    sys.stdout.write(json.dumps({"type": kind, **fields}) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="interlink-mock-agent")
    parser.add_argument("--prompt-file")
    parser.add_argument("--resume")
    args = parser.parse_args(argv)
    prompt = (
        Path(args.prompt_file).read_text(encoding="utf-8") if args.prompt_file else sys.stdin.read()
    )
    state_dir = Path(os.environ.get("HOME", ".")) / ".mock-agent"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "session.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    if args.resume and state.get("session_id") != args.resume:
        emit("error", message="unknown session", session_id=args.resume)
        return 3
    session = state.get("session_id") or str(uuid.uuid4())
    turn = int(state.get("turn", 0)) + 1
    state_file.write_bytes(json.dumps({"session_id": session, "turn": turn}).encode("utf-8"))
    emit("status", event="init", session_id=session, turn=turn, agent="mock")

    code = 0
    for raw in prompt.splitlines():
        line = raw.strip()
        if not line:
            continue
        command, _, rest = line.partition(" ")
        if command == "say":
            emit("text", text=rest)
        elif command == "write":
            path, _, content = rest.partition(" ")
            emit("tool_use", tool="write_file", input={"path": path})
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((content + "\n").encode("utf-8"))
            emit("tool_result", tool="write_file", ok=True, bytes=len(content) + 1)
        elif command == "read":
            emit("tool_use", tool="read_file", input={"path": rest})
            try:
                emit("tool_result", tool="read_file", ok=True, text=Path(rest).read_text())
            except OSError as exc:
                emit("tool_result", tool="read_file", ok=False, error=str(exc))
        elif command == "delete":
            Path(rest).unlink(missing_ok=True)
            emit("tool_result", tool="delete_file", ok=True, path=rest)
        elif command == "ls":
            emit("text", text=" ".join(sorted(p.name for p in Path().iterdir())))
        elif command == "sleep":
            time.sleep(float(rest))
            emit("text", text=f"slept {rest}s")
        elif command == "env":
            emit("text", text=f"{rest}={'set' if rest in os.environ else 'unset'}")
        elif command == "printenv":
            emit("text", text=f"{rest}={os.environ.get(rest, '')}")
        elif command == "whereami":
            emit(
                "text",
                text=json.dumps(
                    {
                        "cwd": str(Path.cwd()),
                        "home": os.environ.get("HOME"),
                        "tmp": os.environ.get("TMPDIR") or os.environ.get("TEMP"),
                    }
                ),
            )
        elif command == "spawn":
            child = subprocess.Popen(
                [sys.executable, "-c", f"import time; time.sleep({float(rest)})"]
            )
            Path("grandchild.pid").write_text(str(child.pid))
            emit("text", text=f"spawned {child.pid}")
        elif command == "stderr":
            sys.stderr.write(rest + "\n")
            sys.stderr.flush()
        elif command == "exit":
            code = int(rest or 0)
            break
        else:
            emit("text", text=f"mock heard: {line}")
    emit("result", text=f"done turn {turn}", exit_code=code, session_id=session)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
