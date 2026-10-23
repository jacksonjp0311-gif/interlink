"""A stand-in for ``hermes chat --oneshot --format stream-json``.

It validates the flags Interlink passes, then replays a small stream-json session.
Prompt keywords steer it: ``FAIL`` exits 1, ``SLOW`` sleeps, ``INTERRUPT`` exits 130.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path


def out(kind: str, **fields: object) -> None:
    print(json.dumps({"type": kind, **fields}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verb")
    parser.add_argument("--oneshot", action="store_true")
    parser.add_argument("--query-file", required=True)
    parser.add_argument("--format", required=True, choices=["stream-json"])
    parser.add_argument("--source")
    parser.add_argument("--ignore-user-config", action="store_true")
    parser.add_argument("--ignore-rules", action="store_true")
    parser.add_argument("--safe-mode", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--provider")
    parser.add_argument("--resume")
    args = parser.parse_args()
    assert args.verb == "chat" and args.oneshot
    home = Path(os.environ["HERMES_HOME"])
    assert home.is_dir(), "HERMES_HOME must exist before hermes starts"
    prompt = Path(args.query_file).read_text(encoding="utf-8")
    sessions = home / "sessions.json"
    known = json.loads(sessions.read_text()) if sessions.exists() else []
    if args.resume and args.resume not in known:
        out("error", message="no such session")
        return 1
    session = args.resume or str(uuid.uuid4())
    sessions.write_text(json.dumps(sorted({*known, session})))
    out(
        "system",
        subtype="init",
        session_id=session,
        model=args.model or "fake/model",
        flags={"ignore_user_config": args.ignore_user_config, "resumed": bool(args.resume)},
    )
    out("tool_use", id="t1", name="terminal", input={"command": "ls"})
    out("tool_result", tool_use_id="t1", output="README.md", is_error=False)
    if "SLOW" in prompt:
        time.sleep(30)
    out("text", text=f"hermes says: {prompt.strip()}")
    if "INTERRUPT" in prompt:
        out("result", session_id=session, exit_code=130, text="interrupted")
        return 130
    code = 1 if "FAIL" in prompt else 0
    out(
        "result",
        session_id=session,
        exit_code=code,
        text="all done",
        duration_ms=12,
        tokens={"input": 10, "output": 5},
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
