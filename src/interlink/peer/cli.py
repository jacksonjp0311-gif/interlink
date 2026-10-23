"""``interlink peer ...`` and ``interlink share``: pairing, policy, serving and sending."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from interlink.config import load
from interlink.peer.crypto import CryptoError, Identity, decode_invite
from interlink.peer.protocol import ProtocolError
from interlink.peer.store import (
    AuditLog,
    PeerBook,
    PeerError,
    Policy,
    check_separation,
    peer_home,
    peer_state,
)
from interlink.security import SecurityError, confine

DEFAULT_PORT = 7464


def _paths(args: argparse.Namespace) -> tuple[Path, Path]:
    home = peer_home()
    if getattr(args, "state_root", None):
        state = peer_state(Path(args.state_root).expanduser().resolve())
    else:
        state = peer_state(load(getattr(args, "config", None)).state_root)
    check_separation(home, state)
    return home, state


def _identity(home: Path) -> Identity:
    return Identity.load_or_create(home)


def _out(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _when(ts: float | None) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"


# -- identity & contacts ---------------------------------------------------------------
def cmd_id(args: argparse.Namespace) -> int:
    """`interlink peer id`: show (and on first use create) your identity."""
    home, _ = _paths(args)
    me = _identity(home)
    if args.json:
        _out({"fingerprint": me.fingerprint, "invite": me.invite, "key_dir": str(home)})
        return 0
    print(f"Your fingerprint: {me.fingerprint}")
    print(f"Your invite code: {me.invite}")
    print("\nSend the invite code to your friend; compare fingerprints over a call or chat.")
    print(f"(Private key: {home / 'identity.key'} - never share this file.)")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """`interlink peer add`: pair with a friend from their invite code."""
    home, _ = _paths(args)
    me = _identity(home)
    public_raw = decode_invite(args.code)
    policy = Policy(
        harnesses=_split(args.allow),
        approval="auto" if args.auto_approve else "prompt",
    )
    if args.ca:
        args.ca = str(Path(args.ca).expanduser().resolve())
    record = PeerBook(home).add(
        args.name,
        public_raw,
        url=args.url,
        tls_ca=args.ca,
        policy=policy,
        own_fingerprint=me.fingerprint,
    )
    print(f"Added {record.name}: fingerprint {record.fingerprint}")
    print("Confirm this fingerprint with them before relying on it.")
    if not record.policy.harnesses:
        print(
            "They can't run anything on this machine (fine if you only send tasks to them).\n"
            f"To let them: interlink peer allow {record.name} <harness>"
        )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """`interlink peer list`."""
    home, _ = _paths(args)
    peers = PeerBook(home).all()
    if args.json:
        _out([p.model_dump() for p in peers])
        return 0
    if not peers:
        print("No peers yet. Start with: interlink peer id")
        return 0
    print(f"{'NAME':<16} {'FINGERPRINT':<30} {'STATUS':<8} {'APPROVAL':<8} HARNESSES")
    for p in peers:
        status = "revoked" if p.revoked else "active"
        print(
            f"{p.name:<16} {p.fingerprint:<30} {status:<8} {p.policy.approval:<8} {','.join(p.policy.harnesses) or '-'}"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """`interlink peer show`."""
    home, _ = _paths(args)
    _out(PeerBook(home).get(args.name).model_dump())
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    """`interlink peer allow`: set the harness allow-list."""
    home, _ = _paths(args)
    harnesses = [] if args.none else sorted(set(args.harnesses))
    record = PeerBook(home).update(args.name, policy={"harnesses": harnesses})
    print(f"{record.name} may run: {', '.join(record.policy.harnesses) or 'nothing'}")
    return 0


POLICY_FLAGS = {
    "approval": "approval",
    "max_concurrent": "max_concurrent",
    "max_tasks_per_hour": "max_tasks_per_hour",
    "max_timeout": "max_timeout_s",
    "max_prompt_chars": "max_prompt_chars",
    "max_files": "max_files",
    "max_file_bytes": "max_file_bytes",
    "max_result_bytes": "max_result_bytes",
}


def cmd_policy(args: argparse.Namespace) -> int:
    """`interlink peer policy`: view or change limits."""
    home, _ = _paths(args)
    book = PeerBook(home)
    changes = {
        field: getattr(args, flag)
        for flag, field in POLICY_FLAGS.items()
        if getattr(args, flag) is not None
    }
    record = book.update(args.name, policy=changes) if changes else book.get(args.name)
    _out(record.policy.model_dump())
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    """`interlink peer revoke`."""
    home, _ = _paths(args)
    record = PeerBook(home).revoke(args.name)
    print(f"Revoked {record.name}. A running `interlink share` refuses them from now on.")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    """`interlink peer remove`."""
    home, _ = _paths(args)
    PeerBook(home).remove(args.name)
    print(f"Removed {args.name}.")
    return 0


# -- hosting ------------------------------------------------------------------------------
def cmd_serve(args: argparse.Namespace) -> int:
    """`interlink share` / `interlink peer serve`: run the peer host."""
    from interlink.peer.host import PeerHost, serve

    home, state = _paths(args)
    me = _identity(home)
    config = load(args.config)
    book = PeerBook(home)

    def notify(kind: str, record: dict[str, Any]) -> None:
        if kind == "pending":
            print(
                f"\n[approval needed] {record['peer']} wants to run {record['harness']!r} "
                f"(task {record['task_id']})\n  prompt: {record['prompt_preview']!r}\n"
                f"  files: {', '.join(record['files']) or '-'}   timeout: {record['timeout_s']:g}s\n"
                f"  approve: interlink peer approve {record['task_id']}\n"
                f"  deny:    interlink peer deny {record['task_id']}",
                flush=True,
            )
        else:
            print(f"[{record['state']}] task {record['task_id']} from {record['peer']}", flush=True)

    host = PeerHost(
        me,
        book,
        config,
        state,
        max_concurrent=args.max_concurrent,
        approval_timeout_s=args.approval_timeout,
        on_event=notify,
    )
    try:
        server = serve(host, args.bind, args.port, tls_cert=args.tls_cert, tls_key=args.tls_key)
    except (PeerError, OSError):
        host.shutdown()
        raise
    scheme = "https" if args.tls_cert else "http"
    bound = server.server_address
    print(f"Interlink is sharing on {scheme}://{args.bind}:{bound[1]}  (Ctrl+C to stop)")
    print(f"Host fingerprint: {me.fingerprint}")
    active = [p for p in book.all() if not p.revoked and p.policy.harnesses]
    print(f"Peers who can run something: {', '.join(p.name for p in active) or 'none yet'}")
    thread = threading.Thread(target=server.serve_forever, name="peer-http", daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        server.shutdown()
        server.server_close()
        host.shutdown()
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    """`interlink peer pending`."""
    from interlink.peer.host import list_pending

    _, state = _paths(args)
    items = list_pending(state)
    if args.json:
        _out(items)
        return 0
    if not items:
        print("Nothing waiting for approval.")
    for item in items:
        print(
            f"{item['task_id']}  {item['peer']:<12} {item['harness']:<12} {item['prompt_preview'][:60]!r}"
        )
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    """`interlink peer approve` / `deny`."""
    from interlink.peer.host import list_pending, write_decision

    _, state = _paths(args)
    if not any(item["task_id"] == args.task_id for item in list_pending(state)):
        raise PeerError(f"no pending task {args.task_id} (see `interlink peer pending`)")
    write_decision(state, args.task_id, args.approve)
    print(
        f"{'Approved' if args.approve else 'Denied'} {args.task_id}; the running host applies it within a second."
    )
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """`interlink peer audit`: print or verify an audit log."""
    _, state = _paths(args)
    log = AuditLog(state / ("client-audit.jsonl" if args.client else "audit.jsonl"))
    if args.verify:
        report = log.verify()
        _out(report)
        return 0 if report["valid"] else 1
    for entry in log.entries()[-args.tail :]:
        extra = {k: v for k, v in entry.items() if k not in ("seq", "at", "event", "prev", "hash")}
        print(
            f"{entry['seq']:>5} {_when(entry['at'])} {entry['event']:<18} {json.dumps(extra, default=str)}"
        )
    return 0


# -- sending ------------------------------------------------------------------------------
def _client(args: argparse.Namespace) -> Any:
    from interlink.peer.client import PeerClient

    home, state = _paths(args)
    return PeerClient(_identity(home), PeerBook(home).get(args.name), state, timeout_s=30)


def _save_files(statement: dict[str, Any], out_dir: str) -> list[str]:
    from interlink.peer.host import safe_relative_path

    root = Path(out_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    written = []
    for item in statement.get("files", []):
        if item.get("text") is None:
            continue
        rel = str(item.get("path", ""))
        try:
            if not safe_relative_path(rel):
                raise SecurityError("unsafe path")
            target = confine(rel, root)
        except SecurityError:
            print(f"  skipped unsafe path from host: {rel[:80]!r}", file=sys.stderr)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(item["text"].encode("utf-8"))  # exactly the bytes that were hashed
        written.append(rel)
    return written


def _show_result(result: dict[str, Any], args: argparse.Namespace) -> int:
    statement, report = result["statement"], result["verification"]
    if args.json:
        _out(result)
    else:
        print(f"state: {statement['state']}   exit: {statement.get('exit_code')}")
        print(
            f"verified: signature OK, chain OK ({report['chain_entries']} entries), evidence {str(report['evidence_sha256'])[:16]}..."
        )
        if statement.get("reason"):
            print(f"reason: {statement['reason']}")
        if statement.get("final_text"):
            print("\n" + statement["final_text"].rstrip())
        for item in statement.get("files", []):
            note = " (content omitted: over size budget)" if item.get("text") is None else ""
            print(f"  {item['status']:<9} {item['path']}  {item['size']} B{note}")
    if args.out:
        written = _save_files(statement, args.out)
        print(f"wrote {len(written)} file(s) to {args.out}", file=sys.stderr)
    return {"complete": 0, "failed": 1, "timed_out": 124, "cancelled": 130}.get(
        statement["state"], 3
    )


def cmd_send(args: argparse.Namespace) -> int:
    """`interlink peer send`: submit a task and, by default, wait for the verified result."""
    client = _client(args)
    prompt = sys.stdin.read() if args.prompt == "-" else args.prompt
    files = {}
    for spec in args.file or []:
        rel, _, local = spec.partition("=")
        files[rel] = Path(local or rel).read_bytes().decode("utf-8")
    status = client.submit(args.harness, prompt, files, timeout_s=args.timeout)
    print(f"sent task {status['task_id']} ({status['state']})", file=sys.stderr)
    if args.no_wait:
        return 0
    if status["state"] == "pending_approval":
        print("waiting for your friend to approve...", file=sys.stderr)
    return _show_result(client.wait(status["task_id"], timeout_s=args.wait), args)


def cmd_ping(args: argparse.Namespace) -> int:
    """Check a friend is reachable and see what they let you run."""
    info = _client(args).hello()
    if args.json:
        _out(info)
        return 0
    print(f"{args.name} is up (Interlink {info['version']}, key verified {info['host']})")
    print(f"you may run: {', '.join(info['harnesses']) or 'nothing yet'}")
    print(f"approval:    {info['approval']}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """`interlink peer status`."""
    _out(_client(args).status(args.task_id))
    return 0


def cmd_result(args: argparse.Namespace) -> int:
    """`interlink peer result`: fetch and verify a result."""
    return _show_result(_client(args).result(args.task_id), args)


def cmd_cancel(args: argparse.Namespace) -> int:
    """`interlink peer cancel`."""
    _out(_client(args).cancel(args.task_id))
    return 0


def cmd_cert(args: argparse.Namespace) -> int:
    """Self-signed TLS certificate for `interlink share --bind <lan-ip>`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    home, _ = _paths(args)
    out = Path(args.out).expanduser().resolve() if args.out else home / "tls"
    out.mkdir(parents=True, exist_ok=True)
    names: list[x509.GeneralName] = []
    for host in args.host:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.host[0])])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = out / "share.key", out / "share.crt"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"certificate: {cert_path}  (give this file to your friend: --ca)")
    print(f"private key: {key_path}  (keep it)")
    print(
        f"serve with:  interlink share --bind {args.host[0]} --tls-cert {cert_path} --tls-key {key_path}"
    )
    return 0


def _split(value: str | None) -> list[str]:
    return sorted({part.strip() for part in (value or "").split(",") if part.strip()})


# -- parser -------------------------------------------------------------------------------
def _serve_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bind", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    p.add_argument("--tls-cert", help="certificate (required for any non-loopback --bind)")
    p.add_argument("--tls-key", help="private key for --tls-cert")
    p.add_argument("--max-concurrent", type=int, default=2, help="tasks running at once, all peers")
    p.add_argument(
        "--approval-timeout",
        type=float,
        default=600,
        help="seconds before an unapproved task expires",
    )
    p.set_defaults(func=cmd_serve)


def register(sub: Any, common: argparse.ArgumentParser) -> None:
    """Add the ``share`` and ``peer`` sub-commands to the main parser."""
    share = sub.add_parser(
        "share", parents=[common], help="let paired friends send you tasks (same as `peer serve`)"
    )
    _serve_args(share)

    peer = sub.add_parser("peer", help="connect with a friend: pair, set policy, send tasks")
    psub = peer.add_subparsers(dest="peer_command", required=True, metavar="ACTION")

    p = psub.add_parser("id", parents=[common], help="show your fingerprint and invite code")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_id)

    p = psub.add_parser("add", parents=[common], help="pair with a friend from their invite code")
    p.add_argument("name", help="a short name for them (a-z, 0-9, - or _)")
    p.add_argument("code", help="their invite code (IL1-...)")
    p.add_argument("--url", help="where their `interlink share` listens, if you'll send to them")
    p.add_argument("--ca", help="their TLS certificate file (for a self-signed https url)")
    p.add_argument("--allow", help="comma-separated harnesses they may run on YOUR machine")
    p.add_argument("--auto-approve", action="store_true", help="run their tasks without asking")
    p.set_defaults(func=cmd_add)

    p = psub.add_parser("list", parents=[common], help="list paired peers")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = psub.add_parser("show", parents=[common], help="show one peer and its policy")
    p.add_argument("name")
    p.set_defaults(func=cmd_show)

    p = psub.add_parser("allow", parents=[common], help="set which harnesses a peer may run here")
    p.add_argument("name")
    p.add_argument("harnesses", nargs="*")
    p.add_argument("--none", action="store_true", help="allow nothing")
    p.set_defaults(func=cmd_allow)

    p = psub.add_parser("policy", parents=[common], help="view or change a peer's limits")
    p.add_argument("name")
    p.add_argument(
        "--approval", choices=["prompt", "auto"], help="ask first, or run without asking"
    )
    p.add_argument("--max-concurrent", type=int, help="their tasks running at once")
    p.add_argument("--max-tasks-per-hour", type=int, help="new tasks per rolling hour")
    p.add_argument("--max-timeout", type=float, help="seconds")
    p.add_argument("--max-prompt-chars", type=int, help="longest prompt accepted")
    p.add_argument("--max-files", type=int, help="files per task, each way")
    p.add_argument("--max-file-bytes", type=int, help="largest single file, each way")
    p.add_argument("--max-result-bytes", type=int, help="total size of returned files")
    p.set_defaults(func=cmd_policy)

    for name, func, text in (
        ("revoke", cmd_revoke, "block a peer immediately (keeps the record)"),
        ("remove", cmd_remove, "forget a peer entirely"),
    ):
        p = psub.add_parser(name, parents=[common], help=text)
        p.add_argument("name")
        p.set_defaults(func=func)

    _serve_args(psub.add_parser("serve", parents=[common], help="same as `interlink share`"))

    p = psub.add_parser("pending", parents=[common], help="tasks waiting for your approval")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_pending)
    for name, approve in (("approve", True), ("deny", False)):
        p = psub.add_parser(name, parents=[common], help=f"{name} a pending task")
        p.add_argument("task_id")
        p.set_defaults(func=cmd_decide, approve=approve)

    p = psub.add_parser("send", parents=[common], help="run a task on a friend's machine")
    p.add_argument("name", help="the peer to send to")
    p.add_argument("harness", help="a harness they allow you (see `interlink peer ping NAME`)")
    p.add_argument("prompt", help="prompt text, or - to read stdin")
    p.add_argument(
        "--file", action="append", metavar="REL=LOCAL", help="send one text file (repeatable)"
    )
    p.add_argument("--timeout", type=float, help="seconds (capped by their policy)")
    p.add_argument("--wait", type=float, default=900, help="how long to wait for the result")
    p.add_argument("--no-wait", action="store_true", help="return right after submitting")
    p.add_argument("--out", help="write returned files into this directory")
    p.add_argument("--json", action="store_true", help="print the verified statement as JSON")
    p.set_defaults(func=cmd_send)

    p = psub.add_parser("ping", parents=[common], help="check a peer is up and what you may run")
    p.add_argument("name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ping)

    for name, func, text in (
        ("status", cmd_status, "check a task you sent"),
        ("result", cmd_result, "fetch and verify a finished task's result"),
        ("cancel", cmd_cancel, "cancel a task you sent"),
    ):
        p = psub.add_parser(name, parents=[common], help=text)
        p.add_argument("name")
        p.add_argument("task_id")
        if name == "result":
            p.add_argument("--out", help="write returned files into this directory")
            p.add_argument("--json", action="store_true")
        p.set_defaults(func=func)

    p = psub.add_parser("audit", parents=[common], help="show or verify the hash-chained audit log")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--client", action="store_true", help="the log of tasks you sent")
    p.add_argument("--tail", type=int, default=50)
    p.set_defaults(func=cmd_audit)

    p = psub.add_parser(
        "cert", parents=[common], help="make a self-signed TLS cert for sharing on a LAN"
    )
    p.add_argument("--host", action="append", required=True, help="IP or DNS name (repeatable)")
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--out", help="directory (default: <peer home>/tls)")
    p.set_defaults(func=cmd_cert)


ERRORS = (PeerError, CryptoError, ProtocolError, ValidationError)
