"""The real transport: loopback HTTP, TLS with a self-signed cert, and the client."""

from __future__ import annotations

import http.client
import json
import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from interlink.peer.client import PeerCallError, PeerClient
from interlink.peer.crypto import Identity
from interlink.peer.host import serve
from interlink.peer.store import PeerError, PeerRecord
from peerkit import Live, Pair, make_pair, start


@pytest.fixture
def pair(tmp_path: Path) -> Iterator[Pair]:
    p = make_pair(tmp_path)
    yield p
    p.host.shutdown()


@pytest.fixture
def live(pair: Pair) -> Iterator[Live]:
    yield from start(pair)


def test_client_round_trip_with_files(live: Live, tmp_path: Path) -> None:
    client = live.client()
    hello = client.hello()
    assert hello["host"] == live.pair.bob.fingerprint
    sent = client.submit("mock", "say hi\nwrite answer.md 42", {"q.txt": "question"}, timeout_s=30)
    result = client.wait(sent["task_id"], timeout_s=30, poll_s=0.1)
    assert result["verification"]["verified"] and result["verification"]["bound_to_sent_task"]
    files = {f["path"]: f for f in result["statement"]["files"]}
    assert files["answer.md"]["text"].strip() == "42"
    assert (tmp_path / "alice-state" / "received" / f"{sent['task_id']}.json").is_file()
    assert client.audit.verify()["valid"]


def test_client_rejects_a_host_with_the_wrong_key(live: Live) -> None:
    impostor = live.client(name="impostor", public_raw=Identity.generate().public_raw)
    with pytest.raises(PeerCallError) as info:
        impostor.hello()
    assert info.value.code in ("bad_response_signature",) and not info.value.verified


def test_refusals_are_signed_and_surface_cleanly(live: Live) -> None:
    client = live.client()
    with pytest.raises(PeerCallError) as info:
        client.submit("envdump", "x")
    assert info.value.code == "harness_not_allowed" and info.value.verified
    live.pair.bob_book.revoke("alice")
    with pytest.raises(PeerCallError) as info:
        client.hello()
    assert info.value.code == "revoked"


def test_raw_http_guards(live: Live) -> None:
    port = live.server.server_address[1]

    def send(raw: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(raw)
            return sock.recv(4096)

    assert b" 411 " in send(b"POST /v1/hello HTTP/1.1\r\nHost: x\r\n\r\n")
    assert b" 413 " in send(
        b"POST /v1/tasks HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n"
    )
    assert b" 405 " in send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("POST", "/v1/hello", body=b"{}")
    response = connection.getresponse()
    assert response.status == 401
    assert json.loads(response.read())["error"]["code"] == "unauthenticated"
    assert response.getheader("Server", "").startswith("Interlink")
    assert "Python" not in response.getheader("Server", "")


def test_non_loopback_requires_tls(pair: Pair) -> None:
    with pytest.raises(PeerError, match="without TLS"):
        serve(pair.host, "0.0.0.0", 0)


def test_client_refuses_plain_http_to_remote_hosts(pair: Pair, tmp_path: Path) -> None:
    bob = pair.alice_book.add("bob", pair.bob.public_raw)
    for url in (
        "http://192.168.1.20:7464",
        "http://example.com",
        "ftp://127.0.0.1",
        "nonsense",
        None,
    ):
        peer = PeerRecord.model_validate({**bob.model_dump(), "url": url})
        with pytest.raises(PeerError):
            PeerClient(pair.alice, peer, tmp_path / "s")
    revoked = PeerRecord.model_validate(
        {**bob.model_dump(), "url": "http://127.0.0.1:1", "revoked_at": 1.0}
    )
    with pytest.raises(PeerError, match="revoked"):
        PeerClient(pair.alice, revoked, tmp_path / "s")


@pytest.fixture
def certs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    from interlink.cli import main

    monkeypatch.setenv("INTERLINK_PEER_HOME", str(tmp_path / "cert-home"))
    monkeypatch.setenv("INTERLINK_STATE", str(tmp_path / "cert-state"))
    assert (
        main(
            [
                "peer",
                "cert",
                "--host",
                "localhost",
                "--host",
                "127.0.0.1",
                "--out",
                str(tmp_path / "tls"),
            ]
        )
        == 0
    )
    key = tmp_path / "tls" / "share.key"
    if os.name != "nt":
        assert key.stat().st_mode & 0o777 == 0o600
    return tmp_path / "tls" / "share.crt", key


def test_tls_round_trip_with_self_signed_cert(pair: Pair, certs: tuple[Path, Path]) -> None:
    cert, key = certs
    for live in start(pair, tls_cert=str(cert), tls_key=str(key)):
        client = live.client(tls_ca=str(cert))
        assert live.url.startswith("https://")
        assert client.hello()["host"] == pair.bob.fingerprint
        sent = client.submit("mock", "say hi", timeout_s=30)
        assert client.wait(sent["task_id"], 30, 0.1)["statement"]["state"] == "complete"
        # a client that doesn't trust the cert can't even connect
        record = PeerRecord.model_validate({**client.peer.model_dump(), "tls_ca": None})
        untrusting = PeerClient(pair.alice, record, pair.tmp / "alice-state", timeout_s=5)
        with pytest.raises(PeerCallError) as info:
            untrusting.hello()
        assert info.value.code == "unreachable"
