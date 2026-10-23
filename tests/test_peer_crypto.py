"""Identities, invite codes and signatures (all primitives come from `cryptography`)."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from interlink.peer.crypto import (
    KEY_FILE,
    CryptoError,
    Identity,
    decode_invite,
    encode_invite,
    fingerprint,
    verify,
)

POSIX = os.name != "nt"


def test_invite_round_trip_and_typo_detection() -> None:
    me = Identity.generate()
    code = me.invite
    assert code.startswith("IL1-")
    assert decode_invite(code) == me.public_raw
    assert decode_invite(code.lower().replace("-", " ")) == me.public_raw  # forgiving format
    body = list(code)
    index = 6
    body[index] = "A" if body[index] != "A" else "B"
    with pytest.raises(CryptoError, match=r"checksum|garbled"):
        decode_invite("".join(body))
    for bad in ("", "hello", "IL1-", "IL2-" + code[4:], "IL1-" + "A" * 200):
        with pytest.raises(CryptoError):
            decode_invite(bad)


def test_fingerprint_is_short_and_stable() -> None:
    me = Identity.generate()
    fp = fingerprint(me.public_raw)
    assert re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){5}", fp)
    assert fp == me.fingerprint
    assert fp != Identity.generate().fingerprint


def test_signatures_are_domain_separated() -> None:
    me = Identity.generate()
    signature = me.sign("request", b"hello")
    assert verify(me.public_raw, "request", b"hello", signature)
    assert not verify(me.public_raw, "result", b"hello", signature)
    assert not verify(me.public_raw, "request", b"hellO", signature)
    assert not verify(Identity.generate().public_raw, "request", b"hello", signature)
    assert not verify(me.public_raw, "request", b"hello", b"\x00" * 64)
    assert not verify(b"short", "request", b"hello", signature)


def test_key_file_is_private_and_reused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    first = Identity.load_or_create(home)
    again = Identity.load_or_create(home)
    assert first.fingerprint == again.fingerprint
    assert first.fingerprint in repr(first) and "PRIVATE" not in repr(first)
    if POSIX:
        assert (home / KEY_FILE).stat().st_mode & 0o777 == 0o600
        assert home.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_world_readable_key_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    Identity.load_or_create(home)
    (home / KEY_FILE).chmod(0o644)
    with pytest.raises(CryptoError, match="readable by other users"):
        Identity.load_or_create(home)


def test_encode_invite_matches_identity() -> None:
    me = Identity.generate()
    assert encode_invite(me.public_raw) == me.invite
