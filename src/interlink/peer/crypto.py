"""Ed25519 identities, fingerprints and invite codes.

All cryptography comes from the ``cryptography`` package; nothing here is hand-rolled.
Signatures always cover a domain-separation prefix so a signature made for one purpose
(request, response, result) can never be replayed as another.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_FILE = "identity.key"
INVITE_PREFIX = "IL1"
DOMAIN = {
    "request": b"interlink-peer/1 request\n",
    "response": b"interlink-peer/1 response\n",
    "result": b"interlink-peer/1 result\n",
}


class CryptoError(ValueError):
    """A key, signature or invite code is malformed."""

    pass


def b64e(data: bytes) -> str:
    """Unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str, *, max_len: int = 1 << 20) -> bytes:
    """Decode unpadded URL-safe base64, rejecting oversized or invalid input."""
    if not isinstance(text, str) or len(text) > max_len:
        raise CryptoError("bad base64 value")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise CryptoError("bad base64 value") from exc


def fingerprint(public_raw: bytes) -> str:
    """Short, human-comparable id: 24 base32 chars of sha256(pubkey), in groups of 4."""
    digest = base64.b32encode(hashlib.sha256(public_raw).digest()[:15]).decode("ascii")
    return "-".join(digest[i : i + 4] for i in range(0, 24, 4))


def public_key(raw: bytes) -> Ed25519PublicKey:
    """Load a raw 32-byte Ed25519 public key."""
    if len(raw) != 32:
        raise CryptoError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify(public_raw: bytes, purpose: str, message: bytes, signature: bytes) -> bool:
    """Check a domain-separated Ed25519 signature. Never raises on bad input."""
    try:
        public_key(public_raw).verify(signature, DOMAIN[purpose] + message)
    except (InvalidSignature, CryptoError, ValueError):
        return False
    return True


@dataclass(frozen=True)
class Identity:
    """This machine's Ed25519 key pair. The private key never leaves this object."""

    private: Ed25519PrivateKey

    @property
    def public_raw(self) -> bytes:
        """The raw 32-byte public key."""
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def fingerprint(self) -> str:
        """Human-comparable fingerprint of the public key."""
        return fingerprint(self.public_raw)

    @property
    def invite(self) -> str:
        """Invite code to give to a friend."""
        return encode_invite(self.public_raw)

    def sign(self, purpose: str, message: bytes) -> bytes:
        """Sign ``message`` for one ``purpose`` (request, response or result)."""
        return self.private.sign(DOMAIN[purpose] + message)

    def __repr__(self) -> str:  # never let the private key reach a log
        return f"Identity({self.fingerprint})"

    @classmethod
    def generate(cls) -> Identity:
        """A new in-memory identity (tests and tools)."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, key_dir: Path) -> Identity:
        """Load ``identity.key`` from ``key_dir``, creating it (0600) on first use."""
        path = key_dir / KEY_FILE
        if path.is_file():
            return cls.load(path)
        key_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            key_dir.chmod(0o700)
        identity = cls.generate()
        pem = identity.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        return identity

    @classmethod
    def load(cls, path: Path) -> Identity:
        """Load a private key file, refusing one other users can read."""
        if os.name != "nt" and sys.platform != "emscripten":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise CryptoError(
                    f"{path} is readable by other users (mode {oct(mode)}); run: chmod 600 {path}"
                )
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise CryptoError(f"{path} is not an Ed25519 key")
        return cls(key)


def _checksum(raw: bytes) -> bytes:
    return hashlib.sha256(b"interlink-invite" + raw).digest()[:3]


def encode_invite(public_raw: bytes) -> str:
    """``IL1-XXXX-...``: the public key plus a typo-catching checksum, in base32."""
    body = base64.b32encode(public_raw + _checksum(public_raw)).decode("ascii").rstrip("=")
    return INVITE_PREFIX + "-" + "-".join(body[i : i + 5] for i in range(0, len(body), 5))


def decode_invite(code: str) -> bytes:
    """Public key bytes from an ``IL1-`` invite code, checking its checksum."""
    cleaned = "".join(code.split()).upper().replace("-", "")
    if not cleaned.startswith(INVITE_PREFIX) or len(cleaned) > 128:
        raise CryptoError("not an Interlink invite code (they start with IL1-)")
    body = cleaned[len(INVITE_PREFIX) :]
    try:
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
    except ValueError as exc:
        raise CryptoError("invite code is garbled") from exc
    if len(raw) != 35 or _checksum(raw[:32]) != raw[32:]:
        raise CryptoError("invite code checksum failed - check for typos")
    public_key(raw[:32])
    return raw[:32]
