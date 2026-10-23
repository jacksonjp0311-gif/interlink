"""Build MANIFEST.sha256 for the package and sign it with a fresh, single-use Ed25519 key.

The private key only ever lives in memory and is discarded; the public key is written to
evidence-signing-key.pub and its hex is quoted in the package README / main README.
"""

import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = Path(sys.argv[1]).resolve()
key = Ed25519PrivateKey.generate()
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
(root / "evidence-signing-key.pub").write_text(
    pub.hex() + "  ed25519 interlink-evidence-package/1\n"
)
skip = {"MANIFEST.sha256", "MANIFEST.sha256.sig"}
files = sorted(
    p
    for p in root.rglob("*")
    if p.is_file() and "__pycache__" not in p.parts and p.relative_to(root).as_posix() not in skip
)
lines = [
    f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}" for p in files
]
manifest = ("\n".join(lines) + "\n").encode()
(root / "MANIFEST.sha256").write_bytes(manifest)
(root / "MANIFEST.sha256.sig").write_text(
    key.sign(b"interlink-evidence-package/1\n" + manifest).hex() + "\n"
)
del key
print(
    len(files),
    "files; pubkey",
    pub.hex(),
    "; manifest sha256",
    hashlib.sha256(manifest).hexdigest(),
)
