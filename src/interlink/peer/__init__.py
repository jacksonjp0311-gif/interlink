"""Interlink peers: hand a sandboxed task to someone else's Interlink and get signed
evidence back. Off unless you run ``interlink share``.

* ``crypto``   - Ed25519 identities, fingerprints, invite codes (via ``cryptography``).
* ``store``    - the contact book, per-peer policy, nonce cache, hash-chained logs.
* ``protocol`` - signed requests/responses/results (``interlink-peer/1``).
* ``host``     - the HTTP(S) server that runs inbound tasks in the normal sandbox.
* ``client``   - submit tasks, poll, verify results.
"""

PROTOCOL = "interlink-peer/1"
