#!/usr/bin/env python3
"""Module 6 demo: password hashing, HMAC, and signatures. Local only."""

from __future__ import annotations

import hashlib
import hmac
import secrets

def demo_password() -> None:
    password = "alice-lab-password"
    salt = secrets.token_bytes(16)
    # Teaching stand-in. Production: use argon2-cffi or bcrypt with parameters
    # chosen for your threat model and hardware.
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    print("pbkdf2 digest:", dk.hex())
    print("salt:", salt.hex())
    print("do not store raw passwords, unsalted sha256, or reversible encryption of passwords")


def demo_mac_and_signature() -> None:
    key = secrets.token_bytes(32)
    message = b"alert_id=DET-003&status=contained"
    tag = hmac.new(key, message, hashlib.sha256).hexdigest()
    print("hmac-sha256:", tag)

    try:
        from nacl.encoding import HexEncoder
        from nacl.signing import SigningKey
    except ImportError as exc:
        raise ImportError("pip install pynacl  # optional for the signature demo") from exc

    signing_key = SigningKey.generate()
    signed = signing_key.sign(message, encoder=HexEncoder)
    verify_key = signing_key.verify_key
    verify_key.verify(signed, encoder=HexEncoder)
    print("ed25519 signature ok")
    print("mac: shared key, both parties equal")
    print("signature: only holder of private key can sign; anyone with public key can verify")


if __name__ == "__main__":
    print("random 32 bytes:", secrets.token_hex(32))
    demo_password()
    try:
        demo_mac_and_signature()
    except ImportError:
        print("pip install pynacl  # optional for the signature demo")
