# Module 6 — Cryptography for engineers

## Why it matters to a software engineer

You will not invent a cipher. You will ship TLS, JWT signatures, password
storage, and signed artifacts. Most “crypto failures” in OWASP
[A04:2025](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) are
**using the wrong primitive, rolling your own, or encrypting instead of
hashing passwords** — not an academic break of AES.

## Visual overview

!!! note "Intuition"
    Skip the math and ask one question per primitive: *"what does possessing
    the key let you prove or do that someone without it can't?"* A hash needs
    no key and proves nothing about origin — it only proves content didn't
    change *if you already trust the hash you're comparing against*. That
    caveat is the whole reason signatures exist.

| Primitive | Visual model | Reversible? | Solves |
| --- | --- | --- | --- |
| Hash | message → fingerprint | No | change detection when expected hash is trusted |
| Encryption | plaintext + key ⇄ ciphertext | Yes, with key | confidentiality |
| MAC | message + shared key → tag | Verification uses same secret | integrity/authenticity among key holders |
| Signature | message + private key → signature; public key verifies | Signature is not decryption | origin/integrity relative to key custody |

```text
Symmetric:   Alice [same secret K] <---- encrypted bulk data ----> Bob [K]
Asymmetric:  public key may be shared; private key stays with its owner
Hybrid:      asymmetric exchange authenticates/derives a symmetric session key
```

!!! tip "Hint"
    TLS is hybrid for a practical reason, not a theoretical one: asymmetric
    crypto is slow and expensive per byte, symmetric crypto is fast. So every
    HTTPS connection you make does a small amount of expensive asymmetric
    work once, just to safely agree on a symmetric key, then switches to
    cheap symmetric encryption for the actual data. That's what the handshake
    below is doing.

```mermaid
sequenceDiagram
  Client->>Server: ClientHello + supported algorithms
  Server-->>Client: ServerHello + certificate + key share
  Client->>Client: validate name, dates, chain to trusted root
  Client->>Server: key share + Finished
  Server-->>Client: Finished
  Note over Client,Server: authenticated encrypted session
```

```text
leaf certificate -> signed by intermediate CA -> signed by trusted root
hostname + validity + usage + revocation/validation policy must also pass

registration: password + unique salt -> slow password KDF -> stored verifier
login:        candidate + stored salt -> same KDF -> constant-time compare
```

!!! note "Intuition"
    "Slow" is a feature, not a limitation, for password hashing. A fast hash
    (like the ones used for file integrity) lets an attacker with a stolen
    database try billions of password guesses per second. A deliberately slow
    KDF (bcrypt/scrypt/Argon2) makes each guess expensive, which is the actual
    defense — the algorithm choice *is* the control.

Crypto does not authorize Alice to Bob's note, preserve deleted data, stop
SSRF, make a compromised endpoint trustworthy, or repair poor key custody.

## Learning objectives

- Distinguish hashing, MACs, signatures, symmetric/asymmetric encryption,
  key exchange, certificates, TLS, password hashing, randomness, and key
  management.
- State what cryptography cannot solve (AuthZ, availability, bad identity).
- Store a password and sign a message using standard libraries.

## Key concepts

**Hash.** One-way fingerprint (`SHA-256`). Integrity of a known file, not
authentication (anyone can hash). Not for passwords by itself.

**MAC (HMAC).** Hash with a **shared secret**. Authenticity between parties
who share the key. Both sides are equal: the verifier could have forged the
tag.

**Digital signature.** Asymmetric: private key signs, public key verifies.
Non-repudiation relative to the private key holder (in the engineering
sense: they signed it, or their key leaked).

**Symmetric encryption.** One key encrypts and decrypts (AES-GCM). Use AEAD
(authenticated encryption). Do not use ECB. Do not invent nonces.

**Asymmetric encryption.** Public encrypts, private decrypts (rarely what
you want for bulk data). Usually you encrypt a symmetric data key.

**Key exchange.** Agree a shared secret over an untrusted network (TLS uses
Diffie–Hellman / hybrid KEMs as standards evolve).

**Certificates and TLS.** A certificate binds a public key to an identity,
signed by a CA you trust. TLS uses certificates to authenticate the server
(and sometimes the client), then symmetric keys for the session. TLS does
not mean the API authorized the request.

**Password hashing.** Slow and salted. **Argon2id** and **scrypt** are
memory-hard (RAM costs hurt GPUs). **bcrypt** is CPU-hard with a small
fixed memory (~4 KiB) — still far better than SHA-256, not in the
memory-hard set. Parameters should hurt attackers. `hashlib.sha256(password)`
is what LAB_MODE does — a teaching anti-pattern. A unique **salt** means
each row hashes differently, so one precomputed rainbow table cannot cover
the whole database. `alice-lab-password` is an unusual string and may not
appear in a public table; the lesson is *fast unsalted hashes invite
precomputation and offline guessing*, not “this exact password is listed.”

**Randomness.** Use `secrets` / OS CSPRNG (`getrandom`), not `random`.
Session ids, tokens, keys, CSRF values.

**Key management.** Generation, storage, rotation, destruction, access
control. The algorithm is not the hard part. KMS/HSM hold keys; apps get
short-lived use. Logging key material is an incident.

**What crypto cannot solve.**

- IDOR (Alice’s valid signature on her token).
- SSRF (HTTPS to IMDS is still IMDS).
- Availability (you can encrypt a deleted disk).
- “The operator pasted the key in Slack.”
- Business-logic abuse.

## Architecture connection

```
password --> Argon2id/bcrypt --> store hash
JWT      --> HS256 with server secret  OR  RS256/EdDSA with private key
artifacts--> minisign/cosign signatures
in transit --> TLS 1.2+ (1.3 preferred)
at rest    --> AEAD with KMS-managed data keys
```

HS256 JWT means every service that verifies can also mint. Asymmetric JWT
lets only the issuer mint. That is an identity-architecture choice.

## Hands-on lab — passwords and signatures

Local Python. No network required. Optional `pynacl`.

### Prerequisites

`python3`. Password and HMAC run without extra packages. `pip install pynacl`
is required only for the Ed25519 half (`nacl` is imported inside that
function so the rest of the demo still runs).

### Steps

1. Read `labs/notes-api/app.py` `hash_password` / `verify_password`.
2. Run `python3 labs/crypto/demo.py`.
3. Explain why unsalted SHA-256 invites rainbow tables and fast offline
   guessing. Do **not** build a table. Salt + slowness are the actual
   controls; this specific lab password need not appear in a public list.
4. Inspect a lab JWT **header** (`alg`: HS256). Decode the first segment
   the same way as Module 3 (base64url + padding). Write down what leaks if
   `JWT_SECRET` is in compose env and someone can `docker inspect`: they can
   **mint any token** because HS256 verifiers share the signing secret.
5. Optional: with `LAB_MODE=false` (after reset so hashes match), confirm
   bcrypt hashes in sqlite:

   ```bash
   docker exec lab-notes-api python -c "import sqlite3; c=sqlite3.connect('/data/notes.db'); print(c.execute('select username,password_hash from users').fetchall())"
   ```

   Bcrypt hashes start with `$2`. SHA-256 hex does not.

### Expected observations

Demo prints PBKDF2 (teaching stand-in) and an Ed25519 verify success.
LAB_MODE users table is hex SHA-256; secure mode is bcrypt.

### Security lessons

Encrypting passwords (reversible) is worse than hashing. MACs are not
signatures. TLS is not AuthZ. Key location is part of the threat model.

### Common mistakes

- `md5(password + salt)` “because it’s salted.”
- Implementing AES-CBC with no MAC.
- Disabling certificate verification in httpx/curl “just in the lab” and
  leaving it off.
- Rolling a custom token format.

### Cleanup

None beyond not committing generated keys. Delete any scratch private keys.

## Knowledge check

1. Can HMAC prove which of two sharing parties created a message?
2. Why is bcrypt/argon2 used instead of SHA-256 for passwords?
3. What does `alg=none` on a JWT mean historically?
4. Does HTTPS to `/notes/2` fix IDOR?
5. Why is `random.random()` wrong for reset tokens?

**Answers:** (1) No. (2) Slow/salted; resists offline guessing. (3) Some
libraries accepted unsigned tokens as valid. (4) No. (5) Not a CSPRNG;
predictable tokens.

## Engineering assignment

Write a 20-line Python function `hash_password` / `verify_password` using
`bcrypt` or `argon2-cffi`. Do not implement PBKDF2 in production code if a
maintained library is available. Document rotation: how you would change
cost parameters later.

## Further reading

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) (authenticator assurance)
- [RFC 7519 JWT](https://www.rfc-editor.org/rfc/rfc7519) and [RFC 8725 JWT BCP](https://www.rfc-editor.org/rfc/rfc8725)
- [libsodium / PyNaCl docs](https://pynacl.readthedocs.io/)
