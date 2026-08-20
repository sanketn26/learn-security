# Module 3 — Identity and access management

## Why it matters to a software engineer

Almost every serious web incident is an identity incident: a session stolen,
a token over-scoped, a missing authorization check, a service account shared
by twelve microservices. Authentication answers “who is this?” Authorization
answers “what may they do to *this* object, *now*?” Mixing them up produces
`if (loggedIn) return note`.

## Visual overview

```mermaid
sequenceDiagram
  User->>API: username + password
  API->>IdentityStore: verify slow password hash
  IdentityStore-->>API: identity + attributes
  API-->>User: short-lived signed token
  User->>API: GET /notes/2 + token
  API->>API: authenticate token
  API->>Policy: authorize actor=alice, object=note:2, action=read
  Policy-->>API: deny (owner=bob)
```

!!! note "Intuition"
    Notice the diagram deliberately ends in a **deny**. Authentication proved
    Alice is Alice — that part succeeded. The request still fails, because
    authentication only answers "who are you," never "are you allowed to
    touch *this* object." Treating a valid token as if it were a yes is the
    single most common access-control bug in real APIs (it has its own name:
    BOLA/IDOR, covered in Module 4).

```mermaid
stateDiagram-v2
  [*] --> Issued
  Issued --> Active: signature, issuer, audience, time valid
  Active --> Expired: exp reached
  Active --> Revoked: response / compromise
  Expired --> [*]
  Revoked --> [*]
```

!!! tip "Hint"
    A token's lifecycle has two exits, not one. Teams routinely build the
    `Expired` path (just let `exp` pass) and forget the `Revoked` path
    (actively invalidate a token *before* it would have expired, e.g. on
    logout or after a suspected leak). If your system has no revocation
    story, a stolen long-lived token stays valid until its natural expiry no
    matter what you do.

```mermaid
sequenceDiagram
  participant U as User
  participant C as Client
  participant AS as Authorization server / OIDC provider
  participant API as Resource API
  U->>C: choose sign in
  C->>AS: authorization request + PKCE challenge
  AS->>U: authenticate + consent
  AS-->>C: authorization code
  C->>AS: code + PKCE verifier
  AS-->>C: access token + ID token
  C->>API: access token
```

!!! note "Intuition"
    This is the "log in with..." button, unrolled. The client (your app)
    never sees the user's password — it only ever gets a short-lived
    authorization code, which it then exchanges for a token. PKCE exists
    specifically so that even if the authorization code leaks in transit
    (e.g. via a mobile deep link), the code alone is useless without the
    verifier secret the client generated for itself.

| Authentication | Authorization |
| --- | --- |
| Who/what is calling? | May this identity perform this action on this object now? |
| Password, MFA, certificate, signed token | RBAC, ABAC, ownership, policy |
| Failure: forged/stolen identity | Failure: valid Alice reads Bob's note |

Human identity usually begins with an interactive login and MFA; workload
identity begins with attested runtime context and receives a short-lived,
audience-bound credential. Both need lifecycle, least privilege, audit, and
revocation. A valid token is input to authorization, not proof of permission.

## Learning objectives

- Separate authentication, authorization, sessions, and tokens.
- Explain cookies, bearer tokens, OAuth 2.0 *concepts*, OIDC *concepts*, API
  keys, MFA, RBAC, and ABAC well enough to review a design.
- Identify common implementation failures in the lab JWT flow.
- Describe service-to-service identity better than a shared static key.

## Key concepts

**Authentication (AuthN).** Establishing identity: password, passkey, OIDC
id_token, mTLS certificate, workload identity. In the lab, `/login` returns
a JWT after a dummy password check.

**Authorization (AuthZ).** A decision: allow or deny an action on a resource.
Must happen on the server for every object. UI hiding a button is not AuthZ.

**Session vs token.** A session is server-side state (session id in a cookie).
A token is typically client-held claims (JWT). Both can be stolen. Both need
expiry, revocation strategy, and transport security.

**Cookies.** Automatically sent by browsers for a site. Need `Secure`,
`HttpOnly`, `SameSite` in real browser apps. This lab uses `Authorization:
Bearer` instead (typical of APIs and SPAs).

**JWT (JSON Web Token).** Three segments: header, payload, signature. Signed
(JWS) tokens are *integrity-protected claims*, not automatically confidential.
Anyone who has the token can read claims. `alg=none`, `HS256` with a leaked
secret, missing `exp`, and confusing `aud` are classic failures.

**OAuth 2.0** is a **delegation** framework: an authorization server grants
an access token so a client can call an API as a user or as itself. It is
not “login.” **OpenID Connect** adds an identity layer (id_token) on top of
OAuth. You do not need to implement either in this course; you need to stop
treating a random JWT your app minted as “we use OAuth.”

**API keys.** Bearer secrets, often long-lived, often pasted into frontends
by accident. Prefer scoped, rotatable keys or workload identity.

**Secrets.** Anything that grants access: passwords, tokens, signing keys.
Not “the config file.”

**MFA.** Additional factor. Phishing-resistant MFA (passkeys, hardware)
beats OTP that can be phished. MFA does not fix IDOR.

**RBAC vs ABAC.**

| | RBAC | ABAC |
| --- | --- | --- |
| Decision inputs | Roles (admin, user) | Attributes (owner, tenant, clearance, time) |
| Strength | Simple ops | Fine-grained, policy-as-data |
| Failure | Role explosion; “admin” means everything | Policy complexity; slow reviews |
| Lab | `role=admin` for `/admin/users` | `note.owner == token.sub` |

You usually need **both**: roles for functions, attributes for objects.

**Service-to-service identity.** Shared `API_KEY=...` in six repos is not
identity. Prefer short-lived credentials: cloud workload identity, SPIFFE/
SPIRE, mTLS with rotation, or OIDC from CI. The mock IMDS in this lab exists
because cloud SDKs historically fetched **instance role keys** from a
link-local service — a powerful identity that SSRF can steal.

**Common implementation failures.**

- AuthN without object AuthZ (IDOR / BOLA).
- Missing function AuthZ (`/admin/*` if logged in).
- Tokens without `exp`/`aud`/`iss`, or accepting `alg=none`.
- Session fixation, cookie without `Secure`.
- Storing passwords with SHA-256 or reversible encryption.
- Logging tokens.
- Confused deputy: API fetches a URL the user supplied (SSRF) using the
  **service’s** identity.

## Architecture connection

```
user --password--> /login --JWT--> client
client --Bearer JWT--> /notes/2
                         |
                         +-- must check: token valid AND owner==sub
```

Zero-trust service communication looks the same for machines: each request
carries a verifiable identity; the callee authorizes.

## Hands-on lab — review the authentication flow

**AUTHORIZED LAB USE ONLY.**

### Prerequisites

Lab running with `LAB_MODE=true` (default).

### Steps

1. Login as Alice; decode the JWT payload (it is base64, not encryption):

   ```bash
   TOKEN=$(curl -s http://127.0.0.1:8080/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice-lab-password"}' \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
   python3 - <<PY
   import os, base64, json
   token = os.environ["TOKEN"] if False else """$TOKEN"""
   payload = token.split(".")[1] + "=="
   print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
   PY
   ```

2. Observe missing `exp` in lab mode (weak session).
3. Call `/whoami` and `/admin/users` with Alice’s token. In LAB_MODE the
   admin route succeeds — broken function-level authorization.
4. Login as Bob; confirm Bob cannot be Alice by comparing `sub`.
5. Read `issue_token` and `current_user` in `labs/notes-api/app.py`. List
   three production fixes: `exp`, `aud`/`iss`, bcrypt, owner checks.

Do **not** try to brute-force real passwords or reuse this token outside
localhost.

### Expected observations

Payload contains `sub` and `role`, likely no `exp` in LAB_MODE. Alice can
hit `/admin/users` while LAB_MODE is true. Logs show `login_success` and
possibly `broken_function_authz`.

### Security lessons

A valid token is the start of authorization, not the end. Role in a JWT is
a claim you signed; still check it on sensitive functions, and still check
object owners.

### Common mistakes

- Putting PII in JWT and assuming it is secret.
- Checking roles only in the frontend.
- Using the same signing secret across all environments.
- Infinite-lived service tokens “for convenience.”

### Cleanup

If you copied tokens into a scratch file, delete it. `lab-down` optional.

## Knowledge check

1. User is logged in and the UI omits the delete button. Is that authorization?
2. Difference between OAuth access token and OIDC id_token (conceptually)?
3. Why does MFA not fix DET-002 (cross-user note access)?
4. Why is IMDS a service-identity concern?
5. Name one RBAC check and one ABAC check in notes-api when LAB_MODE=false.

**Answers:** (1) No. (2) Access token is for an API; id_token asserts
authentication to the client. (3) Alice is already authenticated; the bug is
AuthZ. (4) It hands out the workload’s cloud credentials to anything that can
HTTP to it. (5) RBAC: admin role for `/admin/users`. ABAC: owner equals
subject for GET note.

## Engineering assignment

Document the AuthN/AuthZ path of a service you know: identity provider,
token type, expiry, where object checks live, how services authenticate.
Note one failure mode. No production credential dumps.

## Further reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [RFC 6749 OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [NIST SP 800-63 Digital Identity](https://pages.nist.gov/800-63-3/)
