# Module 3 — Identity and access management

## Why it matters to a software engineer

Almost every serious web incident is an identity incident: a session stolen,
a token over-scoped, a missing authorization check, a service account shared
by twelve microservices. Authentication answers “who is this?” Authorization
answers “what may they do to *this* object, *now*?” Mixing them up produces
`if (loggedIn) return note`.

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
