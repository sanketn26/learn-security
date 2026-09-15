---
description: Learn the TCP/IP, DNS, and Linux process and file fundamentals needed to investigate incidents from packets, sockets, and logs.
---

# Module 2 — Networking and operating-system fundamentals

Two pieces of evidence from the same minute. One is a packet:

```text
IP 127.0.0.1.52814 > 127.0.0.1.8080: Flags [P.], length 142
```

The other is a log line:

```json
{"ts":"2026-09-15T10:00:02.113402Z","event":"cross_user_note_access","service":"notes-api","actor":"alice","note_id":2,"owner":"bob"}
```

Bob’s payroll draft just left the API. Which of these two can prove that?

The packet proves a TCP conversation happened on loopback, and nothing
else. It doesn’t know what a note is. The log line knows the actor, the
object, and the owner, but only because the application chose to write
it, and anyone who can write to that file can write a line just like it.
Neither is “the truth.” Each one proves a different thing, and this module
is about knowing which is which.

## Why it matters to a software engineer

Incidents are reconstructed from packets, processes, files, and logs. If you
cannot explain what a TCP connection, a listening port, a uid, or a timestamp
means, you cannot investigate your own service. Cloud and Kubernetes add
layers; they do not remove Linux or IP.

## Visual overview

```mermaid
sequenceDiagram
  participant C as Client
  participant DNS as DNS resolver
  participant G as Gateway
  participant A as API process
  participant F as Files / sockets
  C->>DNS: resolve api.acme.test
  DNS-->>C: address
  C->>G: TCP connect + TLS handshake
  G->>A: HTTP request on service port
  A->>F: read config / open DB / append log
  A-->>C: HTTP response
```

!!! note "Intuition"
    One HTTP request is really four or five separate systems briefly agreeing
    to cooperate: a name lookup, a network handshake, a process doing file and
    socket I/O, and eventually a human-meaningful response. Each of those
    systems keeps its *own* logs, and none of them alone tells the whole
    story — which is exactly why the "one view usually misses" row below
    matters so much.

```text
user/uid --owns--> process --opens--> socket
                         +--reads--> file / env
                         +--writes-> application log
```

| View | Sees well | Usually misses |
| --- | --- | --- |
| Network | endpoints, timing, bytes, DNS, TLS metadata | encrypted body, object authorization |
| Host | process, uid, files, syscalls, local sockets | upstream intent and full distributed path |
| Application | route, actor, object, decision, business result | kernel activity unless instrumented |

Normal: one DNS answer, TLS session, authorized read, 200. Abnormal: repeated
login failures or API→metadata traffic. Evidence: DNS/network metadata,
gateway access log, process/socket state, application audit event. Improvement:
deny needless egress and join views with UTC timestamps and correlation IDs.

!!! tip "Hint"
    If you can only instrument one layer, instrument the application layer
    first — it is the only one of the three that knows *who* did *what* to
    *which object*. Network and host telemetry tell you a request happened;
    only the app layer tells you whether it should have been allowed.

## Learning objectives

- Explain TCP/IP, DNS, HTTP(S), TLS, routing, ports, proxies, and firewalls
  as they affect service design and visibility.
- Connect processes, files, permissions, users, environment variables,
  system calls, and logs.
- Capture **local** evidence (compose network and container logs) safely.

## Words for the lab

These are the terms the lab uses. The rest of the vocabulary comes
[after the lab](#the-rest-of-the-vocabulary), once you have seen it in action.

**DNS.** Names to addresses. Attacks against DNS (spoofing, cache poisoning,
malicious names in SSRF) are common. In the lab, `mock-imds` is a Docker DNS
name on `labnet`.

**Routing, ports, proxies, firewalls.** A firewall or security group is a
packet filter, not an identity system. A reverse proxy may terminate TLS and
add headers (`X-Forwarded-For`) that your app must not trust blindly for
authorization.

**Processes, files, permissions, users.** On Linux, a process runs as a user,
with a filesystem view, environment, and capabilities. Secrets in env vars
are visible to that process and often to anyone who can `docker inspect` or
read `/proc`. File modes (`0600` vs `0644`) still matter for sqlite and keys.

**Logs.** stdout, files, journald, syslog. They are not evidence until they
have timestamps, integrity, and retention you can defend. Container logs
disappear if you `docker compose down -v` carelessly during an investigation.

**Visibility.**

```
 host            docker-proxy         container
 127.0.0.1:8080 ------------------>  0.0.0.0:8080 notes-api
                                         |
                                         +-- connect() --> mock-imds:80
                                         +-- append JSONL  /logs
```

If you only watch an infrastructure dashboard (metrics, optional Grafana
later — not in this compose file), you may miss that the process still has
a network path to metadata.

## Worked scene — is notes-api exposed?

**Hypothesis.** notes-api can only be reached from this machine.

1. *Expect* the listener on `127.0.0.1:8080`. *Got:* `lsof` (or `ss`) shows
   `127.0.0.1:8080`, not `*:8080`. Nothing on your network can connect.
2. *Expect* the container to have no route to the internet, because
   `labnet` is `internal: true`. *Got:* notes-api is also attached to
   `edgenet`, an ordinary bridge. `getaddrinfo('example.com')` may resolve.
3. *Expect* `/fetch` to reach the world, then. *Got:* it doesn’t, but that
   isn’t the network’s doing. The application’s allowlist refuses
   non-lab hosts.

**What that implies.** The first claim holds, for a reason you can point
at. The second one was wrong: “it’s on an internal network” was never the
control. If someone removes the allowlist, the network won’t catch it.
Write down which bulkhead you’re actually relying on, not the one the
diagram suggests.

## Architecture connection

Service mesh, ingress, and NetworkPolicy are filters on this same model.
East-west TLS is hop security. Authorization still belongs in the service
(or a policy engine that the service actually enforces).

## Hands-on lab — local visibility

**AUTHORIZED LAB USE ONLY.** Capture only on the lab compose network or
loopback. Do not scan your campus, cloud, or neighbors.

### Prerequisites

Lab up. Optional: `ss` or `netstat`, `docker logs`.

### Before you run this

Write down three answers before you run anything:

1. Which host address will port 8080 be bound to, and what would it mean if
   it were `0.0.0.0`?
2. Which user does the notes-api process run as inside the container?
3. After one `GET /notes`, which fields will the new log line have, and
   which field would you need to prove *who* read *what*?

Then run the steps. If a result surprises you, which assumption was wrong?

### Steps

1. `./labs/scripts/lab-up.sh`
2. On the host, confirm the bind is loopback:

   ```bash
   # Linux
   ss -ltnp | grep 8080
   # macOS
   lsof -nP -iTCP:8080 -sTCP:LISTEN
   ```

3. `docker inspect lab-notes-api --format '{{json .NetworkSettings.Networks}}'`
   — note `labnet` IP `172.30.0.20`. “Internal” is a **network** property:

   ```bash
   docker network inspect learn-security-labnet --format '{{.Internal}} {{json .IPAM.Config}}'
   ```

4. The slim image may not include `ps`. Use:

   ```bash
   docker exec lab-notes-api id
   docker exec lab-notes-api ls -l /data /logs
   ```

5. Login and generate one event:

   ```bash
   TOKEN=$(curl -s http://127.0.0.1:8080/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice-lab-password"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
   curl -s http://127.0.0.1:8080/notes -H "Authorization: Bearer $TOKEN"
   ```

6. `docker exec lab-notes-api tail -n 5 /logs/notes-api.jsonl`
7. Optional packets (loopback only):

   ```bash
   # Linux loopback is lo; macOS is lo0. Capture only loopback.
   sudo tcpdump -i lo -n port 8080 -c 20    # Linux
   sudo tcpdump -i lo0 -n port 8080 -c 20   # macOS
   ```

   Stop after 20 packets. You should see TCP to localhost, not to the internet.

8. From inside the API container, resolve the metadata hostname:

   ```bash
   docker exec lab-notes-api python -c "import socket; print(socket.getaddrinfo('mock-imds',80)[0][-1])"
   ```

   notes-api is **also on `edgenet`**, a normal bridge. `getaddrinfo('example.com')`
   may succeed (DNS leak). That does not mean you should contact the public
   internet — do not. The bulkhead that actually blocks `/fetch` to the world
   is the application allowlist, not “the container is on an internal network.”
   See [lab guide](../lab-guide.md) and [How defenders think](../how-defenders-think.md).

### Expected observations

Loopback bind; JSON logs with `ts`, `event`, `trace_id`; process running as
the container user; sqlite file on a volume.

### Security lessons

Publication to `0.0.0.0` on the host would have put the vulnerable API on
every interface. Env-based secrets show up in process listings. Logs need a
volume or they vanish with the container.

### Common mistakes

- Capturing on the wrong interface (your Wi-Fi).
- Trusting `X-Forwarded-For` for allowlists.
- Assuming HTTPS to the load balancer means the app saw a verified client
  identity.

### Cleanup

Stop tcpdump. `./labs/scripts/lab-down.sh` if finished.

## The rest of the vocabulary

Now that you have run the lab, here is the rest of the language people
will use about it.

**TCP/IP.** Packets are routed by IP. Transport protocols (TCP and UDP)
add ports, and TCP adds a handshake and a byte stream. Your API is a
process bound to `0.0.0.0:8080` inside a container, published to
`127.0.0.1:8080` on the host. That publish path is a trust boundary: only
loopback should reach it in this lab.

**HTTP/S and TLS.** HTTP is the application protocol. TLS provides
confidentiality and integrity of the hop and, with certificates, server
(and optionally client) authentication. Module 6 splits that into key
agreement, authentication, and AEAD-protected data. TLS does not authorize
Alice to read Bob’s note. HTTP methods, paths, headers, and bodies are
your app’s surface.

**System calls.** User code asks the kernel to do things (`open`, `connect`,
`execve`). EDR products watch these. You will not run a full EDR here; know
that “the app made an outbound GET to IMDS” is a `connect` + write to a
socket.

## Knowledge check

1. Does TLS between user and ingress authorize object access?
2. Why bind lab ports to `127.0.0.1` rather than `0.0.0.0`?
3. What evidence do you lose if you `down -v` mid-incident?
4. Why is a security group insufficient as the only authorization layer?
5. Where might a JWT secret appear besides application config?

**Answers:** (1) No. (2) Avoid exposing vulnerable lab services on LAN/WAN.
(3) Volume logs, sqlite, cases. (4) It filters packets, not user-to-object
mapping. (5) Env, `docker inspect`, memory, logs if mishandled, CI variables.

## Engineering assignment

For a service you run, list listening ports, identity of the process user,
where logs go, and whether secrets are in env. Propose one visibility
improvement (structured log field or bind-address change). No scanning of
systems you do not own.

## Self-check

Answer before expanding. These are the [assessment](../assessment.md) moves
on this module's Acme Notes lab, not trivia.

??? question "Explain: Why is publishing notes-api on 127.0.0.1:8080 a different trust boundary than 0.0.0.0:8080?"
    Loopback is reachable only from the host. `0.0.0.0` puts the
    intentionally vulnerable API on every interface — LAN/WAN. The
    container still binds `0.0.0.0:8080` *inside* the namespace; the host
    publish mapping is the boundary you chose.

??? question "Predict: What evidence disappears if you `docker compose down -v` in the middle of an investigation?"
    Volume-backed JSONL, sqlite, and soc-lite cases. Container stdout logs
    from the removed instances. A host copy from `preserve-logs.sh` is the
    thing that is supposed to survive.

??? question "Diagnose: labnet is `internal: true`, but `getaddrinfo('example.com')` from notes-api may succeed. What assumption failed?"
    notes-api is dual-homed: edgenet is a normal bridge. Internal labnet
    does not prove the *process* has no DNS or egress. The bulkhead that
    actually blocks `/fetch` to the world is the application allowlist.

??? question "Design: Why is a security group (or compose network) insufficient as the only authorization layer for GET /notes/2?"
    Packet filters decide who can open a TCP connection, not whether Alice
    may read Bob's row. Object AuthZ still belongs in the service.

??? question "Defend: Someone published the lab on a shared Wi-Fi. What do you isolate first, and what remains?"
    Un-publish / bind back to loopback and treat dummy passwords as burned.
    Residual risk: anyone who already reached `:8080` may hold a JWT;
    rotate `JWT_SECRET` and wipe lab volumes after you copy evidence.

## Before you leave

- **Diagnose** — name the failed invariant from this module's telemetry or diagram.
- **Build** — complete the local-visibility lab (bind address, process user, log path, one bulkhead caveat).

How these are graded: [assessment](../assessment.md).

## Further reading

- [RFC 8446 TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [Linux man-pages: credentials(7), systemd-journald](https://man7.org/linux/man-pages/)
- CISA: [Binding Operational Directive / known exploited vulns](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) as context for why internet-exposed services get hunted
