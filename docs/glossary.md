---
description: Glossary of defensive security terms used throughout the course, from AuthZ and IDOR to ATT&CK, detection-as-code, and dwell time.
---

# Glossary

| Term | Meaning |
| --- | --- |
| ABAC | Attribute-based access control; decision uses properties of user, resource, context. |
| Alert | A detection output requiring a human or automated decision. |
| ATT&CK | MITRE knowledge base of adversary tactics and techniques. |
| Asset | Something whose disclosure, change, or downtime would hurt. |
| Attack | An attempt to abuse a system. |
| Attack surface | Reachable interfaces an adversary could use. |
| Audit trail | Security-relevant records intended for later review. |
| AuthN | Authentication: establishing identity. |
| AuthZ | Authorization: allow/deny an action on a resource. |
| Breach | Confirmed compromise/disclosure meeting legal or policy thresholds. |
| CIA | Confidentiality, integrity, availability. |
| Containment | Limiting damage while investigation continues. |
| Control | A measure that changes risk. |
| CEF | Common Event Format; ArcSight-originated vendor log format still widely emitted by legacy network/security appliances. |
| Correlation | Joining multiple individually weak events, across sources/time, sharing an actor or asset, into one higher-confidence case. Not the same as a correlation ID. |
| Correlation ID | Identifier joining events across components (one request, one system). |
| CVE | Publicly disclosed vulnerability identifier for one specific instance (MITRE/NVD ecosystem). |
| CVSS | Severity scoring for vulnerabilities; not the same as risk. |
| CWE | Common Weakness Enumeration; names a *class* of vulnerability (e.g. CWE-89 SQL Injection), not one instance. |
| Detection-as-code | Rules and tests in version control. |
| Diamond Model | Adversary–capability–infrastructure–victim structuring tool for one intrusion event. |
| Dwell time | How long an adversary was present before detection. |
| EDR | Endpoint detection and response. |
| Enrichment | Adding context (asset owner, intel) to an alert. |
| Evidence | Preserved records with process, not just files on disk. |
| Exploit | A specific method using a vulnerability. |
| False positive | Alert without the intended badness. |
| Groundedness | Claims in a summary are supported by cited evidence. |
| Human-in-the-loop | A person must approve before an action. |
| IAM | Identity and access management. |
| IDOR / BOLA | Insecure direct object reference / broken object-level authorization. |
| IMDS | Instance metadata service; often issues cloud credentials to workloads. |
| Incident | Event or adverse occurrence that requires handling. |
| IOC | Indicator of compromise: known-bad artifact. |
| IOA | Indicator of attack: behavioral sign of a technique in progress. |
| JWT | JSON Web Token; signed claims, not automatically confidential. |
| Least privilege | Minimum access for the task, for the minimum time. |
| MAC | Message authentication code (shared-key authenticity). |
| MFA | Multi-factor authentication. |
| MTTA / MTTD / MTTR | Mean time to acknowledge / detect / respond-or-recover (define). |
| NDR | Network detection and response. |
| OAuth 2.0 | Delegation framework for access tokens; not “login” by itself. |
| OIDC | OpenID Connect; identity layer on OAuth. |
| Playbook | Documented investigation/response steps. |
| Purple team | Collaborative validation of detections and controls. |
| Pyramid of Pain | Ranking of indicator types by how costly they are for an attacker to change; TTPs cost the most, hashes the least. |
| RBAC | Role-based access control. |
| Residual risk | Risk remaining after controls. |
| Risk | Effect of uncertainty on objectives (likelihood and impact in context). |
| RoE | Rules of engagement for authorized testing. |
| RPO / RTO | Recovery point/time objective: how much data loss and how much downtime a recovery plan accepts. |
| SIEM | Security information and event management. |
| SOAR | Security orchestration, automation, and response. |
| SOC | Security operations center / function. |
| SSRF | Server-side request forgery. |
| Tactic | Adversary goal at a step (ATT&CK). |
| Technique | Adversary method (ATT&CK). |
| Telemetry | Logs, metrics, traces, and related measurements. |
| Threat | Potential cause of harm. |
| Threat intelligence | External data (IOCs, actor TTPs) used to raise or lower alert confidence and priority; an enrichment input, not proof on its own. |
| Threat model | Structured analysis of what can go wrong and what you will do. |
| Trust boundary | Where trust level changes. |
| TLP | FIRST Traffic Light Protocol for sharing sensitivity. |
| Vulnerability | A weakness that can be abused. |
| XDR | Extended detection and response; a product category for cross-domain correlation (endpoint + network + cloud + identity) with built-in analytics, not a new data source. Vendor-native (single-vendor, pre-integrated) is a common deployment model, not part of the definition — third-party telemetry can be ingested too, still requiring real integration work. |
| Attack surface reduction | Deleting or default-denying reachable interfaces you do not need, cheaper than detecting their abuse. |
| Bulkhead | A partition that limits blast radius: one identity, network, store, process, or tool cannot take down the rest. |
| Event time | Clock of the original event (`ts` in the log). Detection windows should use this, not ingest wall-clock. |
| Processing time | Clock when the pipeline saw the event. Delayed ingest makes processing-time windows lie. |
| Quarantine | Isolate a suspected identity, workload, tenant, or tool so it cannot cause further harm while evidence is preserved. Not the same as delete/kill. |
| STRIDE | Spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege — a prompt for “what can go wrong.” |
| Prompt injection | Untrusted text the model treats as instructions. |
| Jailbreak | Prompt injection aimed at overriding the model’s safety or role instructions. |
| Indirect prompt injection | Prompt injection that arrives in data the model was asked to read (a log, a document), not in the user’s typed prompt. |
| Phishing-resistant MFA | Origin-bound authenticators (passkeys / WebAuthn / hardware keys) that cannot be relayed in real time the way OTP can. |
| DLP | Data loss prevention. A gate on data leaving through an API, a bucket, or an endpoint. It does not add the owner check that should have run first. |
| Encoding | A reversible change of alphabet, such as Base64. No key and no confidentiality. |
| IDS / IPS | Intrusion detection alerts on a signature. Intrusion prevention can also drop the packet. The application's authorization decision is a separate step. |
| PQC | Post-quantum cryptography; classical algorithms (NIST-standardized) intended to resist cryptographically relevant quantum computers. Distinct from quantum cryptography. |
| Threat hunting | A search that starts from a hypothesis and a log you already keep. An empty result is either "it did not happen" or "we do not record it." |
| DoS | Denial of service from one source filling a resource. Separate from whether that resource is bandwidth or expensive work. |
| DDoS | Distributed denial of service: many sources filling one resource. Blocking a single address leaves the others. |
| VPN | An encrypted tunnel into a network. An address on that network is not authentication or authorization. |
| Wi-Fi probe | A client asking the air whether a remembered network name is nearby. Anyone in radio range can hear the name. Association to an answer is not authorization. |
| ZTA | Zero trust architecture. Every request is authorized from identity, device, and the specific resource. Network location is not the decision. NIST SP 800-207. |
| ZTNA | Zero trust network access. A front door that grants an application, not a subnet. The deployment pattern that followed "VPN into the LAN." |
| Quantum cryptography | Cryptography whose security relies on quantum mechanics. The product form is quantum key distribution (QKD). It does not replace TLS. |
| QKD | Quantum key distribution. Hardware that establishes a shared secret over a quantum channel, then used with ordinary symmetric encryption. The classical channel beside it still needs authentication. |
| Hybrid TLS | Handshake that agrees both a classical and a PQC shared secret so either remaining strong is enough. |
| SLSA | Supply-chain levels for software artifacts (provenance), not a certificate. |
| Sigma | Portable log-detection rule format; this lab’s YAML is Sigma-like, not a Sigma backend. |
| YARA | Pattern language for files/memory; not for JSON API logs. |
| Volumetric DoS | Overwhelm capacity with request or packet volume. |
| Algorithmic-complexity DoS | Cheap requests that force expensive work (slow hash, catastrophic regex). |
| Model extraction | Reconstructing a model from query access, without stealing the file. Raise cost (authn, quotas, rate limits, restrict high-information outputs) separately from detect/attribute (query audit, fingerprinting, watermarking). |
| Non-repudiation | Organizational or legal claim that an actor cannot later deny an act. Depends on identity proofing, key custody, revocation, audit evidence, and policy — not an inherent property of a digital signature. |
| Data poisoning | Tampering with training or fine-tuning data so future behavior is attacker-shaped. |
| Adversarial example | Input crafted to be misclassified while looking ordinary. |
| IMDSv2 | Session-oriented instance metadata: PUT a token, then GET with that header. Distinct from hop-limit TTL. |
