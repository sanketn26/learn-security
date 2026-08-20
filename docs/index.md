---
hide:
  - toc
---

<div class="course-hero">
  <div class="course-hero__content">
    <span class="course-eyebrow">Visual overview first · Then the module · Then the lab</span>
    <h1>Learn defensive security<br><span>without a SOC job first.</span></h1>
    <p class="course-hero__lead">Follow one small application from design review to incident response. You do not need prior cybersecurity or SOC experience — this course starts with ideas you already know as a software engineer (requests, processes, identities, databases, logs) and adds one security question at a time: what does this component trust, how could that assumption fail, and what evidence would the failure leave?</p>
    <div class="course-actions">
      <a class="course-button course-button--primary" href="modules/01-security-foundations/">Start module 1 <span aria-hidden="true">→</span></a>
      <a class="course-button course-button--secondary" href="onboarding/">Read onboarding first</a>
      <a class="course-button course-button--coffee" href="https://buymeacoffee.com/sanketn">☕ Support this course</a>
    </div>
    <p class="course-hero__note">17 modules across 4 parts · 1 capstone project · runs entirely on 127.0.0.1, no cloud bill</p>
  </div>
  <div class="course-terminal" aria-label="Course roadmap">
    <div class="course-terminal__bar"><i></i><i></i><i></i><span>learn-security / roadmap</span></div>
    <div class="course-terminal__body">
      <p><span class="terminal-muted">01</span> Security foundations — trust boundaries</p>
      <p><span class="terminal-muted">08</span> MITRE ATT&CK — name the behavior</p>
      <p><span class="terminal-muted">11</span> Detection and incident response</p>
      <p><span class="terminal-muted">13</span> Security architecture — narrower boundaries</p>
      <div class="terminal-status"><span></span> Acme Notes lab, one system throughout</div>
    </div>
  </div>
</div>

<div class="course-proof" aria-label="Course overview">
  <div><strong>17</strong><span>Modules across 4 parts</span></div>
  <div><strong>1</strong><span>Capstone platform</span></div>
  <div><strong>$0</strong><span>Cloud spend (local lab)</span></div>
  <div><strong>127.0.0.1</strong><span>Everything stays on loopback</span></div>
</div>

!!! warning "Authorized lab use only"
    Run offensive-looking exercises only against this repository's local,
    intentionally vulnerable lab. Never reuse them against systems you do not
    own and have explicit permission to test.

## Pick your part

<div class="grid cards" markdown>

-   :material-shield-lock-outline: **Part I — Understand the System**

    ---

    6 modules. Foundations, network and OS, identity, application/API,
    cloud/containers, cryptography.

    The trust boundaries every later module refers back to.

    [Start module 1 →](modules/01-security-foundations.md)

-   :material-eye-outline: **Part II — See and Defend the System**

    ---

    5 modules. Monitoring, MITRE ATT&CK, red/blue/purple, SOC, detection
    and incident response.

    How you'd actually notice and respond.

    [Start module 7 →](modules/07-monitoring-and-logs.md)

-   :material-drafting-compass: **Part III — Design What Comes Next**

    ---

    3 modules. Agentic SOC, security architecture, future directions.

    Move from reacting to designing the system that resists the failure.

    [Start module 12 →](modules/12-agentic-soc.md)

-   :material-layers-outline: **Part IV — Extended Lenses**

    ---

    3 modules. ML/AI system security, availability and DoS, human-factor
    attacks.

    Apply the same trust-and-evidence frame beyond the core stack.

    [Start module 15 →](modules/15-ml-ai-security.md)

</div>

## Start in three steps

1. Read [Onboarding](onboarding.md). It translates the course vocabulary into
   software-engineering language and tells you what you can safely skip.
2. Complete [Setup and first lab](setup.md). It includes a no-Docker preview,
   so setup is not a gate to understanding the system.
3. Begin [Module 1](modules/01-security-foundations.md). Each module opens
   with a **Visual overview** — read that first, then the module text.

## What you will build

```mermaid
flowchart LR
    application --> events["security events"] --> store["searchable store"] --> detections --> alerts
    alerts --> ir["investigation and response"] --> assistant["approval-gated assistant"]
```

By the capstone, you will be able to explain the complete chain from software
behavior to vulnerability, attacker action, telemetry, detection,
investigation, response, and architectural repair.

[Capstone brief →](capstone/README.md){ .md-button .md-button--primary }
[Full course guide →](course.md){ .md-button }

## Choose your next page

| If you are... | Go to... |
| --- | --- |
| New to security terminology | [Onboarding](onboarding.md) |
| Ready to install and test the lab | [Setup](setup.md) |
| Short on time | [Learning paths](learning-paths.md) |
| Looking for a practical task | [Exercise index](exercises.md) |
| Returning to the course | [Modules overview](modules/README.md) |
