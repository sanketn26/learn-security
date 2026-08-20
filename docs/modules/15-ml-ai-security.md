# Module 15 — ML/AI system security

## Why it matters to a software engineer

Module 12 taught you to secure an **application that calls an LLM**. This
module flips the lens: the model, its training data, and its serving
pipeline are now the **asset** you are defending, using the exact same
trust-boundary and asset/threat/risk/control vocabulary from Module 1. If
you build or ship models — recommendation, classification, embeddings,
fraud scoring, or an LLM — this is the module that treats them as production
systems with their own attack surface, not as a black box someone else
secures.

## Learning objectives

- Apply the Module 1 asset/boundary/threat/control lens to a model instead
  of an API.
- Distinguish attacks on training data, the model artifact, and the serving
  API, and name a control for each.
- Explain why a model's outputs are untrusted input to whatever reads them
  next — the same "data becomes code" pattern from Module 4.
- Review a tool-using agent's configuration for supply-chain and
  excessive-agency risk without adding new lab infrastructure.

## Key concepts

**The ML pipeline has the same shape as any other supply chain.** Data
source → collection → labeling → training → evaluation → registry →
serving → monitoring. Module 5's supply-chain diagram (developer → source →
CI identity → artifact → signature → registry → runtime) maps directly:
swap "source code" for "training data" and "build" for "training run." A
compromise at any stage can arrive as an apparently normal deployment.

**Training-data poisoning.** An attacker who can influence training or
fine-tuning data biases the model's future behavior — a backdoor trigger
phrase, a systematically mislabeled class, a skewed recommendation. The
defense is provenance (know where every training example came from) and
evaluation on held-out, trusted data before promotion, the same "verify
before trust" instinct as signature checking in Module 5.

**Model theft / extraction.** An adversary with only query access can
reconstruct a close approximation of a model by querying it heavily and
training a copy on the input/output pairs. This is an availability-and-
confidentiality problem solved by rate limiting, query auditing, and
watermarking — not by encrypting the model file, which does nothing once
the API is public.

**Adversarial examples.** Inputs crafted to be misclassified while looking
normal to a human (or normal-looking log lines crafted to look like
instructions to an LLM — this is Module 12's prompt injection, restated:
the same "interpretation crosses a boundary" pattern from Module 4, with
the model as the unsafe interpreter).

**Excessive agency and tool misuse.** Covered operationally in Module 12;
here, review it as a design-time control. A model that can only *read* is a
different risk than one that can *write*, *delete*, or *call other
services*. The blast radius of a wrong model output is bounded by what its
tools are allowed to do, not by how accurate the model usually is.

**Model/data confidentiality vs business value.** A model trained on
sensitive data can leak fragments of that data through its outputs
(membership inference, verbatim regurgitation). Treat "the model has seen
this data" as equivalent to "this data has an additional access path,"
which changes classification and retention decisions from Module 7.

## Architecture connection

Draw the same trust-boundary diagram as Module 1, with three new boxes:
`Training data` → `Training job` → `Model registry` → `Serving API`. Ask the
Module 1 questions at each boundary: what would hurt if this were disclosed,
changed, or unavailable; who can write to it; what does a caller's token
actually authorize once it reaches the model.

## Hands-on lab — threat-model an added model, audit an existing agent

No new containers. This lab reuses Module 1's method and Module 12's real
lab files — the point is to prove the framework transfers, not to stand up
new ML infrastructure.

### Prerequisites

Completed Module 1 (trust-boundary diagram) and Module 12 (agentic SOC lab).

### Steps

1. **Design exercise.** Acme Notes is adding a "smart search" feature: notes
   are embedded and a similarity model suggests related notes. Draw the
   trust-boundary diagram for this addition: where do embeddings get
   written, who can query the similarity index, does it cross the
   `IMDS`/egress boundary from Module 1's reference diagram if the embedding
   model is a hosted API.
2. Using the STRIDE categories from Module 1, list one concrete threat per
   category for the smart-search feature (e.g. Tampering: a note author
   poisons their own note text to manipulate what gets suggested to other
   users).
3. **Audit exercise.** Open `labs/agentic-soc/policy.yaml` and
   `labs/agentic-soc/agent.py`. For each tool the policy allows, write one
   sentence: what is the worst thing this tool could do if the planner
   chose it based on a manipulated summary. Compare against Module 12's
   "excessive agency" note.
4. Propose one control for the highest-severity item you found in step 3
   that does **not** involve changing the model or prompt (e.g. narrowing
   the policy allowlist, adding an approval gate, capping call frequency).

### Expected observations

A written trust-boundary diagram and STRIDE table for smart search,
matching Module 1's format. A short audit note per tool in
`policy.yaml` naming a concrete worst case, not a generic "could be
misused."

### Security lessons

A model is an interpreter, a data store, and sometimes an actor — decide
which one it is at each boundary before deciding what to trust it with.
Provenance and rate limiting protect a model the way parameterization and
authorization protect an API; the underlying pattern from Module 4 did not
change, only the interpreter did.

### Common mistakes

- Treating "the model is a black box" as a reason to skip the trust-
  boundary exercise instead of a reason to do it more carefully.
- Proposing "make the model more accurate" as a security control. Accuracy
  and safety are different properties; a highly accurate model with
  unbounded tool access is still a high-severity design.
- Confusing model theft (confidentiality/availability of the model) with
  data poisoning (integrity of training data) — they need different
  controls.

### Cleanup

None.

## Knowledge check

1. Why doesn't encrypting a model file stop model extraction?
2. Name the ML-pipeline equivalent of Module 5's "signed artifact."
3. How is a poisoned training example different from a prompt-injected log
   line, and how are they the same?
4. What bounds the blast radius of a wrong model output?
5. Why does "the model has seen this data" change a data-classification
   decision?

**Answers:** (1) The model is served through a public API; extraction only
needs query access, not the file. (2) A trained model with recorded
provenance and an evaluation signoff before it enters the registry.
(3) Different injection point (training time vs. inference time), same
pattern: untrusted content shapes future behavior. (4) The tool permissions
granted to whatever acts on the model's output, not the model's accuracy.
(5) The data now has an additional read path (the model's outputs) that
retention and access-control decisions must account for.

## Engineering assignment

Extend your Module 1 trust-boundary diagram to include the smart-search
addition from step 1. Submit it alongside one paragraph naming the two
highest-severity threats and their controls.

## Further reading

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
