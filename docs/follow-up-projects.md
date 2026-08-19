# Ten follow-up project ideas for software engineers

All projects must stay on systems you own or on local labs. No unauthorized
testing.

1. **Object-level AuthZ test harness.** Replay recorded HTTP fixtures against
   staging you own; fail CI on cross-tenant reads.
2. **Detection replay in CI.** Store JSONL from this lab; unit-test rule
   evaluation without Docker.
3. **Workload identity migration.** Replace a static API key in a service
   you own with OIDC/workload identity; document residual risk.
4. **IMDS lock-down design.** For a cloud account you own: hop limits, no
   app-path to metadata, scoped roles; prove with logs.
5. **Signed image pipeline.** Cosign or equivalent on a personal registry;
   admission that rejects unsigned tags.
6. **Sigma → your log backend.** Translate DET-001–005 into the query
   language you actually have (even if that is just `jq`).
7. **IR tabletop + telemetry gap list.** Run a paper incident on your
   service; list events you cannot currently see.
8. **Safe copilot, not an agent.** PR-review assistant that only reads diffs
   you own and cannot call deploy APIs.
9. **PQC inventory.** Find RSA/ECC uses in a codebase you own (TLS, JWT,
   artifact signing); write a migration sketch referencing NIST PQC.
10. **AI-app threat model.** If you ship RAG/tools: trust boundaries for
    documents, tools, memory; map to OWASP LLM/Agentic 2026; add prompt-
    injection tests that must not grant tools.

Stretch: contribute detections or docs back to this repository.
