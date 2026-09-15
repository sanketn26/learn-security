# Course improvement plan

Maintainer plan (not student-facing). Captures two reviews of this repository:

1. **Module writing** — why the lessons feel bland and fail to hold attention.
2. **Platform capstone** — why the first capstone is hard to navigate, and the work to reorganise it.

Do not mix these into one undifferentiated rewrite. The writing pass touches module prose; the capstone pass touches information architecture, the brief, templates, and the handful of module *links* that currently write into git-tracked templates. Lab code, DET-001–005, and the 100-point pass bar numbers stay as they are unless a later decision says otherwise.

---

## Review 1 — Module articles feel bland

### Diagnosis

The articles feel bland because they are **correct, complete, and templated**. That is a voice and pacing problem, not a knowledge problem. The course is unusually precise. The reading experience is a glossary with labs attached.

Do **not** throw out the good parts:

- One system throughout (Acme Notes), so ideas can compound.
- A real stance: coverage is not security, a valid token is not authorization, a SOC is not a dashboard.
- Pages that already *show* a failure before they name it: Module 3’s sequence that ends in deny; Module 4’s green/red request pair; Module 11’s DET-001 walkthrough; Module 17’s “every arrow after the fake page is indistinguishable from Alice.”
- `docs/how-defenders-think.md` is the most alive page in the repo. “The interesting bug is usually not ‘the request succeeds.’ It is ‘the request succeeds *for the wrong reason*.’” Almost nothing in the module openings does this.

The fix is: **spread the Module 4 / Module 11 / defenders-think pattern, and stop leading with the catalog.** Not slogans, not TryHackMe hype.

### Why attention slips

**Every module is the same shape.** All 17 lessons are: Why it matters → Visual overview (mermaid + Intuition + table + Hint) → Learning objectives → Key concepts → Architecture connection → Lab with the same predict/run/compare block → Knowledge check → (sometimes) exit criteria → assignment → self-check → Before you leave (Predict / Diagnose / Build / Defend / pass bar) → Further reading.

After three modules the reader can predict the **page** better than the **idea**. The lab ritual is copy-paste in 13 of 17 modules (“Predict: (1) which evidence appears (2) which does not (3) why.”). The close is the same five bullets with one clause swapped.

**The hook tells the conclusion instead of opening a problem.** Openings are accurate and slightly scolding. They do not create a question the reader cannot yet answer.

| Module | First beat now | What a binding opening would do |
| --- | --- | --- |
| 1 | “You already make security decisions…” | Show Alice’s token, Bob’s payroll note, HTTP 200, then ask what word that is |
| 2 | “If you cannot explain what a TCP connection… means, you cannot investigate” | Drop one real log line and a packet and ask which one can prove the theft |
| 8 | ATT&CK is shared language / fake progress | Put a painted-green matrix next to a miss, then name the lie |
| 10 | “When your service pages at 2 a.m.…” (closest to a scene) | Stay in that minute: one alert, two hypotheses, a bad metric |
| 11 | “Detections are code… NIST now frames IR inside CSF 2.0” | A rule that is green on the matrix and silent on the fixture |

Module 4 is the exception and still wastes it: “This is the module that maps to your pull requests” plus an OWASP citation. The actual hook is ~100 lines later, in the sequence diagram.

**Vocabulary comes before the scene.** Module 1 is the worst case and the first impression. Before the lab (~line 219 of 375), the reader has CIA, a seven-term table, a six-class origin taxonomy, CWE vs CVE, asset, trust boundary, attack surface, bulkhead, control, residual risk, least privilege, defense in depth, secure defaults, zero trust, STRIDE, PASTA, plus IDOR/SSRF/IMDS/JWT as forward references. That is a reference chapter. The interesting object — draw the trust boundaries of the thing you can run — is buried under the glossary the lab would have motivated.

Key concepts across the set are written as: **Term.** Definition. Lab example. What it is not. Correct. Exhausting in series.

**Alice and Bob are labels, not stakes.** They appear constantly. They never want anything. “Bob’s payroll draft” is a severity hint, not a consequence. There is no moment of *you just leaked payroll*. Module 17 almost has a story (Alice types her password into a fake page) and then spends a paragraph on scope.

**The dominant move is correction, not discovery.** House style is *X is not Y* (zero trust is not a product; coverage ≠ security; a SOC is not a room; XDR is not a new data source; crypto does not authorize Alice to Bob’s note). That stance is why the course is trustworthy. As a reading diet it is a teacher who grades every sentence. Discovery first, disabusing second.

**Diagrams are taxonomies, not scenes.** The visuals that work are one request, two paths (Module 3 deny, Module 4 NORMAL vs ATTACK, Module 17 fake-page relay). The ones that do not are abstract nouns in boxes: GOAL → Tactic → Technique; Telemetry → Detection → Alert → Triage; Chatbot → copilot → agent. Those are tables drawn as flowcharts. The landing page has a hero and a fake terminal; the modules inherit none of that personality.

**The course keeps talking about the course.** “See COURSE.md section 5,” “the pass bar,” “How defenders think,” “this module.” Meta-structure belongs in onboarding. Inside a lesson it is a second narrator standing in front of the incident. The pass bar alone appears 24 times across `docs/modules/`, even though `docs/assessment.md` already owns it.

**Caution is the emotional register.** `AUTHORIZED LAB USE ONLY`, dummy secrets, versioning caveats, “typical, not mandatory.” Necessary in a security course. Saturated, it flattens every page to the same careful grey. Ethics belongs at the door and at the offensive step — not as atmosphere.

### Pattern to copy (already in the repo)

- **Module 4 sequence:** same `GET /notes/2`, two colours, one missing check. Then: that `owner=bob` line only exists because logging was designed to carry `owner`.
- **Module 3:** first diagram fails on purpose. “Authentication proved Alice is Alice. The request still fails.”
- **Module 11 DET-001:** a detection as a claim a skeptic can test (fields, grouping key, window, threshold, what must stay quiet). A detective story — currently buried in a 600-line catalog.
- **Module 17:** “Every arrow after the fake page is indistinguishable, at the API, from Alice using her own account.”
- **How defenders think:** short, imperative, invents a next move. No learning-objectives block. No glossary run.

Shared shape: **scene → mismatch → name the idea → only then the catalog.** The modules reverse that.

### Writing work items (highest leverage first)

These are a change of beat, not a rewrite of 17 files as one PR.

| ID | Work item | Notes |
| --- | --- | --- |
| **A1** | Open every module on the failure, not the syllabus. First screen: one request, one log line, or one wrong 200. Put “Why it matters” after the reader has a problem. Cut the OWASP/NIST citation from paragraph 1. | Prototype Module 1 (and optionally 4 or 10) before touching the rest. |
| **A2** | Move Key concepts after the lab, or cut it to the five terms the lab actually needs. Everything else is a sidebar / glossary link. | Module 1 should not teach STRIDE, PASTA, CWE, and six origin classes before the reader has drawn a box around `notes-api`. |
| **A3** | Give Alice and Bob one concrete want per module. Not character fiction — one sentence of consequence. | “Bob’s note is a payroll draft. A 200 here is a compensation leak. The log currently cannot prove it.” |
| **A4** | Keep the template for labs and checks; vary the *opening and visual*. Alternate: cold-start log line, before/after architecture, a bad metric, a painted matrix, a deny. | If the first 30 lines of Module 8 look like Module 2, the template has won. |
| **A5** | Make “Before you run this” specific or delete it. | Module 4 already does it right: “If the IDOR scenario succeeds, what should appear in the API log?” |
| **A6** | Promote Intuition from caption to the actual lesson. Write the `!!! note "Intuition"` boxes as what you would say at a whiteboard, then let Key concepts be shorter. | Those boxes are often the only human sentences on the page, and they currently restate the diagram. |
| **A7** | One worked scene per module, like DET-001. A single path at human speed: hypothesis, what you expected, what you got, what that implies. | Module 4’s reasoning loop and Module 11’s rule walkthrough are the models. |
| **A8** | Stop restating the pass bar at the bottom of every file. One assessment page is enough — it already exists: `docs/assessment.md`. Replace the 24 module-level pass-bar mentions with a link there, keeping only the module-specific Build/Defend bullet. | The closing ritual is identical enough that people skip it — including the one bullet that actually changed. |
| **A9** | Define “prototype accepted” before writing it. Checks: the first screen contains a request, log line, or wrong 200 and no citation; no more than five terms defined before the lab; the Intuition box says something the diagram doesn’t; the first 30 lines differ in shape from the previous module; `mkdocs build --strict` and front-matter tests pass. One cold read by someone who hasn’t seen the old version. | Without a bar, “accept the beat” is a vibe, and A4–A8 roll out on an unreviewed prototype. |

**Prototype opening (Module 1), still in this course’s voice:**

> Alice has a valid login. She asks for note 2. Note 2 is Bob’s. The API returns 200 and the body.
>
> Nothing in that sentence required malware, a kernel exploit, or a stolen laptop. It required a missing decision at a trust boundary you can draw in five boxes.
>
> This module names the boxes. The lab is drawing them on the system you are about to run.

Same pedagogy. The reader now has a reason to care what “asset” and “residual risk” mean.

**Suggested first slice for writing:** rewrite Module 1 (or 1 + 4) as a prototype of the beat. Do not rewrite all 17 until that prototype is accepted.

---

## Review 2 — Platform capstone organisation

The first capstone is `docs/capstone/README.md` (defensive platform). The scanner capstone is out of scope except as a contrast: it already has “How to work through,” a module map, staged steps, and an hour budget. The platform capstone does not.

### Diagnosis

The platform capstone is **not under-specified**. It is **over-specified in five overlapping lists**, and **under-structured as a path**. A student who finished the modules still cannot answer: *what do I open first, where do I write, what is already done, and what is actually scored?*

### Why it is hard to use

**The brief is five documents taped together.**

| List in `capstone/README.md` | Count | Job it is trying to do |
| --- | --- | --- |
| What you must include | 13 | Scope |
| Milestones M0–M9 | 10 | Sequence |
| Acceptance checkboxes | 12 | Pass/fail |
| Rubric | 9 criteria / 100 pts | Scoring |
| Expected artifacts | 8 files | Output |
| Failure scenarios | 21 rows | Test matrix |
| Stretch goals | 7 | Extra |

These do not map 1:1:

- **SDR** is in must-include, artifacts, and the architecture rubric cell — not in any milestone.
- **Purple report** is a required artifact — no acceptance checkbox says it exists.
- **M6 Respond** (“simulated actions with APPROVE”) and **M8 Agent** (“denied then approved action”) are the same lab step twice.
- **Replay fixtures** are required (“this was a stretch goal; it is now required”) — no template, no path, no example file; `labs/detections/` only contains `rules.yaml`.
- **`agent-run.json`** is an expected artifact — no template, no example.
- Title says **build** a platform. Item 1 is “use the provided `notes-api`.” This is an **operate-and-write** capstone. The scanner is the build capstone.

**Three conflicting places to put the work.**

- Brief: create `docs/capstone/artifacts/` and gitignore logs.
- Module 8: copy the ATT&CK table into `docs/capstone/attack-coverage.md` (the **template in git**).
- `course.md`: complete the templates under `docs/capstone/` (setup block, line ~684), and “Fill `capstone/attack-coverage.md` draft” / “Timeline + RCA template in capstone” in the deliverables table (lines ~583–588).

`.gitignore` does **not** ignore `docs/capstone/artifacts/`. That directory does not exist. The official output folder is fictional. People overwrite templates — then lose them on the next pull, or commit dummy secrets.

Any real output folder under `docs/` has its own trap. MkDocs builds everything in `docs_dir` (only the `search` and `social` plugins are set up; there is no `exclude_docs` and no redirects), so gitignored student files would still render into `site/` and could fail `mkdocs build --strict` locally. `tests/test_docs_front_matter.py` scans `docs/**/*.md`, so it would also test student files. And moving templates to new paths changes their published URLs with nothing redirecting the old ones.

**The nav is a 15-item junk drawer.** Under Defensive platform, the site lists at the same level: the brief, six Helix examples, seven blank-ish templates. Helix Tickets looks like the assignment. A student can submit Dana/Eli/`HELIX_DEBUG` and think they finished. The Helix examples are good; they are in the wrong place.

**The capstone is mostly already done — the brief pretends it is week-13 greenfield.**

| Artifact | Already produced in |
| --- | --- |
| Threat model | Module 1 lab + assignment |
| Coverage matrix (5 rows) | Module 8, written into the template |
| Purple loop | Module 9 (10-line report) |
| Case + triage | Module 10 |
| Incident timeline / RCA | Module 11 |
| Extra detections | Module 11 assignment |
| Agent investigate + APPROVE | Module 12 |
| Architecture findings + ADR | Module 13 |

The table holds for the *work*, but there is no *hand-off*. Module 8 is the only module that points at a capstone file, and it points at the template. Modules 1, 9, 10, 11, 12 and 13 produce these artifacts without telling the student to keep them. So at week 13, the student may not have saved the work at all.

The map also has holes. Module 7 (monitoring and logs) feeds M2 Telemetry but isn't listed. Modules 2–6 are background knowledge. Modules 14–17 map to nothing in the platform capstone.

The scanner brief has **Course knowledge you will use**. The platform brief has no module → artifact map. Week 13 looks like a second copy of modules 1–13.

Time estimates fight each other: condensed plan **12 hours of polish**; milestones **7 days**; failure-scenario table a second project; no hour budget on the brief itself.

**Templates are uneven, and two leak answers.**

| Template | State | Problem |
| --- | --- | --- |
| `threat-model.md` | Diagram, assets, boundaries **pre-filled** | Module 1’s answer key sitting in the submission file |
| `attack-coverage.md` | DET-001–005 **mapped** | Same, plus Module 8 has to say “do not treat the stub as an answer key” |
| `incident-report.md` | Empty headings | No prompts; Helix uses a different outline (`UTC timeline` vs `Timeline`) |
| `purple-report.md` | Labels only | Helix is a TP/FN/TN table the template does not ask for |
| `architecture-review.md` | One empty table row | Helix uses F1–F5 prose with owner/evidence |
| `containment-runbook.md` | Actually guided | Best template; still not linked from a milestone |
| `security-decision-record.md` | Actually guided | Not on the milestone chart |
| Replay fixtures | Missing | Required for a pass |
| Agent run | Missing | Required artifact |

Helix examples also do not match template headings, so “copy the shape” still requires translation.

**The 21-row failure table is unscoped.** Rows like “Alice reads `/notes/2`” and “agent `approval=nope`” are the course. Rows like producer clock skew, duplicate delivery, collector outage, synthetic dependency alert, action-verification rollback are production SOC maturity. They are not labeled required vs stretch, and they are not attached to a milestone.

### Target shape

One operating model:

**The platform capstone is the bound copy of work you already started in the modules**, plus three authored detections, plus a containment runbook and a decision record that modules only sketched.

Then the pages should look like the scanner’s:

1. **Start here** — what this is, what you will hand in, how long, ethics. Open on the incident (Alice / Bob / 200), not on a 13-item list.
2. **How to work through** — module → artifact map; “if you already have X from module Y, promote it, do not redo it.”
3. **One requirements table** — milestone, you do, template, Helix example, done-when, scored as. This *replaces* must-include + milestones + acceptance as separate lists.
4. **Templates** on their own index, actually blank, same headings as Helix.
5. **Helix** nested under “worked example,” with a one-line “wrong product, right shape.”
6. **Student work** in one gitignored (or clearly local) directory, with a committed README that lists the filenames.
7. **Failure scenarios** split: 8–10 core (the ones the rubric can see) vs stretch.

Proposed nav:

```text
Capstones
  Defensive platform
    Start here                  capstone/README.md
    How to work through         capstone/howto.md          (or a section of README)
    Templates                   capstone/templates/README.md
      (children: the 8 templates)
    Worked example (Helix)      capstone/reference/README.md
      (children: the 6 examples)
  Python vulnerability scanner  capstone/vulnerability-scanner.md
```

Student files never appear in nav.

### Capstone work items

Do **W1–W2 as a written decision first**. If student work stays “edit the templates in git,” W3–W15 are wasted.

#### Decision (W1 + W2) — accepted 2026-09-15

- **(a) Scope.** The platform capstone collects and extends module work. It isn’t built from scratch. The only new engineering is three authored rules and eight replay fixtures.
- **(b) Student files.** They live in `docs/capstone/work/`. Git ignores everything there except `README.md`, and MkDocs excludes the folder (`exclude_docs`). The front-matter test skips it.
- **(c) Templates** stay blank in git. Students copy each one into `work/` and never edit the template itself.
- **(d) Title:** “Operate a small defensive security platform”.
- **(e) Scored set:** the “Suggested scored set” table below, with M6 renamed from Respond to **Contain** (the approval-gated agent action moves to M8 only) and the SDR on M9. Its “Core test” column becomes the brief’s “Done when” column and replaces the acceptance checklist. To pass: ≥80 and every Done-when, with no real secrets and no testing outside scope.
- **(f)** The 24-row failure table stays unsplit until W9. The three agent rows (approval, allowlist, instruction-like text) are core through M8.
- **(g) Budget (W8):** 12–20 hours on the assemble path, 25–30 cold. The low end matches the condensed plan’s 12-hour row, so the ~100-hour total is unchanged; the plan’s original 15–20 would have broken it.
- **(h) Failure scenarios (W9):** 9 core rows, each tied to a milestone’s Done-when. The other 15 are stretch, placed next to the stretch goals and fed by Modules 14–17.

#### P0 — Operating model

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W1** | Write a one-page decision: (a) capstone = assemble + extend module work, not a greenfield build; (b) student files live in `docs/capstone/work/` (gitignored except README); (c) templates stay pristine in git; (d) title becomes “Operate a small defensive platform” or similar. | Every other item forks on this. | — |
| **W2** | Freeze the scored set: 10 milestones, 8 artifacts, 8 core failure scenarios, stretch clearly marked. Drop or merge M6/M8 duplication; put SDR on M9. | Stops editing lists in three places. | W1 |

Suggested scored set after W2:

| Milestone | Student does | Artifact | Core test |
| --- | --- | --- | --- |
| M0 Environment | `lab-up`, ethics | — | loopback bind; sim refuses non-local |
| M1 Model | Promote Module 1 threat model to Acme Notes | `work/threat-model.md` | assets, boundaries, residual risk |
| M2 Telemetry | Verify/fix events (not rebuild logging) | cited in coverage + incident | UTC, actor, object, `trace_id` |
| M3 Emulate | `simulate.py --scenario all` | evidence snapshot path | local-only |
| M4 Detect | 5 given + 3 authored, each with JSONL fixture | `rules.yaml` + `work/fixtures/` + `work/attack-coverage.md` | 8 fire or documented FN; fixtures quiet on normal |
| M5 Investigate | Case + UTC timeline + competing hypotheses | `work/incident-report.md` | case exists; evidence unmodified after preserve |
| M6 Contain | Preserve → contain → verify; `LAB_MODE=false` retest | `work/containment-runbook.md` | evidence-before-containment; one control retested |
| M7 Purple | One hypothesis, TP/FN/TN, one improved rule or control | `work/purple-report.md` | delta recorded |
| M8 Agent | `/investigate`; deny; APPROVE | `work/agent-run.json` | 403 without APPROVE; unsafe tool denied |
| M9 Review | ≥5 findings + one SDR | `work/architecture-review.md` + `work/security-decision-record.md` | residual risk named |

Acceptance checkboxes become the “Core test” column. Rubric rows stay, but each points at a milestone.

#### P1 — Information architecture

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W3** | Add `docs/capstone/work/README.md` listing the eight filenames + `fixtures/`; gitignore `docs/capstone/work/**` except that README. | Makes the output folder real. | W1 |
| **W4** | Move current templates to `docs/capstone/templates/`. Add `templates/README.md`: copy into `work/`, never edit the template. | Separates “blank form” from “Helix” from “my submission.” | W1 |
| **W5** | Regroup `mkdocs.yml` nav as in the target shape. Helix only under Worked example. Templates only under Templates. Brief is one Start here. | Fixes the junk-drawer first impression. | W4 |
| **W6** | Add missing templates: replay fixture (abnormal JSONL, normal JSONL, assert rule id / quiet) and agent-run (JSON skeleton + redaction notes). Optional Helix miniature fixture in `reference/`. | Required work currently has no form. | W2, W4 |
| **W22** | Keep student files out of the site build and tests. `docs/capstone/work/` sits inside `docs_dir`, so MkDocs will render every local student file into `site/` and `mkdocs build --strict` will fail locally on a student’s broken link; `tests/test_docs_front_matter.py` uses `DOCS.rglob("*.md")` and will fail on student files with bad front matter. Add `exclude_docs: capstone/work/` (keeping `work/README.md` if it should render) and skip `docs/capstone/work/` in the front-matter test — or place `work/` outside `docs/`. | Otherwise the gitignored folder breaks the build for exactly the students using it. | W1, W3 |
| **W23** | Decide on URL breakage from the template move. No redirect plugin is configured (`plugins: search, social`). Either add `mkdocs-redirects` to `requirements-docs.txt` + `mkdocs.yml` mapping `capstone/<template>.md → capstone/templates/<template>.md`, or accept broken external links and say so in the PR. Also fix `reference/README.md:24` (“the templates beside it”). | Published Pages URLs change on W4. | W4 |

#### P2 — Single source of truth on the brief

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W7** | Rewrite `capstone/README.md` as a path, not a list dump. Sections: hook (the Alice/Bob 200), what you hand in, how this relates to modules, the one milestone table (W2), time budget, ethics, link to templates + Helix. Delete the redundant must-include list. | This is the organisation fix. Also applies Review 1: scene first. | W2–W6 |
| **W8** | Add **How to work through** (own page or README section): for each milestone, “you already did this in module N — promote, don’t redo,” plus the three new detections as the only greenfield engineering. Include a 15–20h assemble budget and a 25–30h if-starting-cold budget. Mark condensed-plan’s “12h polish” as the assemble path only. | Matches the scanner brief; kills week-13 déjà vu. | W7 |
| **W9** | Split the 21-row failure table: **Core** (the 8–10 that acceptance already implies) vs **Stretch** (clock skew, duplicate ingest, collector gap, root/privileged, dependency alert, rollback, misleading evidence). Move current stretch goals next to stretch tests. | Makes the brief finite. | W2, W7 |
| **W10** | Point rubric cells at milestones/artifacts (“Investigation / 15 → M5 `incident-report.md`”). Keep 100 points / pass at 80 + all core checkboxes. | Scoring stops being a third list. | W7 |

#### P3 — Templates and Helix actually match

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W11** | Blank `threat-model.md` and `attack-coverage.md`. Leave one commented or collapsed “shape” row, or point at Helix. | Stops leaking DET mappings and trust-boundary answers. Module 8’s “do not treat the stub as an answer key” goes away. | W4 |
| **W12** | Align every template’s headings with the matching Helix example (and vice versa). Incident: UTC timeline, competing hypotheses, RCA that names a control defect. Purple: TP/FN/TN table + detection delta + control delta. Architecture: five falsifiable findings with owner and “not this,” plus “what we will not automate.” | “Copy the shape” only works if the shape is the same. | W4 |
| **W13** | On each template, add a 3-line header: fill during module N; submit as `work/<file>`; Helix example link; “if you copy Helix names (Dana, HELIX_DEBUG, ticket 42) you modeled the wrong system.” | Prevents the most likely submission failure. | W4, W12 |
| **W14** | Add a Helix `attack-coverage` example (currently missing) so Module 8/M4 have a parallel matrix. | Coverage is the one artifact students start earliest. | W6, W12 |

#### P4 — Point the rest of the course at the new paths

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W15** | Update Module 8 step 5 (`08-mitre-attack.md:162`): copy the table into `docs/capstone/work/attack-coverage.md` (created from the template), not into the template. Module 8 is the **only** module that currently writes into a template; Modules 1, 9, 10, 11, 12, 13 have **no** capstone hand-off at all, so for them this is *adding* a one-line “save this as `work/<file>`” at the end of the lab, not changing a path. | Stops modules and the capstone fighting, and makes the “already produced in” table true. **This is the only module-prose change that belongs to the capstone pass.** | W3, W7 |
| **W16** | Shrink `course.md` §9 to a pointer + the one table (or a link). Also fix the other `course.md` template pointers: the deliverables table (lines ~583–588: “Fill `capstone/attack-coverage.md` draft”, “Timeline + RCA template in capstone”) and the setup code block (line ~684: “Complete the capstone templates under docs/capstone/”). Same for condensed-plan capstone row (`Capstone polish | 12` → “assemble path, see brief”) and `exercises.md:79` capstone sentence. | One brief, not three slightly different ones (5 vs 8 detections). | W7, W8 |
| **W17** | Add the platform equivalent of the scanner’s **Course knowledge you will use** table on the howto page. Cover all 17 modules, not just the 8 in the “already produced in” table: Module 7 feeds M2 Telemetry; Modules 2–6 feed M1/M3 knowledge; Modules 14–17 (future, ML/AI, availability, human factor) currently map to nothing — mark them as stretch-scenario inputs or explicitly “not used by this capstone.” | Makes “you already did this” visible, and stops students wondering why 14–17 exist before week 13. | W8 |

#### P5 — Writing pass on the brief

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W18** | Open the brief on the incident, not the inventory. Cut AUTHORIZED LAB / dummy-secret atmosphere to the ethics block and the emulate step. | The brief is currently the blandest page in Capstones. | W7 |
| **W19** | In Helix index, lead with “wrong product, right shape” and one anti-pattern (do not paste `LAB_MODE` / DET-001 into Helix, or Dana into Acme). Keep the success/warning callouts. | Organisation + attention in one place. | W5 |

#### P6 — Verify

| ID | Work item | Why | Depends on |
| --- | --- | --- | --- |
| **W20** | Link check: every module → `work/` or `templates/`; nav builds; front-matter tests still pass; `mkdocs build --strict` both clean and **with a populated local `work/`** (proves W22). `grep -rn "docs/capstone/[a-z-]*\.md\|capstone/attack-coverage" docs README.md` returns only intended hits. | Moves always break paths. | W3–W17, W22, W23 |
| **W21** | Walk the capstone as a student who has finished Module 13: can you find the next file in under 30 seconds at each milestone? If not, the howto is still a list. | Organisation is a UX property. | W20 |

### Capstone execution order

```text
W1 → W2
      → W3, W4, W6, W22
            → W5, W11, W12, W13, W14, W23
                  → W7, W8, W9, W10, W18
                        → W15, W16, W17, W19
                              → W20 → W21
```

**Tight first slice** (visible improvement before the full set): **W1, W3, W22, W5, W7, W11, W15** — nav grouped, brief as a path, leaked answers removed, Module 8 no longer writes into the template. W3 + W22 are in the slice because W15 points Module 8 at `work/`, which must exist and must not break the build. That is the “I know where I am” fix.

---

## Combined sequence (if both reviews are executed)

Do not rewrite 17 modules and reorganise the capstone in the same PR. Suggested order:

1. **This file** — land the plan (this commit).
2. **Capstone first slice** — W1, W3, W22, W5, W7, W11, W15. Unblocks students immediately; does not depend on a writing prototype.
3. **Writing prototype** — A1–A3 on Module 1 (optionally Module 4). Accept the beat against A9 before rolling it out.
4. **Capstone remainder** — W4, W6, W8–W10, W12–W14, W16–W21, W23.
5. **Writing rollout** — A4–A8 across remaining modules, using the accepted Module 1/4 prototype. Capstone W15 already reserved the module-link edits; do not fight that in the writing pass.

### Out of scope (both reviews)

- Changing the lab, DET-001–005 behaviour, or the 100-point pass bar numbers.
- Merging Helix into Acme or adding a notes-api answer key.
- Building a fixture runner in CI (already a stretch goal).
- Becoming a slogan-heavy / “elite hacker” course. Honesty and anti-hype stay.

---

## Status

| Track | Status |
| --- | --- |
| Review 1 captured | Yes |
| Review 2 captured | Yes |
| Plan landed | Yes (10e7d4d, branch `docs/course-improvement-plan`) |
| Plan verified against repo | Yes — added W22, W23, A9; corrected W15, W16, W17, W20, A8 |
| Capstone first slice (W1, W2, W3, W5, W7, W11, W15, W22) | Done on branch `capstone/first-slice`. Strict build passes, including with a broken file in `work/`; front-matter tests pass |
| Capstone remainder (W4, W6, W8–W10, W12–W14, W16–W21, W23) | Done on branch `capstone/templates`. Strict build passes with seeded student files; 93 tests pass; old template URLs redirect; replay command verified on the host (the Docker variant is untested) |
| Writing A1, A3, A4, A5, A8 | Done in all 17 modules on branch `writing/module-openings`: every module opens on a scene (log line, deny, before/after, bad metric, painted matrix); OWASP/NIST citations moved out of paragraph 1; specific “Before you run this” replaces the generic one; generic Predict/Defend/pass-bar bullets removed |
| Writing A2 | Module 1 only: five terms before the lab, rest moved after it. Not rolled out to Modules 2–17, because their labs use terms defined in Key concepts; moving them would need per-lab rewording |
| Writing A6 | Rewrote Intuition boxes that restated the diagram (Modules 1, 5, 7, 8, 9, 11); kept the rest |
| Writing A7 | Worked scene in every module (new in 1, 2, 3, 5–10, 12–17; existing in 4 and 11) |
| Writing A9 | Checked against Module 1: first screen is a request + 200 with no citation; five terms before the lab; the Intuition box says what the diagram doesn’t; strict build and tests pass. Still needs a cold read by someone who hasn’t seen the old version |
