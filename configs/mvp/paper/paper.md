# TraceProbe Paper Draft and Main Narrative

This document is the paper-facing writing blueprint for TraceProbe. It assumes the
planned experiments have been completed and that the results support the core claims.
It should be read together with:

- `configs/mvp/paper.md`: earlier narrative notes.
- `configs/mvp/EXPERIMENT_GUIDE.md`: experiment runbook.
- `configs/mvp/docs/v0_2_experiment_matrix.md`: suite hierarchy and reporting rules.
- `configs/mvp/paper/related work.md`: related-work map and comparison table.
- `configs/mvp/paper/plot.md`: figure plan.

The paper should be written as a benchmark / methodology paper, not as a defense
paper. The central contribution is not that TraceProbe is the largest or most
realistic agent-safety benchmark. The central contribution is that TraceProbe makes
agent safety failures diagnosable through executable scenarios, trajectory evidence,
structured attribution labels, and replay-grounded post-hoc analysis.

---

## 1. Core Narrative

### 1.1 One-Sentence Thesis

> TraceProbe shifts agent safety evaluation from endpoint judgment to
> execution-grounded attribution: instead of only asking whether an agent failed, it
> asks where the risk entered, which component accepted it, how it propagated, and
> where it could have been blocked.

Chinese shorthand:

> TraceProbe 的主线不是“又做了一个 Agent 安全榜单”，而是“把 Agent 为什么失败变成可运行、可复现、可归因、可重放分析的问题”。

### 1.2 The Main Story Arc

The paper should follow this arc:

1. Modern LLM agents are not single-turn text generators. They read files, call
   tools, use memory, consume retrieved content, coordinate with other agents, and
   mutate environments.
2. Therefore, safety failures often occur inside the execution trajectory, before or
   without an obviously unsafe final answer.
3. Existing endpoint metrics such as task success, attack success, or final safety
   violation remain necessary, but they are insufficient for diagnosis.
4. TraceProbe introduces executable agent-safety scenarios with structured
   attribution ground truth: source, channel, mechanism, first failed component,
   impact, counterfactual block point, and failure chain.
5. TraceProbe evaluates live agent behavior in sandboxes, exports traces, scores
   outcomes, and replays recorded actions in fresh sandboxes to validate and localize
   safety-relevant events.
6. Experiments show that strong models still fail, guarded prompting is not enough,
   similar overall scores hide different failure profiles, endpoint-safe runs can
   still contain latent trajectory violations, and multi-risk scenarios require
   replay-grounded dominance analysis.

### 1.3 What Reviewers Should Remember

The reviewer takeaway should be:

> TraceProbe is a benchmark for diagnosing safety failures in live agent execution.

More concretely:

- It is narrower than broad agent-safety benchmarks, but deeper in failure diagnosis.
- It compares non-adversarial failures, internal authority compromise, and external
  attacks under one attribution schema.
- It treats traces as evidence, not just logs.
- It uses replay to validate that recorded actions can reproduce safety-relevant
  events in the original scenario environment.
- It provides a compositional stress suite to check whether configured hazards are
  actually activated, dominant, masked, or order-dependent.

---

## 2. Recommended Title

Recommended:

> TraceProbe: A Benchmark for Diagnosing Safety Failures in Live Agent Execution

Alternatives:

> TraceProbe: An Execution-Grounded Benchmark for Diagnosing Agent Safety Failures

> TraceProbe: Diagnosing Agent Safety Failures with Executable Traces

> TraceProbe: A Benchmark for Execution-Grounded Diagnosis of Agent Safety Failures

> Beyond Outcomes: Attribution-Level Evaluation of Agent Safety Failures

> From Outcomes to Causes: Execution-Grounded Diagnosis of Agent Safety Failures

The recommended title is safest after TRAJECT-Bench, FAMAS, and ATBench-CodeX. It
keeps the benchmark identity while avoiding three crowded framings:

- **Trajectory-aware benchmark**, which overlaps with TRAJECT-Bench and ATBench.
- **Attributing failures**, which overlaps with FAMAS-style multi-agent failure
  attribution.
- **Trajectory safety evaluation**, which overlaps with ATBench and its CodeX
  extension.

TraceProbe should foreground live agent execution: the evaluated model is placed in
an executable scenario, produces its own actions, and is then diagnosed through
outcome scoring, latent trace events, structured attribution labels, and replay.

---

## 3. Abstract Draft

Use this as the first full abstract draft. Replace bracketed quantities after the
final experiment table is frozen.

```text
LLM agents increasingly act through tools, files, memory, retrieved content, and
multi-agent communication. As a result, safety failures may arise inside a multi-step
execution trajectory rather than only in the final response. Existing agent-safety
benchmarks largely report outcome-level metrics, which can identify whether a run is
unsafe but often cannot explain where a risk entered, how it propagated, or where an
intervention could have blocked it. We introduce TraceProbe, a benchmark for
diagnosing safety failures in live agent execution. Unlike trajectory-auditing
benchmarks that ask models to classify pre-constructed traces, TraceProbe places
agents in executable sandboxed scenarios and diagnoses the traces they actually
produce. TraceProbe contains 155 executable scenarios spanning non-adversarial
failures, internal authority compromise, and external attacks, each annotated with
structured attribution labels covering risk source, channel, mechanism, first failed
component, impact, counterfactual block point, and failure chain. TraceProbe exports
normalized traces, scores outcome and latent violations, and includes a trace
replayer that reconstructs scenarios in fresh sandboxes to replay recorded actions
and localize safety-relevant events. Across
[N] contemporary models, we find that strong agents still exhibit non-trivial safety
failures, prompt-only safety reminders do not reliably eliminate risk, and similar
aggregate scores can hide distinct family-level failure mechanisms. Replay analysis
further shows that endpoint-safe runs may contain latent trajectory violations and
that multi-risk compositional scenarios require distinguishing configured hazards
from activated and dominant hazards. TraceProbe provides a reproducible framework
for moving agent safety evaluation beyond outcome metrics toward execution-grounded
failure attribution.
```

If the final paper is tight, shorten the abstract by dropping the explicit list of
all attribution fields and moving the compositional sentence to the end.

---

## 4. Introduction Plan

The introduction should be concrete and fast. Do not start with generic "LLMs are
powerful" prose. Start with an agent-specific failure.

### 4.1 Opening Example

Use a compact example like this:

> Consider an agent asked to summarize a support ticket and attach sanitized
> evidence. During execution, the agent reads a retrieved appendix that contains an
> instruction to include a support token. The final answer may or may not expose the
> token, but the trace already shows that the agent treated untrusted retrieved
> content as authority and accessed a sensitive path. An endpoint-only metric can say
> whether the final answer leaked the token; it cannot explain whether the failure
> was caused by retrieval, memory, tool output, policy prompt contamination, or
> unsafe execution.

This example should support the thesis:

> Agent safety is trajectory safety.

### 4.2 Introduction Paragraph Structure

Paragraph 1: Agent systems create trajectory-level safety risk.

- Agents use tools, memory, retrieval, files, and multi-agent messages.
- Safety failures can occur in intermediate actions and state transitions.
- Final answers are only one surface.

Paragraph 2: Outcome-only evaluation is necessary but insufficient.

- TSR, SVR, ASR, and STCR are useful.
- But they do not explain risk source, channel, mechanism, first failed component, or
  block point.
- Similar aggregate scores may hide different failure mechanisms.

Paragraph 3: The missing benchmark target is attribution.

- We need controlled executable scenarios where the intended hazard and expected
  failure chain are labeled.
- The evaluated model should generate its own actions, not merely inspect a
  pre-written trajectory.
- The trace should be replay-validated where possible.

Paragraph 4: Introduce TraceProbe.

- 155 executable v0.2 main scenarios.
- A/B/C risk source taxonomy.
- Structured attribution labels.
- Sandboxed execution and normalized trace export.
- Outcome scoring, latent-trajectory scoring, and trace replay.

Paragraph 5: Contributions and findings.

- State contributions.
- State empirical headline findings.
- State that TraceProbe is complementary to broad benchmarks such as OpenAgentSafety
  and security environments such as AgentDojo.

### 4.3 Contribution Bullets

Use five contributions:

1. **A live-execution diagnostic benchmark.** TraceProbe provides executable
   agent-safety scenarios where agents must act in sandboxed environments rather
   than classify pre-written trajectories.
2. **A unified risk-source taxonomy.** TraceProbe compares non-adversarial failures,
   internal authority compromise, and external attacks in one schema, including
   policy prompt, memory state, multi-agent message, retrieved content, and tool
   output channels.
3. **Safety-specific attribution ground truth.** TraceProbe labels source, channel,
   mechanism, first failed component, impact, counterfactual block point, and
   failure chain, making safety diagnosis comparable across risk families.
4. **Execution-grounded analysis with trace replay.** TraceProbe exports live traces
   and replays recorded tool actions in fresh sandboxes to validate trace fidelity,
   localize first safety-relevant events, and support case studies.
5. **A multi-layer empirical evaluation.** We evaluate contemporary models on the
   main benchmark, compare naive and guarded prompting, analyze family-level failure
   profiles and attribution recovery, and use transient and compositional stress
   suites to study latent process violations and multi-risk dominance.

The fifth contribution can be shortened or folded into the experiments paragraph if
the paper needs fewer claims.

---

## 5. Related Work Positioning

The related-work section should be respectful and defensive against obvious reviewer
pushback. The goal is not to claim that prior work is weak; the goal is to show that
TraceProbe answers a different question.

### 5.1 Paragraph 1: General LLM Safety Benchmarks

Mention SafetyBench, HarmBench, JailbreakBench, and SALAD-Bench.

Claim:

> General safety benchmarks standardize harmful-content and jailbreak evaluation,
> but usually evaluate prompt-response behavior rather than multi-step tool-mediated
> trajectories.

Transition:

> Agentic systems require evaluating intermediate actions and state transitions.

### 5.2 Paragraph 2: Agent Capability Benchmarks

Mention AgentBench, WebArena, OSWorld, tau-bench, TRAJECT-Bench, and
ToolBench/API-Bank-style work.

Claim:

> These benchmarks measure interactive task completion and realistic tool use.
> TraceProbe is complementary: it uses controlled workflow-inspired scenarios to
> isolate safety mechanisms and provide attribution labels.

Specific comparison:

- **TRAJECT-Bench:** close for trajectory-aware tool-use capability. It evaluates
  whether agents select, order, and parameterize tools correctly. TraceProbe shares
  the view that final answers are insufficient, but uses execution traces as safety
  evidence for risk entry, propagation, latent violations, replay localization, and
  attribution.

### 5.3 Paragraph 3: Agent Safety and Security Benchmarks

Mention ToolEmu, AgentHarm, Agent Security Bench, InjecAgent, AgentDojo, and
OpenAgentSafety.

Claim:

> Existing agent-safety and agent-security benchmarks move beyond static harmful
> prompts, but many focus on attack success, defense evaluation, or broad safety
> coverage. TraceProbe focuses on structured failure attribution.

Specific comparison:

- **OpenAgentSafety:** broad, realistic, close neighbor. TraceProbe should not claim
  to outsize it. Our angle is structured attribution ground truth, replay evidence,
  and compositional controls.
- **AgentDojo / InjecAgent:** close for prompt injection and tool-use security. Our
  angle is that external injection is only one risk source; TraceProbe also covers
  internal authority contamination and non-adversarial failures.
- **Agent Security Bench / AgentHarm / ToolEmu:** important safety/security
  neighbors. Our angle is diagnosis rather than attack/defense breadth.

### 5.4 Paragraph 4: Trajectory Safety, Diagnosis, and Attribution

Mention ATBench, ATBench-Claw / ATBench-CodeX, HINTBench, AgentRx, FAMAS, and
trace-based LLM-as-judge work.

Key distinction:

> Many trajectory-diagnosis benchmarks evaluate trajectory auditing: a model or
> judge is given an existing trajectory and asked whether it is safe or where it
> failed. TraceProbe evaluates scenario-grounded live behavior: the model is placed
> in an executable scenario and produces its own actions, which are then scored and
> replay-analyzed.

Closest benchmark distinction:

> ATBench and ATBench-CodeX evaluate safety of already-realized trajectories.
> TraceProbe evaluates safety of agents producing trajectories in executable
> scenarios.

Failure-attribution method distinction:

> FAMAS ranks responsible agents/actions in failed multi-agent executions using
> repeated runs and spectrum-style suspiciousness scoring. TraceProbe is a benchmark
> with safety-specific attribution labels and replay-grounded evidence, not primarily
> an attribution algorithm.

Do not say prior trajectories are "fake" or "useless". Say:

- Static trajectories are valuable for auditing.
- But they may encode a presumed causal path.
- They cannot directly measure whether a live agent would take that path, ignore the
  hazard, recover, or fail through another mechanism.
- TraceProbe's executable scenarios and replay analysis let us compare intended
  hazard labels with observed failure paths.

### 5.5 Optional Paragraph 5: Compositional Stress Testing

Use only if RQ5 is in the main paper.

Claim:

> Most benchmarks evaluate isolated risks. TraceProbe includes a supplementary
> compositional playground with clean, single, combo, and reverse-combo variants,
> enabling analysis of dominance, masking, amplification, and order effects.

---

## 6. Benchmark Design Section

This should be the technical core of the paper. The section should be concise but
specific enough that reviewers believe the benchmark is reproducible.

### 6.1 Design Goals

State three design goals:

1. **Executable realism under control.** Scenarios should resemble realistic agent
   workflows but remain controlled enough to assign attribution labels.
2. **Trajectory observability.** The benchmark should record tool calls, file
   access, final outputs, final state, and latent safety events.
3. **Attribution comparability.** Failures across different risk sources should be
   comparable through a shared schema.

Avoid saying "full production realism". The better phrasing is:

> TraceProbe chooses controlled workflow realism over open-ended environment breadth
> because its goal is failure attribution.

### 6.2 Scenario Format

Explain that each scenario is a YAML specification containing:

- user-facing task instruction;
- initial files and environment state;
- optional memory state, policy prompt, retrieved content, tool output, or
  multi-agent messages;
- allowed tools and mock tools;
- acceptance criteria;
- safety constraints;
- attribution ground truth;
- optional transient violation markers or compositional hazard metadata.

Important point:

> The evaluated agent is not given the attribution labels. The labels are used only
> for scoring and analysis.

### 6.3 Risk-Source Taxonomy

Report the main v0.2 split:

| Source class | Families | Role |
| --- | --- | --- |
| A. Non-adversarial failures | A1, A2, A3, A4 | Agent can fail without an attacker through boundary overreach, faulty inference, unstable execution, or data-minimization failure. |
| B. Internal authority compromise | B1, B2, B3 | Agent over-trusts internal-looking authority signals such as policy prompts, memory state, or multi-agent messages. |
| C. External attacks | C1, C2.1, C2.2 | Agent is exposed to direct user attacks, retrieved-content injection, or tool-output injection. |

Dataset counts:

- Main benchmark: `v0_2_test`, 155 scenarios.
- Core 20-sample families: A1, A4, B1, B2, B3, C2.1, C2.2.
- Promoted 5-sample gap families: A2, A3, C1.
- Optional trajectory pilot: `v0_2_transient`, 8 scenarios.
- Optional compositional stress suite: `mvp_compositional_playground`, 60 generated scenarios from 12 pairwise composition groups.

Writing rule:

> Treat A2, A3, and C1 as promoted gap probes, not as equally powered family-level
> conclusions.

### 6.4 Attribution Schema

Define the attribution labels:

| Dimension | Question answered |
| --- | --- |
| `primary_source` | Where does the risk originate: non-adversarial, internal compromise, or external attack? |
| `primary_channel` | Through what channel does the risk reach the agent? |
| `primary_mechanism` | What failure mechanism turns the risk into unsafe behavior? |
| `first_failed_component` | Which agent subsystem first accepts or propagates the risk? |
| `primary_impact` | What kind of harm or boundary violation occurs? |
| `counterfactual_block_point` | Where could a structural check have blocked the failure? |
| `failure_chain` | What is the expected sequence from risk entry to impact? |

Core sentence:

> Outcome metrics say whether the run failed; attribution labels say why the run
> failed.

### 6.5 Execution and Trace Export

Explain:

- Agents run in sandboxed scenarios.
- The system records tool calls, observations, final output, and final state.
- The export normalizes traces for scoring and post-hoc analysis.
- Scoring uses both final-state evidence and trace-level latent evidence.

Make clear:

> TraceProbe evaluates live agent behavior, not only pre-written traces.

### 6.6 Outcome and Latent Metrics

Define:

- `TSR`: task success rate.
- `SVR`: safety violation rate.
- `ASR`: attack success rate over attack-labeled tasks.
- `STCR`: safe task completion rate.
- `resource_overrun_rate`: excessive or out-of-scope helper/tool usage.
- `latent_violation_rate`: safety-relevant trace events not necessarily visible in
  final outcome.
- `internal_message_exposure_rate` and `unsafe_internal_message_exposure_rate`: B3
  output isolation failures.

Explain `STCR` clearly:

> STCR requires both useful task completion and absence of safety violation.

### 6.7 Trace Replayer

This is a central method section, but do not oversell it as causal proof.

Definition:

> The trace replayer reconstructs the original YAML scenario in a fresh sandbox and
> re-executes the recorded tool calls with the recorded arguments. It does not rerun
> the LLM, does not replan, and does not simulate alternative actions.

It answers four questions:

1. **Trace fidelity.** Can the recorded tool calls be reproduced in a fresh
   scenario environment?
2. **Step-level safety localization.** At which step does the first sensitive read,
   untrusted sink, watched-path mutation, safety failure, or risk-positive probe
   appear?
3. **Execution-grounded support.** Is the unsafe final or latent state consistent
   with the recorded action sequence?
4. **Compositional dominance support.** In multi-risk scenarios, does the observed
   failure path support the configured dominant hazard hypothesis?

Important phrasing:

> Replay provides execution-grounded evidence, not definitive causal proof.

For counterfactual replay:

> Counterfactual replay is a natural extension, but the main paper's first-pass
> analysis uses exact replay and stepwise probes.

### 6.8 Compositional Playground

Describe as supplementary:

- Uses substrate + hazard plugins + recipes.
- Generates clean, single, combo, and reverse-combo variants.
- Asks whether multiple hazards produce dominance, masking, amplification, or order
  effects.
- Uses replay dominance to distinguish configured hazards from activated hazards.

Critical distinction:

| Term | Meaning |
| --- | --- |
| configured hazard | A hazard specified in YAML or generated by a recipe. |
| activated hazard | A hazard whose evidence appears in the observed/replayed trajectory. |
| dominant observed path | The hazard path most consistent with the first failure evidence in a combo scenario. |

Do not write "dominant cause" unless a stronger counterfactual analysis is actually
implemented.

---

## 7. Experiments Section

The experiments should be organized by RQ, not by script names.

### 7.1 Experimental Setup

Report:

- Main benchmark: `v0_2_test`, 155 scenarios.
- Baselines: `naive` and `guarded`.
- Models: final model list after all runs complete.
- Infrastructure: sandbox backend, timeout, retry/resume policy.
- Metrics: TSR, SVR, ASR, STCR, latent violations, unsafe internal exposure.
- Statistical reporting: bootstrap confidence intervals over tasks and paired
  deltas for guarded vs naive.

Suggested wording:

> We report the main leaderboard only on `v0_2_test`. Guarded prompting is a paired
> prompt-only condition on the same scenarios. Transient and compositional suites are
> reported separately as targeted analyses and are not mixed into the headline
> leaderboard.

### 7.2 RQ1: How safe are current agents under TraceProbe?

Data:

- `v0_2_test`, `naive`.
- All main models.

Metrics:

- TSR, SVR, ASR, STCR.
- Resource overrun.
- Latent violation rate.
- Unsafe internal exposure.

Expected supported finding:

> Strong models achieve high task success but still produce non-trivial safety
> violations in executable agentic scenarios.

How to write the result:

> Across [N] models, TraceProbe reveals a wide spread in safe task completion. The
> best-performing models substantially reduce safety violations, but no model
> eliminates them. In several cases, high task success coexists with measurable
> latent or trace-level violations, showing that capability and safety do not move in
> lockstep.

Figure:

- Figure 3: main model outcome comparison.

Table:

- Main leaderboard with TSR, SVR, ASR, STCR, 95% CI, number of evaluable tasks.

### 7.3 RQ2: Are prompt-only safety reminders enough?

Data:

- Same `v0_2_test`.
- `naive` vs `guarded`.

Metrics:

- Paired delta in TSR, SVR, STCR, latent violation rate.
- Family-level deltas for high-risk families.

Expected supported finding:

> Guarded prompting changes model behavior but does not reliably eliminate agentic
> safety failures and can trade off with task utility.

How to write:

> Guarded prompting reduces some direct violations for some models, but the effect is
> inconsistent across families and models. In several conditions, guarded prompting
> improves refusal-like behavior without addressing trajectory-level hazards such as
> sensitive reads or internal-message exposure. We therefore treat guarded prompting
> as a prompt-only safety-awareness baseline, not a defense. The guarded prompt asks
> agents to treat retrieved content, tool output, logs, config text, memory, prior
> notes, and other agents' messages as untrusted evidence unless explicitly part of
> trusted system instructions; it does not add enforcement, permission checks, tool
> isolation, or memory integrity mechanisms.

Figure:

- Delta heatmap or paired slope chart, main paper if space allows, otherwise
  appendix.

### 7.4 RQ3: Do aggregate scores hide different failure mechanisms?

Data:

- Main `naive` runs.
- Family breakdown and attribution breakdown.

Metrics:

- Per-family SVR/ASR/STCR.
- Per-family latent violation rate.
- Attribution distributions by source/channel/mechanism/component.

Expected supported finding:

> Similar aggregate scores can correspond to different failure profiles.

How to write:

> Models with similar overall ASR often fail in different ways. Some are dominated by
> internal authority compromise, especially policy-prompt or multi-agent-message
> channels; others are more vulnerable to retrieved-content or tool-output injection.
> Non-adversarial and data-minimization scenarios expose a separate axis where agents
> can complete tasks by crossing boundaries even without an attacker.

Important nuance:

> Because A2, A3, and C1 are 5-sample promoted gap probes, we use them to identify
> possible risk directions rather than to make strong family-level statistical
> claims.

Figure:

- Family-level failure heatmap.

### 7.5 RQ4: Can failure attribution be recovered from execution evidence?

Data:

- Structured attribution evidence extracted from export traces.
- Optional replay-grounded evidence, when replay has been run.
- Deterministic evidence-rule attribution analysis.
- Evidence-grounded LLM attribution analysis, if run.
- Raw-trace LLM judge only as a weak baseline / ablation, not as the main method.
- Ground-truth attribution labels.

Metrics:

- Source accuracy.
- Channel accuracy.
- Mechanism accuracy/F1.
- First failed component accuracy/F1.
- Impact accuracy.
- Block point match.
- Failure-chain overlap.
- Evidence-supported prediction rate.
- Invalid evidence-reference rate.
- Abstention rate.

Expected supported finding:

> Coarse attribution signals can be recovered from structured execution evidence,
> especially source and channel. Fine-grained mechanism, component, and block-point
> labels remain harder, and raw LLM trajectory judgment is less reliable than
> evidence-grounded recovery.

How to write:

> Because prior work has shown raw LLM trajectory judgment to be unreliable,
> TraceProbe does not use LLM judgments as safety labels or attribution ground
> truth. Each scenario instead provides task-side attribution annotations, and
> post-hoc analysis first extracts structured, redacted execution evidence from
> traces and replay outputs. We then evaluate deterministic and constrained LLM
> recovery baselines against the benchmark labels. The constrained LLM sees only
> evidence packets, must choose from the closed TraceProbe schema, and must cite
> evidence event identifiers; unsupported predictions are counted separately. This
> turns LLM participation into an auditable recovery baseline rather than a
> free-form judge.

Figure:

- Attribution recovery bar chart by dimension.
- Evidence-support quality chart.
- Raw-trace LLM judge ablation or appendix confusion matrices.

### 7.6 RQ5: Does endpoint safety imply trajectory safety?

Data:

- `v0_2_transient`.
- Replay analysis on selected main benchmark runs.
- Latent violation labels from outcome scorer.

Metrics:

- Latent violation rate.
- Transient unsafe modification rate.
- Replay first sensitive read / first watched-path mutation / first risk-positive
  step.
- Fraction of endpoint-safe but trajectory-unsafe runs.

Expected supported finding:

> Endpoint-safe runs can still contain latent trajectory violations.

How to write:

> In the transient pilot, some runs restore a clean final state while still crossing a
> safety boundary during execution. Replay localizes these crossings to specific
> tool steps, showing that final-state scoring alone can miss process violations.
> This supports treating trajectory safety as a distinct evaluation target.

Figure:

- Replay-grounded failure localization.
- Timeline case study.

If space is limited, fold RQ5 into the replay/case-study section rather than making
it a full main RQ.

### 7.7 RQ6: What happens when multiple hazards coexist?

Data:

- `mvp_compositional_playground`.
- Clean / single / combo / reverse-combo variants.
- Replay dominance analyzer.

Metrics:

- Outcome rates by composition type.
- Dominant hypothesis supported / contradicted.
- Masking, amplification, and order-effect counts.
- Single-to-combo path overlap.

Expected supported finding:

> Multi-risk scenarios are not simple sums of single-risk scenarios; observed failure
> paths can show dominance, masking, amplification, and order effects.

How to write:

> The compositional playground shows that a hazard configured in a scenario is not
> necessarily the hazard that explains the observed failure. Replay dominance
> distinguishes configured hazards from activated hazards and reveals cases where a
> single hazard dominates the combo path, where one hazard masks another, or where
> reversing the order changes the first failure evidence.

Figure:

- Compositional dominance figure.

Reporting rule:

> Keep this as supplementary or a compact final RQ. Do not mix it with the main
> leaderboard.

---

## 8. Results Narrative

This section is the qualitative story the final results should support. Replace
bracketed placeholders with exact numbers after the complete experiment run.

### Finding 1: Strong agents still fail in controlled executable scenarios.

Paper prose:

> The main TraceProbe leaderboard shows that current frontier and strong open models
> do not collapse on utility: many complete a substantial fraction of tasks.
> Nevertheless, all evaluated models produce measurable safety violations. The best
> models reduce ASR and SVR substantially, but the residual violations are not rare
> edge cases; they occur across multiple risk channels and include both final-output
> violations and latent trajectory events.

What this supports:

- TraceProbe is not too easy.
- TraceProbe is not only measuring incapability.
- Agent safety remains a live problem even for strong models.

### Finding 2: Safety reminders are insufficient.

Paper prose:

> The guarded condition improves some outcomes but does not consistently solve the
> benchmark. In particular, prompt-only reminders do not reliably prevent the agent
> from reading sensitive paths, over-trusting internal authority, or treating
> untrusted retrieved/tool content as instructions. This suggests that agent safety
> failures require structural evaluation and targeted interventions rather than only
> stronger wording in the prompt.

What this supports:

- TraceProbe is not just a prompt engineering benchmark.
- Future defenses need channel isolation, tool permission checks, memory integrity,
  and pre-action verification.

### Finding 3: Aggregate scores hide mechanism differences.

Paper prose:

> Overall ASR and SVR hide large variation across risk families. Some models are
> comparatively robust to external retrieved-content injection but vulnerable to
> internal policy or multi-agent authority signals; others exhibit the opposite
> pattern. This matters because two models with similar aggregate scores would
> require different mitigations.

What this supports:

- Family heatmaps are central, not appendix-only.
- Attribution labels are analytically useful.

### Finding 4: Internal authority compromise is a distinct risk surface.

Paper prose:

> Internal authority channels produce failures that differ from ordinary external
> prompt injection. Policy prompts, memory state, and multi-agent messages often look
> more authoritative to the agent than retrieved or user-provided content, making
> them difficult to handle with simple untrusted-content heuristics. TraceProbe
> exposes this risk surface by separating B1/B2/B3 from external C-family attacks.

What this supports:

- B family is a paper contribution, not just extra examples.
- This helps differentiate from prompt-injection-only benchmarks.

### Finding 5: Endpoint-safe does not mean trajectory-safe.

Paper prose:

> Several runs that appear safe under final-output or final-state criteria contain
> latent trajectory violations, including sensitive reads, unsafe internal-message
> exposure, transient unsafe modifications, or watched-path mutations. Replay
> localizes these events to specific tool steps, demonstrating that endpoint-only
> safety evaluation can miss process failures.

What this supports:

- Replay and latent violations are necessary.
- Case studies should be in the main paper if space allows.

### Finding 6: Multi-risk settings require observed-path analysis.

Paper prose:

> In compositional scenarios, the hazard specified by the recipe is not always the
> hazard that explains the observed failure. Some combo settings follow the same path
> as a single dominant hazard, while others show masking, amplification, or order
> effects. Replay dominance analysis prevents overinterpreting YAML configuration as
> causal evidence.

What this supports:

- The playground is a meaningful supplementary contribution.
- The paper can discuss more extreme multi-risk settings without making them the main
  benchmark.

---

## 9. Case Study Templates

Use two or three case studies. Each case must be short and structured. Avoid long
trace dumps.

### 9.1 Case Study A: External Injection Through Retrieved or Tool Content

Goal:

- Show how untrusted content becomes an instruction.
- Show first sensitive read or unsafe sink.
- Show replay-localized evidence.

Template:

```text
Task. The user asks the agent to [benign task].
Hazard. A retrieved document/tool output contains [malicious instruction].
Observed behavior. The agent treats the untrusted content as authority and [unsafe action].
Outcome. The final output/state [violates / does not visibly violate] the safety criterion.
Replay evidence. Exact replay localizes the first sensitive read at step [k] and the first
risk-positive probe at step [m].
Attribution. source=external_attack, channel=[retrieved_content/tool_output],
mechanism=untrusted_content_confusion, block_point=untrusted_content_isolation.
```

### 9.2 Case Study B: Internal Authority Compromise

Goal:

- Show why internal-looking content is dangerous.
- Prefer B3 if internal-message exposure is clear, or B1/B2 if policy/memory
  authority is the issue.

Template:

```text
Task. The executor receives a normal user-facing task, but an internal message or
memory state contains [unsafe authority signal].
Observed behavior. The agent follows the internal signal and [unsafe action/leak].
Outcome. The run shows [unsafe internal exposure / sensitive access / policy bypass].
Replay evidence. The unsafe event appears after [internal message/memory] is consumed,
with first evidence at step [k].
Attribution. source=internal_compromise, channel=[multi_agent_message/memory_state/
policy_prompt], mechanism=false_authorization or authority_confusion.
```

### 9.3 Case Study C: Non-Adversarial Boundary Failure

Goal:

- Show that not all safety failures require an attacker.
- Good choices: A1/A4, or A2/A3 as probe examples if clearly explained.

Template:

```text
Task. The user asks for a legitimate maintenance/data-processing action.
Hazard. No attacker is present; the risk arises from ambiguous scope or execution
pressure.
Observed behavior. The agent over-generalizes the task and crosses a boundary by
[reading/deleting/uploading/modifying] an out-of-scope resource.
Replay evidence. The first boundary crossing occurs at step [k].
Attribution. source=non_adversarial, mechanism=[boundary_overreach/data_minimization_
failure/faulty_inference/unstable_execution], block_point=pre_action_verification.
```

### 9.4 Case Study D: Compositional Dominance

Use only if there is a clean compact example.

Template:

```text
Clean. The substrate completes safely without hazards.
Single H1. The first unsafe evidence is [event].
Single H2. The hazard is [activated/not activated].
Combo. The first unsafe evidence matches H1's single path, supporting H1 as the
dominant observed path.
Reverse combo. Reversing hazard order [does/does not] change first failure evidence.
Conclusion. The configured dominant hazard is [supported/contradicted/masked] by replay.
```

---

## 10. Figures and Tables

Use the plan in `plot.md`. For the main paper, the ideal figure set is:

1. **Figure 1: TraceProbe pipeline.**
   - Shows executable YAML -> live execution -> trace export -> scorer -> replayer
     -> attribution analysis.
2. **Figure 2: Risk-source and attribution taxonomy.**
   - Shows A/B/C risk families and attribution schema.
3. **Figure 3: Main model outcome comparison.**
   - Shows TSR/SVR/ASR/STCR or TSR-vs-SVR scatter.
4. **Figure 4: Family-level failure heatmap.**
   - Shows how models fail differently across families.
5. **Figure 5: Replay-grounded failure localization.**
   - Shows replay fidelity and first safety-evidence steps, plus one timeline.
6. **Figure 6: Compositional dominance analysis.**
   - Shows clean/single/combo/reverse-combo and dominance/masking/order effects.

If space is tight, demote Figure 2 or guarded-delta plots to appendix. Keep Figures
1, 3, 4, and 5 if possible.

Main tables:

| Table | Content | Location |
| --- | --- | --- |
| Table 1 | Dataset composition and family counts | Dataset section or appendix |
| Table 2 | Main leaderboard with TSR/SVR/ASR/STCR and CI | Results |
| Table 3 | Comparison with related benchmarks | Related work or appendix |
| Table 4 | Attribution schema definitions | Method or appendix |
| Table 5 | Guarded paired deltas | Results or appendix |

The related-work comparison table should emphasize design differences, not universal
superiority.

---

## 11. Discussion Section

The discussion should make three broader points.

### 11.1 Evaluation Should Separate Outcome, Trajectory, and Attribution

Paper prose:

> TraceProbe suggests that agent safety evaluation should report at least three
> layers: endpoint outcomes, trajectory-level latent events, and attribution-level
> failure mechanisms. These layers answer different questions and can disagree in
> important ways.

### 11.2 Diagnosis Enables Better Defense Design, But TraceProbe Is Not a Defense

Paper prose:

> TraceProbe does not propose a mitigation system. Instead, it identifies where
> mitigations should operate: untrusted-content isolation, memory integrity checks,
> internal-message isolation, tool-output verification, pre-action permission checks,
> and output filtering. This separation is important because a single aggregate ASR
> cannot tell practitioners which control is missing.

### 11.3 Controlled Scenarios Are a Feature, Not Only a Limitation

Paper prose:

> TraceProbe uses controlled workflow-inspired scenarios rather than unconstrained
> production environments. This choice trades some environmental breadth for
> attribution validity: each scenario has a known hazard source, expected channel,
> and counterfactual block point. We view this as complementary to broad realistic
> benchmarks.

---

## 12. Limitations

Be explicit. This will make the paper stronger.

1. **Representative, not exhaustive.** TraceProbe covers representative risk sources
   across non-adversarial, internal-compromise, and external-attack settings, but it
   does not cover all agent safety risks.
2. **Controlled workflows.** The scenarios are workflow-inspired and executable, but
   they are not full production systems.
3. **Unbalanced family sizes.** The main v0.2 split has 155 tasks. Core families have
   20 scenarios, while A2/A3/C1 are 5-scenario promoted gap probes.
4. **Attribution labels encode intended controlled hazards.** They should not be
   interpreted as proof that every observed run follows the intended causal path.
   This is why trace and replay analysis matter.
5. **Replay is exact-action evidence, not causal proof.** It validates and localizes
   recorded actions but does not by itself prove counterfactual causality.
6. **Raw LLM trajectory judgment is imperfect.** We do not use LLM judgments as
   safety labels or attribution ground truth. LLMs appear only as constrained
   evidence-grounded recovery baselines, and unsupported predictions are counted
   separately.
7. **Model and provider drift.** Some evaluated models may change over time. The
   paper should report model IDs, dates, endpoints, and runtime metadata where
   possible.

---

## 13. Claims to Avoid

Avoid:

- "TraceProbe is the first agent safety benchmark."
- "TraceProbe is more realistic than OpenAgentSafety or AgentDojo."
- "TraceProbe comprehensively covers all agent risks."
- "Trace replay proves causality."
- "LLM judge provides reliable causal attribution."
- "Raw trace LLM judgment is our attribution method."
- "Guarded prompting is a defense."
- "A configured hazard is the same as an activated hazard."

Prefer:

- "TraceProbe is attribution-oriented."
- "TraceProbe is complementary to broad agent-safety benchmarks."
- "TraceProbe covers representative risk sources."
- "Replay provides execution-grounded evidence."
- "Guarded prompting is a prompt-only baseline."
- "Compositional analysis distinguishes configured hazards from observed failure
  paths."

---

## 14. Section-by-Section Paper Outline

### 1. Introduction

Length target: 1 to 1.25 pages.

Content:

- Start with concrete agent failure.
- Explain why endpoint-only evaluation is insufficient.
- Introduce trajectory-aware attribution.
- Summarize TraceProbe and contributions.
- Preview findings.

### 2. Related Work

Length target: 0.75 to 1 page.

Content:

- General LLM safety benchmarks.
- Agent capability benchmarks.
- Agent safety/security benchmarks.
- Trajectory diagnosis and attribution.
- Optional compositional stress testing.

Key contrast:

> TraceProbe evaluates live scenario-grounded behavior and makes attribution labels
> first-class benchmark targets.

### 3. TraceProbe Benchmark

Length target: 2 pages.

Content:

- Design goals.
- Scenario YAML and sandbox execution.
- Risk-source taxonomy.
- Attribution schema.
- Dataset composition.
- Trace export and outcome metrics.

### 4. Trace Replay and Analysis

Length target: 1 page.

Content:

- Why replay is needed.
- Exact replay definition.
- Stepwise safety probes.
- Watched-path diffs.
- Replay outputs.
- What replay can and cannot claim.

This can also be a subsection under Benchmark if page budget is tight.

### 5. Experimental Setup

Length target: 0.75 page.

Content:

- Models.
- Baselines.
- Splits and reporting rules.
- Metrics.
- Confidence intervals.
- Runtime metadata and reproducibility.

### 6. Results

Length target: 2 to 2.5 pages.

Recommended subsections:

- RQ1 Main leaderboard.
- RQ2 Guarded prompting.
- RQ3 Family and attribution breakdown.
- RQ4 Attribution recovery.
- RQ5 Replay, transient violations, and compositional analysis.

If the paper gets crowded, move RQ2 and RQ4 details to appendix and keep their
headline results in the main text.

### 7. Case Studies

Length target: 0.75 page.

Use 2-3 compact timelines.

### 8. Discussion and Limitations

Length target: 0.75 to 1 page.

Content:

- Outcome vs trajectory vs attribution.
- TraceProbe as diagnosis, not defense.
- Limitations.
- Future work: counterfactual replay, broader risk families, stronger stress suites.

---

## 15. Final Paper Spine

If the whole paper must be compressed into a single spine, use this:

1. **Problem:** Agent failures unfold through trajectories, not just final answers.
2. **Gap:** Existing benchmarks report outcomes but rarely provide structured,
   execution-grounded attribution.
3. **Method:** TraceProbe provides executable scenarios with attribution ground truth,
   sandboxed traces, outcome/latent scoring, and trace replay.
4. **Evidence:** Across models, strong agents still fail; guarded prompting is
   insufficient; aggregate scores hide family-specific mechanisms.
5. **Diagnosis:** Replay and attribution labels localize where failures enter and
   propagate, including endpoint-safe but trajectory-unsafe runs.
6. **Stress:** Compositional scenarios show that configured hazards can be activated,
   masked, dominant, or order-dependent.
7. **Conclusion:** Agent safety evaluation should move beyond outcome metrics toward
   execution-grounded failure attribution.

This is the narrative to preserve even if sections are reorganized.
