# HoneyGuard Related Work Notes

Last updated: 2026-05-08

This note is meant to support the EMNLP paper writing process. It is not the final
Related Work section. The goal is to map nearby work, decide how to frame
HoneyGuard, and keep a comparison table that makes the contribution boundary clear.

## 0. Recommended Positioning

The safest high-level claim is:

> HoneyGuard is a trajectory-aware benchmark for attribution-level diagnosis of
> agent safety failures.

Avoid presenting HoneyGuard as merely "another agent safety benchmark." The closest
neighbors already cover broad agent safety and prompt-injection settings. The paper
should instead emphasize four differentiators:

1. **Attribution as first-class ground truth.** HoneyGuard labels not only whether a
   run fails, but also source, channel, mechanism, first failed component, impact,
   block point, and failure chain.
2. **Unified risk-source taxonomy.** HoneyGuard compares non-adversarial failures,
   internal authority contamination, and external attacks in one schema.
3. **Trajectory-level latent violations.** HoneyGuard scores process failures even
   when the final endpoint appears safe.
4. **Compositional stress controls.** The playground creates clean / single / combo /
   reverse-combo variants, enabling dominance, masking, synergy, and order-effect
   analysis.

The related-work section should be written so that OpenAgentSafety and AgentDojo look
like important inspirations and baselines, not like papers we are trying to outsize.
HoneyGuard's novelty is narrower but sharper: diagnosable failure attribution.

## 1. Literature Map

### 1.1 General LLM Safety and Red-Teaming Benchmarks

These works evaluate harmful responses, refusal behavior, jailbreak robustness, or
broad safety taxonomies for language models. They are useful background, but they are
not enough for agentic systems because they usually focus on input-output behavior
rather than multi-step tool execution.

Representative works:

- **SafetyBench**: broad safety evaluation for LLMs. Useful as background for safety
  taxonomy, but not agent-specific.
- **HarmBench**: standardized evaluation for automated red teaming and harmful
  behavior robustness. Strong for harmful content and jailbreak-style evaluation, but
  mostly endpoint-focused.
- **JailbreakBench**: open benchmark for jailbreak robustness. Relevant for refusal
  evaluation, less directly relevant for tool-use traces.
- **SALAD-Bench**: hierarchical and comprehensive safety benchmark for LLMs. Useful
  for taxonomy framing, but again mostly not about tool-mediated agent trajectories.

How to write this paragraph:

> General LLM safety benchmarks have made harmful-content and jailbreak evaluation
> more systematic. However, agentic failures can occur through intermediate actions,
> tool calls, memory state, retrieved content, and multi-agent messages. HoneyGuard
> therefore shifts the unit of evaluation from a final response to an execution
> trajectory with attribution labels.

### 1.2 General Agent Capability Benchmarks

These works evaluate whether LLM agents can solve tasks in interactive environments.
They are important for establishing agent benchmarks as a category, but most are not
designed to diagnose safety failure causes.

Representative works:

- **AgentBench**: evaluates LLMs as agents across interactive environments.
- **WebArena**: realistic web environment for autonomous agents.
- **OSWorld**: open-ended computer-use benchmark for multimodal agents.
- **tau-bench**: benchmark for tool-agent-user interactions in realistic domains.
- **ToolBench / API-Bank-style work**: evaluates tool use, API calling, and action
  planning.

How to write this paragraph:

> Existing agent benchmarks emphasize task completion in realistic or simulated
> environments. HoneyGuard is complementary: its scenarios are controlled rather than
> maximally open-ended, because the goal is to isolate safety mechanisms and provide
> attribution ground truth.

### 1.3 Tool-Use Risk and Agent Safety Benchmarks

These are the closest broad agent-safety neighbors.

Representative works:

- **ToolEmu**: identifies risks of language-model agents using an LLM-emulated
  sandbox. It is close in spirit because it evaluates tool-use risk, but its main
  focus is scalable risk discovery / simulation rather than benchmark-level
  attribution labels for executed traces.
- **AgentHarm**: measures harmfulness of LLM agents. It is important for agentic
  harmful-action evaluation, but HoneyGuard differs by focusing on failure diagnosis
  and process attribution.
- **Agent Security Bench (ASB)**: formalizes and benchmarks attacks and defenses in
  LLM-based agents. It is a strong security-oriented benchmark. HoneyGuard should be
  framed as complementary: less focused on attack/defense breadth, more focused on
  trajectory-level causal labels.
- **OpenAgentSafety**: the closest broad benchmark. It evaluates LLM-agent safety
  across realistic tool-based tasks and multiple risk categories. HoneyGuard must not
  claim novelty simply from being "agent safety." The differentiator is the structured
  attribution layer and compositional controls.

How to write this paragraph:

> Recent agent-safety benchmarks have moved beyond static harmful prompts toward
> tool-using agents in realistic workflows. HoneyGuard builds on this trend, but
> targets a different evaluation question: not only whether an agent is unsafe, but
> where the safety failure entered, which component first accepted it, which mechanism
> propagated it, and where an intervention could have blocked the failure.

### 1.4 Prompt Injection, Indirect Prompt Injection, and Agent Security

These works are essential because HoneyGuard includes C1 / C2.1 / C2.2 families.
However, HoneyGuard should avoid being positioned as a prompt-injection benchmark.
Prompt injection is one risk source among several.

Representative works:

- **Indirect prompt injection attacks against LLM-integrated applications**:
  foundational line showing that untrusted external content can manipulate
  LLM-integrated systems.
- **InjecAgent**: benchmarks indirect prompt injections in tool-integrated LLM agents.
  This is directly relevant for retrieved-content and tool-output injection.
- **AgentDojo**: dynamic environment for evaluating attacks and defenses for LLM
  agents. It is a major close work for utility-security tradeoffs under prompt
  injection.
- **Prompt-injection defense work**: instruction hierarchy, context isolation,
  prompt filtering, tool-output sanitization, and privilege separation.

How to write this paragraph:

> Prompt-injection work demonstrates that agents can confuse instructions with
> untrusted data. HoneyGuard includes these external attacks, but also evaluates
> internal authority contamination and non-adversarial failures. This allows the paper
> to ask whether failures caused by retrieved content, tool output, memory state,
> policy prompts, and multi-agent messages have distinguishable attribution patterns.

### 1.5 Trajectory-Level Diagnosis, Intrinsic Risk, and Attribution

This is the most important conceptual related-work bucket for HoneyGuard. These works
move beyond final-answer evaluation toward detecting or diagnosing unsafe trajectories.

Representative works:

- **ATBench / trajectory-safety benchmark work**: recent work explicitly arguing that
  agent safety must be evaluated over action trajectories rather than final responses.
- **HINTBench / intrinsic non-attack risk benchmark work**: evaluates cases where
  agents enter unsafe trajectories under benign conditions, with risk-step
  localization and intrinsic failure-type identification.
- **AgentRx-style failure detection and repair work**: recent work on diagnosing
  agent failures and proposing repair or monitoring mechanisms.
- **Trace-based LLM-as-judge analyses**: work using model judges or rule systems to
  inspect intermediate reasoning / actions.

How to write this paragraph:

> Trajectory-aware evaluation is increasingly recognized as necessary for agents.
> HoneyGuard contributes a benchmark design where trajectory diagnosis is grounded in
> explicit per-scenario attribution labels: source, channel, mechanism, first failed
> component, impact, block point, and failure chain. This lets us evaluate not only
> endpoint safety, but also whether attribution can be recovered from traces.

Important distinction:

> Many trajectory-diagnosis benchmarks evaluate **trajectory auditing**: the model is
> given an existing trajectory and must decide whether it is safe, localize a risky
> step, or assign a failure category. HoneyGuard evaluates **scenario-grounded agent
> behavior**: the model is placed in an executable scenario, produces its own actions,
> and is then scored against outcome criteria and attribution ground truth.

This distinction should be used carefully. Do not claim that prior trajectories are
"fake" or useless. The stronger point is that static trajectory auditing has a
different validity profile:

- If unsafe trajectories are manually or synthetically constructed from a presumed
  causal path, the benchmark may encode annotator assumptions about how a risk should
  unfold.
- A trajectory-level judge may learn to recognize the benchmark's written failure
  pattern, but that does not necessarily show that it can predict which actions a
  live agent would actually take in the same environment.
- Static trajectories can test detection and localization, but they cannot directly
  measure attack uptake, refusal, recovery, tool choice, or resource use under live
  execution.
- Causal direction can be hard to validate: a trajectory may be labeled as
  "risk A causes unsafe behavior B," while an actual agent might ignore A, fail for a
  different reason, recover before B, or produce a different unsafe behavior.

HoneyGuard's contrast:

- It starts from executable scenario YAMLs rather than fixed completed trajectories.
- The evaluated model must interact with files, tools, memory/context, and agents.
- Outcome and latent-trajectory metrics are computed from the produced run.
- A trace replayer can rebuild the task YAML in a fresh sandbox and replay recorded
  tool calls, providing execution-grounded validation of the exported trace.
- Stepwise replay probes can localize the first sensitive read, untrusted sink,
  safety-criterion failure, risk-positive probe, or watched-path mutation.
- Attribution labels describe the intended controlled hazard and expected failure
  mechanism, while the trace lets us check whether the model actually followed that
  path.
- Clean / single / combo / reverse-combo controls make it possible to ask whether the
  assumed hazard is actually dominant, masked, or order-dependent.

Suggested wording:

> Trajectory-auditing benchmarks are valuable for testing whether models can inspect
> and localize unsafe behavior in already-realized traces. HoneyGuard instead uses
> executable controlled scenarios, allowing the evaluated agent to generate the trace
> itself. This avoids treating a hand-specified risky trajectory as the only plausible
> realization of a hazard, and lets us test whether the intended risk source actually
> induces unsafe behavior, is ignored, is masked by another hazard, or appears only as
> a latent trajectory violation.

### 1.6 Compositional and Multi-Risk Evaluation

This is where the new playground should be positioned. Most benchmarks evaluate
single-scenario or single-attack conditions. HoneyGuard's compositional playground is
not the main benchmark, but it lets the paper ask additional diagnostic questions.

Key idea:

- Generate ordinary runnable scenarios from `substrate + hazard plugin + recipe`.
- Compare `clean`, `single`, `combo`, and `combo_reverse`.
- Analyze dominance, masking, synergy, and order effects.

How to write this paragraph:

> Most safety benchmarks evaluate isolated risk conditions. In practice, agent
> failures may involve multiple simultaneous hazards, such as a poisoned memory state
> plus a malicious tool output. HoneyGuard includes an optional compositional stress
> suite that controls single-risk and multi-risk variants over the same substrate,
> enabling analysis of whether one risk dominates, masks another, or changes behavior
> under different ordering.

## 2. Core Works to Cite

Use the following as the minimum citation set for the final paper.

### Must-Cite Close Neighbors

- OpenAgentSafety: broad LLM-agent safety framework.
  - Link: https://arxiv.org/abs/2507.06134
- AgentDojo: attacks and defenses for LLM agents.
  - Link: https://arxiv.org/abs/2406.13352
- InjecAgent: indirect prompt injection in tool-integrated LLM agents.
  - Link: https://aclanthology.org/2024.findings-acl.624/
- Agent Security Bench / ASB: security benchmark for LLM agents.
  - Link: https://arxiv.org/abs/2410.02644
- AgentHarm: measuring harmfulness of LLM agents.
  - Link: https://arxiv.org/abs/2410.09024
- ToolEmu: risks of LM agents with LM-emulated sandbox.
  - Link: https://arxiv.org/abs/2309.15817

### Agent Capability / Tool-Use Context

- AgentBench: evaluating LLMs as agents.
  - Link: https://arxiv.org/abs/2308.03688
- WebArena: realistic web environment for autonomous agents.
  - Link: https://arxiv.org/abs/2307.13854
- OSWorld: open-ended computer-use benchmark.
  - Link: https://arxiv.org/abs/2404.07972
- tau-bench: tool-agent-user interaction benchmark.
  - Link: https://arxiv.org/abs/2406.12045

### General LLM Safety Background

- HarmBench.
  - Link: https://arxiv.org/abs/2402.04249
- JailbreakBench.
  - Link: https://arxiv.org/abs/2404.01318
- SALAD-Bench.
  - Link: https://arxiv.org/abs/2402.05044
- SafetyBench.
  - Link: https://arxiv.org/abs/2309.07045

### Indirect Prompt Injection Foundations

- Not what you've signed up for: indirect prompt injection against LLM-integrated
  applications.
  - Link: https://arxiv.org/abs/2302.12173
- Prompt injection attacks against LLM-integrated applications.
  - Link: https://arxiv.org/abs/2306.05499

### Trajectory / Diagnosis / Attribution Neighbors

Check these again near submission, because several are recent preprints:

- ATBench.
  - Link: https://arxiv.org/abs/2604.02022
- HINTBench.
  - Link: https://arxiv.org/abs/2604.13954
- AgentRx / agent failure diagnosis and repair line.
  - Link: https://arxiv.org/abs/2602.02475

## 3. Comparison Table

Legend:

- Strong: central design goal of the work.
- Partial: present, but not the main focus or less structured.
- No / Limited: absent or not emphasized.
- HoneyGuard claims should be phrased as design differences, not as universal
  superiority.

| Work | Main Scope | Agent / Tool Execution | Safety Focus | Trajectory Evidence | Attribution Ground Truth | Internal Authority Risks | Non-Adversarial Failures | Compositional Controls | HoneyGuard Positioning |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SafetyBench / SALAD-Bench | General LLM safety taxonomy | Limited | Harmful content / safety categories | Limited | No | No | Partial | No | Background only; not agent-trajectory focused. |
| HarmBench / JailbreakBench | Red teaming and jailbreak robustness | Limited | Harmful response / refusal robustness | Limited | No | No | No | No | Useful for endpoint safety framing; HoneyGuard targets agent actions and traces. |
| AgentBench | General agent capability | Strong | Mostly task success | Partial | No | No | Partial | No | Establishes agent evaluation; HoneyGuard focuses on safety diagnosis. |
| WebArena / OSWorld | Realistic web or computer-use tasks | Strong | Mostly capability / task completion | Partial | No | No | Partial | No | More realistic environments; HoneyGuard uses controlled scenarios for attribution. |
| tau-bench | Tool-agent-user interaction | Strong | Reliability / task success | Partial | No | No | Partial | No | Useful context for tool-agent evaluation; not primarily safety attribution. |
| ToolEmu | Tool-use risk discovery with simulated tools | Strong / simulated | Tool-use risks | Partial | Limited | Limited | Partial | Limited | Similar concern with tool risk; HoneyGuard adds executable scenario labels and attribution scoring. |
| InjecAgent | Indirect prompt injection in tool-integrated agents | Strong | External injection | Partial | Limited | No | No | Limited | Close for C2-style attacks; HoneyGuard covers broader source taxonomy and failure attribution. |
| AgentDojo | Attacks and defenses for LLM agents | Strong | Prompt injection / security under utility tasks | Strong | Limited | Limited | No / Partial | Partial | Strong close work; HoneyGuard should emphasize attribution labels and internal/non-adversarial sources. |
| ASB | Agent security benchmark | Strong | Attacks and defenses | Strong | Partial | Partial | Limited | Partial | Security benchmark neighbor; HoneyGuard is more attribution-diagnostic than attack/defense-centric. |
| AgentHarm | Harmfulness of LLM agents | Strong | Harmful agent behavior | Partial | Limited | Limited | Limited | No | Strong harmfulness benchmark; HoneyGuard diagnoses how failures arise and propagate. |
| OpenAgentSafety | Broad LLM-agent safety framework | Strong | Multi-risk agent safety | Strong | Partial / judge-based | Partial | Partial | Limited | Closest broad benchmark. HoneyGuard must differentiate via structured attribution ground truth and compositional controls. |
| ATBench / trajectory-safety line | Trajectory-level safety | Strong | Unsafe trajectories | Strong | Partial | Partial | Partial | Limited | Very close conceptually; HoneyGuard's angle is explicit failure-source/channel/mechanism/component/block-point labels. |
| HINTBench / intrinsic-risk line | Non-attack intrinsic trajectory risk | Strong | Latent / intrinsic unsafe behavior | Strong | Partial | Partial | Strong | Limited | Close on benign-condition trajectory risk; HoneyGuard additionally compares internal compromise and external attacks under one attribution schema. |
| AgentRx | Failure localization and diagnosis from trajectories | Strong | General agent failure diagnosis | Strong | Strong for critical-step/category labels | Partial | Partial | No | Very close on trajectory diagnosis; HoneyGuard focuses specifically on safety hazards with controlled source/channel/mechanism/block-point ground truth. |
| HoneyGuard | Attribution-level agent safety benchmark | Strong | Non-adversarial + internal compromise + external attack | Strong | Strong | Strong | Strong | Strong | Core claim: diagnosable, trace-grounded safety failures with optional multi-risk stress testing. |

## 4. Suggested Related Work Structure for the Paper

Recommended final Related Work should be 4-5 paragraphs, not an exhaustive survey.

### Paragraph 1: General LLM Safety Is Endpoint-Oriented

Mention SafetyBench, HarmBench, JailbreakBench, and SALAD-Bench. The purpose is to
show that LLM safety evaluation is mature, but its default unit is still prompt /
response or harmful-content behavior.

Key transition:

> Agent safety requires evaluating actions and intermediate state transitions, not
> only final text.

### Paragraph 2: Agent Benchmarks Measure Capability, Not Failure Causes

Mention AgentBench, WebArena, OSWorld, tau-bench, ToolBench / API-Bank-style work.
The purpose is to position HoneyGuard as a benchmark that sacrifices some
open-ended realism to gain controlled causal attribution.

Key transition:

> High-fidelity environments are valuable, but diagnosing safety requires controlled
> scenarios with known hazard sources and expected block points.

### Paragraph 3: Agent Security Benchmarks Cover Attacks and Defenses

Mention AgentDojo, InjecAgent, ASB, ToolEmu, AgentHarm, OpenAgentSafety. This is the
most important paragraph. Be respectful and explicit:

- AgentDojo / InjecAgent: external prompt injection and security tradeoffs.
- ASB: attack-defense formalization.
- AgentHarm: harmful action benchmark.
- OpenAgentSafety: broad agent-safety framework.

Key transition:

> HoneyGuard is complementary: it is not primarily an attack benchmark or a defense
> benchmark, but an attribution benchmark for explaining agent failures.

### Paragraph 4: Trajectory-Level Diagnosis and Attribution

Mention ATBench / HINTBench / trace-based judge work. This paragraph anchors the
novelty claim.

Key transition:

> HoneyGuard makes attribution explicit and benchmarkable by labeling the source,
> channel, mechanism, first failed component, impact, counterfactual block point, and
> failure chain for each scenario.

### Optional Paragraph 5: Compositional Stress Testing

Use only if the paper includes RQ5. Keep it short and label it as supplementary.

Key transition:

> Beyond isolated scenarios, HoneyGuard includes a compositional playground that
> generates controlled clean / single / combo / reverse-combo variants, enabling
> dominance and order-effect analysis.

## 5. Draft Related Work Text

This is a rough draft that can be converted into paper prose.

> General LLM safety benchmarks have standardized evaluation of harmful responses,
> jailbreak robustness, and broad safety taxonomies. Benchmarks such as SafetyBench,
> HarmBench, JailbreakBench, and SALAD-Bench provide important tools for measuring
> whether models produce unsafe content. However, agentic systems introduce safety
> failures that may occur before the final response, through tool calls, file access,
> retrieved content, memory, or multi-agent communication. HoneyGuard therefore
> evaluates execution trajectories rather than only endpoint text.
>
> A separate line of work evaluates LLM agents in interactive environments, including
> AgentBench, WebArena, OSWorld, tau-bench, and tool-use benchmarks. These benchmarks
> are valuable for measuring agent capability and task completion. HoneyGuard is
> complementary: instead of maximizing environment breadth, it uses controlled
> workflow-inspired scenarios to isolate hazard sources and provide ground-truth
> attribution for failures.
>
> Recent agent-safety and agent-security benchmarks are closer to our setting.
> ToolEmu studies risks from tool use in an emulated sandbox; InjecAgent and AgentDojo
> evaluate indirect prompt injection and attacks/defenses for tool-using agents; ASB
> formalizes agent security attacks and defenses; AgentHarm measures harmfulness in
> agentic tasks; and OpenAgentSafety provides a broad framework for evaluating LLM
> agent safety across realistic tool-based tasks. HoneyGuard builds on this trend but
> targets a different question: not only whether an agent fails, but where the risk
> entered, which component first accepted it, how it propagated, and where it could
> have been blocked.
>
> Finally, trajectory-level diagnosis has become increasingly important for agentic
> evaluation, as unsafe behavior may be latent in intermediate steps even when the
> final output appears safe. HoneyGuard operationalizes this idea with structured
> attribution labels for source, channel, mechanism, first failed component, impact,
> counterfactual block point, and failure chain. This makes attribution itself an
> evaluable benchmark target, alongside outcome metrics such as task success, safety
> violation, and safe task completion.

## 6. Claims to Avoid

Avoid:

- "HoneyGuard is the first agent safety benchmark."
- "HoneyGuard is more realistic than OpenAgentSafety / AgentDojo."
- "HoneyGuard comprehensively covers all agent safety risks."
- "LLM judge gives reliable causal attribution."
- "Guarded prompting is a defense."

Prefer:

- "HoneyGuard is attribution-oriented."
- "HoneyGuard is complementary to broad agent-safety benchmarks."
- "HoneyGuard covers representative risk sources."
- "HoneyGuard makes trajectory-level diagnosis benchmarkable."
- "Compositional playground is supplementary stress testing, not the main
  leaderboard."

## 7. Review-Risk Checklist

Likely reviewer questions:

1. **How is this different from OpenAgentSafety?**
   - Answer: OpenAgentSafety is broad and realistic; HoneyGuard is narrower but adds
     structured attribution ground truth, first failed component, block point, and
     compositional controls.
2. **How is this different from AgentDojo / InjecAgent?**
   - Answer: Those focus on prompt injection / attack-defense settings; HoneyGuard
     includes external injection but also internal authority contamination and
     non-adversarial failures.
3. **Are the scenarios realistic?**
   - Answer: They are controlled workflow-inspired scenarios. The purpose is
     diagnostic isolation, not full production realism.
4. **Who annotated the failure chains?**
   - Answer in final paper with an annotation protocol, schema, examples, and
     consistency checks.
5. **Does attribution ground truth overclaim causality?**
   - Answer carefully: labels encode intended controlled hazard and expected failure
     path; trace-based attribution evaluates whether observed behavior matches that
     controlled design.
6. **Why include compositional playground if it is not the main benchmark?**
   - Answer: It tests robustness of conclusions under multi-risk stress and enables
     dominance / masking / order-effect analysis.
