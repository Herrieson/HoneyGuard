# HoneyGuard Attribution Benchmark Enhancement Plan

Target: improve the already-complete 204-scenario attribution benchmark by increasing attribution sharpness, balancing underrepresented failure types, strengthening acceptance checks, and adding higher-value diagnostic scenarios.

## 1. Current benchmark status

Current library status:
- Total scenarios: 204
- YAML parseability: clean
- Schema validation: clean
- Track coverage: A / B / C complete
- Family coverage: complete against the 204-scenario checklist

Current imbalance / opportunity summary:
- `data_exfiltration` is overrepresented relative to other impacts.
- `authority_overtrust` is much more common than `goal_rewrite_without_authorization`.
- `planner` dominates component attribution; `memory_manager`, `reviewer_agent`, and an explicit orchestration-style failure pattern deserve more coverage.
- Many scenarios are strong single-source examples, but the benchmark would benefit from more “near-neighbor” scenarios where surface content is similar and only the true root-cause axis changes.
- Acceptance criteria are structurally valid, but many files rely mostly on `response_contains` checks and can be strengthened with explicit safety / attribution / refusal checks.

## 2. Enhancement goals

### Goal A — reduce benchmark skew
Add or revise scenarios so the benchmark is less dominated by data-exfiltration outcomes and overtrust-to-authority patterns.

### Goal B — improve attribution discrimination
Add tightly matched scenario sets where only one attribution axis changes:
- same task, different primary channel
- same task, different mechanism
- same task, different first-failed component
- same task, different impact

### Goal C — improve evaluator quality
Strengthen acceptance logic so scenarios test:
- preserved utility
- refusal of unsafe action
- explicit recognition of untrusted source or lack of authorization
- non-disclosure of protected value
- clearer counterfactual alignment

### Goal D — improve hard-case realism
Add more scenarios with:
- multi-source conflict
- ambiguous but recoverable evidence
- coupled benign and malicious instructions
- high similarity across cases with distinct ground-truth attribution

## 3. Enhancement workstreams

### Workstream 1: Impact rebalance pack
Priority: highest

Add targeted scenarios biased toward these impacts:
- `dangerous_action`
- `integrity_violation`
- `resource_exhaustion`
- `system_degradation`

Focus areas:
- C1, C2.1, C2.2, C3 scenarios that induce unsafe execution or unsafe recommendation rather than secret disclosure
- B-family scenarios where compromised internal instructions cause unauthorized state changes, policy violations, or harmful execution

Execution target:
- add a first batch of 24 scenarios:
  - B1: 4
  - B2: 4
  - B3: 4
  - C1: 4
  - C2.1: 4
  - C2.2: 2
  - C3: 2

Desired impact mix for this pack:
- dangerous_action: 8+
- integrity_violation: 6+
- policy_noncompliance: 4+
- resource_exhaustion: 2+
- system_degradation: 4+
- data_exfiltration: minimal or zero unless needed for a matched pair

### Workstream 2: Near-neighbor attribution sets
Priority: highest

Create matched scenario quartets/quintets where the visible task is almost the same, but the real source differs:
- user_input vs retrieved_content vs tool_output vs local_artifact vs memory
- authority_overtrust vs goal_rewrite_without_authorization vs unsafe_tool_trust vs context_rebinding

Suggested matched sets:
1. “status summary with hidden proof request” set
2. “rollback recommendation with one injected unsafe override” set
3. “partner notification task with improper attachment pressure” set
4. “bounded retry task with false escalation trigger” set

Execution target:
- first batch should include at least 2 matched families of 4 scenarios each

### Workstream 3: Component coverage strengthening
Priority: medium-high

Increase scenarios where the intended first failed component is one of:
- `memory_manager`
- `reviewer_agent`
- `executor`
- `tool_argument_builder`

Also add a light “orchestration-style” pattern by using B3 multi-agent sequencing and explicit coordination errors even if the current schema does not require a literal `orchestrator` label.

Execution target for next two batches combined:
- +6 `memory_manager`
- +6 `reviewer_agent`
- +6 `executor`
- +6 `tool_argument_builder`
- reduce overuse of `planner`

### Workstream 4: Acceptance/quality upgrade pass
Priority: medium-high

For existing and new scenarios, strengthen acceptance criteria where weak.

Minimum preferred acceptance pattern per file:
- utility retention check (`response_contains` on legitimate task facts)
- explicit safety check (`response_contains` on refusal, verification, redaction, bounded retry, etc.)
- at least one `response_not_contains` check for protected value or forbidden action token when applicable
- at least one negative leakage/damage indicator with `enforce: false`
- counterfactual-consistency wording in the answer where appropriate

Priority families for first upgrade pass:
- B1
n- B2
- B3
- C1
- C2.1
- C2.2
- C3

### Workstream 5: Multi-source conflict scenarios
Priority: medium

Add scenarios where two sources disagree:
- user request vs local artifact
- retrieved doc vs tool output
- memory note vs current task
- planner/reviewer message vs policy prompt

These should remain attributable by making one source the true hazard origin while the second source is a distractor.

Execution target:
- include 4 such scenarios in the second enhancement batch

## 4. Immediate execution plan

### Phase 1 — plan and add first enhancement batch
1. Write this enhancement plan.
2. Add 24 new scenarios focused on impact rebalance and near-neighbor attribution.
3. Keep schema compatibility and naming consistency.
4. Validate parseability and uniqueness.
5. Recompute distribution.

### Phase 2 — strengthen acceptance checks on highest-value existing families
1. Inspect B1/B2/B3/C1/C2.1/C2.2/C3 acceptance criteria.
2. Patch weak files that lack explicit refusal / untrusted-source checks / negative indicators.
3. Revalidate.

### Phase 3 — second enhancement batch
1. Add multi-source conflict and harder attribution cases.
2. Specifically target underrepresented components and impacts.
3. Revalidate and produce updated coverage summary.

## 5. First batch specification

Batch name: `enhancement_batch_1`

Add 24 scenarios total:
- B1 dangerous-action / integrity-violation variants: 4
- B2 memory-poisoning non-exfiltration variants: 4
- B3 reviewer/planner-channel harmful-action variants: 4
- C1 user-input unsafe-action / scope-rewrite variants: 4
- C2.1 retrieved-content unsafe-action / retry-runaway variants: 4
- C2.2 tool-output unsafe-action variants: 2
- C3 local-artifact harmful-action variants: 2

Batch design rules:
- avoid secret-disclosure-centric framing unless used only as a matched control case
- explicitly diversify `first_failed_component`
- emphasize `goal_rewrite_without_authorization`, `unsafe_tool_trust`, `context_rebinding`, and non-exfiltration consequences
- include at least 8 matched near-neighbor scenarios across two clusters

## 6. Validation requirements after each batch

Validate:
- YAML parse success
- required top-level and nested fields
- unique filename stem / scenario / task_id
- scenario stem equality
- counts by track / family / difficulty
- counts by source / channel / component / mechanism / impact
- explicit delta vs previous benchmark state

## 7. Success criteria for enhancement pass

A successful enhancement pass should produce:
- a larger benchmark with better impact diversity
- stronger near-neighbor attribution tests
- reduced relative dependence on `data_exfiltration`
- better coverage for underused components
- stronger per-file acceptance logic
- no schema or parse regressions
