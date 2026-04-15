# HoneyGuard Attribution Scenario Coverage Report

Generated for:
- `/home/hyx/workplace/HoneyGuard/configs/attribution/scenarios`

## 1. Snapshot

Total scenarios: 292

Track counts:
- A: 84
- B: 99
- C: 109

Family counts:
- A1: 20
- A2: 22
- A3: 22
- A4: 20
- B1: 31
- B2: 31
- B3: 37
- C1: 26
- C2.1: 26
- C2.2: 30
- C3: 27

Difficulty counts:
- easy: 65
- medium: 90
- hard: 111
- veryhard: 26

## 2. Validation status

Validation results:
- YAML parse success: 292 / 292
- `scripts.init_from_config.load_config` success: 292 / 292
- duplicate `scenario`: none
- duplicate `task_id`: none
- required top-level attribution fields: present across all files

## 3. Coverage by attribution axes

### 3.1 Source
- non_adversarial: 84
- internal_compromise: 99
- external_attack: 109

Assessment:
- Source coverage remains broad.
- The B-track expansion increased internal-compromise density without harming diversity.

### 3.2 Primary channel
- goal_specification: 72
- multi_agent_message: 37
- policy_prompt: 31
- memory: 31
- tool_output: 30
- retrieved_content: 28
- local_artifact: 27
- user_input: 26
- environment_state: 10

Assessment:
- The biggest remaining channel gap is still `environment_state`, but it is no longer critically absent.
- Internal-compromise channels are now much stronger, especially `policy_prompt` and `multi_agent_message`.

### 3.3 First failed component
- planner: 68
- instruction_resolver: 47
- reasoner: 41
- executor: 34
- tool_argument_builder: 31
- tool_selector: 29
- reviewer_agent: 24
- memory_manager: 18

Assessment:
- `executor` and `reviewer_agent` improved again.
- `memory_manager` improved slightly.
- `planner` still dominates, but the library now contains a healthier late-failure tail.

Remaining gap:
- More `memory_manager` cases are still worthwhile.
- Future batches should continue to create scenarios where planning stays nominally safe and only later execution/review/memory handling fails.

### 3.4 Mechanism
- authority_overtrust: 73
- goal_rewrite_without_authorization: 31
- memory_poisoning: 30
- unsafe_tool_trust: 28
- context_rebinding: 27
- instruction_data_confusion: 23
- unverified_state_assumption: 22
- retry_escalation_runaway: 22
- unsafe_objective_optimization: 18
- privilege_boundary_failure: 18

Assessment:
- The second enrichment batch intentionally leaned on `authority_overtrust` because it targeted B1 policy-prompt cases.
- Mechanism diversity is still good, but the library is now even more clearly over-indexed on overtrust patterns.

Remaining gap:
- Future growth should bias toward:
  - `goal_rewrite_without_authorization`
  - `context_rebinding`
  - `privilege_boundary_failure`
  - `retry_escalation_runaway`
without defaulting to overtrust when a sharper explanation is available.

### 3.5 Impact
- data_exfiltration: 101
- unauthorized_access: 36
- system_degradation: 33
- policy_noncompliance: 32
- dangerous_action: 31
- integrity_violation: 23
- resource_exhaustion: 23
- hidden_policy_violation: 13

Assessment:
- `hidden_policy_violation` improved again from 9 -> 13.
- `resource_exhaustion` also improved from 21 -> 23.
- `dangerous_action`, `system_degradation`, and `integrity_violation` all ticked upward.
- `data_exfiltration` is still the single dominant impact, but the non-exfiltration tail is stronger than before.

## 4. Difficulty balance

Per-family difficulty distribution:
- A1: easy 5 / medium 6 / hard 7 / veryhard 2
- A2: easy 6 / medium 7 / hard 8 / veryhard 1
- A3: easy 6 / medium 7 / hard 8 / veryhard 1
- A4: easy 5 / medium 6 / hard 7 / veryhard 2
- B1: easy 6 / medium 8 / hard 11 / veryhard 6
- B2: easy 6 / medium 11 / hard 11 / veryhard 2
- B3: easy 6 / medium 10 / hard 17 / veryhard 4
- C1: easy 6 / medium 8 / hard 10 / veryhard 2
- C2.1: easy 7 / medium 9 / hard 8 / veryhard 2
- C2.2: easy 6 / medium 9 / hard 12 / veryhard 3
- C3: easy 6 / medium 9 / hard 10 / veryhard 2

Assessment:
- This batch solved the biggest explicit difficulty problem: B1 now has a real `veryhard` tail.
- The overall hard tail is much healthier.

Remaining gap:
- A2 and A3 still only have one `veryhard` each.
- B2 and C3 could still use more `veryhard` additions.

## 5. Track-specific findings

### Track A
Assessment:
- A-track remains healthy and much less one-dimensional than the original recovered baseline.
- Its next best gains would come from more state/topology ambiguity and more environment-state-heavy patterns.

### Track B
Assessment:
- This is the track that improved the most in the latest batch.
- B1 now meaningfully covers `veryhard` policy-prompt scenarios.
- B3 now has a stronger late-failure reviewer/executor tail.
- B2 gained another memory-driven hidden-policy case.

Remaining gap:
- B-track still leans too heavily toward `authority_overtrust`.
- More B-track scenarios should use non-exfiltration outcomes with mechanisms other than pure overtrust.

### Track C
Assessment:
- C-track remains the richest by channel variety.
- It is still stronger on disclosure-related external attacks than on silent damage or state corruption.
- No urgent structural problem remains, but it still benefits from integrity/system-degradation-heavy C3 additions.

## 6. What improved in the latest batch

The 9-scenario second enrichment batch delivered the intended changes:
- B1 `veryhard`: 0 -> 6
- `policy_prompt`: 25 -> 31
- `executor`: 31 -> 34
- `reviewer_agent`: 23 -> 24
- `instruction_resolver`: 44 -> 47
- `hidden_policy_violation`: 9 -> 13
- `resource_exhaustion`: 21 -> 23
- `system_degradation`: 32 -> 33
- `dangerous_action`: 30 -> 31
- `veryhard`: 17 -> 26

This batch successfully strengthened:
- B1 high-complexity coverage
- late-failure internal-compromise cases
- hidden policy drift coverage
- the overall hard tail

## 7. Remaining highest-priority enrichment targets

If adding another 8-16 scenarios, the best ROI targets are now:

1. More `environment_state` cases
- especially A2/A3/A4
- focus on topology ambiguity, stale state, state-collision, and path aliasing

2. More `memory_manager` late-failure cases
- B2 still remains the lightest major late-failure component family
- especially non-overtrust, non-exfiltration memory cases

3. More non-overtrust internal-compromise mechanisms
- target:
  - `goal_rewrite_without_authorization`
  - `memory_poisoning`
  - `privilege_boundary_failure`
rather than further increasing `authority_overtrust`

4. More non-exfiltration C-track cases
- especially C3 integrity/system-degradation/local corruption cases
- especially tool-output cases with silent override behavior instead of explicit leak requests

5. A2/A3/B2/C3 veryhard growth
- B1 is now fixed; these are the next best difficulty-tail targets

## 8. Bottom line

The scenario library is now substantially stronger than the original recovered attribution set.

Main strengths now:
- broad family coverage
- strong medium/hard/veryhard density
- real B1 veryhard tail
- stronger reviewer/executor late-failure coverage
- stronger hidden-policy-violation coverage
- better state-channel and non-exfiltration diversity than before

Main remaining weaknesses:
- `data_exfiltration` still dominates the impact distribution
- `authority_overtrust` still dominates mechanism counts
- `planner` still dominates first-failure attribution
- `environment_state` and `memory_manager` still remain smaller than the other major axes

Best next move:
- if expanding again, do a smaller precision batch aimed at environment-state ambiguity, memory-manager late failures, and non-overtrust internal-compromise cases.
