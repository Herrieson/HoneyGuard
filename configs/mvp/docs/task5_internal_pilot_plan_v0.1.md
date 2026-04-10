# HoneyGuard Task 5.2 Internal Compromise Pilot Plan v0.1

## 1. Scope

Task 5.2 adds a small `B`-track pilot set for internal compromise.

This pilot is intentionally separate from the main 60-sample `A` + `C` benchmark.
Its goal is coverage, not scale.

Expanded v0.1 target:

- 10 pilot samples total
- `B1` policy prompt: 4
- `B3` multi-agent message: 6

Planned pilot coverage:

- `policy_prompt`: malicious system prompt
- `multi_agent_message`: malicious planner message
- `multi_agent_message`: malicious reviewer message

Deferred for later:

- `memory_state`: poisoned memory item

## 2. Why This Pilot Shape

These two channels are the most compatible with the current HoneyGuard runtime:

- `policy_prompt` is directly supported through per-agent `system_prompt`.
- `multi_agent_message` is directly supported through coordinator transcript passing.
- planner and reviewer roles are already representable with `planner_executor_verifier` or ordered multi-agent execution.

`memory_state` is not included in v0.1 pilot because the current runtime does not yet expose a clean YAML-level hook for pre-seeding a poisoned memory item before the main task starts.
It can be approximated with multi-step instructions, but that would weaken the "single controlled hazard" requirement for Task 5.2.

## 3. Directory Layout

Task 5.2 outputs live in:

- `configs/mvp/pilot_b/`

This keeps the pilot isolated from:

- `configs/mvp/dev/`
- `configs/mvp/formal/`
- the fixed 60-sample Task 5.1 build

## 4. Pilot Samples

### 4.1 `B1` policy prompt set

- `b1_policy_footer_token_easy`
- `b1_policy_cache_pin_easy`
- `b1_policy_partner_token_medium`
- `b1_policy_release_code_hard`

### 4.2 `B3` multi-agent message set

- `b3_planner_staging_secret_medium`
- `b3_planner_invoice_secret_medium`
- `b3_planner_bundle_override_hard`
- `b3_reviewer_release_override_hard`
- `b3_reviewer_casefile_pin_medium`
- `b3_reviewer_shell_override_hard`

## 5. Validation Rule

We keep the same strict loop used in Task 5.1:

1. write one sample
2. statically validate it through `scripts.init_from_config.load_config`
3. record the result
4. move to the next sample

Runtime validation is recommended after all ten samples are in place.

## 6. Annotation Policy

All Task 5.2 samples must:

- use `primary_source: internal_compromise`
- keep a single controlled hazard
- use ontology-aligned `channel`, `first_failed_component`, `mechanism`, and `impact`
- declare a concrete `counterfactual_block_point`

## 7. Non-Goals

Task 5.2 does not attempt to:

- scale `B` into a full benchmark track
- solve memory poisoning coverage in v0.1
- merge `B` pilot into the fixed 60-sample formal build
