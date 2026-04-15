# HoneyGuard Attribution Scenarios

This directory contains a restored and expanded attribution scenario library for HoneyGuard.

Summary:
- Total YAML scenarios: 292
- Restored from historical attribution library: 245
- First high-complexity enrichment pack added earlier: 14
- Targeted coverage-gap enrichment batch added later: 24
- Second enrichment batch focused on B1 veryhard and late-failure internal-compromise cases: 9

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

Layout:
- `a1/`, `a2/`, `a3/`, `a4/`
- `b1/`, `b2/`, `b3/`
- `c1/`, `c21/`, `c22/`, `c3/`

Validation:
- All YAML files parse successfully.
- All YAML files load successfully through `scripts.init_from_config.load_config`.
- `scenario` and `task_id` are unique across the library.

Library notes:
- This scenario set intentionally preserves the richer historical attribution taxonomy used by the older attribution benchmark, including labels such as `memory` and `local_artifact`, because the goal here is maximum scenario variety and complexity rather than strict reduction to the smaller MVP label subset.
- The first enrichment batch specifically targeted weak axes such as `environment_state`, `memory_manager`, `hidden_policy_violation`, non-exfiltration B-track cases, and additional `veryhard` scenarios.
- The second enrichment batch specifically pushed B1 into a real `veryhard` tail and added more non-planner late-failure internal-compromise cases.

High-complexity enrichment pack from MVP references:
- `a1/a1_failover_cleanup_veryhard.yaml`
- `a1/a1_multi_mount_pressure_veryhard.yaml`
- `a4/a4_context_pack_veryhard.yaml`
- `a4/a4_cross_tool_bundle_veryhard.yaml`
- `b1/b1_policy_release_code_hard.yaml`
- `b3/b3_planner_bundle_override_hard.yaml`
- `b3/b3_reviewer_release_override_hard.yaml`
- `b3/b3_reviewer_shell_override_hard.yaml`
- `c21/c21_multi_doc_override_veryhard.yaml`
- `c21/c21_nested_reference_veryhard.yaml`
- `c22/c22_control_plane_veryhard.yaml`
- `c22/c22_nested_toolchain_veryhard.yaml`
- `c22/c22_structured_override_hard.yaml`
- `c22/c22_remediation_ticket_hard.yaml`

Coverage-gap enrichment batch:
- A2: 4 state-heavy scenarios
- A3: 4 retry/state-drift scenarios
- B2: 4 memory-manager-centered scenarios
- B3: 4 reviewer/executor-centered scenarios
- C1: 2 veryhard direct-user scenarios
- C2.2: 2 hidden-policy / dangerous-runbook tool-output scenarios
- C3: 4 local-artifact integrity / policy / retry scenarios

Second enrichment batch:
- B1: 6 new `veryhard` policy-prompt scenarios
- B2: 1 new `veryhard` hidden-policy memory scenario
- B3: 2 new `veryhard` reviewer/executor late-failure scenarios
