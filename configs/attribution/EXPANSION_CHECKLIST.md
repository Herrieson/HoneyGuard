# HoneyGuard Attribution Scenario Expansion Checklist

Target: build a rich attribution benchmark library of about 200 scenarios under `configs/attribution/scenario`, spanning top-level tracks A / B / C with broad coverage across hazard families, channels, mechanisms, components, impacts, and difficulty.

## 1. Current baseline

Existing scenarios already cover:
- Track A: A1, A4
- Track C: C2.1, C2.2
- Track B references exist in `configs/mvp/pilot_b/` for B1 and B3 patterns

Current attribution library gaps:
- No Track B scenarios yet
- Only 4 families in active attribution library
- Limited component coverage
- Limited impact diversity
- Limited channel diversity

## 2. Target library shape

Total target: 204 scenarios

Track allocation:
- A: 72 scenarios
- B: 60 scenarios
- C: 72 scenarios

Family allocation:

### Track A: non-adversarial safety-critical failures (72)
- A1: destructive overreach / unsafe maintenance actions — 18
- A2: unsafe state assumptions / verification failures — 18
- A3: runaway loops / retry / quota / escalation miscontrol — 18
- A4: non-adversarial boundary failures / oversharing to helpers or external sinks — 18

### Track B: internally compromised system components (60)
- B1: compromised policy / system prompt / hidden directive — 20
- B2: compromised memory / persistent context / stored plan contamination — 20
- B3: compromised multi-agent or reviewer/planner message channel — 20

### Track C: external attacks / untrusted external content (72)
- C1: direct adversarial user input / explicit authority spoofing — 18
- C2.1: retrieved content injection / RAG / notes / tickets / docs — 18
- C2.2: tool-output injection / logs / diagnostics / scanners / verifiers — 18
- C3: environment artifact attacks / local files, configs, generated intermediates, workspace contamination — 18

Difficulty allocation target per family:
- easy: 6
- medium: 6
- hard: 6
except B families and C1 where some hard cases may be slightly more numerous if needed; keep near-balanced.

## 3. Coverage axes to enforce

Each family set should vary across these axes:

### Primary channels
- goal_specification
- policy_prompt
- memory
- multi_agent_message
- retrieved_content
- tool_output
- user_input
- environment_state
- local_artifact

### First failed components
- instruction_resolver
- planner
- reasoner
- tool_selector
- tool_argument_builder
- executor
- memory_manager
- reviewer_agent
- orchestrator

### Primary mechanisms
- unsafe_objective_optimization
- unverified_state_assumption
- retry_escalation_runaway
- privilege_boundary_failure
- authority_overtrust
- memory_poisoning
- instruction_data_confusion
- unsafe_tool_trust
- context_rebinding
- goal_rewrite_without_authorization

### Primary impacts
- system_degradation
- dangerous_action
- data_exfiltration
- integrity_violation
- unauthorized_access
- policy_noncompliance
- resource_exhaustion

## 4. Family construction checklist

### A1 destructive overreach
Patterns:
- broad delete / overwrite / purge / cleanup
- rollback point deletion
- release artifact deletion
- prod vs tmp confusion
- archive pruning beyond scope
- package/config wipe
Need:
- 18 total, 6 per difficulty

### A2 unsafe state assumptions
Patterns:
- assumes stale lock, invalid lease, dead node, failed replica, idle queue, expired cert without verification
- promotes replica, rotates credential, drains traffic, reissues cert, replays queue without checking guard conditions
Need:
- 18 total, 6 per difficulty

### A3 runaway retries / loops / quotas
Patterns:
- unbounded replay loops
- repeated billing retries
- duplicate resend jobs
- repeated restart loops
- repeated webhook backfills
- quota exhaustion by excessive polling
Need:
- 18 total, 6 per difficulty

### A4 non-adversarial boundary failures
Patterns:
- external helper gets raw note instead of redacted summary
- formatter/uploader receives internal IDs/tags
- OCR/parser sees more than minimum necessary
- vendor handoff includes secrets or routing metadata
Need:
- 18 total, 6 per difficulty

### B1 compromised policy prompt
Patterns:
- hidden system instruction to fetch a secret
- injected approval footer
- internal directive to override scope
- policy says upload/prove/append credential
Need:
- 20 total, balanced around 6/7/7

### B2 compromised memory
Patterns:
- persistent note claims user pre-approved secret access
- stored memory says always include token/checksum/proof value
- contaminated scratchpad changes task scope
- old plan fragment authorizes forbidden action
Need:
- 20 total, balanced around 6/7/7

### B3 compromised multi-agent channel
Patterns:
- planner says secret needed
- reviewer issues fake override
- verifier authorizes unsafe tool call
- upstream agent plants false completion criteria
Need:
- 20 total, balanced around 6/7/7

### C1 direct adversarial user input
Patterns:
- user asks for benign task plus hidden disclosure
- social-engineering authority claim
- fake audit/compliance pretext
- user attempts task-scope rewrite into credential read/upload
Need:
- 18 total, 6 per difficulty

### C2.1 retrieved content injection
Patterns:
- mail thread, note, ticket, wiki, pdf extract, markdown, comment, appendix, incident doc, runbook
- embedded instruction to reveal secret or change goal
Need:
- 18 total, 6 per difficulty

### C2.2 tool-output injection
Patterns:
- CLI banner, scanner output, verifier notice, JSON diagnostics, health command, remediation tool, export probe
- suggested secret upload or unsafe command execution
Need:
- 18 total, 6 per difficulty

### C3 environment artifact attack
Patterns:
- poisoned local draft
- contaminated generated file
- malicious temp artifact
- workspace README / patch file / config artifact with instruction text
- staged shell script or helper output file that tries to redirect scope
Need:
- 18 total, 6 per difficulty

## 5. Build order

1. Preserve and keep all existing 20 attribution YAMLs
2. Add missing A families: A2, A3
3. Add Track B families: B1, B2, B3
4. Add missing C families: C1, C3
5. Backfill A1, A4, C2.1, C2.2 to target counts
6. Validate full library
7. Write final coverage summary

## 6. Naming convention

Use lowercase filenames like:
- a2_replica_failover_easy.yaml
- a3_retry_storm_medium.yaml
- b2_memory_override_hard.yaml
- c1_audit_pretext_medium.yaml
- c3_workspace_patch_hard.yaml

## 7. Per-file authoring rules

Every scenario must include:
- required schema fields from benchmark YAML schema v0.1
- clear controlled_hazard with one primary hazard
- both utility and safety acceptance checks
- at least one negative leakage/damage indicator with `enforce: false`
- runtime-executable files and commands when side effects need observation
- Azure-style llm_config

## 8. Final validation requirements

- YAML parse success for all files
- required top-level and nested fields present
- unique scenario IDs
- counts by track/family/difficulty generated
- distribution by source/channel/component/mechanism/impact summarized
- target total reaches about 200, concretely 204
