# HoneyGuard v0.2 Gap-Family Promotion Note

## Purpose

This note records the A2/A3/C1 gap-family batch that was promoted into `v0_2_test` on 2026-04-30.

The goal is broader family coverage. These families remain smaller than the core balanced families, so interpret them with family-level breakdowns rather than only aggregate headline metrics.

## Current Main Coverage

`v0_2_test` currently uses 7 core balanced reporting families plus 3 promoted gap families:

- `A1`: non-adversarial decision / operation boundary failure
- `A2`: non-adversarial reasoning distortion
- `A3`: non-adversarial execution instability
- `A4`: non-adversarial data-boundary / minimization failure
- `B1`: internal policy-prompt compromise
- `B2`: poisoned memory state
- `B3`: compromised multi-agent message
- `C1`: direct user-instruction attack
- `C2.1`: retrieved-content injection
- `C2.2`: tool-output poisoning

This covers the three source classes in the ontology:

- `non_adversarial`
- `internal_compromise`
- `external_attack`

It does not claim full coverage of every Agent safety family.

## Promoted Families

### A2: Non-Adversarial Reasoning Distortion

Definition: the agent adopts a wrong factual, causal, or authorization premise without an explicit attacker.

Primary distinction from `A1`: `A1` is mostly unsafe objective expansion or operational overreach; `A2` centers on false inference before the plan is selected.

Added samples:

- `a2_payment_callback_false_cause_easy`
- `a2_snapshot_age_misclassification_medium`
- `a2_feature_flag_correlation_hard`
- `a2_alert_owner_inference_medium`
- `a2_tenant_alias_false_mapping_hard`

### A3: Non-Adversarial Execution Instability

Definition: the user goal and broad plan can be safe, but the action execution, command arguments, path scope, permissions, or retry behavior becomes unsafe.

Primary distinction from `A1`: `A1` is bad high-level decision scope; `A3` is bad low-level execution realization.

Added samples:

- `a3_report_glob_cleanup_easy`
- `a3_hook_chmod_scope_medium`
- `a3_tenant_report_path_join_medium`
- `a3_staging_copy_overwrite_hard`
- `a3_queue_retry_marker_hard`

### C1: External User-Instruction Attack

Definition: the risk enters through the direct user message, including malicious requests, fake authority claims, roleplay authorization, or user-supplied fake policy blocks.

Primary distinction from `C2.1` / `C2.2`: the attacker is not hidden in retrieved content or tool output; the attack is in the direct user instruction channel.

Added samples:

- `c1_user_debug_key_easy`
- `c1_user_support_export_medium`
- `c1_user_roleplay_auditor_hard`
- `c1_user_secret_scan_hard`
- `c1_user_fake_policy_block_veryhard`

## Split

These YAMLs now live directly in:

- `configs/mvp/v0_2/test/`

The old `v0_2_candidates` split has been removed from the active runner.

## Recommended Paper Use

For v0.2, treat these as promoted but small gap-family slices:

- Use `C1` to show that direct user-channel attacks are supported by the ontology.
- Use `A2/A3` to show the framework can extend beyond current non-adversarial slices.
- Avoid over-interpreting aggregate rates because A2/A3/C1 have 5 samples each while core families have 20 each.
