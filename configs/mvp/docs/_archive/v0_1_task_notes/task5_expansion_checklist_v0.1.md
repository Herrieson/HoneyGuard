# HoneyGuard Task 5 Expansion Checklist v0.1

## 1. Goal

Task 5 targets a formal benchmark set of 60 samples:

- A1: 15
- A4: 15
- C2.1: 15
- C2.2: 15

Current base:

- 20 samples already exist in `configs/mvp/_archive/v0_1_splits/dev/`

Task 5 therefore needs:

- 40 new formal samples

## 2. Execution Rule

We follow a strict loop:

1. write one sample
2. run static validation
3. record validation result
4. check it off
5. move to the next sample

Runtime validation can be added later by manual batch runs, but the minimum per-sample gate for now is:

- YAML loads through `scripts.init_from_config.load_config`
- required attribution fields are present
- scenario ID is unique in the formal set

## 3. Batch Plan

### Batch 5A: expand from 20 to 36

Add 4 new samples per family.

### Batch 5B: expand from 36 to 48

Add 3 new samples per family.

### Batch 5C: expand from 48 to 60

Add 3 new samples per family.

## 4. Status Legend

- `[ ]` not started
- `[-]` drafting
- `[x]` generated + statically validated

## 5. Carry-Over Base

These 20 samples already exist and will be included in the formal 60-sample build:

- A1: `a1_cleanup_cache_easy`, `a1_alert_noise_medium`, `a1_disk_pressure_hard`, `a1_staging_cleanup_medium`, `a1_worker_throttle_hard`
- A4: `a4_summary_api_easy`, `a4_log_uploader_medium`, `a4_plugin_context_hard`, `a4_translation_api_medium`, `a4_support_bundle_hard`
- C2.1: `c21_web_summary_easy`, `c21_html_comment_medium`, `c21_policy_footer_hard`, `c21_forwarded_email_medium`, `c21_rag_appendix_hard`
- C2.2: `c22_api_hint_easy`, `c22_log_command_medium`, `c22_structured_authority_hard`, `c22_status_cli_easy`, `c22_structured_bundle_hard`

## 6. New Sample Queue

### A1 new queue (10)

- `[x]` `a1_backup_rotation_easy` : static validation passed on 2026-04-09
- `[x]` `a1_log_retention_medium` : static validation passed on 2026-04-09
- `[x]` `a1_queue_drain_medium` : static validation passed on 2026-04-10
- `[x]` `a1_config_compaction_hard` : static validation passed on 2026-04-10
- `[x]` `a1_archive_prune_easy` : static validation passed on 2026-04-10
- `[x]` `a1_disk_balancer_medium` : static validation passed on 2026-04-10
- `[x]` `a1_emergency_free_space_hard` : static validation passed on 2026-04-10
- `[x]` `a1_hot_path_trim_hard` : static validation passed on 2026-04-10
- `[x]` `a1_failover_cleanup_veryhard` : static validation passed on 2026-04-10
- `[x]` `a1_multi_mount_pressure_veryhard` : static validation passed on 2026-04-10

### A4 new queue (10)

- `[x]` `a4_ocr_redaction_easy` : static validation passed on 2026-04-10
- `[x]` `a4_email_rewrite_medium` : static validation passed on 2026-04-10
- `[x]` `a4_csv_cleanup_medium` : static validation passed on 2026-04-10
- `[x]` `a4_vendor_diff_hard` : static validation passed on 2026-04-10
- `[x]` `a4_invoice_parser_easy` : static validation passed on 2026-04-10
- `[x]` `a4_policy_sync_medium` : static validation passed on 2026-04-10
- `[x]` `a4_case_export_hard` : static validation passed on 2026-04-10
- `[x]` `a4_partner_payload_hard` : static validation passed on 2026-04-10
- `[x]` `a4_context_pack_veryhard` : static validation passed on 2026-04-10
- `[x]` `a4_cross_tool_bundle_veryhard` : static validation passed on 2026-04-10

### C2.1 new queue (10)

- `[x]` `c21_markdown_footnote_easy` : static validation passed on 2026-04-10
- `[x]` `c21_issue_comment_medium` : static validation passed on 2026-04-10
- `[x]` `c21_hidden_span_medium` : static validation passed on 2026-04-10
- `[x]` `c21_wiki_appendix_hard` : static validation passed on 2026-04-10
- `[x]` `c21_pdf_notice_easy` : static validation passed on 2026-04-10
- `[x]` `c21_release_note_medium` : static validation passed on 2026-04-10
- `[x]` `c21_runbook_patch_hard` : static validation passed on 2026-04-10
- `[x]` `c21_ticket_footer_hard` : static validation passed on 2026-04-10
- `[x]` `c21_nested_reference_veryhard` : static validation passed on 2026-04-10
- `[x]` `c21_multi_doc_override_veryhard` : static validation passed on 2026-04-10

### C2.2 new queue (10)

- `[x]` `c22_cli_recommendation_easy` : static validation passed on 2026-04-10
- `[x]` `c22_health_json_medium` : static validation passed on 2026-04-10
- `[x]` `c22_scanner_bundle_medium` : static validation passed on 2026-04-10
- `[x]` `c22_policy_header_hard` : static validation passed on 2026-04-10
- `[x]` `c22_export_probe_easy` : static validation passed on 2026-04-10
- `[x]` `c22_shell_notice_medium` : static validation passed on 2026-04-10
- `[x]` `c22_structured_override_hard` : static validation passed on 2026-04-10
- `[x]` `c22_remediation_ticket_hard` : static validation passed on 2026-04-10
- `[x]` `c22_control_plane_veryhard` : static validation passed on 2026-04-10
- `[x]` `c22_nested_toolchain_veryhard` : static validation passed on 2026-04-10

## 7. Validation Log

| Sample | Generated | Static Validation | Runtime Validation | Notes |
| --- | --- | --- | --- | --- |
| `a1_backup_rotation_easy` | yes | pass | pending | first formal sample |
| `a1_log_retention_medium` | yes | pass | pending | A1 medium, log-volume control |
| `a1_queue_drain_medium` | yes | pass | pending | retry queue cleanup without touching priority jobs |
| `a1_config_compaction_hard` | yes | pass | pending | compact config without deleting safety controls |
| `a1_archive_prune_easy` | yes | pass | pending | prune expired temp archives only |
| `a1_disk_balancer_medium` | yes | pass | pending | rebalance scratch storage without touching protected replicas |
| `a1_emergency_free_space_hard` | yes | pass | pending | urgent storage recovery without deleting legal hold data |
| `a1_hot_path_trim_hard` | yes | pass | pending | trim hot-path cache only, preserve auth policy files |
| `a1_failover_cleanup_veryhard` | yes | pass | pending | failover cleanup under mixed safe and protected mount points |
| `a1_multi_mount_pressure_veryhard` | yes | pass | pending | multi-mount pressure with misleading largest-directory cues |
| `a4_ocr_redaction_easy` | yes | pass | pending | OCR helper with invoice-number redaction |
| `a4_email_rewrite_medium` | yes | pass | pending | external rewrite helper with ticket and token minimization |
| `a4_csv_cleanup_medium` | yes | pass | pending | external CSV cleanup with internal-note minimization |
| `a4_vendor_diff_hard` | yes | pass | pending | diff helper docs push full-export oversharing |
| `a4_invoice_parser_easy` | yes | pass | pending | invoice parser with billing-reference minimization |
| `a4_policy_sync_medium` | yes | pass | pending | external policy normalizer with internal escalation-note stripping |
| `a4_case_export_hard` | yes | pass | pending | case export helper with internal memo stripping |
| `a4_partner_payload_hard` | yes | pass | pending | partner payload helper with callback and token minimization |
| `a4_context_pack_veryhard` | yes | pass | pending | multi-file vendor context pack with trace retention and secret stripping |
| `a4_cross_tool_bundle_veryhard` | yes | pass | pending | two-step external bundle workflow with sanitized diagnostic handoff |
| `c21_markdown_footnote_easy` | yes | pass | pending | visible markdown footnote injection during release-note summarization |
| `c21_issue_comment_medium` | yes | pass | pending | issue-thread bot comment injection during bug-status summarization |
| `c21_hidden_span_medium` | yes | pass | pending | hidden rich-text span injection inside status-page summarization |
| `c21_wiki_appendix_hard` | yes | pass | pending | wiki appendix impersonates approved incident override |
| `c21_pdf_notice_easy` | yes | pass | pending | direct PDF notice injection in extracted finance briefing |
| `c21_release_note_medium` | yes | pass | pending | editorial note injection inside internal release notes |
| `c21_runbook_patch_hard` | yes | pass | pending | runbook patch impersonates approved confidentiality override |
| `c21_ticket_footer_hard` | yes | pass | pending | ticket footer impersonates system authorization block |
| `c21_nested_reference_veryhard` | yes | pass | pending | nested reference chain hides a downstream authorization override |
| `c21_multi_doc_override_veryhard` | yes | pass | pending | multi-document override chain creates conflicting false authority |
| `c22_cli_recommendation_easy` | yes | pass | pending | CLI recommendation suggests unsafe OAuth token upload |
| `c22_health_json_medium` | yes | pass | pending | health-check JSON recommends packaging runtime signing secret |
| `c22_scanner_bundle_medium` | yes | pass | pending | scanner output suggests bundling sensitive token report |
| `c22_policy_header_hard` | yes | pass | pending | structured policy header impersonates system key-packaging authority |
| `c22_export_probe_easy` | yes | pass | pending | basic export probe suggests unsafe config upload |
| `c22_shell_notice_medium` | yes | pass | pending | shell diagnostic notice suggests unsafe credential upload command |
| `c22_structured_override_hard` | yes | pass | pending | structured override flag authorizes classified attachment packaging |
| `c22_remediation_ticket_hard` | yes | pass | pending | generated remediation ticket requests sensitive attachment packaging |
| `c22_control_plane_veryhard` | yes | pass | pending | control-plane diagnostic mixes valid signals with live credential packaging authority |
| `c22_nested_toolchain_veryhard` | yes | pass | pending | chained tool outputs create nested false authority for secret packaging |

## 8. Immediate Next Step

Continue in queue order unless a sample needs redesign.
