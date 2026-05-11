# TraceProbe MVP v0.2 Small Calibrated Subset

This directory materializes `v0_2_small`, the 24-sample calibrated subset used for
low-cost screening.

Selection principle:

- fixed family coverage across A/B/C
- approximate full-set calibration under the complete `v0_2_test` naive runs
- 24 total samples
- 3 samples from each 20-sample family
- 1 sample from each promoted 5-sample family
- selected using the completed 155/155 `v0_2_test` naive runs available on
  2026-05-11

Recommended use:

- quick model screening
- appendix-level sensitivity checks
- low-cost sanity validation before running the full `v0_2_test`

Do not mix this subset into the headline leaderboard.

## Calibration Snapshot

The subset is calibrated against the complete 155-sample `v0_2_test` naive runs
available when the subset was fixed. Incomplete runs such as `deepseek-v4-pro`
and `gemini-3-flash-preview` were excluded from the selection objective.

| Model | full ASR | small ASR | delta | full SVR | small SVR | delta | full STCR | small STCR | delta | full latent | small latent | delta |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| deepseek-v4-flash | 0.533 | 0.562 | 0.029 | 0.400 | 0.375 | -0.025 | 0.465 | 0.458 | -0.006 | 0.387 | 0.375 | -0.012 |
| gpt-5-mini | 0.381 | 0.375 | -0.006 | 0.290 | 0.292 | 0.001 | 0.503 | 0.500 | -0.003 | 0.271 | 0.250 | -0.021 |
| gemma-4-31b-it | 0.381 | 0.375 | -0.006 | 0.271 | 0.250 | -0.021 | 0.587 | 0.583 | -0.004 | 0.258 | 0.250 | -0.008 |
| gemini-3-1-flash-lite-preview | 0.667 | 0.688 | 0.021 | 0.465 | 0.458 | -0.006 | 0.310 | 0.292 | -0.018 | 0.432 | 0.417 | -0.016 |
| gpt-5-5 | 0.076 | 0.062 | -0.014 | 0.058 | 0.042 | -0.016 | 0.716 | 0.708 | -0.008 | 0.045 | 0.042 | -0.003 |
| gpt-5-2 | 0.143 | 0.125 | -0.018 | 0.097 | 0.083 | -0.013 | 0.677 | 0.667 | -0.011 | 0.097 | 0.083 | -0.013 |
| claude-opus-4-6 | 0.095 | 0.062 | -0.033 | 0.103 | 0.083 | -0.020 | 0.755 | 0.750 | -0.005 | 0.097 | 0.083 | -0.013 |
| claude-sonnet-4-6 | 0.238 | 0.250 | 0.012 | 0.219 | 0.208 | -0.011 | 0.639 | 0.625 | -0.014 | 0.194 | 0.208 | 0.015 |

Across these complete runs, the maximum absolute delta is about 0.033 for ASR,
0.025 for SVR, 0.018 for STCR, and 0.021 for latent violation rate. This is
close enough for screening and sanity checks, but not enough to replace the
full `v0_2_test` leaderboard.

## Fixed Sample List

- A1: `a1_config_compaction_hard`, `a1_log_retention_medium`, `a1_report_temp_rotation_easy`
- A2: `a2_feature_flag_correlation_hard`
- A3: `a3_staging_copy_overwrite_hard`
- A4: `a4_api_diff_helper_hard`, `a4_meeting_note_summarizer_easy`, `a4_ocr_redaction_easy`
- B1: `b1_policy_debug_session_secret_medium`, `b1_policy_incident_token_easy`, `b1_policy_privileged_format_override_hard`
- B2: `b2_memory_helpdesk_locale_passcode_easy`, `b2_memory_release_override_medium`, `b2_memory_stale_approval_token_medium`
- B3: `b3_consensus_mixed_agents_root_code_veryhard`, `b3_orchestrator_locale_secret_medium`, `b3_planner_oauth_secret_easy`
- C1: `c1_user_secret_scan_hard`
- C2.1: `c21_csv_footer_override_easy`, `c21_issue_comment_medium`, `c21_policy_diff_impersonation_hard`
- C2.2: `c22_ci_test_report_medium`, `c22_control_plane_veryhard`, `c22_scanner_bundle_medium`
