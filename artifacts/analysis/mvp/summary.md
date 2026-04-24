# HoneyGuard MVP Result Analysis

## 1. Three-model horizontal comparison

| Model | Baseline | Eval N | TSR | SVR | STCR | ASR | Latent |
| --- | --- | --- | --- | --- | --- | --- | --- |
| deepseek-v3-2 | attribution_aware | 40 | 0.425 | 0.575 | 0.075 | 0.650 | 0.150 |
| deepseek-v3-2 | guarded | 40 | 0.375 | 0.475 | 0.100 | 0.550 | 0.100 |
| deepseek-v3-2 | naive | 40 | 0.350 | 0.500 | 0.075 | 0.600 | 0.125 |
| gpt-4o | attribution_aware | 40 | 0.575 | 0.500 | 0.125 | 0.600 | 0.100 |
| gpt-4o | guarded | 40 | 0.625 | 0.525 | 0.100 | 0.600 | 0.075 |
| gpt-4o | naive | 40 | 0.575 | 0.625 | 0.025 | 0.800 | 0.200 |
| gpt-5-4 | attribution_aware | 40 | 0.950 | 0.725 | 0.150 | 0.450 | 0.000 |
| gpt-5-4 | guarded | 40 | 0.950 | 0.725 | 0.175 | 0.450 | 0.000 |
| gpt-5-4 | naive | 40 | 0.975 | 0.750 | 0.150 | 0.500 | 0.000 |

## 2. All naive model comparison

| Model | Eval N | Infra Fail | TSR | SVR | STCR | ASR | Latent |
| --- | --- | --- | --- | --- | --- | --- | --- |
| deepseek-v3-2 | 40 | 0.000 | 0.350 | 0.500 | 0.075 | 0.600 | 0.125 |
| gpt-4o | 40 |  | 0.575 | 0.625 | 0.025 | 0.800 | 0.200 |
| gpt-4o-mini | 40 | 0.000 | 0.700 | 0.750 | 0.025 | 0.900 | 0.225 |
| gpt-5-4 | 40 |  | 0.975 | 0.750 | 0.150 | 0.500 | 0.000 |
| kimi-k2-5 | 40 | 0.000 | 0.750 | 0.625 | 0.125 | 0.500 | 0.050 |
| gpt-5 | 39 | 0.025 | 0.744 | 0.590 | 0.154 | 0.400 | 0.000 |
| grok-4-20-non-reasoning | 0 | 0.900 |  |  |  |  |  |

## 3. Attribution over observed failures

This is not manual eyeballing: each failed/latent run is grouped by the benchmark's task-side attribution labels. It explains what failure classes each model actually triggered.

| Model | Baseline | Dimension | Label | Count | Share |
| --- | --- | --- | --- | --- | --- |
| deepseek-v3-2 | attribution_aware | primary_channel | tool_output | 10 | 0.435 |
| deepseek-v3-2 | attribution_aware | primary_channel | goal_specification | 6 | 0.261 |
| deepseek-v3-2 | attribution_aware | primary_channel | retrieved_content | 4 | 0.174 |
| deepseek-v3-2 | attribution_aware | primary_channel | environment_state | 3 | 0.130 |
| deepseek-v3-2 | attribution_aware | first_failed_component | instruction_resolver | 8 | 0.348 |
| deepseek-v3-2 | attribution_aware | first_failed_component | tool_argument_builder | 6 | 0.261 |
| deepseek-v3-2 | attribution_aware | first_failed_component | planner | 5 | 0.217 |
| deepseek-v3-2 | attribution_aware | first_failed_component | reasoner | 3 | 0.130 |
| deepseek-v3-2 | attribution_aware | first_failed_component | tool_selector | 1 | 0.043 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | unsafe_tool_trust | 6 | 0.261 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | authority_overtrust | 6 | 0.261 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | goal_rewrite_without_authorization | 4 | 0.174 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | sensitive_data_overdisclosure | 2 | 0.087 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | instruction_data_confusion | 2 | 0.087 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | unverified_state_assumption | 1 | 0.043 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | unsafe_objective_optimization | 1 | 0.043 |
| deepseek-v3-2 | attribution_aware | primary_mechanism | privilege_boundary_failure | 1 | 0.043 |
| deepseek-v3-2 | guarded | primary_channel | tool_output | 8 | 0.421 |
| deepseek-v3-2 | guarded | primary_channel | goal_specification | 4 | 0.211 |
| deepseek-v3-2 | guarded | primary_channel | retrieved_content | 4 | 0.211 |
| deepseek-v3-2 | guarded | primary_channel | environment_state | 3 | 0.158 |
| deepseek-v3-2 | guarded | first_failed_component | instruction_resolver | 7 | 0.368 |
| deepseek-v3-2 | guarded | first_failed_component | planner | 6 | 0.316 |
| deepseek-v3-2 | guarded | first_failed_component | tool_argument_builder | 3 | 0.158 |
| deepseek-v3-2 | guarded | first_failed_component | reasoner | 2 | 0.105 |
| deepseek-v3-2 | guarded | first_failed_component | tool_selector | 1 | 0.053 |
| deepseek-v3-2 | guarded | primary_mechanism | unsafe_tool_trust | 5 | 0.263 |
| deepseek-v3-2 | guarded | primary_mechanism | authority_overtrust | 5 | 0.263 |
| deepseek-v3-2 | guarded | primary_mechanism | goal_rewrite_without_authorization | 4 | 0.211 |
| deepseek-v3-2 | guarded | primary_mechanism | unsafe_objective_optimization | 2 | 0.105 |
| deepseek-v3-2 | guarded | primary_mechanism | instruction_data_confusion | 2 | 0.105 |
| deepseek-v3-2 | guarded | primary_mechanism | unverified_state_assumption | 1 | 0.053 |
| deepseek-v3-2 | naive | primary_channel | tool_output | 8 | 0.400 |
| deepseek-v3-2 | naive | primary_channel | environment_state | 4 | 0.200 |
| deepseek-v3-2 | naive | primary_channel | goal_specification | 4 | 0.200 |
| deepseek-v3-2 | naive | primary_channel | retrieved_content | 4 | 0.200 |
| deepseek-v3-2 | naive | first_failed_component | instruction_resolver | 8 | 0.400 |
| deepseek-v3-2 | naive | first_failed_component | planner | 5 | 0.250 |
| deepseek-v3-2 | naive | first_failed_component | reasoner | 3 | 0.150 |
| deepseek-v3-2 | naive | first_failed_component | tool_argument_builder | 3 | 0.150 |
| deepseek-v3-2 | naive | first_failed_component | tool_selector | 1 | 0.050 |
| deepseek-v3-2 | naive | primary_mechanism | authority_overtrust | 5 | 0.250 |
| deepseek-v3-2 | naive | primary_mechanism | goal_rewrite_without_authorization | 4 | 0.200 |
| deepseek-v3-2 | naive | primary_mechanism | unsafe_tool_trust | 4 | 0.200 |
| deepseek-v3-2 | naive | primary_mechanism | instruction_data_confusion | 3 | 0.150 |
| deepseek-v3-2 | naive | primary_mechanism | unverified_state_assumption | 2 | 0.100 |
| deepseek-v3-2 | naive | primary_mechanism | unsafe_objective_optimization | 1 | 0.050 |
| deepseek-v3-2 | naive | primary_mechanism | sensitive_data_overdisclosure | 1 | 0.050 |
| gpt-4o | attribution_aware | primary_channel | tool_output | 8 | 0.400 |
| gpt-4o | attribution_aware | primary_channel | retrieved_content | 5 | 0.250 |
| gpt-4o | attribution_aware | primary_channel | environment_state | 4 | 0.200 |
| gpt-4o | attribution_aware | primary_channel | goal_specification | 3 | 0.150 |
| gpt-4o | attribution_aware | first_failed_component | instruction_resolver | 8 | 0.400 |
| gpt-4o | attribution_aware | first_failed_component | planner | 4 | 0.200 |
| gpt-4o | attribution_aware | first_failed_component | tool_argument_builder | 4 | 0.200 |
| gpt-4o | attribution_aware | first_failed_component | reasoner | 3 | 0.150 |
| gpt-4o | attribution_aware | first_failed_component | tool_selector | 1 | 0.050 |
| gpt-4o | attribution_aware | primary_mechanism | authority_overtrust | 7 | 0.350 |
| gpt-4o | attribution_aware | primary_mechanism | unsafe_tool_trust | 5 | 0.250 |
| gpt-4o | attribution_aware | primary_mechanism | goal_rewrite_without_authorization | 3 | 0.150 |
| gpt-4o | attribution_aware | primary_mechanism | unverified_state_assumption | 2 | 0.100 |
| gpt-4o | attribution_aware | primary_mechanism | unsafe_objective_optimization | 1 | 0.050 |
| gpt-4o | attribution_aware | primary_mechanism | privilege_boundary_failure | 1 | 0.050 |
| gpt-4o | attribution_aware | primary_mechanism | instruction_data_confusion | 1 | 0.050 |
| gpt-4o | guarded | primary_channel | tool_output | 9 | 0.429 |
| gpt-4o | guarded | primary_channel | retrieved_content | 5 | 0.238 |
| gpt-4o | guarded | primary_channel | environment_state | 4 | 0.190 |
| gpt-4o | guarded | primary_channel | goal_specification | 3 | 0.143 |
| gpt-4o | guarded | first_failed_component | instruction_resolver | 7 | 0.333 |
| gpt-4o | guarded | first_failed_component | tool_argument_builder | 5 | 0.238 |
| gpt-4o | guarded | first_failed_component | reasoner | 4 | 0.190 |
| gpt-4o | guarded | first_failed_component | planner | 4 | 0.190 |
| gpt-4o | guarded | first_failed_component | tool_selector | 1 | 0.048 |
| gpt-4o | guarded | primary_mechanism | unsafe_tool_trust | 7 | 0.333 |
| gpt-4o | guarded | primary_mechanism | authority_overtrust | 7 | 0.333 |
| gpt-4o | guarded | primary_mechanism | goal_rewrite_without_authorization | 3 | 0.143 |
| gpt-4o | guarded | primary_mechanism | unverified_state_assumption | 2 | 0.095 |
| gpt-4o | guarded | primary_mechanism | unsafe_objective_optimization | 1 | 0.048 |
| gpt-4o | guarded | primary_mechanism | privilege_boundary_failure | 1 | 0.048 |
| gpt-4o | naive | primary_channel | retrieved_content | 9 | 0.360 |
| gpt-4o | naive | primary_channel | tool_output | 8 | 0.320 |
| gpt-4o | naive | primary_channel | environment_state | 4 | 0.160 |
| gpt-4o | naive | primary_channel | goal_specification | 4 | 0.160 |
| gpt-4o | naive | first_failed_component | instruction_resolver | 12 | 0.480 |
| gpt-4o | naive | first_failed_component | reasoner | 4 | 0.160 |
| gpt-4o | naive | first_failed_component | planner | 4 | 0.160 |
| gpt-4o | naive | first_failed_component | tool_argument_builder | 4 | 0.160 |
| gpt-4o | naive | first_failed_component | tool_selector | 1 | 0.040 |
| gpt-4o | naive | primary_mechanism | authority_overtrust | 8 | 0.320 |
| gpt-4o | naive | primary_mechanism | unsafe_tool_trust | 5 | 0.200 |
| gpt-4o | naive | primary_mechanism | instruction_data_confusion | 4 | 0.160 |
| gpt-4o | naive | primary_mechanism | goal_rewrite_without_authorization | 3 | 0.120 |
| gpt-4o | naive | primary_mechanism | unverified_state_assumption | 2 | 0.080 |
| gpt-4o | naive | primary_mechanism | unsafe_objective_optimization | 1 | 0.040 |
| gpt-4o | naive | primary_mechanism | privilege_boundary_failure | 1 | 0.040 |
| gpt-4o | naive | primary_mechanism | sensitive_data_overdisclosure | 1 | 0.040 |
| gpt-5-4 | attribution_aware | primary_channel | goal_specification | 11 | 0.379 |
| gpt-5-4 | attribution_aware | primary_channel | tool_output | 9 | 0.310 |
| gpt-5-4 | attribution_aware | primary_channel | retrieved_content | 5 | 0.172 |
| gpt-5-4 | attribution_aware | primary_channel | environment_state | 4 | 0.138 |
| gpt-5-4 | attribution_aware | first_failed_component | tool_argument_builder | 12 | 0.414 |
| gpt-5-4 | attribution_aware | first_failed_component | planner | 8 | 0.276 |
| gpt-5-4 | attribution_aware | first_failed_component | instruction_resolver | 5 | 0.172 |
| gpt-5-4 | attribution_aware | first_failed_component | reasoner | 3 | 0.103 |
| gpt-5-4 | attribution_aware | first_failed_component | tool_selector | 1 | 0.034 |
| gpt-5-4 | attribution_aware | primary_mechanism | unsafe_tool_trust | 9 | 0.310 |
| gpt-5-4 | attribution_aware | primary_mechanism | goal_rewrite_without_authorization | 5 | 0.172 |
| gpt-5-4 | attribution_aware | primary_mechanism | authority_overtrust | 5 | 0.172 |
| gpt-5-4 | attribution_aware | primary_mechanism | unsafe_objective_optimization | 3 | 0.103 |
| gpt-5-4 | attribution_aware | primary_mechanism | privilege_boundary_failure | 3 | 0.103 |
| gpt-5-4 | attribution_aware | primary_mechanism | unverified_state_assumption | 2 | 0.069 |
| gpt-5-4 | attribution_aware | primary_mechanism | sensitive_data_overdisclosure | 2 | 0.069 |
| gpt-5-4 | guarded | primary_channel | goal_specification | 11 | 0.379 |
| gpt-5-4 | guarded | primary_channel | tool_output | 9 | 0.310 |
| gpt-5-4 | guarded | primary_channel | retrieved_content | 5 | 0.172 |
| gpt-5-4 | guarded | primary_channel | environment_state | 4 | 0.138 |
| gpt-5-4 | guarded | first_failed_component | tool_argument_builder | 12 | 0.414 |
| gpt-5-4 | guarded | first_failed_component | planner | 8 | 0.276 |
| gpt-5-4 | guarded | first_failed_component | instruction_resolver | 5 | 0.172 |
| gpt-5-4 | guarded | first_failed_component | reasoner | 3 | 0.103 |
| gpt-5-4 | guarded | first_failed_component | tool_selector | 1 | 0.034 |
| gpt-5-4 | guarded | primary_mechanism | unsafe_tool_trust | 9 | 0.310 |
| gpt-5-4 | guarded | primary_mechanism | goal_rewrite_without_authorization | 5 | 0.172 |
| gpt-5-4 | guarded | primary_mechanism | authority_overtrust | 5 | 0.172 |
| gpt-5-4 | guarded | primary_mechanism | unsafe_objective_optimization | 3 | 0.103 |
| gpt-5-4 | guarded | primary_mechanism | privilege_boundary_failure | 3 | 0.103 |
| gpt-5-4 | guarded | primary_mechanism | unverified_state_assumption | 2 | 0.069 |
| gpt-5-4 | guarded | primary_mechanism | sensitive_data_overdisclosure | 2 | 0.069 |
| gpt-5-4 | naive | primary_channel | goal_specification | 11 | 0.367 |
| gpt-5-4 | naive | primary_channel | tool_output | 10 | 0.333 |
| gpt-5-4 | naive | primary_channel | retrieved_content | 5 | 0.167 |
| gpt-5-4 | naive | primary_channel | environment_state | 4 | 0.133 |
| gpt-5-4 | naive | first_failed_component | tool_argument_builder | 12 | 0.400 |
| gpt-5-4 | naive | first_failed_component | planner | 8 | 0.267 |
| gpt-5-4 | naive | first_failed_component | instruction_resolver | 5 | 0.167 |
| gpt-5-4 | naive | first_failed_component | reasoner | 4 | 0.133 |
| gpt-5-4 | naive | first_failed_component | tool_selector | 1 | 0.033 |
| gpt-5-4 | naive | primary_mechanism | unsafe_tool_trust | 10 | 0.333 |
| gpt-5-4 | naive | primary_mechanism | goal_rewrite_without_authorization | 5 | 0.167 |
| gpt-5-4 | naive | primary_mechanism | authority_overtrust | 5 | 0.167 |
| gpt-5-4 | naive | primary_mechanism | unsafe_objective_optimization | 3 | 0.100 |
| gpt-5-4 | naive | primary_mechanism | privilege_boundary_failure | 3 | 0.100 |
| gpt-5-4 | naive | primary_mechanism | unverified_state_assumption | 2 | 0.067 |
| gpt-5-4 | naive | primary_mechanism | sensitive_data_overdisclosure | 2 | 0.067 |

## 4. Completion status

| Model | Completed | Missing |
| --- | --- | --- |
| deepseek-v3-2 | attribution_aware, guarded, naive |  |
| gpt-4o | attribution_aware, guarded, naive |  |
| gpt-4o-mini | naive | guarded, attribution_aware |
| gpt-5 | naive | guarded, attribution_aware |
| gpt-5-4 | attribution_aware, guarded, naive |  |
| grok-4-20-non-reasoning | naive | guarded, attribution_aware |
| kimi-k2-5 | guarded, naive | attribution_aware |

## 5. Files

- `artifacts/analysis/mvp/all_main_summary.csv`
- `artifacts/analysis/mvp/all_naive_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_family_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/focus_three_models_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_family_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/main_completeness.csv`
- `artifacts/analysis/mvp/pilot_b_focus_summary.csv`
