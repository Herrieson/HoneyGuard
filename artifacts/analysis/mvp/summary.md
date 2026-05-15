# HoneyGuard MVP Result Analysis

## 1. Three-model horizontal comparison



## 2. All naive model comparison

| Model | Split | Eval N | Infra Fail | TSR | SVR | STCR | ASR | Latent | Unsafe IntExp |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| claude-opus-4-6 | v0_2_test | 155 | 0.000 | 0.852 | 0.103 | 0.755 | 0.095 | 0.097 | 0.019 |
| claude-sonnet-4-6 | v0_2_test | 155 | 0.000 | 0.819 | 0.219 | 0.639 | 0.238 | 0.194 | 0.116 |
| deepseek-v4-flash | v0_2_test | 155 | 0.000 | 0.852 | 0.400 | 0.465 | 0.533 | 0.387 | 0.090 |
| gemini-3-1-flash-lite-preview | v0_2_test | 155 | 0.000 | 0.626 | 0.465 | 0.310 | 0.667 | 0.432 | 0.077 |
| gemma-4-31b-it | v0_2_test | 155 | 0.000 | 0.761 | 0.271 | 0.587 | 0.381 | 0.258 | 0.116 |
| gpt-5-2 | v0_2_test | 155 | 0.000 | 0.761 | 0.097 | 0.677 | 0.143 | 0.097 | 0.013 |
| gpt-5-5 | v0_2_test | 155 | 0.000 | 0.832 | 0.058 | 0.716 | 0.076 | 0.045 | 0.006 |
| gpt-5-mini | v0_2_test | 155 | 0.000 | 0.684 | 0.290 | 0.503 | 0.381 | 0.271 | 0.103 |
| minimax-m2-5 | v0_2_test | 155 | 0.000 | 0.858 | 0.161 | 0.729 | 0.219 | 0.142 | 0.013 |
| mirothinker-1-7 | v0_2_test | 147 | 0.000 | 0.007 | 0.020 | 0.007 | 0.031 | 0.020 | 0.014 |
| gemini-3-flash-preview | v0_2_test | 154 | 0.006 | 0.766 | 0.383 | 0.455 | 0.558 | 0.377 | 0.104 |
| deepseek-v4-pro | v0_2_test | 153 | 0.013 | 0.778 | 0.353 | 0.516 | 0.467 | 0.327 | 0.072 |
| gemini-3-1-pro-preview | v0_2_test | 139 | 0.077 | 0.820 | 0.266 | 0.576 | 0.402 | 0.259 | 0.108 |

## 3. Attribution over observed failures

This is not manual eyeballing: each failed/latent run is grouped by the benchmark's task-side attribution labels. It explains what failure classes each model actually triggered.



## 4. Completion status

| Model | Completed | Missing |
| --- | --- | --- |
| claude-opus-4-6 | guarded, naive |  |
| claude-sonnet-4-6 | guarded, naive |  |
| deepseek-v4-flash | guarded, naive |  |
| deepseek-v4-pro | guarded, naive |  |
| gemini-3-1-flash-lite-preview | guarded, naive |  |
| gemini-3-1-pro-preview | naive | guarded |
| gemini-3-flash-preview | guarded, naive |  |
| gemma-4-31b-it | naive | guarded |
| gpt-5-2 | guarded, naive |  |
| gpt-5-5 | guarded, naive |  |
| gpt-5-mini | guarded, naive |  |
| minimax-m2-5 | naive | guarded |
| mirothinker-1-7 | naive | guarded |

## 5. Files

- `artifacts/analysis/mvp/all_main_summary.csv`
- `artifacts/analysis/mvp/all_naive_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_family_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/attribution_evidence_rule_v0_2_summary.csv`
- `artifacts/analysis/mvp/attribution_rule_v0_2_summary.csv`
- `artifacts/analysis/mvp/focus_three_models_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_family_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/guard_delta_family_breakdown.csv`
- `artifacts/analysis/mvp/guard_delta_summary.csv`
- `artifacts/analysis/mvp/main_completeness.csv`
- `artifacts/analysis/mvp/pilot_b_focus_summary.csv`
