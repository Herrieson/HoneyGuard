# HoneyGuard MVP Result Analysis

## 1. Three-model horizontal comparison



## 2. All naive model comparison

| Model | Split | Eval N | Infra Fail | TSR | SVR | STCR | ASR | Latent | Unsafe IntExp |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| claude-opus-4-6 | v0_2_test | 155 | 0.000 | 0.858 | 0.110 | 0.729 | 0.105 | 0.090 | 0.026 |
| claude-sonnet-4-6 | v0_2_test | 155 | 0.000 | 0.826 | 0.219 | 0.665 | 0.248 | 0.200 | 0.123 |
| deepseek-v4-pro | v0_2_test | 155 | 0.000 | 0.826 | 0.310 | 0.561 | 0.400 | 0.284 | 0.084 |
| gpt-5-2 | v0_2_test | 155 | 0.000 | 0.735 | 0.148 | 0.626 | 0.190 | 0.123 | 0.019 |
| gpt-5-5 | v0_2_test | 155 | 0.000 | 0.865 | 0.058 | 0.735 | 0.076 | 0.045 | 0.006 |
| gpt-5-mini | v0_2_test | 155 | 0.000 | 0.684 | 0.323 | 0.452 | 0.410 | 0.303 | 0.110 |
| deepseek-v4-flash | v0_2_test | 154 | 0.006 | 0.883 | 0.403 | 0.468 | 0.543 | 0.383 | 0.091 |
| gemini-3-1-flash-lite-preview | v0_2_test | 154 | 0.006 | 0.636 | 0.461 | 0.325 | 0.654 | 0.429 | 0.078 |
| gemini-3-1-pro-preview | v0_2_test | 154 | 0.006 | 0.838 | 0.260 | 0.571 | 0.385 | 0.253 | 0.117 |
| gemini-3-flash-preview | v0_2_test | 154 | 0.006 | 0.773 | 0.403 | 0.429 | 0.587 | 0.396 | 0.104 |
| gpt-5 | v0_2_test | 151 | 0.026 | 0.715 | 0.192 | 0.636 | 0.252 | 0.166 | 0.132 |
| grok-4 | v0_2_test | 131 | 0.155 | 0.771 | 0.282 | 0.534 | 0.370 | 0.282 | 0.076 |

## 3. Attribution over observed failures

This is not manual eyeballing: each failed/latent run is grouped by the benchmark's task-side attribution labels. It explains what failure classes each model actually triggered.



## 4. Completion status

| Model | Completed | Missing |
| --- | --- | --- |
| claude-opus-4-6 | naive | guarded |
| claude-sonnet-4-6 | naive | guarded |
| deepseek-v4-flash | naive | guarded |
| deepseek-v4-pro | naive | guarded |
| gemini-3-1-flash-lite-preview | naive | guarded |
| gemini-3-1-pro-preview | naive | guarded |
| gemini-3-flash-preview | naive | guarded |
| gpt-5 | naive | guarded |
| gpt-5-2 | naive | guarded |
| gpt-5-5 | naive | guarded |
| gpt-5-mini | naive | guarded |
| grok-4 | naive | guarded |

## 5. Files

- `artifacts/analysis/mvp/all_main_summary.csv`
- `artifacts/analysis/mvp/all_naive_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_family_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/attribution_rule_v0_2_summary.csv`
- `artifacts/analysis/mvp/focus_three_models_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_family_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/main_completeness.csv`
- `artifacts/analysis/mvp/pilot_b_focus_summary.csv`
