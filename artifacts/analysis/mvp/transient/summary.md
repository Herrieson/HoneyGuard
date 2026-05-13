# HoneyGuard MVP Result Analysis

## 1. Three-model horizontal comparison



## 2. All naive model comparison

| Model | Split | Eval N | Infra Fail | TSR | SVR | STCR | ASR | Latent | Unsafe IntExp |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| claude-opus-4-6 | v0_2_transient | 8 | 0.000 | 1.000 | 0.000 | 0.750 | 0.000 | 0.000 | 0.000 |
| claude-sonnet-4-6 | v0_2_transient | 8 | 0.000 | 1.000 | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| deepseek-v4-flash | v0_2_transient | 8 | 0.000 | 0.750 | 0.375 | 0.625 | 0.429 | 0.375 | 0.000 |
| deepseek-v4-pro | v0_2_transient | 8 | 0.000 | 0.875 | 0.375 | 0.625 | 0.429 | 0.375 | 0.000 |
| gemini-3-1-flash-lite-preview | v0_2_transient | 8 | 0.000 | 0.750 | 0.375 | 0.500 | 0.429 | 0.375 | 0.000 |
| gemini-3-flash-preview | v0_2_transient | 8 | 0.000 | 1.000 | 0.250 | 0.750 | 0.286 | 0.250 | 0.000 |
| gpt-5-2 | v0_2_transient | 8 | 0.000 | 1.000 | 0.125 | 0.625 | 0.143 | 0.125 | 0.000 |
| gpt-5-5 | v0_2_transient | 8 | 0.000 | 1.000 | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| gpt-5-mini | v0_2_transient | 8 | 0.000 | 1.000 | 0.250 | 0.750 | 0.286 | 0.125 | 0.000 |

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
| gemini-3-flash-preview | naive | guarded |
| gpt-5-2 | naive | guarded |
| gpt-5-5 | naive | guarded |
| gpt-5-mini | naive | guarded |

## 5. Files

- `artifacts/analysis/mvp/transient/all_main_summary.csv`
- `artifacts/analysis/mvp/transient/all_naive_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/transient/all_naive_family_breakdown.csv`
- `artifacts/analysis/mvp/transient/all_naive_summary.csv`
- `artifacts/analysis/mvp/transient/focus_three_models_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/transient/focus_three_models_family_breakdown.csv`
- `artifacts/analysis/mvp/transient/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/transient/main_completeness.csv`
- `artifacts/analysis/mvp/transient/pilot_b_focus_summary.csv`
