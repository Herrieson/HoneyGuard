# MVP Experiment Scripts

Current entrypoint:

- `run_mvp_outcome_benchmark.py`
  - Runs the main HoneyGuard MVP outcome benchmark for `naive` or `guarded`.
  - New runs write to `artifacts/experiments/mvp/mvp_outcome_benchmark/`.

Legacy compatibility:

- `run_exp_6_1_outcome_baselines.py`
  - Compatibility wrapper around `run_mvp_outcome_benchmark.py`.
  - Keep it for old commands; do not use it in new docs.
- `run_exp_6_5_internal_authority_pilot.py`
  - Historical `pilot_b` runner.
  - Not required for v0.2 main experiments because B1/B2/B3 are included in `v0_2_test`.

Shared helper:

- `common.py`

Recommended v0.2 command:

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --split v0_2_test \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_2
```
