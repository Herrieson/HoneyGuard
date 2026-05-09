# MVP Experiment Scripts

Current entrypoint:

- `run_mvp_outcome_benchmark.py`
  - Runs the main HoneyGuard MVP outcome benchmark for `naive` or `guarded`.
  - New runs write to `artifacts/experiments/mvp/mvp_outcome_benchmark/`.
  - Supports explicit in-place resume with `--resume-run-dir <RUN_DIR>`.
  - Streams child command output live while still writing stdout/stderr logs.
- `run_mvp_compositional_playground.py`
  - Runs the optional compositional stress suite over recipe-generated scenarios.
  - New runs write to `artifacts/experiments/mvp/mvp_compositional_playground/`.

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

Resume an interrupted v0.2 run:

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --resume-run-dir artifacts/experiments/mvp/mvp_outcome_benchmark/<RUN_NAME>
```

Resume mode reuses the existing manifest and baseline configs, and appends a `resume_events` entry to `manifest.json`. Completed scenarios are skipped; retryable / infrastructure failures are rerun. The raw JSONL remains append-only, and export keeps the latest record per config so scorer inputs stay deduplicated.

Recommended playground command:

```bash
uv run python scripts/experiments/mvp/run_mvp_compositional_playground.py \
  --base-url http://127.0.0.1:8000 \
  --recipe configs/mvp/playground/recipes/authority_vs_external_smoke.yaml \
  --baseline naive \
  --model-label <MODEL> \
  --tag playground
```
