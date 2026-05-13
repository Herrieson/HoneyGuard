# MVP Experiment Scripts

Current entrypoint:

- `run_mvp_outcome_benchmark.py`
  - Runs the main HoneyGuard MVP outcome benchmark for `naive` or `guarded`.
  - Also accepts `v0_2_small` as the calibrated low-cost screening split.
  - New runs write to `artifacts/experiments/mvp/mvp_outcome_benchmark/`.
  - Supports explicit in-place resume with `--resume-run-dir <RUN_DIR>`.
  - Streams child command output live while still writing stdout/stderr logs.
- `run_mvp_model_batch.py`
  - Starts one TraceProbe API server per model, waits for runtime metadata, runs one or more MVP jobs, then stops the server.
  - Use this when running many models so you do not manually restart uvicorn after changing `OPENAI_MODEL`.
  - Preserves the existing runtime-model match check; it does not bypass provenance validation.
  - Batch manifests and server logs write to `artifacts/experiments/mvp/batch_runs/`.
- `run_mvp_compositional_playground.py`
  - Runs the optional compositional stress suite over recipe-generated scenarios.
  - Recommended v0.2 recipe: `configs/mvp/playground/recipes/v0_2_compositional_playground.yaml` (60 generated scenarios).
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

Run several models without manually restarting the API server:

```bash
export OPENAI_API_KEY="..."
export OPENAI_BASE_URL="https://your-provider/v1"

uv run python scripts/experiments/mvp/run_mvp_model_batch.py \
  --models deepseek-v4-flash deepseek-v4-pro gpt-5.5 gpt-5-mini \
  --baseline naive \
  --baseline guarded \
  --tag v0_2 \
  --continue-on-error
```

The batch runner starts uvicorn with `OPENAI_MODEL=<MODEL>` for each model, waits for `/v1/server/runtime_metadata`, invokes `run_mvp_outcome_benchmark.py`, and shuts the server down before moving to the next model.

For providers that need different keys or base URLs, use a matrix YAML:

```yaml
models:
  - label: gpt-5.5
    env:
      OPENAI_BASE_URL: ${OPENAI_BASE_URL_OPENAI}
      OPENAI_API_KEY: ${OPENAI_API_KEY_OPENAI}
      OPENAI_MODEL: gpt-5.5
  - label: claude-sonnet-4-6
    env:
      OPENAI_BASE_URL: ${OPENAI_BASE_URL_ANTHROPIC_COMPAT}
      OPENAI_API_KEY: ${OPENAI_API_KEY_ANTHROPIC}
      OPENAI_MODEL: claude-sonnet-4-6
jobs:
  - suite: outcome
    split: v0_2_test
    baseline: naive
    tag: v0_2
  - suite: outcome
    split: v0_2_test
    baseline: guarded
    tag: v0_2
```

```bash
uv run python scripts/experiments/mvp/run_mvp_model_batch.py \
  --matrix configs/mvp/private_model_matrix.yaml \
  --continue-on-error
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
  --recipe configs/mvp/playground/recipes/v0_2_compositional_playground.yaml \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_2_compositional_playground
```

Batch playground command:

```bash
uv run python scripts/experiments/mvp/run_mvp_model_batch.py \
  --models gpt-5.5 gpt-5-mini claude-sonnet-4-6 \
  --suite playground \
  --recipe configs/mvp/playground/recipes/v0_2_compositional_playground.yaml \
  --baseline naive \
  --tag v0_2_compositional_playground \
  --continue-on-error
```

Batch transient command:

```bash
uv run python scripts/experiments/mvp/run_mvp_model_batch.py \
  --models gpt-5.5 gpt-5-mini claude-sonnet-4-6 \
  --split v0_2_transient \
  --baseline naive \
  --tag v0_2_transient \
  --continue-on-error
```
