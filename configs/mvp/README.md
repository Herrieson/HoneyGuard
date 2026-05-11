# TraceProbe MVP Configs

This directory contains the MVP benchmark configuration corpus and its current experiment guide.

## Active Entry Points

- `EXPERIMENT_GUIDE.md`: authoritative runbook for current MVP experiments.
- `docs/v0_2_experiment_matrix.md`: compact registry of the main benchmark, controlled conditions, planned stress suites, and replay layer.
- `v0_2/`: active v0.2 benchmark dataset.
- `playground/`: optional compositional stress suite for multi-hazard experiments.
- `docs/`: active schema, ontology, scoring, and expansion notes.

## Archived Material

- `_archive/v0_1_splits/`: legacy v0.1 data splits kept for reproducibility.
- `docs/_archive/`: old planning notes, v0.1 task notes, and paper/background drafts.

## Current Main Split

Use `v0_2_test` for current benchmark runs:

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --split v0_2_test \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_2
```

Legacy split names such as `test`, `dev`, and `pilot_b` still work through `scripts/assemble_mvp_benchmark.py`, but their source YAMLs now live under `_archive/v0_1_splits/`.

For paper planning, keep the following distinction in mind:

- `v0_2_test`: main benchmark.
- `v0_2_transient`: trajectory-safety pilot.
- compositional playground (`mvp_compositional_playground`): multi-hazard stress suite.
- `v0_2_small`: current calibrated subset with 24 fixed samples.
- `v0_2_task_hard` / `v0_2_risk_broad` / `v0_2_attack_hard`: recommended derived suite names, currently treated as design/planning terms unless materialized separately.
