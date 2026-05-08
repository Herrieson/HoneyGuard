# HoneyGuard MVP Configs

This directory contains the MVP benchmark configuration corpus and its current experiment guide.

## Active Entry Points

- `EXPERIMENT_GUIDE.md`: authoritative runbook for current MVP experiments.
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
