# HoneyGuard MVP Test Set v0.1

This directory was produced during Task 5.1 expansion and is frozen as the MVP v0.1 `test` split in Task 5.3.

Current size:

- 40 samples total
- 10 per family across `A1`, `A4`, `C2.1`, `C2.2`

Split role:

- `configs/mvp/_archive/v0_1_splits/dev/`: 20-sample development set
- `configs/mvp/_archive/v0_1_splits/formal/`: 40-sample frozen test set
- full MVP benchmark: `dev + formal = 60`

Tracking document:

- `configs/mvp/docs/task5_expansion_checklist_v0.1.md`
- `configs/mvp/docs/benchmark_split_v0.1.md`

Validation rule for each new sample:

1. YAML loads via `scripts.init_from_config.load_config`
2. attribution-aware fields are complete
3. scenario ID is unique

Runtime validation guide:

- `configs/mvp/docs/task5_runtime_validation_v0.1.md`

To assemble the frozen test set into one runnable directory:

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split test \
  --output /tmp/hg_mvp_v01_test
```

To assemble the full 60-sample benchmark (`dev + formal`):

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split full \
  --output /tmp/hg_mvp_v01_full
```
